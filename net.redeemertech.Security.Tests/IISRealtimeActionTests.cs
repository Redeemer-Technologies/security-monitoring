using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security.Model;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class IISRealtimeActionTests
    {
        private readonly DateTime _now = new DateTime( 2026, 9, 4, 12, 0, 0, DateTimeKind.Local );
        private AdjustableClock _clock;
        private RecordingActionQueue _queue;
        private IISAlertRequestRuleProcessor _requestProcessor;

        [TestInitialize]
        public void Initialize()
        {
            _clock = new AdjustableClock { Now = _now };
            _queue = new RecordingActionQueue();
            _requestProcessor = new IISAlertRequestRuleProcessor( _queue, _clock );
        }

        [TestMethod]
        public void ConcurrentMatchesThrottleNotificationButEnforceDistinctTargets()
        {
            var events = new ConcurrentBag<IISAlertRealtimeEvent>();
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                events.Add( alertEvent );
                return true;
            };
            var configuration = Configuration( Rule( blockIp: true, lockAccounts: true ) );

            Parallel.Invoke(
                () => _requestProcessor.Process( configuration, Snapshot( "192.0.2.10", "alice" ), IISRequestRuleStage.PostAuthentication ),
                () => _requestProcessor.Process( configuration, Snapshot( "192.0.2.11", "bob" ), IISRequestRuleStage.PostAuthentication ) );

            Assert.AreEqual( 2, events.Count );
            Assert.AreEqual( 1, events.Count( alertEvent => alertEvent.NotificationClaimed ) );
            CollectionAssert.AreEquivalent(
                new[] { "192.0.2.10", "192.0.2.11" },
                events.Select( alertEvent => alertEvent.IpAddressToPersist ).ToArray() );
            CollectionAssert.AreEquivalent(
                new[] { "alice", "bob" },
                events.Select( alertEvent => alertEvent.UserNameToLockOut ).ToArray() );
        }

        [TestMethod]
        public void ProcessorInstancesDoNotShareClaimsOrClockState()
        {
            var firstEvents = new List<IISAlertRealtimeEvent>();
            var secondEvents = new List<IISAlertRealtimeEvent>();
            var firstQueue = new RecordingActionQueue
            {
                OnQueue = ( alertEvent, claimReleaser ) =>
                {
                    firstEvents.Add( alertEvent );
                    return true;
                }
            };
            var secondQueue = new RecordingActionQueue
            {
                OnQueue = ( alertEvent, claimReleaser ) =>
                {
                    secondEvents.Add( alertEvent );
                    return true;
                }
            };
            var configuration = Configuration( Rule() );

            new IISAlertRequestRuleProcessor( firstQueue, new AdjustableClock { Now = _now } )
                .Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            new IISAlertRequestRuleProcessor( secondQueue, new AdjustableClock { Now = _now.AddHours( 1 ) } )
                .Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );

            Assert.AreEqual( 1, firstEvents.Count );
            Assert.AreEqual( 1, secondEvents.Count );
            Assert.AreEqual( _now, firstEvents[0].MatchedDateTime );
            Assert.AreEqual( _now.AddHours( 1 ), secondEvents[0].MatchedDateTime );
        }

        [TestMethod]
        public void NextNotificationReportsMatchesSuppressedDuringPriorInterval()
        {
            var events = new List<IISAlertRealtimeEvent>();
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                events.Add( alertEvent );
                return true;
            };
            var configuration = Configuration( Rule() );

            _requestProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            _requestProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            _requestProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            _clock.Now = _now.AddMinutes( 6 );
            _requestProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );

            Assert.AreEqual( 2, events.Count );
            Assert.AreEqual( 2, events[1].SuppressedMatchCount );
            Assert.AreEqual( "2", events[1].Result["SuppressedMatchCount"] );
        }

        [TestMethod]
        public void QueuedEventRetainsCapturedRuleSettingsAfterConfigurationChanges()
        {
            IISAlertRealtimeEvent capturedEvent = null;
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                capturedEvent = alertEvent;
                return true;
            };
            var originalRule = Rule( name: "Original", summary: "Original summary", recipients: "old@example.org" );

            _requestProcessor.Process( Configuration( originalRule ), Snapshot(), IISRequestRuleStage.PostAuthentication );
            var changedRule = Rule( name: "Changed", summary: "Changed summary", recipients: "new@example.org" );

            Assert.IsNotNull( capturedEvent );
            Assert.AreEqual( "Original", capturedEvent.RuleName );
            Assert.AreEqual( "Original summary", capturedEvent.SummaryLava );
            Assert.AreEqual( "old@example.org", capturedEvent.NotificationEmails.Single() );
            Assert.AreEqual( originalRule.Version, capturedEvent.RuleVersion );
            Assert.AreNotEqual( changedRule.Version, capturedEvent.RuleVersion );
            Assert.AreEqual( _now, capturedEvent.MatchedDateTime );
        }

        [TestMethod]
        public void IndependentFailuresDoNotStopActionsAndIdempotentEnforcementRetriesInWorker()
        {
            var ipAttempts = 0;
            var accountAttempts = 0;
            var emailAttempts = 0;
            var loggedExceptions = 0;
            var queuedEvents = new List<IISAlertRealtimeEvent>();
            var operations = new FakeActionOperations();
            var actionProcessor = new IISAlertRealtimeActionProcessor(
                operations,
                new DelegateExceptionLogger( exception => loggedExceptions++ ) );
            operations.ResolveSummaryAction = alertEvent => "summary";
            operations.PersistHistoryAction = alertEvent =>
            {
                throw new InvalidOperationException( "injected history failure" );
            };
            operations.PersistIpBlockAction = ( alertEvent, historyId ) =>
            {
                ipAttempts++;
                if ( ipAttempts < 3 )
                {
                    throw new InvalidOperationException( "injected IP persistence failure" );
                }
            };
            operations.LockOutUserAccountAction = alertEvent =>
            {
                accountAttempts++;
                return true;
            };
            operations.SendAlertEmailAction = ( alertEvent, summary, historyId ) =>
            {
                emailAttempts++;
                throw new InvalidOperationException( "injected email failure" );
            };
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                queuedEvents.Add( alertEvent );
                actionProcessor.Process( alertEvent, claimReleaser );
                return true;
            };
            var configuration = Configuration( Rule( blockIp: true, lockAccounts: true ) );
            var snapshot = Snapshot( "192.0.2.20", "alice" );

            _requestProcessor.Process( configuration, snapshot, IISRequestRuleStage.PostAuthentication );
            _requestProcessor.Process( configuration, snapshot, IISRequestRuleStage.PostAuthentication );

            Assert.AreEqual( 3, ipAttempts, "The idempotent IP action should retry within the worker." );
            Assert.AreEqual( 1, accountAttempts, "A successful account action should remain deduplicated." );
            Assert.AreEqual( 1, emailAttempts, "Notification delivery should remain on its independent cooldown." );
            Assert.AreEqual( 2, loggedExceptions, "History and email failures should each be logged without aborting enforcement." );
            Assert.AreEqual( 1, queuedEvents.Count, "The second match should not duplicate successful enforcement." );
            Assert.AreEqual( "Failed", queuedEvents[0].ActionOutcomes["ActionHistory"] );
            Assert.AreEqual( "Succeeded", queuedEvents[0].ActionOutcomes["ActionIpBlock"] );
            Assert.AreEqual( "Succeeded", queuedEvents[0].ActionOutcomes["ActionAccountLockout"] );
            Assert.AreEqual( "Failed", queuedEvents[0].ActionOutcomes["ActionEmail"] );
        }

        [TestMethod]
        public void DeletedHistoryAndFailedLoggerDoNotPreventCapturedEnforcementOrEmail()
        {
            var accounts = 0;
            var emails = 0;
            var operations = new FakeActionOperations();
            var actionProcessor = new IISAlertRealtimeActionProcessor(
                operations,
                new DelegateExceptionLogger( exception => { throw new Exception( "logger unavailable" ); } ) );
            operations.PersistHistoryAction = alertEvent => new IISAlertHistoryResult { HistoryId = null, Summary = "captured summary" };
            operations.PersistIpBlockAction = ( alertEvent, historyId ) => { throw new Exception( "database unavailable" ); };
            operations.LockOutUserAccountAction = alertEvent =>
            {
                accounts++;
                return true;
            };
            operations.SendAlertEmailAction = ( alertEvent, summary, historyId ) =>
            {
                Assert.IsNull( historyId );
                Assert.AreEqual( "captured summary", summary );
                emails++;
            };
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                actionProcessor.Process( alertEvent, claimReleaser );
                return true;
            };
            _requestProcessor.Process( Configuration( Rule( blockIp: true, lockAccounts: true ) ), Snapshot(), IISRequestRuleStage.PostAuthentication );
            Assert.AreEqual( 1, accounts );
            Assert.AreEqual( 1, emails );
        }

        [TestMethod]
        public void RejectedQueueReleasesClaimsForTheNextMatch()
        {
            var events = new List<IISAlertRealtimeEvent>();
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                events.Add( alertEvent );
                return events.Count > 1;
            };
            var configuration = Configuration( Rule( lockAccounts: true ) );
            _requestProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            _requestProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            Assert.AreEqual( 2, events.Count );
            Assert.IsTrue( events[1].NotificationClaimed );
            Assert.AreEqual( "user", events[1].UserNameToLockOut );
        }

        [TestMethod]
        public void LocalRequestStillNotifiesButSuppressesEveryEnforcementAction()
        {
            IISAlertRealtimeEvent capturedEvent = null;
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                capturedEvent = alertEvent;
                return true;
            };
            var snapshot = Snapshot();
            snapshot.IsLocalRequest = true;

            var blockResult = _requestProcessor.Process(
                Configuration( Rule( blockIp: true, lockAccounts: true, blockRequest: true ) ),
                snapshot,
                IISRequestRuleStage.PostAuthentication );

            Assert.IsNull( blockResult );
            Assert.IsNotNull( capturedEvent );
            Assert.IsTrue( capturedEvent.NotificationClaimed );
            Assert.IsNull( capturedEvent.IpAddressToPersist );
            Assert.IsNull( capturedEvent.UserNameToLockOut );
        }

        [TestMethod]
        public void ProtectedAdministratorIdentitySuppressesOnlyAccountLockout()
        {
            IISAlertRealtimeEvent capturedEvent = null;
            _queue.OnQueue = ( alertEvent, claimReleaser ) =>
            {
                capturedEvent = alertEvent;
                return true;
            };
            var snapshot = Snapshot();
            snapshot.SetIdentity( true, "administrator", Guid.NewGuid(), true );

            _requestProcessor.Process(
                Configuration( Rule( blockIp: true, lockAccounts: true ) ),
                snapshot,
                IISRequestRuleStage.PostAuthentication );

            Assert.IsNotNull( capturedEvent );
            Assert.AreEqual( "192.0.2.1", capturedEvent.IpAddressToPersist );
            Assert.IsNull( capturedEvent.UserNameToLockOut );
        }

        private static IISAlertRuleConfiguration Configuration( IISRealtimeRule rule )
        {
            return new IISAlertRuleConfiguration( new[] { rule } );
        }

        private static IISRealtimeRule Rule(
            string name = "Rule",
            string summary = "Summary",
            string recipients = "alerts@example.org",
            bool blockIp = false,
            bool lockAccounts = false,
            bool blockRequest = false )
        {
            var condition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.Equal,
                Value = "/login",
                IgnoreCase = true
            };
            return new IISRealtimeRule(
                7,
                name,
                IISRequestRuleStage.PostAuthentication,
                IISRequestRuleConditionLogic.All,
                summary,
                recipients,
                5,
                blockRequest,
                403,
                "Forbidden",
                blockIp,
                30,
                lockAccounts,
                new[] { condition },
                new[] { new IISRequestRuleConditionMatcher( condition ) } );
        }

        private static IISRequestRuleSnapshot Snapshot( string ipAddress = "192.0.2.1", string userName = "user" )
        {
            var snapshot = new IISRequestRuleSnapshot();
            snapshot.SetValue( IISRequestRuleField.Path, "/login" );
            snapshot.SetValue( IISRequestRuleField.ClientIp, ipAddress );
            snapshot.SetIdentity( true, userName, null );
            return snapshot;
        }

        private sealed class AdjustableClock : IIISAlertClock
        {
            public DateTime Now { get; set; }
        }

        private sealed class RecordingActionQueue : IIISAlertRealtimeActionQueue
        {
            public Func<IISAlertRealtimeEvent, IIISAlertClaimReleaser, bool> OnQueue { get; set; }

            public bool Queue( IISAlertRealtimeEvent alertEvent, IIISAlertClaimReleaser claimReleaser )
            {
                return OnQueue == null || OnQueue( alertEvent, claimReleaser );
            }
        }

        private sealed class DelegateExceptionLogger : IIISAlertExceptionLogger
        {
            private readonly Action<Exception> _log;

            public DelegateExceptionLogger( Action<Exception> log )
            {
                _log = log;
            }

            public void Log( Exception exception )
            {
                _log( exception );
            }
        }

        private sealed class FakeActionOperations : IIISAlertRealtimeActionOperations
        {
            public Func<IISAlertRealtimeEvent, IISAlertHistoryResult> PersistHistoryAction { get; set; }

            public Action<IISAlertRealtimeEvent, int?> PersistIpBlockAction { get; set; }

            public Func<IISAlertRealtimeEvent, bool> LockOutUserAccountAction { get; set; }

            public Action<IISAlertRealtimeEvent, string, int?> SendAlertEmailAction { get; set; }

            public Action<int, Dictionary<string, string>> UpdateHistoryOutcomesAction { get; set; }

            public Func<IISAlertRealtimeEvent, string> ResolveSummaryAction { get; set; }

            public IISAlertHistoryResult PersistHistory( IISAlertRealtimeEvent alertEvent )
            {
                return PersistHistoryAction == null
                    ? new IISAlertHistoryResult()
                    : PersistHistoryAction( alertEvent );
            }

            public void PersistIpBlock( IISAlertRealtimeEvent alertEvent, int? historyId )
            {
                PersistIpBlockAction?.Invoke( alertEvent, historyId );
            }

            public bool LockOutUserAccount( IISAlertRealtimeEvent alertEvent )
            {
                return LockOutUserAccountAction == null || LockOutUserAccountAction( alertEvent );
            }

            public void SendAlertEmail( IISAlertRealtimeEvent alertEvent, string summary, int? historyId )
            {
                SendAlertEmailAction?.Invoke( alertEvent, summary, historyId );
            }

            public void UpdateHistoryOutcomes( int historyId, Dictionary<string, string> result )
            {
                UpdateHistoryOutcomesAction?.Invoke( historyId, result );
            }

            public string ResolveSummary( IISAlertRealtimeEvent alertEvent )
            {
                return ResolveSummaryAction == null ? string.Empty : ResolveSummaryAction( alertEvent );
            }
        }
    }
}
