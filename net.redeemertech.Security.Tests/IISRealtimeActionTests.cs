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

        [TestInitialize]
        public void Initialize()
        {
            IISAlertRequestRuleProcessor.ResetStateForTests();
            IISAlertRealtimeActionProcessor.ResetTestHooks();
            IISAlertRequestRuleProcessor.CurrentDateTime = () => _now;
            IISAlertRealtimeActionProcessor.ExceptionLoggerOverride = exception => { };
        }

        [TestCleanup]
        public void Cleanup()
        {
            IISAlertRealtimeActionProcessor.ResetTestHooks();
            IISAlertRequestRuleProcessor.ResetStateForTests();
        }

        [TestMethod]
        public void ConcurrentMatchesThrottleNotificationButEnforceDistinctTargets()
        {
            var events = new ConcurrentBag<IISAlertRealtimeEvent>();
            IISAlertRealtimeActionProcessor.QueueOverride = alertEvent =>
            {
                events.Add( alertEvent );
                return true;
            };
            var configuration = Configuration( Rule( blockIp: true, lockAccounts: true ) );

            Parallel.Invoke(
                () => IISAlertRequestRuleProcessor.Process( configuration, Snapshot( "192.0.2.10", "alice" ), IISRequestRuleStage.PostAuthentication ),
                () => IISAlertRequestRuleProcessor.Process( configuration, Snapshot( "192.0.2.11", "bob" ), IISRequestRuleStage.PostAuthentication ) );

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
        public void NextNotificationReportsMatchesSuppressedDuringPriorInterval()
        {
            var events = new List<IISAlertRealtimeEvent>();
            IISAlertRealtimeActionProcessor.QueueOverride = alertEvent =>
            {
                events.Add( alertEvent );
                return true;
            };
            var configuration = Configuration( Rule() );

            IISAlertRequestRuleProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            IISAlertRequestRuleProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            IISAlertRequestRuleProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            IISAlertRequestRuleProcessor.CurrentDateTime = () => _now.AddMinutes( 6 );
            IISAlertRequestRuleProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );

            Assert.AreEqual( 2, events.Count );
            Assert.AreEqual( 2, events[1].SuppressedMatchCount );
            Assert.AreEqual( "2", events[1].Result["SuppressedMatchCount"] );
        }

        [TestMethod]
        public void QueuedEventRetainsCapturedRuleSettingsAfterConfigurationChanges()
        {
            IISAlertRealtimeEvent capturedEvent = null;
            IISAlertRealtimeActionProcessor.QueueOverride = alertEvent =>
            {
                capturedEvent = alertEvent;
                return true;
            };
            var originalRule = Rule( name: "Original", summary: "Original summary", recipients: "old@example.org" );

            IISAlertRequestRuleProcessor.Process( Configuration( originalRule ), Snapshot(), IISRequestRuleStage.PostAuthentication );
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
            IISAlertRealtimeActionProcessor.ExceptionLoggerOverride = exception => loggedExceptions++;
            IISAlertRealtimeActionProcessor.ResolveSummaryOverride = alertEvent => "summary";
            IISAlertRealtimeActionProcessor.PersistHistoryOverride = alertEvent =>
            {
                throw new InvalidOperationException( "injected history failure" );
            };
            IISAlertRealtimeActionProcessor.PersistIpBlockOverride = ( alertEvent, historyId ) =>
            {
                ipAttempts++;
                if ( ipAttempts < 3 )
                {
                    throw new InvalidOperationException( "injected IP persistence failure" );
                }
            };
            IISAlertRealtimeActionProcessor.LockOutUserAccountOverride = alertEvent => accountAttempts++;
            IISAlertRealtimeActionProcessor.SendAlertEmailOverride = ( alertEvent, summary, historyId ) =>
            {
                emailAttempts++;
                throw new InvalidOperationException( "injected email failure" );
            };
            IISAlertRealtimeActionProcessor.QueueOverride = alertEvent =>
            {
                queuedEvents.Add( alertEvent );
                IISAlertRealtimeActionProcessor.Process( alertEvent );
                return true;
            };
            var configuration = Configuration( Rule( blockIp: true, lockAccounts: true ) );
            var snapshot = Snapshot( "192.0.2.20", "alice" );

            IISAlertRequestRuleProcessor.Process( configuration, snapshot, IISRequestRuleStage.PostAuthentication );
            IISAlertRequestRuleProcessor.Process( configuration, snapshot, IISRequestRuleStage.PostAuthentication );

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
            IISAlertRealtimeActionProcessor.ExceptionLoggerOverride = exception => { throw new Exception( "logger unavailable" ); };
            IISAlertRealtimeActionProcessor.PersistHistoryOverride = alertEvent => new IISAlertHistoryResult { HistoryId = null, Summary = "captured summary" };
            IISAlertRealtimeActionProcessor.PersistIpBlockOverride = ( alertEvent, historyId ) => { throw new Exception( "database unavailable" ); };
            IISAlertRealtimeActionProcessor.LockOutUserAccountOverride = alertEvent => accounts++;
            IISAlertRealtimeActionProcessor.SendAlertEmailOverride = ( alertEvent, summary, historyId ) =>
            {
                Assert.IsNull( historyId );
                Assert.AreEqual( "captured summary", summary );
                emails++;
            };
            IISAlertRealtimeActionProcessor.QueueOverride = alertEvent =>
            {
                IISAlertRealtimeActionProcessor.Process( alertEvent );
                return true;
            };
            IISAlertRequestRuleProcessor.Process( Configuration( Rule( blockIp: true, lockAccounts: true ) ), Snapshot(), IISRequestRuleStage.PostAuthentication );
            Assert.AreEqual( 1, accounts );
            Assert.AreEqual( 1, emails );
        }

        [TestMethod]
        public void RejectedQueueReleasesClaimsForTheNextMatch()
        {
            var events = new List<IISAlertRealtimeEvent>();
            IISAlertRealtimeActionProcessor.QueueOverride = alertEvent =>
            {
                events.Add( alertEvent );
                return events.Count > 1;
            };
            var configuration = Configuration( Rule( lockAccounts: true ) );
            IISAlertRequestRuleProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            IISAlertRequestRuleProcessor.Process( configuration, Snapshot(), IISRequestRuleStage.PostAuthentication );
            Assert.AreEqual( 2, events.Count );
            Assert.IsTrue( events[1].NotificationClaimed );
            Assert.AreEqual( "user", events[1].UserNameToLockOut );
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
            bool lockAccounts = false )
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
                false,
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
    }
}
