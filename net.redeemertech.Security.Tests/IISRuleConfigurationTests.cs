using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security.Model;

using Rock.Model;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http.Controllers;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class IISRuleConfigurationTests
    {
        [TestMethod]
        public void ConcurrentReloadsAreSerializedAndPublishTheLatestConfiguration()
        {
            var firstConfiguration = CreateConfiguration( "X-First", "first" );
            var secondConfiguration = CreateConfiguration( "X-Second", "second" );
            var firstLoaderEntered = new ManualResetEventSlim();
            var allowFirstLoaderToFinish = new ManualResetEventSlim();
            var secondCallStarted = new ManualResetEventSlim();
            var secondLoaderEntered = new ManualResetEventSlim();
            var activeLoaders = 0;
            var maximumActiveLoaders = 0;
            Task firstReload = null;
            Task secondReload = null;

            var previousConfiguration = IISAlertRuleCache.PublishConfiguration( new IISAlertRuleConfiguration( new IISRealtimeRule[0] ) );
            try
            {
                firstReload = Task.Run( () => IISAlertRuleCache.Reload( new DelegateConfigurationLoader( () =>
                {
                    var active = Interlocked.Increment( ref activeLoaders );
                    SetMaximum( ref maximumActiveLoaders, active );
                    firstLoaderEntered.Set();
                    Assert.IsTrue( allowFirstLoaderToFinish.Wait( TimeSpan.FromSeconds( 5 ) ) );
                    Interlocked.Decrement( ref activeLoaders );
                    return firstConfiguration;
                } ), new RecordingExceptionLogger() ) );

                Assert.IsTrue( firstLoaderEntered.Wait( TimeSpan.FromSeconds( 5 ) ) );
                secondReload = Task.Run( () =>
                {
                    secondCallStarted.Set();
                    IISAlertRuleCache.Reload( new DelegateConfigurationLoader( () =>
                    {
                        var active = Interlocked.Increment( ref activeLoaders );
                        SetMaximum( ref maximumActiveLoaders, active );
                        secondLoaderEntered.Set();
                        Interlocked.Decrement( ref activeLoaders );
                        return secondConfiguration;
                    } ), new RecordingExceptionLogger() );
                } );

                Assert.IsTrue( secondCallStarted.Wait( TimeSpan.FromSeconds( 5 ) ) );
                Assert.IsFalse( secondLoaderEntered.Wait( TimeSpan.FromMilliseconds( 100 ) ), "The second loader entered while the first reload was still building." );
                allowFirstLoaderToFinish.Set();
                Task.WaitAll( firstReload, secondReload );

                Assert.AreEqual( 1, maximumActiveLoaders );
                CollectionAssert.AreEqual( new[] { "X-Second" }, IISAlertRuleCache.Capture().RequiredHeaderNames.ToArray() );
            }
            finally
            {
                allowFirstLoaderToFinish.Set();
                WaitForCleanup( firstReload, secondReload );
                RestoreConfiguration( previousConfiguration );
            }
        }

        [TestMethod]
        public void InFlightRequestKeepsItsCapturedHeadersAndRulesAfterReload()
        {
            var originalConfiguration = CreateConfiguration( "X-Generation", "old" );
            var replacementConfiguration = CreateConfiguration( "X-Replacement", "new" );
            var snapshot = new IISRequestRuleSnapshot();
            snapshot.SetHeader( "X-Generation", "old" );

            var previousConfiguration = IISAlertRuleCache.PublishConfiguration( originalConfiguration );
            try
            {
                var capturedConfiguration = IISAlertRuleCache.Capture();
                IISAlertRuleCache.PublishConfiguration( replacementConfiguration );

                CollectionAssert.AreEqual( new[] { "X-Generation" }, capturedConfiguration.RequiredHeaderNames.ToArray() );
                Assert.AreEqual( 1, capturedConfiguration.GetMatchingRules( IISRequestRuleStage.PreAuthentication, snapshot ).Count );
                Assert.AreEqual( 0, IISAlertRuleCache.Capture().GetMatchingRules( IISRequestRuleStage.PreAuthentication, snapshot ).Count );
            }
            finally
            {
                RestoreConfiguration( previousConfiguration );
            }
        }

        [TestMethod]
        public void FailedReloadKeepsLastKnownGoodConfigurationAndLogsTheFailure()
        {
            var originalConfiguration = CreateConfiguration( "X-Original", "old" );
            var previousConfiguration = IISAlertRuleCache.PublishConfiguration( originalConfiguration );
            var exceptionLogger = new RecordingExceptionLogger();

            try
            {
                IISAlertRuleCache.Reload(
                    new DelegateConfigurationLoader( () => throw new InvalidOperationException( "injected reload failure" ) ),
                    exceptionLogger );

                CollectionAssert.AreEqual( new[] { "X-Original" }, IISAlertRuleCache.Capture().RequiredHeaderNames.ToArray() );
                Assert.IsNotNull( exceptionLogger.LastException );
                StringAssert.Contains( exceptionLogger.LastException.Message, "failed open" );
                Assert.IsInstanceOfType( exceptionLogger.LastException.InnerException, typeof( InvalidOperationException ) );
            }
            finally
            {
                RestoreConfiguration( previousConfiguration );
            }
        }

        [TestMethod]
        public void RequestBoundaryLogsAndSwallowsFailures()
        {
            var exceptionLogger = new RecordingExceptionLogger();
            var completed = IISAlertBlockHttpModule.ExecuteFailOpen(
                "test boundary",
                () => throw new InvalidOperationException( "injected request failure" ),
                exceptionLogger );

            Assert.IsFalse( completed );
            Assert.IsNotNull( exceptionLogger.LastException );
            StringAssert.Contains( exceptionLogger.LastException.Message, "test boundary" );

            Assert.IsFalse( IISAlertBlockHttpModule.ExecuteFailOpen(
                "test boundary with unavailable logger",
                () => throw new InvalidOperationException( "injected request failure" ),
                new ThrowingExceptionLogger() ) );
        }

        [TestMethod]
        public void ApiFilterUsesCapturedConfigurationAndQueuesOneEventWithResolvedIdentity()
        {
            var capturedConfiguration = CreateConfiguration( IISRequestRuleField.UserName, "alice", IISRequestRuleStage.PostAuthentication, false, 987654 );
            var replacementConfiguration = CreateConfiguration( IISRequestRuleField.UserName, "bob", IISRequestRuleStage.PostAuthentication, false, 987655 );
            var context = new HttpContext(
                new HttpRequest( string.Empty, "http://localhost/api/test", string.Empty ),
                new HttpResponse( new StringWriter() ) );
            var snapshot = new IISRequestRuleSnapshot();
            context.Items[IISAlertBlockHttpModule.ConfigurationContextKey] = capturedConfiguration;
            context.Items[IISAlertBlockHttpModule.SnapshotContextKey] = snapshot;

            var principal = new GenericPrincipal( new GenericIdentity( "alice", "test" ), new string[0] );
            var personGuid = Guid.NewGuid();
            var request = new HttpRequestMessage( HttpMethod.Get, "http://localhost/api/test" );
            request.Properties["Person"] = new Person { Guid = personGuid };
            var requestContext = new HttpRequestContext { Principal = principal };
            var actionContext = new HttpActionContext
            {
                ControllerContext = new HttpControllerContext { Request = request, RequestContext = requestContext }
            };
            var actionQueue = new RecordingActionQueue();
            var requestRuleProcessor = new IISAlertRequestRuleProcessor( actionQueue, new FixedClock( DateTime.Now ) );
            var filter = new IISAlertApiPostAuthenticationFilter( requestRuleProcessor, new RecordingExceptionLogger() );
            var queuedCount = 0;
            IISAlertRealtimeEvent queuedEvent = null;
            var previousHttpContext = HttpContext.Current;
            var previousConfiguration = IISAlertRuleCache.PublishConfiguration( replacementConfiguration );

            try
            {
                HttpContext.Current = context;
                actionQueue.OnQueue = ( alertEvent, claimReleaser ) =>
                {
                    queuedEvent = alertEvent;
                    Interlocked.Increment( ref queuedCount );
                    return false;
                };

                filter.OnActionExecuting( actionContext );
                requestContext.Principal = new GenericPrincipal( new GenericIdentity( "bob", "test" ), new string[0] );
                filter.OnActionExecuting( actionContext );

                Assert.AreEqual( 1, queuedCount, "The API filter must process post-authentication rules once per request." );
                Assert.IsNotNull( queuedEvent );
                Assert.AreEqual( 987654, queuedEvent.RuleId, "The request must use its captured configuration after a reload." );
                Assert.AreEqual( "alice", queuedEvent.Result[IISRequestRuleField.UserName] );
                Assert.AreEqual( "true", queuedEvent.Result[IISRequestRuleField.IsAuthenticated] );
                Assert.AreEqual( personGuid, snapshot.PersonGuid );
                Assert.AreEqual( "alice", snapshot.GetValue( IISRequestRuleField.UserName ), "API identity must be captured only once." );
            }
            finally
            {
                HttpContext.Current = previousHttpContext;
                RestoreConfiguration( previousConfiguration );
                request.Dispose();
            }
        }

        [TestMethod]
        public void SnapshotCapturesMarkupInQueryStringWithoutTriggeringRequestValidation()
        {
            // Rock's connection board sends a Lava/HTML status icon template in the query string.
            const string queryString = "statusIconsTemplate=%3Cdiv+class%3D%27board-card%27%3E%3C%2Fdiv%3E";
            var request = new HttpRequest( string.Empty, "http://localhost/api/ConnectionRequests/ConnectionBoardStatusViewModels/1", queryString );
            request.ValidateInput();
            var context = new HttpContext( request, new HttpResponse( new StringWriter() ) );

            Assert.ThrowsException<HttpRequestValidationException>(
                () => request.QueryString.ToString(),
                "The test request must have request validation enabled." );

            var snapshot = IISAlertBlockHttpModule.CreateSnapshot( context, "127.0.0.1", CreateConfiguration( "X-Test", "value" ) );

            StringAssert.Contains( snapshot.GetValue( IISRequestRuleField.QueryString ), "board-card" );
        }

        private static IISAlertRuleConfiguration CreateConfiguration(
            string fieldOrHeader,
            string expectedValue,
            IISRequestRuleStage stage = IISRequestRuleStage.PreAuthentication,
            bool isHeader = true,
            int ruleId = 1 )
        {
            var condition = new IISRequestRuleCondition
            {
                Field = isHeader ? IISRequestRuleField.RequestHeader : fieldOrHeader,
                HeaderName = isHeader ? fieldOrHeader : null,
                Operator = IISRequestRuleOperator.Equal,
                Value = expectedValue
            };
            var conditions = new List<IISRequestRuleCondition> { condition };
            var rule = new IISRealtimeRule(
                ruleId,
                "Configuration Test",
                stage,
                IISRequestRuleConditionLogic.All,
                string.Empty,
                string.Empty,
                5,
                false,
                403,
                string.Empty,
                false,
                60,
                false,
                conditions,
                new[] { new IISRequestRuleConditionMatcher( condition ) } );
            return new IISAlertRuleConfiguration( new[] { rule } );
        }

        private static void RestoreConfiguration( IISAlertRuleConfiguration configuration )
        {
            IISAlertRuleCache.PublishConfiguration( configuration ?? new IISAlertRuleConfiguration( new IISRealtimeRule[0] ) );
        }

        private static void WaitForCleanup( params Task[] tasks )
        {
            var runningTasks = tasks.Where( task => task != null ).ToArray();
            if ( runningTasks.Length > 0 )
            {
                Task.WaitAll( runningTasks, TimeSpan.FromSeconds( 5 ) );
            }
        }

        private static void SetMaximum( ref int maximum, int value )
        {
            int current;
            do
            {
                current = maximum;
                if ( current >= value )
                {
                    return;
                }
            }
            while ( Interlocked.CompareExchange( ref maximum, value, current ) != current );
        }

        private sealed class DelegateConfigurationLoader : IIISAlertRuleConfigurationLoader
        {
            private readonly Func<IISAlertRuleConfiguration> _load;

            public DelegateConfigurationLoader( Func<IISAlertRuleConfiguration> load )
            {
                _load = load;
            }

            public IISAlertRuleConfiguration Load()
            {
                return _load();
            }
        }

        private sealed class RecordingExceptionLogger : IIISAlertExceptionLogger
        {
            public Exception LastException { get; private set; }

            public void Log( Exception exception )
            {
                LastException = exception;
            }
        }

        private sealed class ThrowingExceptionLogger : IIISAlertExceptionLogger
        {
            public void Log( Exception exception )
            {
                throw new InvalidOperationException( "injected logger failure" );
            }
        }

        private sealed class FixedClock : IIISAlertClock
        {
            public FixedClock( DateTime now )
            {
                Now = now;
            }

            public DateTime Now { get; private set; }
        }

        private sealed class RecordingActionQueue : IIISAlertRealtimeActionQueue
        {
            public Func<IISAlertRealtimeEvent, IIISAlertClaimReleaser, bool> OnQueue { get; set; }

            public bool Queue( IISAlertRealtimeEvent alertEvent, IIISAlertClaimReleaser claimReleaser )
            {
                return OnQueue == null || OnQueue( alertEvent, claimReleaser );
            }
        }
    }
}

