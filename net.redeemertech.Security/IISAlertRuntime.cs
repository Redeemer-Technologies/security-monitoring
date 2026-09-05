using Rock;

using System;

namespace net.redeemertech.Security
{
    internal interface IIISAlertClock
    {
        DateTime Now { get; }
    }

    internal sealed class IISAlertSystemClock : IIISAlertClock
    {
        public DateTime Now => RockDateTime.Now;
    }

    internal interface IIISAlertClaimReleaser
    {
        void ReleaseUnprocessedClaims( IISAlertRealtimeEvent alertEvent );

        void ReleaseEnforcementClaim( int ruleId, string ruleVersion, string action, string target, DateTime? claimedExpiresDateTime );
    }

    internal interface IIISAlertRealtimeActionQueue
    {
        bool Queue( IISAlertRealtimeEvent alertEvent, IIISAlertClaimReleaser claimReleaser );
    }

    /// <summary>
    /// Immutable production composition root for request-rule services.
    /// </summary>
    internal static class IISAlertRuntime
    {
        internal static readonly IIISAlertExceptionLogger ExceptionLogger;
        internal static readonly IISAlertRequestRuleProcessor RequestRuleProcessor;

        static IISAlertRuntime()
        {
            ExceptionLogger = new IISAlertExceptionLogger();
            var realtimeActionProcessor = new IISAlertRealtimeActionProcessor(
                new IISAlertRealtimeActionOperations( ExceptionLogger ),
                ExceptionLogger );
            RequestRuleProcessor = new IISAlertRequestRuleProcessor(
                realtimeActionProcessor,
                new IISAlertSystemClock() );
        }
    }
}
