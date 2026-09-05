using net.redeemertech.Security.Model;

using Rock;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace net.redeemertech.Security
{
    internal sealed class IISRequestBlockResult
    {
        public int StatusCode { get; set; }

        public string Message { get; set; }
    }

    /// <summary>
    /// Executes matching rule actions independently of the ASP.NET host surface that
    /// supplied the authenticated identity.
    /// </summary>
    internal static class IISAlertRequestRuleProcessor
    {
        private const int EnforcementClaimCleanupThreshold = 10000;
        private static readonly object NotificationClaimLock = new object();
        private static readonly Dictionary<string, NotificationClaimState> NotificationClaims = new Dictionary<string, NotificationClaimState>( StringComparer.OrdinalIgnoreCase );
        private static readonly ConcurrentDictionary<string, DateTime> EnforcementClaims = new ConcurrentDictionary<string, DateTime>( StringComparer.OrdinalIgnoreCase );
        private static int _enforcementCleanupCounter;
        internal static Func<DateTime> CurrentDateTime = () => RockDateTime.Now;

        public static IISRequestBlockResult Process( IISRequestRuleSnapshot snapshot, IISRequestRuleStage stage, bool? requiresResponseBytes = null )
        {
            return Process( IISAlertRuleCache.Capture(), snapshot, stage, requiresResponseBytes );
        }

        public static IISRequestBlockResult Process( IISAlertRuleConfiguration configuration, IISRequestRuleSnapshot snapshot, IISRequestRuleStage stage, bool? requiresResponseBytes = null )
        {
            var matchingRules = configuration.GetMatchingRules( stage, snapshot, requiresResponseBytes );
            IISRealtimeRule blockingRule = null;
            var matchedDateTime = CurrentDateTime();

            foreach ( var rule in matchingRules )
            {
                int suppressedMatchCount;
                DateTime notificationClaimExpiresDateTime;
                var notificationClaimed = TryClaimNotification( rule, matchedDateTime, out suppressedMatchCount, out notificationClaimExpiresDateTime );
                var ipAddress = rule.BlockIpAddress
                    ? IISAlertBlockedIpCache.NormalizeIpAddress( snapshot.GetValue( IISRequestRuleField.ClientIp ) )
                    : null;
                var userName = rule.LockOutUserAccounts
                    ? snapshot.GetValue( IISRequestRuleField.UserName ).Trim()
                    : null;

                DateTime? ipEnforcementClaimExpiresDateTime = null;
                var ipEnforcementClaimed = !ipAddress.IsNullOrWhiteSpace()
                    && TryClaimEnforcement( rule, "ip", ipAddress, matchedDateTime, rule.BlockIpAddressMinutes, out ipEnforcementClaimExpiresDateTime );
                DateTime? accountEnforcementClaimExpiresDateTime = null;
                var accountEnforcementClaimed = !userName.IsNullOrWhiteSpace()
                    && TryClaimEnforcement( rule, "account", userName, matchedDateTime, rule.EvaluationFrequencyMinutes, out accountEnforcementClaimExpiresDateTime );

                if ( ipEnforcementClaimed )
                {
                    IISAlertBlockedIpCache.AddOrRefresh( ipAddress, matchedDateTime.AddMinutes( rule.BlockIpAddressMinutes ) );
                }

                if ( notificationClaimed || ipEnforcementClaimed || accountEnforcementClaimed )
                {
                    var alertEvent = IISAlertRealtimeEvent.Capture(
                        rule,
                        snapshot,
                        matchedDateTime,
                        notificationClaimed,
                        notificationClaimExpiresDateTime,
                        suppressedMatchCount,
                        ipEnforcementClaimed ? ipAddress : null,
                        ipEnforcementClaimExpiresDateTime,
                        accountEnforcementClaimed ? userName : null,
                        accountEnforcementClaimExpiresDateTime );

                    if ( !IISAlertRealtimeActionProcessor.Queue( alertEvent ) )
                    {
                        ReleaseUnprocessedClaims( alertEvent );
                    }
                }

                if ( blockingRule == null && rule.BlockRequest && stage != IISRequestRuleStage.EndRequest )
                {
                    blockingRule = rule;
                }
            }

            return blockingRule == null
                ? null
                : new IISRequestBlockResult
                {
                    StatusCode = blockingRule.BlockResponseStatusCode,
                    Message = blockingRule.BlockResponseMessage
                };
        }

        internal static void ReleaseUnprocessedClaims( IISAlertRealtimeEvent alertEvent )
        {
            if ( alertEvent.NotificationClaimed )
            {
                lock ( NotificationClaimLock )
                {
                    var key = GetNotificationKey( alertEvent.RuleId, alertEvent.RuleVersion );
                    NotificationClaimState state;
                    if ( NotificationClaims.TryGetValue( key, out state )
                        && state.NextNotificationDateTime == alertEvent.NotificationClaimExpiresDateTime )
                    {
                        NotificationClaims.Remove( key );
                    }
                }
            }

            ReleaseEnforcementClaim( alertEvent.RuleId, alertEvent.RuleVersion, "ip", alertEvent.IpAddressToPersist, alertEvent.IpEnforcementClaimExpiresDateTime );
            ReleaseEnforcementClaim( alertEvent.RuleId, alertEvent.RuleVersion, "account", alertEvent.UserNameToLockOut, alertEvent.AccountEnforcementClaimExpiresDateTime );
        }

        internal static void ResetStateForTests()
        {
            lock ( NotificationClaimLock )
            {
                NotificationClaims.Clear();
            }

            EnforcementClaims.Clear();
            _enforcementCleanupCounter = 0;
            CurrentDateTime = () => RockDateTime.Now;
        }

        internal static void ReleaseEnforcementClaim( int ruleId, string ruleVersion, string action, string target, DateTime? claimedExpiresDateTime )
        {
            if ( target.IsNullOrWhiteSpace() || !claimedExpiresDateTime.HasValue )
            {
                return;
            }

            var key = GetEnforcementKey( ruleId, ruleVersion, action, target );
            ( ( ICollection<KeyValuePair<string, DateTime>> ) EnforcementClaims ).Remove(
                new KeyValuePair<string, DateTime>( key, claimedExpiresDateTime.Value ) );
        }

        private static bool TryClaimNotification( IISRealtimeRule rule, DateTime now, out int suppressedMatchCount, out DateTime claimExpiresDateTime )
        {
            var key = GetNotificationKey( rule.Id, rule.Version );
            lock ( NotificationClaimLock )
            {
                NotificationClaimState state;
                if ( !NotificationClaims.TryGetValue( key, out state ) || state.NextNotificationDateTime <= now )
                {
                    suppressedMatchCount = state == null ? 0 : state.SuppressedMatchCount;
                    NotificationClaims[key] = new NotificationClaimState
                    {
                        NextNotificationDateTime = now.AddMinutes( Math.Max( 1, rule.EvaluationFrequencyMinutes ) )
                    };
                    claimExpiresDateTime = NotificationClaims[key].NextNotificationDateTime;
                    return true;
                }

                if ( state.SuppressedMatchCount < int.MaxValue - 1 )
                {
                    state.SuppressedMatchCount++;
                }
                suppressedMatchCount = 0;
                claimExpiresDateTime = default( DateTime );
                return false;
            }
        }

        private static bool TryClaimEnforcement( IISRealtimeRule rule, string action, string target, DateTime now, int deduplicationMinutes, out DateTime? claimedExpiresDateTime )
        {
            var key = GetEnforcementKey( rule.Id, rule.Version, action, target );
            var nextDateTime = now.AddMinutes( Math.Max( 1, deduplicationMinutes ) );

            while ( true )
            {
                DateTime existingDateTime;
                if ( !EnforcementClaims.TryGetValue( key, out existingDateTime ) )
                {
                    if ( EnforcementClaims.TryAdd( key, nextDateTime ) )
                    {
                        claimedExpiresDateTime = nextDateTime;
                        CleanupExpiredEnforcementClaims( now );
                        return true;
                    }

                    continue;
                }

                if ( existingDateTime > now )
                {
                    claimedExpiresDateTime = null;
                    return false;
                }

                if ( EnforcementClaims.TryUpdate( key, nextDateTime, existingDateTime ) )
                {
                    claimedExpiresDateTime = nextDateTime;
                    CleanupExpiredEnforcementClaims( now );
                    return true;
                }
            }
        }

        private static void CleanupExpiredEnforcementClaims( DateTime now )
        {
            if ( EnforcementClaims.Count <= EnforcementClaimCleanupThreshold
                || ( Interlocked.Increment( ref _enforcementCleanupCounter ) & 255 ) != 0 )
            {
                return;
            }

            foreach ( var claim in EnforcementClaims )
            {
                if ( claim.Value <= now )
                {
                    ( ( ICollection<KeyValuePair<string, DateTime>> ) EnforcementClaims ).Remove( claim );
                }
            }
        }

        private static string GetNotificationKey( int ruleId, string ruleVersion )
        {
            return ruleId + "|" + ruleVersion;
        }

        private static string GetEnforcementKey( int ruleId, string ruleVersion, string action, string target )
        {
            return ruleId + "|" + ruleVersion + "|" + action + "|" + target;
        }

        private sealed class NotificationClaimState
        {
            public DateTime NextNotificationDateTime { get; set; }

            public int SuppressedMatchCount { get; set; }
        }
    }
}
