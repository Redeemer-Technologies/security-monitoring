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
    internal sealed class IISAlertRequestRuleProcessor : IIISAlertClaimReleaser
    {
        private const int EnforcementClaimCleanupThreshold = 10000;
        private readonly object _notificationClaimLock = new object();
        private readonly Dictionary<string, NotificationClaimState> _notificationClaims = new Dictionary<string, NotificationClaimState>( StringComparer.OrdinalIgnoreCase );
        private readonly ConcurrentDictionary<string, DateTime> _enforcementClaims = new ConcurrentDictionary<string, DateTime>( StringComparer.OrdinalIgnoreCase );
        private readonly IIISAlertRealtimeActionQueue _actionQueue;
        private readonly IIISAlertClock _clock;
        private int _enforcementCleanupCounter;

        internal IISAlertRequestRuleProcessor( IIISAlertRealtimeActionQueue actionQueue, IIISAlertClock clock )
        {
            _actionQueue = actionQueue ?? throw new ArgumentNullException( nameof( actionQueue ) );
            _clock = clock ?? throw new ArgumentNullException( nameof( clock ) );
        }

        public IISRequestBlockResult Process( IISRequestRuleSnapshot snapshot, IISRequestRuleStage stage )
        {
            return Process( IISAlertRuleCache.Capture(), snapshot, stage );
        }

        public IISRequestBlockResult Process( IISAlertRuleConfiguration configuration, IISRequestRuleSnapshot snapshot, IISRequestRuleStage stage )
        {
            var matchingRules = configuration.GetMatchingRules( stage, snapshot );
            IISRealtimeRule blockingRule = null;
            var matchedDateTime = _clock.Now;

            foreach ( var rule in matchingRules )
            {
                int suppressedMatchCount;
                DateTime notificationClaimExpiresDateTime;
                var notificationClaimed = TryClaimNotification( rule, matchedDateTime, out suppressedMatchCount, out notificationClaimExpiresDateTime );
                var enforcementAllowed = !snapshot.IsLocalRequest;
                var ipAddress = enforcementAllowed && rule.BlockIpAddress
                    ? IISAlertBlockedIpCache.NormalizeIpAddress( snapshot.GetValue( IISRequestRuleField.ClientIp ) )
                    : null;
                var userName = enforcementAllowed && rule.LockOutUserAccounts && !snapshot.SuppressAccountLockout
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

                    if ( !_actionQueue.Queue( alertEvent, this ) )
                    {
                        ReleaseUnprocessedClaims( alertEvent );
                    }
                }

                if ( enforcementAllowed && blockingRule == null && rule.BlockRequest && stage != IISRequestRuleStage.EndRequest )
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

        public void ReleaseUnprocessedClaims( IISAlertRealtimeEvent alertEvent )
        {
            if ( alertEvent.NotificationClaimed )
            {
                lock ( _notificationClaimLock )
                {
                    var key = GetNotificationKey( alertEvent.RuleId, alertEvent.RuleVersion );
                    NotificationClaimState state;
                    if ( _notificationClaims.TryGetValue( key, out state )
                        && state.NextNotificationDateTime == alertEvent.NotificationClaimExpiresDateTime )
                    {
                        _notificationClaims.Remove( key );
                    }
                }
            }

            ReleaseEnforcementClaim( alertEvent.RuleId, alertEvent.RuleVersion, "ip", alertEvent.IpAddressToPersist, alertEvent.IpEnforcementClaimExpiresDateTime );
            ReleaseEnforcementClaim( alertEvent.RuleId, alertEvent.RuleVersion, "account", alertEvent.UserNameToLockOut, alertEvent.AccountEnforcementClaimExpiresDateTime );
        }

        public void ReleaseEnforcementClaim( int ruleId, string ruleVersion, string action, string target, DateTime? claimedExpiresDateTime )
        {
            if ( target.IsNullOrWhiteSpace() || !claimedExpiresDateTime.HasValue )
            {
                return;
            }

            var key = GetEnforcementKey( ruleId, ruleVersion, action, target );
            ( ( ICollection<KeyValuePair<string, DateTime>> ) _enforcementClaims ).Remove(
                new KeyValuePair<string, DateTime>( key, claimedExpiresDateTime.Value ) );
        }

        private bool TryClaimNotification( IISRealtimeRule rule, DateTime now, out int suppressedMatchCount, out DateTime claimExpiresDateTime )
        {
            var key = GetNotificationKey( rule.Id, rule.Version );
            lock ( _notificationClaimLock )
            {
                NotificationClaimState state;
                if ( !_notificationClaims.TryGetValue( key, out state ) || state.NextNotificationDateTime <= now )
                {
                    suppressedMatchCount = state == null ? 0 : state.SuppressedMatchCount;
                    _notificationClaims[key] = new NotificationClaimState
                    {
                        NextNotificationDateTime = now.AddMinutes( Math.Max( 1, rule.EvaluationFrequencyMinutes ) )
                    };
                    claimExpiresDateTime = _notificationClaims[key].NextNotificationDateTime;
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

        private bool TryClaimEnforcement( IISRealtimeRule rule, string action, string target, DateTime now, int deduplicationMinutes, out DateTime? claimedExpiresDateTime )
        {
            var key = GetEnforcementKey( rule.Id, rule.Version, action, target );
            var nextDateTime = now.AddMinutes( Math.Max( 1, deduplicationMinutes ) );

            while ( true )
            {
                DateTime existingDateTime;
                if ( !_enforcementClaims.TryGetValue( key, out existingDateTime ) )
                {
                    if ( _enforcementClaims.TryAdd( key, nextDateTime ) )
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

                if ( _enforcementClaims.TryUpdate( key, nextDateTime, existingDateTime ) )
                {
                    claimedExpiresDateTime = nextDateTime;
                    CleanupExpiredEnforcementClaims( now );
                    return true;
                }
            }
        }

        private void CleanupExpiredEnforcementClaims( DateTime now )
        {
            if ( _enforcementClaims.Count <= EnforcementClaimCleanupThreshold
                || ( Interlocked.Increment( ref _enforcementCleanupCounter ) & 255 ) != 0 )
            {
                return;
            }

            foreach ( var claim in _enforcementClaims )
            {
                if ( claim.Value <= now )
                {
                    ( ( ICollection<KeyValuePair<string, DateTime>> ) _enforcementClaims ).Remove( claim );
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
