using net.redeemertech.Security.Model;

using Rock;
using Rock.Communication;
using Rock.Data;
using Rock.Lava;
using Rock.Model;

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Web.Hosting;
using System.Web.Script.Serialization;

namespace net.redeemertech.Security
{
    /// <summary>
    /// An immutable description of one rule match. Background actions use only this captured
    /// data, so editing a rule while work is queued cannot change the resulting history or email.
    /// </summary>
    internal sealed class IISAlertRealtimeEvent
    {
        private IISAlertRealtimeEvent()
        {
        }

        public int RuleId { get; private set; }

        public string RuleVersion { get; private set; }

        public string RuleName { get; private set; }

        public IISRequestRuleStage RuleStage { get; private set; }

        public DateTime MatchedDateTime { get; private set; }

        public string SummaryLava { get; private set; }

        public IReadOnlyList<string> NotificationEmails { get; private set; }

        public bool NotificationClaimed { get; private set; }

        public DateTime NotificationClaimExpiresDateTime { get; private set; }

        public int SuppressedMatchCount { get; private set; }

        public int BlockIpAddressMinutes { get; private set; }

        public string IpAddressToPersist { get; private set; }

        public DateTime? IpEnforcementClaimExpiresDateTime { get; private set; }

        public string UserNameToLockOut { get; private set; }

        public DateTime? AccountEnforcementClaimExpiresDateTime { get; private set; }

        public IReadOnlyDictionary<string, string> Result { get; private set; }

        internal Dictionary<string, string> ActionOutcomes { get; private set; }

        public static IISAlertRealtimeEvent Capture(
            IISRealtimeRule rule,
            IISRequestRuleSnapshot snapshot,
            DateTime matchedDateTime,
            bool notificationClaimed,
            DateTime notificationClaimExpiresDateTime,
            int suppressedMatchCount,
            string ipAddressToPersist,
            DateTime? ipEnforcementClaimExpiresDateTime,
            string userNameToLockOut,
            DateTime? accountEnforcementClaimExpiresDateTime )
        {
            var result = snapshot.ToResultDictionary();
            result["RuleStage"] = rule.Stage.ToString();
            result["RuleVersion"] = rule.Version;
            result["MatchedDateTime"] = matchedDateTime.ToUniversalTime().ToString( "O" );
            result["SuppressedMatchCount"] = suppressedMatchCount.ToString( System.Globalization.CultureInfo.InvariantCulture );

            return new IISAlertRealtimeEvent
            {
                RuleId = rule.Id,
                RuleVersion = rule.Version,
                RuleName = rule.Name,
                RuleStage = rule.Stage,
                MatchedDateTime = matchedDateTime,
                SummaryLava = rule.SummaryLava,
                NotificationEmails = new ReadOnlyCollection<string>( rule.NotificationEmails.SplitDelimitedValues()
                    .Where( email => email.IsNotNullOrWhiteSpace() )
                    .Distinct( StringComparer.OrdinalIgnoreCase )
                    .ToList() ),
                NotificationClaimed = notificationClaimed,
                NotificationClaimExpiresDateTime = notificationClaimExpiresDateTime,
                SuppressedMatchCount = suppressedMatchCount,
                BlockIpAddressMinutes = rule.BlockIpAddressMinutes,
                IpAddressToPersist = ipAddressToPersist,
                IpEnforcementClaimExpiresDateTime = ipEnforcementClaimExpiresDateTime,
                UserNameToLockOut = userNameToLockOut,
                AccountEnforcementClaimExpiresDateTime = accountEnforcementClaimExpiresDateTime,
                Result = new ReadOnlyDictionary<string, string>( result ),
                ActionOutcomes = new Dictionary<string, string>( StringComparer.OrdinalIgnoreCase )
            };
        }

        internal Dictionary<string, string> CreatePersistedResult()
        {
            var persistedResult = Result.ToDictionary( pair => pair.Key, pair => pair.Value, StringComparer.OrdinalIgnoreCase );
            foreach ( var outcome in ActionOutcomes )
            {
                persistedResult[outcome.Key] = outcome.Value;
            }

            return persistedResult;
        }
    }

    internal static class IISAlertRealtimeActionProcessor
    {
        private static readonly Guid AlertSystemCommunicationGuid = new Guid( "94fbe63b-5e70-4332-898a-d8031512dc82" );
        private const string AlertHistoryDetailPageGuid = "20FBEDA7-3028-4924-B29A-B445CF6CAEAE";
        internal static Func<IISAlertRealtimeEvent, bool> QueueOverride;
        internal static Func<IISAlertRealtimeEvent, IISAlertHistoryResult> PersistHistoryOverride;
        internal static Action<IISAlertRealtimeEvent, int?> PersistIpBlockOverride;
        internal static Action<IISAlertRealtimeEvent> LockOutUserAccountOverride;
        internal static Action<IISAlertRealtimeEvent, string, int?> SendAlertEmailOverride;
        internal static Action<int, Dictionary<string, string>> UpdateHistoryOutcomesOverride;
        internal static Action<Exception> ExceptionLoggerOverride;
        internal static Func<IISAlertRealtimeEvent, string> ResolveSummaryOverride;

        public static bool Queue( IISAlertRealtimeEvent alertEvent )
        {
            if ( QueueOverride != null )
            {
                return QueueOverride( alertEvent );
            }

            try
            {
                HostingEnvironment.QueueBackgroundWorkItem( cancellationToken =>
                {
                    if ( cancellationToken.IsCancellationRequested )
                    {
                        IISAlertRequestRuleProcessor.ReleaseUnprocessedClaims( alertEvent );
                        return;
                    }

                    Process( alertEvent );
                } );
                return true;
            }
            catch ( Exception ex )
            {
                // An application shutdown can reject new background work. Never fail the request for that reason.
                LogException( ex );
                return false;
            }
        }

        internal static void Process( IISAlertRealtimeEvent alertEvent )
        {
            int? historyId = null;
            string summary = null;

            if ( alertEvent.NotificationClaimed )
            {
                var historySucceeded = TryExecute( "save realtime IIS alert history", () =>
                {
                    if ( PersistHistoryOverride == null )
                    {
                        historyId = PersistHistory( alertEvent, out summary );
                    }
                    else
                    {
                        var historyResult = PersistHistoryOverride( alertEvent );
                        historyId = historyResult.HistoryId;
                        summary = historyResult.Summary;
                    }
                } );
                alertEvent.ActionOutcomes["ActionHistory"] = historySucceeded && historyId.HasValue ? "Succeeded" : "Failed";
            }
            else
            {
                alertEvent.ActionOutcomes["ActionHistory"] = "NotClaimed";
            }

            if ( alertEvent.IpAddressToPersist.IsNotNullOrWhiteSpace() )
            {
                var ipBlockSucceeded = TryExecuteWithRetry( "persist realtime IIS IP block", 3, () =>
                {
                    if ( PersistIpBlockOverride == null )
                    {
                        PersistIpBlock( alertEvent, historyId );
                    }
                    else
                    {
                        PersistIpBlockOverride( alertEvent, historyId );
                    }
                } );
                alertEvent.ActionOutcomes["ActionIpBlock"] = ipBlockSucceeded ? "Succeeded" : "Failed";
                if ( !ipBlockSucceeded )
                {
                    // Persistent enforcement is idempotent. Let the next matching request retry a failed write.
                    IISAlertRequestRuleProcessor.ReleaseEnforcementClaim(
                        alertEvent.RuleId,
                        alertEvent.RuleVersion,
                        "ip",
                        alertEvent.IpAddressToPersist,
                        alertEvent.IpEnforcementClaimExpiresDateTime );
                }
            }
            else
            {
                alertEvent.ActionOutcomes["ActionIpBlock"] = "NotClaimed";
            }

            if ( alertEvent.UserNameToLockOut.IsNotNullOrWhiteSpace() )
            {
                var lockoutSucceeded = TryExecuteWithRetry( "lock out realtime IIS alert account", 3, () =>
                {
                    if ( LockOutUserAccountOverride == null )
                    {
                        LockOutUserAccount( alertEvent );
                    }
                    else
                    {
                        LockOutUserAccountOverride( alertEvent );
                    }
                } );
                alertEvent.ActionOutcomes["ActionAccountLockout"] = lockoutSucceeded ? "Succeeded" : "Failed";
                if ( !lockoutSucceeded )
                {
                    IISAlertRequestRuleProcessor.ReleaseEnforcementClaim(
                        alertEvent.RuleId,
                        alertEvent.RuleVersion,
                        "account",
                        alertEvent.UserNameToLockOut,
                        alertEvent.AccountEnforcementClaimExpiresDateTime );
                }
            }
            else
            {
                alertEvent.ActionOutcomes["ActionAccountLockout"] = "NotClaimed";
            }

            if ( alertEvent.NotificationClaimed && alertEvent.NotificationEmails.Count > 0 )
            {
                if ( summary == null )
                {
                    TryExecute( "render realtime IIS alert summary", () => summary = RenderSummary( alertEvent ) );
                }

                alertEvent.ActionOutcomes["ActionEmail"] = TryExecute(
                    "send realtime IIS alert email",
                    () =>
                    {
                        if ( SendAlertEmailOverride == null )
                        {
                            SendAlertEmail( alertEvent, summary ?? string.Empty, historyId );
                        }
                        else
                        {
                            SendAlertEmailOverride( alertEvent, summary ?? string.Empty, historyId );
                        }
                    } )
                    ? "Succeeded"
                    : "Failed";
            }
            else
            {
                alertEvent.ActionOutcomes["ActionEmail"] = alertEvent.NotificationClaimed ? "NoRecipients" : "NotClaimed";
            }

            if ( historyId.HasValue )
            {
                TryExecute( "record realtime IIS alert action outcomes", () =>
                {
                    if ( UpdateHistoryOutcomesOverride == null )
                    {
                        UpdateHistoryOutcomes( historyId.Value, alertEvent.CreatePersistedResult() );
                    }
                    else
                    {
                        UpdateHistoryOutcomesOverride( historyId.Value, alertEvent.CreatePersistedResult() );
                    }
                } );
            }
        }

        internal static void ResetTestHooks()
        {
            QueueOverride = null;
            PersistHistoryOverride = null;
            PersistIpBlockOverride = null;
            LockOutUserAccountOverride = null;
            SendAlertEmailOverride = null;
            UpdateHistoryOutcomesOverride = null;
            ExceptionLoggerOverride = null;
            ResolveSummaryOverride = null;
        }

        private static int? PersistHistory( IISAlertRealtimeEvent alertEvent, out string summary )
        {
            summary = RenderSummary( alertEvent );
            using ( var rockContext = new RockContext() )
            {
                var alert = new IISAlertService( rockContext ).Get( alertEvent.RuleId );
                if ( alert == null )
                {
                    // History requires a live parent row. Other captured actions remain valid and continue below.
                    LogException( new InvalidOperationException(
                        string.Format(
                            "Realtime IIS alert {0} ({1}, version {2}) was deleted before its captured event could be saved. History was skipped.",
                            alertEvent.RuleId,
                            alertEvent.RuleName,
                            alertEvent.RuleVersion ) ) );
                    return null;
                }

                var history = new IISAlertHistory
                {
                    IISAlertId = alertEvent.RuleId,
                    AlertName = alertEvent.RuleName,
                    TrippedDateTime = alertEvent.MatchedDateTime,
                    ResultCount = alertEvent.SuppressedMatchCount + 1,
                    Summary = summary,
                    ResultJson = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize( new[] { alertEvent.CreatePersistedResult() } )
                };

                new IISAlertHistoryService( rockContext ).Add( history );
                alert.LastRunDateTime = alertEvent.MatchedDateTime;
                rockContext.SaveChanges();
                return history.Id;
            }
        }

        private static string ResolveSummary( IISAlertRealtimeEvent alertEvent )
        {
            var template = alertEvent.SummaryLava.IfEmpty( "Real-time request rule matched." );
            var mergeFields = new Dictionary<string, object>
            {
                { "Request", alertEvent.Result },
                { "results", new List<object> { alertEvent.Result } },
                { "SuppressedMatchCount", alertEvent.SuppressedMatchCount },
                { "ResultCount", alertEvent.SuppressedMatchCount + 1 }
            };

            return template.ResolveMergeFields( mergeFields, string.Empty );
        }

        private static string RenderSummary( IISAlertRealtimeEvent alertEvent )
        {
            return ResolveSummaryOverride == null
                ? ResolveSummary( alertEvent )
                : ResolveSummaryOverride( alertEvent );
        }

        private static void PersistIpBlock( IISAlertRealtimeEvent alertEvent, int? historyId )
        {
            var now = RockDateTime.Now;
            var expiresDateTime = alertEvent.MatchedDateTime.AddMinutes( Math.Max( 1, alertEvent.BlockIpAddressMinutes ) );
            int blockedIpId;
            using ( var rockContext = new RockContext() )
            {
                var blockedIpService = new IISAlertBlockedIpService( rockContext );
                var blockedIp = blockedIpService.Queryable()
                    .Where( block => block.IpAddress == alertEvent.IpAddressToPersist && block.ExpiresDateTime > now )
                    .OrderByDescending( block => block.ExpiresDateTime )
                    .FirstOrDefault();

                if ( blockedIp == null )
                {
                    blockedIp = new IISAlertBlockedIp
                    {
                        IpAddress = alertEvent.IpAddressToPersist,
                        BlockedDateTime = alertEvent.MatchedDateTime
                    };
                    blockedIpService.Add( blockedIp );
                }

                blockedIp.ExpiresDateTime = blockedIp.ExpiresDateTime > expiresDateTime ? blockedIp.ExpiresDateTime : expiresDateTime;
                blockedIp.AlertName = alertEvent.RuleName;
                rockContext.SaveChanges();
                blockedIpId = blockedIp.Id;
            }

            // Attribution is useful but optional. Persist the enforcement first so a concurrently
            // deleted rule or history row cannot prevent the captured block from taking effect.
            TryExecute( "link realtime IIS IP block attribution", () => LinkIpBlockAttribution( blockedIpId, alertEvent.RuleId, historyId ) );
        }

        private static void LinkIpBlockAttribution( int blockedIpId, int ruleId, int? historyId )
        {
            using ( var rockContext = new RockContext() )
            {
                var blockedIp = new IISAlertBlockedIpService( rockContext ).Get( blockedIpId );
                if ( blockedIp == null )
                {
                    return;
                }

                blockedIp.IISAlertId = new IISAlertService( rockContext ).Get( ruleId ) == null ? ( int? ) null : ruleId;
                blockedIp.IISAlertHistoryId = historyId.HasValue
                    && new IISAlertHistoryService( rockContext ).Get( historyId.Value ) != null
                    ? historyId
                    : null;
                rockContext.SaveChanges();
            }
        }

        private static void LockOutUserAccount( IISAlertRealtimeEvent alertEvent )
        {
            using ( var rockContext = new RockContext() )
            {
                var userLogin = new UserLoginService( rockContext ).Queryable()
                    .FirstOrDefault( login => login.UserName == alertEvent.UserNameToLockOut );
                if ( userLogin == null )
                {
                    return;
                }

                userLogin.IsLockedOut = true;
                userLogin.LastLockedOutDateTime = alertEvent.MatchedDateTime;
                rockContext.SaveChanges();
            }
        }

        private static void SendAlertEmail( IISAlertRealtimeEvent alertEvent, string summary, int? historyId )
        {
            var mergeFields = Rock.Lava.LavaHelper.GetCommonMergeFields( null );
            mergeFields.AddOrReplace( "AlertName", alertEvent.RuleName );
            mergeFields.AddOrReplace( "AlertType", "Real-time IIS Rule" );
            mergeFields.AddOrReplace( "AlertDate", alertEvent.MatchedDateTime.ToShortDateString() );
            mergeFields.AddOrReplace( "AlertTime", alertEvent.MatchedDateTime.ToShortTimeString() );
            mergeFields.AddOrReplace( "Summary", summary );
            mergeFields.AddOrReplace( "AlertHistoryUrl", historyId.HasValue ? GetAlertHistoryUrl( historyId.Value ) : string.Empty );
            mergeFields.AddOrReplace( "RuleVersion", alertEvent.RuleVersion );
            mergeFields.AddOrReplace( "SuppressedMatchCount", alertEvent.SuppressedMatchCount );
            mergeFields.AddOrReplace( "ResultCount", alertEvent.SuppressedMatchCount + 1 );

            var emailMessage = new RockEmailMessage( AlertSystemCommunicationGuid );
            foreach ( var email in alertEvent.NotificationEmails )
            {
                emailMessage.AddRecipient( RockEmailMessageRecipient.CreateAnonymous( email, mergeFields ) );
            }

            List<string> errors;
            if ( !emailMessage.Send( out errors ) )
            {
                throw new Exception( errors != null && errors.Any()
                    ? errors.JoinStrings( "; " )
                    : "The real-time IIS alert email provider reported failure without an error message." );
            }
        }

        private static bool TryExecuteWithRetry( string actionName, int maximumAttempts, Action action )
        {
            Exception lastException = null;
            for ( var attempt = 1; attempt <= maximumAttempts; attempt++ )
            {
                try
                {
                    action();
                    return true;
                }
                catch ( Exception ex )
                {
                    lastException = ex;
                }
            }

            LogException( new Exception(
                string.Format( "Unable to {0} after {1} attempts.", actionName, maximumAttempts ),
                lastException ) );
            return false;
        }

        private static bool TryExecute( string actionName, Action action )
        {
            try
            {
                action();
                return true;
            }
            catch ( Exception ex )
            {
                LogException( new Exception( "Unable to " + actionName + ".", ex ) );
                return false;
            }
        }

        private static void LogException( Exception exception )
        {
            try
            {
                if ( ExceptionLoggerOverride == null )
                {
                    ExceptionLogService.LogException( exception );
                }
                else
                {
                    ExceptionLoggerOverride( exception );
                }
            }
            catch ( Exception loggingException )
            {
                Trace.TraceError(
                    "Unable to record real-time IIS alert failure. Original: {0} Logging: {1}",
                    exception,
                    loggingException );
            }
        }

        private static void UpdateHistoryOutcomes( int historyId, Dictionary<string, string> result )
        {
            using ( var rockContext = new RockContext() )
            {
                var history = new IISAlertHistoryService( rockContext ).Get( historyId );
                if ( history == null )
                {
                    return;
                }

                history.ResultJson = new JavaScriptSerializer { MaxJsonLength = int.MaxValue }.Serialize( new[] { result } );
                rockContext.SaveChanges();
            }
        }

        private static string GetAlertHistoryUrl( int historyId )
        {
            var pageReference = new Rock.Web.PageReference(
                AlertHistoryDetailPageGuid,
                new Dictionary<string, string> { { "IISAlertHistoryId", historyId.ToString() } } );
            return pageReference.PageId > 0 ? pageReference.BuildUrl() : string.Empty;
        }
    }

    internal sealed class IISAlertHistoryResult
    {
        public int? HistoryId { get; set; }

        public string Summary { get; set; }
    }
}
