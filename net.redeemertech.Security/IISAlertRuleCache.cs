using net.redeemertech.Security.Model;

using Rock;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace net.redeemertech.Security
{
    internal sealed class IISRealtimeRule
    {
        public int Id { get; private set; }

        public string Name { get; private set; }

        public IISRequestRuleStage Stage { get; private set; }

        public IISRequestRuleConditionLogic ConditionLogic { get; private set; }

        public string SummaryLava { get; private set; }

        public string NotificationEmails { get; private set; }

        public int EvaluationFrequencyMinutes { get; private set; }

        public bool BlockRequest { get; private set; }

        public int BlockResponseStatusCode { get; private set; }

        public string BlockResponseMessage { get; private set; }

        public bool BlockIpAddress { get; private set; }

        public int BlockIpAddressMinutes { get; private set; }

        public bool LockOutUserAccounts { get; private set; }

        public bool RequiresResponseBytes { get; private set; }

        private IReadOnlyList<IISRequestRuleCondition> Conditions { get; set; }

        public IReadOnlyList<IISRequestRuleConditionMatcher> ConditionMatchers { get; private set; }

        public string Version { get; private set; }

        internal bool HasSecurityRoleCondition => Conditions.Any( condition =>
            string.Equals( condition.Field, IISRequestRuleField.SecurityRole, StringComparison.OrdinalIgnoreCase ) );

        internal IEnumerable<string> GetRequiredHeaderNames( string field )
        {
            return Conditions
                .Where( condition => string.Equals( condition.Field, field, StringComparison.OrdinalIgnoreCase ) )
                .Select( condition => condition.HeaderName )
                .Where( name => !string.IsNullOrWhiteSpace( name ) );
        }

        internal IISRealtimeRule(
            int id,
            string name,
            IISRequestRuleStage stage,
            IISRequestRuleConditionLogic conditionLogic,
            string summaryLava,
            string notificationEmails,
            int evaluationFrequencyMinutes,
            bool blockRequest,
            int blockResponseStatusCode,
            string blockResponseMessage,
            bool blockIpAddress,
            int blockIpAddressMinutes,
            bool lockOutUserAccounts,
            IEnumerable<IISRequestRuleCondition> conditions,
            IEnumerable<IISRequestRuleConditionMatcher> conditionMatchers )
        {
            Id = id;
            Name = name;
            Stage = stage;
            ConditionLogic = conditionLogic;
            SummaryLava = summaryLava;
            NotificationEmails = notificationEmails;
            EvaluationFrequencyMinutes = evaluationFrequencyMinutes;
            BlockRequest = blockRequest;
            BlockResponseStatusCode = blockResponseStatusCode;
            BlockResponseMessage = blockResponseMessage;
            BlockIpAddress = blockIpAddress;
            BlockIpAddressMinutes = blockIpAddressMinutes;
            LockOutUserAccounts = lockOutUserAccounts;

            var conditionCopies = ( conditions ?? Enumerable.Empty<IISRequestRuleCondition>() )
                .Select( condition => new IISRequestRuleCondition
                {
                    Field = condition.Field,
                    Operator = condition.Operator,
                    Value = condition.Value,
                    HeaderName = condition.HeaderName,
                    IgnoreCase = condition.IgnoreCase
                } )
                .ToList();
            Conditions = new ReadOnlyCollection<IISRequestRuleCondition>( conditionCopies );
            ConditionMatchers = new ReadOnlyCollection<IISRequestRuleConditionMatcher>(
                ( conditionMatchers ?? Enumerable.Empty<IISRequestRuleConditionMatcher>() ).ToList() );
            RequiresResponseBytes = conditionCopies.Any( condition => string.Equals( condition.Field, IISRequestRuleField.ResponseBytes, StringComparison.OrdinalIgnoreCase ) );
            Version = ComputeVersion();
        }

        private string ComputeVersion()
        {
            var canonical = new StringBuilder();
            AppendVersionValue( canonical, Id );
            AppendVersionValue( canonical, Name );
            AppendVersionValue( canonical, ( int ) Stage );
            AppendVersionValue( canonical, ( int ) ConditionLogic );
            AppendVersionValue( canonical, SummaryLava );
            AppendVersionValue( canonical, NotificationEmails );
            AppendVersionValue( canonical, EvaluationFrequencyMinutes );
            AppendVersionValue( canonical, BlockRequest );
            AppendVersionValue( canonical, BlockResponseStatusCode );
            AppendVersionValue( canonical, BlockResponseMessage );
            AppendVersionValue( canonical, BlockIpAddress );
            AppendVersionValue( canonical, BlockIpAddressMinutes );
            AppendVersionValue( canonical, LockOutUserAccounts );
            foreach ( var condition in Conditions )
            {
                AppendVersionValue( canonical, condition.Field );
                AppendVersionValue( canonical, condition.Operator );
                AppendVersionValue( canonical, condition.Value );
                AppendVersionValue( canonical, condition.HeaderName );
                AppendVersionValue( canonical, condition.IgnoreCase );
            }

            using ( var sha256 = SHA256.Create() )
            {
                return BitConverter.ToString( sha256.ComputeHash( Encoding.UTF8.GetBytes( canonical.ToString() ) ) ).Replace( "-", string.Empty );
            }
        }

        private static void AppendVersionValue( StringBuilder canonical, object value )
        {
            var text = Convert.ToString( value, System.Globalization.CultureInfo.InvariantCulture ) ?? string.Empty;
            canonical.Append( text.Length ).Append( ':' ).Append( text ).Append( ';' );
        }

        public bool IsMatch( IISRequestRuleSnapshot snapshot )
        {
            if ( ConditionMatchers == null || ConditionMatchers.Count == 0 )
            {
                return false;
            }

            try
            {
                if ( ConditionLogic == IISRequestRuleConditionLogic.Any )
                {
                    return ConditionMatchers.Any( matcher => matcher.IsMatch( snapshot.GetValue, snapshot.IsPersonInSecurityRole ) );
                }

                return ConditionMatchers.All( matcher => matcher.IsMatch( snapshot.GetValue, snapshot.IsPersonInSecurityRole ) );
            }
            catch ( RegexMatchTimeoutException )
            {
                // A hostile input can cause an otherwise valid backtracking expression to time out.
                // Treat a timeout as no match so a rule cannot hold the request open indefinitely.
                return false;
            }
        }
    }

    internal sealed class IISAlertRuleConfiguration
    {
        private readonly IReadOnlyList<IISRealtimeRule> _preAuthenticationRules;
        private readonly IReadOnlyList<IISRealtimeRule> _postAuthenticationRules;
        private readonly IReadOnlyList<IISRealtimeRule> _endRequestRules;

        internal IISAlertRuleConfiguration( IEnumerable<IISRealtimeRule> rules, IEnumerable<string> loadDiagnostics = null )
        {
            var ruleList = ( rules ?? Enumerable.Empty<IISRealtimeRule>() ).ToList();
            _preAuthenticationRules = AsReadOnly( ruleList.Where( rule => rule.Stage == IISRequestRuleStage.PreAuthentication ) );
            _postAuthenticationRules = AsReadOnly( ruleList.Where( rule => rule.Stage == IISRequestRuleStage.PostAuthentication ) );
            _endRequestRules = AsReadOnly( ruleList.Where( rule => rule.Stage == IISRequestRuleStage.EndRequest ) );

            HasActiveRules = ruleList.Count > 0;
            RequiresResponseByteCounting = _endRequestRules.Any( rule => rule.RequiresResponseBytes );
            HasPostAuthenticationRules = _postAuthenticationRules.Count > 0;
            HasEndRequestRules = _endRequestRules.Count > 0;
            HasSecurityRoleConditions = ruleList.Any( rule => rule.HasSecurityRoleCondition );
            RequiredHeaderNames = GetRequiredHeaders( ruleList, IISRequestRuleField.RequestHeader );
            RequiredResponseHeaderNames = GetRequiredHeaders( ruleList, IISRequestRuleField.ResponseHeader );
            LoadDiagnostics = AsReadOnly( loadDiagnostics ?? Enumerable.Empty<string>() );
        }

        public bool HasActiveRules { get; private set; }

        public bool RequiresResponseByteCounting { get; private set; }

        public bool HasPostAuthenticationRules { get; private set; }

        public bool HasEndRequestRules { get; private set; }

        public bool HasSecurityRoleConditions { get; private set; }

        public IReadOnlyList<string> RequiredHeaderNames { get; private set; }

        public IReadOnlyList<string> RequiredResponseHeaderNames { get; private set; }

        public IReadOnlyList<string> LoadDiagnostics { get; private set; }

        internal List<IISRealtimeRule> GetMatchingRules( IISRequestRuleStage stage, IISRequestRuleSnapshot snapshot, bool? requiresResponseBytes = null )
        {
            return GetRules( stage ).Where( rule =>
                ( !requiresResponseBytes.HasValue || rule.RequiresResponseBytes == requiresResponseBytes.Value )
                && rule.IsMatch( snapshot ) ).ToList();
        }

        private IReadOnlyList<IISRealtimeRule> GetRules( IISRequestRuleStage stage )
        {
            switch ( stage )
            {
                case IISRequestRuleStage.PreAuthentication:
                    return _preAuthenticationRules;
                case IISRequestRuleStage.PostAuthentication:
                    return _postAuthenticationRules;
                case IISRequestRuleStage.EndRequest:
                    return _endRequestRules;
                default:
                    return new IISRealtimeRule[0];
            }
        }

        private static IReadOnlyList<T> AsReadOnly<T>( IEnumerable<T> values )
        {
            return new ReadOnlyCollection<T>( values.ToList() );
        }

        private static IReadOnlyList<string> GetRequiredHeaders( IEnumerable<IISRealtimeRule> rules, string field )
        {
            return AsReadOnly( rules.SelectMany( rule => rule.GetRequiredHeaderNames( field ) )
                .Distinct( StringComparer.OrdinalIgnoreCase ) );
        }
    }

    internal sealed class IISRequestRuleSnapshot
    {
        private readonly Dictionary<string, string> _values = new Dictionary<string, string>( StringComparer.OrdinalIgnoreCase );
        private readonly Dictionary<string, string> _headers = new Dictionary<string, string>( StringComparer.OrdinalIgnoreCase );
        private readonly Dictionary<string, string> _responseHeaders = new Dictionary<string, string>( StringComparer.OrdinalIgnoreCase );

        public DateTime StartedDateTimeUtc { get; set; }

        public long ResponseBytes { get; set; }

        public bool ResponseBytesAvailable { get; set; }

        public Guid? PersonGuid { get; private set; }

        public bool IdentityResolved { get; private set; }

        public void SetValue( string field, object value )
        {
            _values[field] = value == null ? string.Empty : Convert.ToString( value, System.Globalization.CultureInfo.InvariantCulture );
        }

        public void SetIdentity( bool isAuthenticated, string userName, Guid? personGuid )
        {
            SetValue( IISRequestRuleField.IsAuthenticated, isAuthenticated ? "true" : "false" );
            SetValue( IISRequestRuleField.UserName, isAuthenticated ? userName : string.Empty );
            PersonGuid = personGuid;
            IdentityResolved = true;
        }

        public bool IsPersonInSecurityRole( Guid securityRoleGuid )
        {
            return PersonGuid.HasValue
                && RoleCache.Get( securityRoleGuid )?.IsPersonInRole( PersonGuid ) == true;
        }

        public void SetHeader( string name, string value )
        {
            if ( !string.IsNullOrWhiteSpace( name ) )
            {
                _headers[name] = value ?? string.Empty;
            }
        }

        public void SetResponseHeader( string name, string value )
        {
            if ( !string.IsNullOrWhiteSpace( name ) )
            {
                _responseHeaders[name] = value ?? string.Empty;
            }
        }

        public string GetValue( IISRequestRuleCondition condition )
        {
            string value;
            if ( string.Equals( condition.Field, IISRequestRuleField.RequestHeader, StringComparison.OrdinalIgnoreCase ) )
            {
                return _headers.TryGetValue( condition.HeaderName ?? string.Empty, out value ) ? value : string.Empty;
            }

            if ( string.Equals( condition.Field, IISRequestRuleField.ResponseHeader, StringComparison.OrdinalIgnoreCase ) )
            {
                return _responseHeaders.TryGetValue( condition.HeaderName ?? string.Empty, out value ) ? value : string.Empty;
            }

            return _values.TryGetValue( condition.Field ?? string.Empty, out value ) ? value : string.Empty;
        }

        public string GetValue( string field )
        {
            string value;
            return _values.TryGetValue( field ?? string.Empty, out value ) ? value : string.Empty;
        }

        public Dictionary<string, string> ToResultDictionary()
        {
            var result = new Dictionary<string, string>( _values, StringComparer.OrdinalIgnoreCase );
            foreach ( var header in _headers )
            {
                result["Header:" + header.Key] = IsSensitiveHeader( header.Key ) ? "<redacted>" : header.Value;
            }
            foreach ( var header in _responseHeaders )
            {
                result["ResponseHeader:" + header.Key] = IsSensitiveHeader( header.Key ) ? "<redacted>" : header.Value;
            }

            return result;
        }

        public IISRequestRuleSnapshot Clone()
        {
            var clone = new IISRequestRuleSnapshot
            {
                StartedDateTimeUtc = StartedDateTimeUtc,
                ResponseBytes = ResponseBytes,
                ResponseBytesAvailable = ResponseBytesAvailable,
                PersonGuid = PersonGuid,
                IdentityResolved = IdentityResolved
            };

            foreach ( var value in _values )
            {
                clone._values[value.Key] = value.Value;
            }

            foreach ( var header in _headers )
            {
                clone._headers[header.Key] = header.Value;
            }
            foreach ( var header in _responseHeaders )
            {
                clone._responseHeaders[header.Key] = header.Value;
            }

            return clone;
        }

        private static bool IsSensitiveHeader( string name )
        {
            return name.IndexOf( "authorization", StringComparison.OrdinalIgnoreCase ) >= 0
                || name.IndexOf( "cookie", StringComparison.OrdinalIgnoreCase ) >= 0
                || name.IndexOf( "api-key", StringComparison.OrdinalIgnoreCase ) >= 0
                || name.IndexOf( "apikey", StringComparison.OrdinalIgnoreCase ) >= 0
                || name.IndexOf( "token", StringComparison.OrdinalIgnoreCase ) >= 0;
        }
    }

    public static class IISAlertRuleCache
    {
        private static readonly object LoadLock = new object();
        private static readonly ConcurrentDictionary<int, DateTime> NextTriggerDateTimes = new ConcurrentDictionary<int, DateTime>();
        private static IISAlertRuleConfiguration _configuration;
        private static long _reloadSequence;
        private static long _publishedReloadSequence;

        public static bool HasActiveRules
        {
            get
            {
                return Capture().HasActiveRules;
            }
        }

        public static bool RequiresResponseByteCounting
        {
            get
            {
                return Capture().RequiresResponseByteCounting;
            }
        }

        public static bool HasPostAuthenticationRules
        {
            get
            {
                return Capture().HasPostAuthenticationRules;
            }
        }

        public static bool HasSecurityRoleConditions
        {
            get
            {
                return Capture().HasSecurityRoleConditions;
            }
        }

        public static bool HasEndRequestRules
        {
            get
            {
                return Capture().HasEndRequestRules;
            }
        }

        public static IReadOnlyList<string> RequiredHeaderNames
        {
            get
            {
                return Capture().RequiredHeaderNames;
            }
        }

        public static IReadOnlyList<string> RequiredResponseHeaderNames
        {
            get
            {
                return Capture().RequiredResponseHeaderNames;
            }
        }

        public static IReadOnlyList<string> LoadDiagnostics
        {
            get
            {
                return Capture().LoadDiagnostics;
            }
        }

        internal static List<IISRealtimeRule> GetMatchingRules( IISRequestRuleStage stage, IISRequestRuleSnapshot snapshot, bool? requiresResponseBytes = null )
        {
            return Capture().GetMatchingRules( stage, snapshot, requiresResponseBytes );
        }

        internal static IISAlertRuleConfiguration Capture()
        {
            EnsureLoaded();
            return Volatile.Read( ref _configuration );
        }

        internal static IISAlertRuleConfiguration PublishConfiguration( IISAlertRuleConfiguration configuration )
        {
            if ( configuration == null )
            {
                throw new ArgumentNullException( nameof( configuration ) );
            }

            return Interlocked.Exchange( ref _configuration, configuration );
        }

        public static void EnsureLoaded()
        {
            if ( Volatile.Read( ref _configuration ) != null )
            {
                return;
            }

            lock ( LoadLock )
            {
                if ( Volatile.Read( ref _configuration ) == null )
                {
                    ReloadCore( Interlocked.Increment( ref _reloadSequence ), BuildConfiguration );
                }
            }
        }

        public static void Reload()
        {
            ReloadCore( Interlocked.Increment( ref _reloadSequence ), BuildConfiguration );
        }

        internal static void Reload( Func<IISAlertRuleConfiguration> configurationLoader )
        {
            if ( configurationLoader == null )
            {
                throw new ArgumentNullException( nameof( configurationLoader ) );
            }

            ReloadCore( Interlocked.Increment( ref _reloadSequence ), configurationLoader );
        }

        private static void ReloadCore( long reloadSequence, Func<IISAlertRuleConfiguration> configurationLoader )
        {
            lock ( LoadLock )
            {
                if ( reloadSequence <= _publishedReloadSequence )
                {
                    return;
                }

                var configuration = configurationLoader();
                if ( configuration == null )
                {
                    throw new InvalidOperationException( "The IIS alert configuration loader returned null." );
                }
                if ( configuration.HasSecurityRoleConditions )
                {
                    IISAuthenticatedUserCache.Reload();
                }

                PublishConfiguration( configuration );
                _publishedReloadSequence = reloadSequence;
            }
        }

        private static IISAlertRuleConfiguration BuildConfiguration()
        {
            var serializer = new JavaScriptSerializer();
            var compiledRules = new List<IISRealtimeRule>();
            var loadDiagnostics = new List<string>();

            using ( var rockContext = new RockContext() )
            {
                var alerts = new IISAlertService( rockContext ).Queryable()
                    .Where( alert => alert.IsActive && alert.EvaluationMode == IISAlertEvaluationMode.RealTimeRule )
                    .ToList();

                foreach ( var alert in alerts )
                {
                    List<IISRequestRuleCondition> conditions;
                    try
                    {
                        conditions = serializer.Deserialize<List<IISRequestRuleCondition>>( alert.ConditionsJson.IfEmpty( "[]" ) ) ?? new List<IISRequestRuleCondition>();
                    }
                    catch ( Exception ex )
                    {
                        loadDiagnostics.Add( FormatLoadDiagnostic( alert.Id, alert.Name, "Conditions JSON could not be read: " + ex.Message ) );
                        continue;
                    }

                    List<IISRequestRuleConditionMatcher> matchers;
                    List<string> errors;
                    if ( !IISRequestRuleCompiler.TryCompile( alert.RequestStage, alert.ConditionLogic, conditions, out matchers, out errors ) )
                    {
                        loadDiagnostics.Add( FormatLoadDiagnostic( alert.Id, alert.Name, string.Join( " ", errors ) ) );
                        continue;
                    }

                    var missingRoleConditions = conditions
                        .Where( condition => string.Equals( condition.Field, IISRequestRuleField.SecurityRole, StringComparison.OrdinalIgnoreCase ) )
                        .Where( condition => RoleCache.Get( condition.Value.AsGuid() ) == null )
                        .ToList();
                    if ( missingRoleConditions.Count > 0 )
                    {
                        loadDiagnostics.Add( FormatLoadDiagnostic( alert.Id, alert.Name, "One or more referenced security roles do not exist." ) );
                        continue;
                    }

                    compiledRules.Add( new IISRealtimeRule(
                        alert.Id,
                        alert.Name,
                        alert.RequestStage,
                        alert.ConditionLogic,
                        alert.SummaryLava,
                        alert.NotificationEmails,
                        alert.EvaluationFrequencyMinutes,
                        alert.BlockRequest && alert.RequestStage != IISRequestRuleStage.EndRequest,
                        alert.BlockResponseStatusCode ?? 403,
                        alert.BlockResponseMessage,
                        alert.BlockIpAddress,
                        Math.Max( 1, alert.BlockIpAddressMinutes ?? 60 ),
                        alert.LockOutUserAccounts && alert.RequestStage != IISRequestRuleStage.PreAuthentication,
                        conditions,
                        matchers ) );
                }
            }

            foreach ( var diagnostic in loadDiagnostics )
            {
                try
                {
                    ExceptionLogService.LogException( new InvalidOperationException( diagnostic ) );
                }
                catch
                {
                    // Diagnostics remain available on the published configuration even
                    // when the exception-log store cannot accept a write.
                }
            }

            return new IISAlertRuleConfiguration( compiledRules, loadDiagnostics );
        }

        private static string FormatLoadDiagnostic( int id, string name, string message )
        {
            return string.Format( "IIS alert {0} ('{1}') was skipped: {2}", id, name ?? string.Empty, message );
        }
    }
}

