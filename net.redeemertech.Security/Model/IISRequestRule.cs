using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text.RegularExpressions;

namespace net.redeemertech.Security.Model
{
    public enum IISAlertEvaluationMode
    {
        LogQuery = 0,
        RealTimeRule = 1
    }

    public enum IISRequestRuleStage
    {
        PreAuthentication = 0,
        PostAuthentication = 1,
        EndRequest = 2
    }

    public enum IISRequestRuleConditionLogic
    {
        All = 0,
        Any = 1
    }

    public static class IISRequestRuleField
    {
        public const string ClientIp = "ClientIp";
        public const string HttpMethod = "HttpMethod";
        public const string Host = "Host";
        public const string Path = "Path";
        public const string RawUrl = "RawUrl";
        public const string QueryString = "QueryString";
        public const string UserAgent = "UserAgent";
        public const string Referrer = "Referrer";
        public const string RequestContentType = "RequestContentType";
        public const string RequestContentLength = "RequestContentLength";
        public const string RequestHeader = "RequestHeader";
        public const string IsAuthenticated = "IsAuthenticated";
        public const string UserName = "UserName";
        public const string SecurityRole = "SecurityRole";
        public const string ResponseStatusCode = "ResponseStatusCode";
        public const string ResponseSubStatusCode = "ResponseSubStatusCode";
        public const string ResponseContentType = "ResponseContentType";
        public const string ResponseHeader = "ResponseHeader";
        public const string ResponseBytes = "ResponseBytes";
        public const string DurationMilliseconds = "DurationMilliseconds";

        private static readonly HashSet<string> PreAuthenticationFields = new HashSet<string>( StringComparer.OrdinalIgnoreCase )
        {
            ClientIp,
            HttpMethod,
            Host,
            Path,
            RawUrl,
            QueryString,
            UserAgent,
            Referrer,
            RequestContentType,
            RequestContentLength,
            RequestHeader
        };

        private static readonly HashSet<string> PostAuthenticationFields = new HashSet<string>( PreAuthenticationFields, StringComparer.OrdinalIgnoreCase )
        {
            IsAuthenticated,
            UserName,
            SecurityRole
        };

        private static readonly HashSet<string> EndRequestFields = new HashSet<string>( PostAuthenticationFields, StringComparer.OrdinalIgnoreCase )
        {
            ResponseStatusCode,
            ResponseSubStatusCode,
            ResponseContentType,
            ResponseHeader,
            ResponseBytes,
            DurationMilliseconds
        };

        public static bool IsAvailable( string field, IISRequestRuleStage stage )
        {
            switch ( stage )
            {
                case IISRequestRuleStage.PreAuthentication:
                    return PreAuthenticationFields.Contains( field ?? string.Empty );
                case IISRequestRuleStage.PostAuthentication:
                    return PostAuthenticationFields.Contains( field ?? string.Empty );
                case IISRequestRuleStage.EndRequest:
                    return EndRequestFields.Contains( field ?? string.Empty );
                default:
                    return false;
            }
        }

        public static bool IsEndRequestOnly( string field )
        {
            return EndRequestFields.Contains( field ?? string.Empty ) && !PostAuthenticationFields.Contains( field ?? string.Empty );
        }
    }

    public static class IISRequestRuleOperator
    {
        public const string Equal = "Equals";
        public const string NotEquals = "NotEquals";
        public const string Contains = "Contains";
        public const string StartsWith = "StartsWith";
        public const string EndsWith = "EndsWith";
        public const string Regex = "Regex";
        public const string Exists = "Exists";
        public const string DoesNotExist = "DoesNotExist";
        public const string GreaterThan = "GreaterThan";
        public const string GreaterThanOrEqual = "GreaterThanOrEqual";
        public const string LessThan = "LessThan";
        public const string LessThanOrEqual = "LessThanOrEqual";
        public const string IsMemberOf = "IsMemberOf";
        public const string IsNotMemberOf = "IsNotMemberOf";

        public static readonly HashSet<string> All = new HashSet<string>( StringComparer.OrdinalIgnoreCase )
        {
            Equal,
            NotEquals,
            Contains,
            StartsWith,
            EndsWith,
            Regex,
            Exists,
            DoesNotExist,
            GreaterThan,
            GreaterThanOrEqual,
            LessThan,
            LessThanOrEqual,
            IsMemberOf,
            IsNotMemberOf
        };
    }

    public class IISRequestRuleCondition
    {
        public string Field { get; set; }

        public string Operator { get; set; }

        public string Value { get; set; }

        public string HeaderName { get; set; }

        public bool IgnoreCase { get; set; }
    }

    public enum IISRequestRuleMatchResult
    {
        NotMatched = 0,
        Matched = 1,
        RegexInputTooLong = 2,
        RegexTimedOut = 3
    }

    public static class IISRequestRuleCompiler
    {
        public static bool TryCompile(
            IISRequestRuleStage stage,
            IISRequestRuleConditionLogic conditionLogic,
            IEnumerable<IISRequestRuleCondition> conditions,
            out List<IISRequestRuleConditionMatcher> matchers,
            out List<string> errors )
        {
            matchers = new List<IISRequestRuleConditionMatcher>();
            errors = new List<string>();

            if ( !Enum.IsDefined( typeof( IISRequestRuleStage ), stage ) )
            {
                errors.Add( string.Format( "The processing stage value '{0}' is invalid.", ( int ) stage ) );
            }

            if ( !Enum.IsDefined( typeof( IISRequestRuleConditionLogic ), conditionLogic ) )
            {
                errors.Add( string.Format( "The condition logic value '{0}' is invalid.", ( int ) conditionLogic ) );
            }

            var conditionList = conditions == null ? new List<IISRequestRuleCondition>() : conditions.ToList();
            if ( conditionList.Count == 0 )
            {
                errors.Add( "At least one condition is required. Add an explicit condition to create a match-all rule." );
            }

            for ( var index = 0; index < conditionList.Count; index++ )
            {
                var condition = conditionList[index];
                var validationMessage = IISRequestRuleConditionMatcher.Validate( condition, stage );
                if ( validationMessage != null )
                {
                    errors.Add( string.Format( "Condition {0}: {1}", index + 1, validationMessage ) );
                    continue;
                }

                matchers.Add( new IISRequestRuleConditionMatcher( condition ) );
            }

            if ( errors.Count > 0 )
            {
                matchers.Clear();
                return false;
            }

            return true;
        }
    }

    public class IISRequestRuleConditionMatcher
    {
        private const int RegexTimeoutMilliseconds = 5;
        private const int MaximumInputLength = 16384;

        private readonly IISRequestRuleCondition _condition;
        private readonly string _operator;
        private readonly Regex _regex;

        public IISRequestRuleConditionMatcher( IISRequestRuleCondition condition )
        {
            if ( condition == null )
            {
                throw new ArgumentNullException( nameof( condition ) );
            }
            _condition = new IISRequestRuleCondition
            {
                Field = condition.Field,
                Operator = condition.Operator,
                Value = condition.Value,
                HeaderName = condition.HeaderName,
                IgnoreCase = condition.IgnoreCase
            };
            _operator = IISRequestRuleOperator.All.FirstOrDefault( value => string.Equals( value, condition.Operator, StringComparison.OrdinalIgnoreCase ) )
                ?? condition.Operator;

            if ( string.Equals( condition.Operator, IISRequestRuleOperator.Regex, StringComparison.OrdinalIgnoreCase ) )
            {
                var options = RegexOptions.Compiled | RegexOptions.CultureInvariant;
                if ( condition.IgnoreCase )
                {
                    options |= RegexOptions.IgnoreCase;
                }

                _regex = new Regex( condition.Value ?? string.Empty, options, TimeSpan.FromMilliseconds( RegexTimeoutMilliseconds ) );
            }
        }

        public bool IsMatch( Func<IISRequestRuleCondition, string> valueProvider, Func<Guid, bool> securityRoleMembershipProvider = null )
        {
            return Evaluate( valueProvider, securityRoleMembershipProvider ) == IISRequestRuleMatchResult.Matched;
        }

        public IISRequestRuleMatchResult Evaluate( Func<IISRequestRuleCondition, string> valueProvider, Func<Guid, bool> securityRoleMembershipProvider = null )
        {
            if ( string.Equals( _condition.Field, IISRequestRuleField.SecurityRole, StringComparison.OrdinalIgnoreCase ) )
            {
                Guid securityRoleGuid;
                var isMember = Guid.TryParse( _condition.Value, out securityRoleGuid )
                    && securityRoleMembershipProvider != null
                    && securityRoleMembershipProvider( securityRoleGuid );

                var isRoleMatch = string.Equals( _operator, IISRequestRuleOperator.IsMemberOf, StringComparison.OrdinalIgnoreCase )
                    ? isMember
                    : !isMember;
                return isRoleMatch ? IISRequestRuleMatchResult.Matched : IISRequestRuleMatchResult.NotMatched;
            }

            var actualValue = valueProvider( _condition ) ?? string.Empty;
            var expectedValue = _condition.Value ?? string.Empty;
            var comparison = _condition.IgnoreCase ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
            bool isMatch;

            switch ( _operator )
            {
                case IISRequestRuleOperator.Equal:
                    isMatch = string.Equals( actualValue, expectedValue, comparison );
                    break;
                case IISRequestRuleOperator.NotEquals:
                    isMatch = !string.Equals( actualValue, expectedValue, comparison );
                    break;
                case IISRequestRuleOperator.Contains:
                    isMatch = actualValue.IndexOf( expectedValue, comparison ) >= 0;
                    break;
                case IISRequestRuleOperator.StartsWith:
                    isMatch = actualValue.StartsWith( expectedValue, comparison );
                    break;
                case IISRequestRuleOperator.EndsWith:
                    isMatch = actualValue.EndsWith( expectedValue, comparison );
                    break;
                case IISRequestRuleOperator.Regex:
                    if ( actualValue.Length > MaximumInputLength )
                    {
                        return IISRequestRuleMatchResult.RegexInputTooLong;
                    }

                    try
                    {
                        isMatch = _regex.IsMatch( actualValue );
                    }
                    catch ( RegexMatchTimeoutException )
                    {
                        return IISRequestRuleMatchResult.RegexTimedOut;
                    }
                    break;
                case IISRequestRuleOperator.Exists:
                    isMatch = !string.IsNullOrWhiteSpace( actualValue );
                    break;
                case IISRequestRuleOperator.DoesNotExist:
                    isMatch = string.IsNullOrWhiteSpace( actualValue );
                    break;
                case IISRequestRuleOperator.GreaterThan:
                    isMatch = CompareNumbers( actualValue, expectedValue, c => c > 0 );
                    break;
                case IISRequestRuleOperator.GreaterThanOrEqual:
                    isMatch = CompareNumbers( actualValue, expectedValue, c => c >= 0 );
                    break;
                case IISRequestRuleOperator.LessThan:
                    isMatch = CompareNumbers( actualValue, expectedValue, c => c < 0 );
                    break;
                case IISRequestRuleOperator.LessThanOrEqual:
                    isMatch = CompareNumbers( actualValue, expectedValue, c => c <= 0 );
                    break;
                default:
                    isMatch = false;
                    break;
            }

            return isMatch ? IISRequestRuleMatchResult.Matched : IISRequestRuleMatchResult.NotMatched;
        }

        public static string Validate( IISRequestRuleCondition condition, IISRequestRuleStage stage )
        {
            if ( condition == null )
            {
                return "A condition is missing.";
            }

            if ( string.IsNullOrWhiteSpace( condition.Field ) )
            {
                return "A condition field is required.";
            }

            if ( !IISRequestRuleField.IsAvailable( condition.Field, stage ) )
            {
                return string.Format( "The {0} field is not available at the {1} stage.", condition.Field, stage );
            }

            if ( string.IsNullOrWhiteSpace( condition.Operator ) )
            {
                return "A condition operator is required.";
            }

            if ( !IISRequestRuleOperator.All.Contains( condition.Operator ?? string.Empty ) )
            {
                return string.Format( "The {0} condition operator is not supported.", condition.Operator );
            }

            var isSecurityRoleCondition = string.Equals( condition.Field, IISRequestRuleField.SecurityRole, StringComparison.OrdinalIgnoreCase );
            var isSecurityRoleOperator = string.Equals( condition.Operator, IISRequestRuleOperator.IsMemberOf, StringComparison.OrdinalIgnoreCase )
                || string.Equals( condition.Operator, IISRequestRuleOperator.IsNotMemberOf, StringComparison.OrdinalIgnoreCase );

            if ( isSecurityRoleCondition && !isSecurityRoleOperator )
            {
                return "Security Role conditions must use Is Member Of or Is Not Member Of.";
            }

            if ( !isSecurityRoleCondition && isSecurityRoleOperator )
            {
                return "Is Member Of and Is Not Member Of can only be used with the Security Role field.";
            }

            Guid securityRoleGuid;
            if ( isSecurityRoleCondition && !Guid.TryParse( condition.Value, out securityRoleGuid ) )
            {
                return "A valid security role is required.";
            }

            if ( ( string.Equals( condition.Field, IISRequestRuleField.RequestHeader, StringComparison.OrdinalIgnoreCase )
                    || string.Equals( condition.Field, IISRequestRuleField.ResponseHeader, StringComparison.OrdinalIgnoreCase ) )
                && string.IsNullOrWhiteSpace( condition.HeaderName ) )
            {
                return "A header name is required for header conditions.";
            }

            if ( !string.Equals( condition.Operator, IISRequestRuleOperator.Exists, StringComparison.OrdinalIgnoreCase )
                && !string.Equals( condition.Operator, IISRequestRuleOperator.DoesNotExist, StringComparison.OrdinalIgnoreCase )
                && condition.Value == null )
            {
                return "A condition value is required.";
            }

            if ( ( string.Equals( condition.Operator, IISRequestRuleOperator.Contains, StringComparison.OrdinalIgnoreCase )
                    || string.Equals( condition.Operator, IISRequestRuleOperator.StartsWith, StringComparison.OrdinalIgnoreCase )
                    || string.Equals( condition.Operator, IISRequestRuleOperator.EndsWith, StringComparison.OrdinalIgnoreCase )
                    || string.Equals( condition.Operator, IISRequestRuleOperator.Regex, StringComparison.OrdinalIgnoreCase ) )
                && string.IsNullOrEmpty( condition.Value ) )
            {
                return "A non-empty condition value is required for this operator.";
            }

            if ( string.Equals( condition.Operator, IISRequestRuleOperator.GreaterThan, StringComparison.OrdinalIgnoreCase )
                || string.Equals( condition.Operator, IISRequestRuleOperator.GreaterThanOrEqual, StringComparison.OrdinalIgnoreCase )
                || string.Equals( condition.Operator, IISRequestRuleOperator.LessThan, StringComparison.OrdinalIgnoreCase )
                || string.Equals( condition.Operator, IISRequestRuleOperator.LessThanOrEqual, StringComparison.OrdinalIgnoreCase ) )
            {
                decimal numericValue;
                if ( !decimal.TryParse( condition.Value, NumberStyles.Number, CultureInfo.InvariantCulture, out numericValue ) )
                {
                    return "A valid numeric condition value is required for this operator.";
                }
            }

            if ( string.Equals( condition.Operator, IISRequestRuleOperator.Regex, StringComparison.OrdinalIgnoreCase ) )
            {
                try
                {
                    new IISRequestRuleConditionMatcher( condition );
                }
                catch ( ArgumentException ex )
                {
                    return "The regular expression is invalid: " + ex.Message;
                }
            }

            return null;
        }

        private static bool CompareNumbers( string actualValue, string expectedValue, Func<int, bool> predicate )
        {
            decimal actualNumber;
            decimal expectedNumber;
            if ( !decimal.TryParse( actualValue, NumberStyles.Number, CultureInfo.InvariantCulture, out actualNumber )
                || !decimal.TryParse( expectedValue, NumberStyles.Number, CultureInfo.InvariantCulture, out expectedNumber ) )
            {
                return false;
            }

            return predicate( actualNumber.CompareTo( expectedNumber ) );
        }
    }
}
