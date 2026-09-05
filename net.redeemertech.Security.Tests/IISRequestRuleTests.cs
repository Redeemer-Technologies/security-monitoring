using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security.Model;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class IISRequestRuleTests
    {
        [TestMethod]
        public void CompiledMatcherDoesNotChangeWhenSourceConditionIsEdited()
        {
            var condition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.Equal,
                Value = "/original"
            };
            var matcher = new IISRequestRuleConditionMatcher( condition );
            condition.Field = IISRequestRuleField.UserName;
            condition.Value = "changed";
            Assert.IsTrue( matcher.IsMatch( captured => captured.Field == IISRequestRuleField.Path ? "/original" : "other" ) );
        }

        [TestMethod]
        public void StageValidationOnlyAllowsAvailableFields()
        {
            Assert.IsFalse( IISRequestRuleField.IsAvailable( IISRequestRuleField.UserName, IISRequestRuleStage.PreAuthentication ) );
            Assert.IsTrue( IISRequestRuleField.IsAvailable( IISRequestRuleField.UserName, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsFalse( IISRequestRuleField.IsAvailable( IISRequestRuleField.SecurityRole, IISRequestRuleStage.PreAuthentication ) );
            Assert.IsTrue( IISRequestRuleField.IsAvailable( IISRequestRuleField.SecurityRole, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsTrue( IISRequestRuleField.IsAvailable( IISRequestRuleField.SecurityRole, IISRequestRuleStage.EndRequest ) );
            Assert.IsFalse( IISRequestRuleField.IsAvailable( IISRequestRuleField.ResponseBytes, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsTrue( IISRequestRuleField.IsAvailable( IISRequestRuleField.ResponseBytes, IISRequestRuleStage.EndRequest ) );
            Assert.IsFalse( IISRequestRuleField.IsAvailable( IISRequestRuleField.ResponseHeader, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsTrue( IISRequestRuleField.IsAvailable( IISRequestRuleField.ResponseHeader, IISRequestRuleStage.EndRequest ) );
        }

        [TestMethod]
        public void RegexConditionMatchesWithConfiguredCaseHandling()
        {
            var condition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.Regex,
                Value = @"^/api/people/\d+$",
                IgnoreCase = true
            };
            var matcher = new IISRequestRuleConditionMatcher( condition );

            Assert.IsTrue( matcher.IsMatch( ignored => "/API/People/42" ) );
            Assert.IsFalse( matcher.IsMatch( ignored => "/api/groups/42" ) );
        }

        [TestMethod]
        public void NumericConditionUsesNumericComparison()
        {
            var condition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.ResponseBytes,
                Operator = IISRequestRuleOperator.GreaterThanOrEqual,
                Value = "1048576"
            };
            var matcher = new IISRequestRuleConditionMatcher( condition );

            Assert.IsTrue( matcher.IsMatch( ignored => "1048576" ) );
            Assert.IsFalse( matcher.IsMatch( ignored => "999999" ) );
        }

        [TestMethod]
        public void OrdinaryComparisonsUseTheCompleteInput()
        {
            var suffix = "needle";
            var longValue = new string( 'x', 16384 ) + suffix;
            var endsWith = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.EndsWith,
                Value = suffix
            };
            var equalsTruncatedPrefix = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.Equal,
                Value = longValue.Substring( 0, 16384 )
            };

            Assert.IsTrue( new IISRequestRuleConditionMatcher( endsWith ).IsMatch( ignored => longValue ) );
            Assert.IsFalse( new IISRequestRuleConditionMatcher( equalsTruncatedPrefix ).IsMatch( ignored => longValue ) );
        }

        [TestMethod]
        public void RegexOversizeAndTimeoutHaveExplicitNonMatchOutcomes()
        {
            var ordinaryRegex = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.Regex,
                Value = "needle$"
            };
            var expensiveRegex = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.Regex,
                Value = "^(a+)+$"
            };

            var ordinaryMatcher = new IISRequestRuleConditionMatcher( ordinaryRegex );
            var boundaryResult = ordinaryMatcher.Evaluate( ignored => new string( 'x', 16378 ) + "needle" );
            var oversizedResult = ordinaryMatcher.Evaluate( ignored => new string( 'x', 16384 ) + "needle" );
            var timeoutResult = new IISRequestRuleConditionMatcher( expensiveRegex )
                .Evaluate( ignored => new string( 'a', 10000 ) + "!" );

            Assert.AreEqual( IISRequestRuleMatchResult.Matched, boundaryResult );
            Assert.AreEqual( IISRequestRuleMatchResult.RegexInputTooLong, oversizedResult );
            Assert.AreEqual( IISRequestRuleMatchResult.RegexTimedOut, timeoutResult );
        }

        [TestMethod]
        public void SharedCompilerReturnsIndexedConfigurationErrors()
        {
            var conditions = new IISRequestRuleCondition[]
            {
                null,
                new IISRequestRuleCondition
                {
                    Field = IISRequestRuleField.ResponseBytes,
                    Operator = IISRequestRuleOperator.GreaterThan,
                    Value = "many"
                },
                new IISRequestRuleCondition
                {
                    Field = IISRequestRuleField.Path,
                    Operator = IISRequestRuleOperator.Contains,
                    Value = string.Empty
                }
            };

            List<IISRequestRuleConditionMatcher> matchers;
            List<string> errors;
            var wasCompiled = IISRequestRuleCompiler.TryCompile(
                IISRequestRuleStage.EndRequest,
                ( IISRequestRuleConditionLogic ) 99,
                conditions,
                out matchers,
                out errors );

            Assert.IsFalse( wasCompiled );
            Assert.AreEqual( 0, matchers.Count );
            Assert.IsTrue( errors.Any( error => error.Contains( "condition logic" ) ) );
            Assert.IsTrue( errors.Any( error => error.StartsWith( "Condition 1:" ) ) );
            Assert.IsTrue( errors.Any( error => error.StartsWith( "Condition 2:" ) && error.Contains( "numeric" ) ) );
            Assert.IsTrue( errors.Any( error => error.StartsWith( "Condition 3:" ) && error.Contains( "non-empty" ) ) );

            IISRequestRuleCompiler.TryCompile(
                ( IISRequestRuleStage ) 99,
                IISRequestRuleConditionLogic.All,
                new[] { new IISRequestRuleCondition { Field = IISRequestRuleField.Path, Operator = IISRequestRuleOperator.Exists } },
                out matchers,
                out errors );
            Assert.IsTrue( errors.Any( error => error.Contains( "processing stage" ) ) );
        }

        [TestMethod]
        public void SharedCompilerRejectsImplicitMatchAllRule()
        {
            List<IISRequestRuleConditionMatcher> matchers;
            List<string> errors;

            Assert.IsFalse( IISRequestRuleCompiler.TryCompile(
                IISRequestRuleStage.PreAuthentication,
                IISRequestRuleConditionLogic.All,
                new IISRequestRuleCondition[0],
                out matchers,
                out errors ) );
            Assert.IsTrue( errors.Single().Contains( "explicit condition" ) );
        }

        [TestMethod]
        public void SecurityRoleConditionUsesMembershipProvider()
        {
            var roleGuid = Guid.NewGuid();
            var memberCondition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.SecurityRole,
                Operator = IISRequestRuleOperator.IsMemberOf,
                Value = roleGuid.ToString()
            };
            var notMemberCondition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.SecurityRole,
                Operator = IISRequestRuleOperator.IsNotMemberOf,
                Value = roleGuid.ToString()
            };

            Assert.IsTrue( new IISRequestRuleConditionMatcher( memberCondition ).IsMatch( ignored => string.Empty, guid => guid == roleGuid ) );
            Assert.IsFalse( new IISRequestRuleConditionMatcher( notMemberCondition ).IsMatch( ignored => string.Empty, guid => guid == roleGuid ) );
            Assert.IsFalse( new IISRequestRuleConditionMatcher( memberCondition ).IsMatch( ignored => string.Empty, guid => false ) );
            Assert.IsTrue( new IISRequestRuleConditionMatcher( notMemberCondition ).IsMatch( ignored => string.Empty, guid => false ) );
        }

        [TestMethod]
        public void SecurityRoleConditionRequiresRoleOperatorAndGuid()
        {
            var roleConditionWithTextOperator = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.SecurityRole,
                Operator = IISRequestRuleOperator.Equal,
                Value = Guid.NewGuid().ToString()
            };
            var roleConditionWithInvalidGuid = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.SecurityRole,
                Operator = IISRequestRuleOperator.IsMemberOf,
                Value = "not-a-guid"
            };
            var pathConditionWithRoleOperator = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.Path,
                Operator = IISRequestRuleOperator.IsMemberOf,
                Value = Guid.NewGuid().ToString()
            };
            var validRoleCondition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.SecurityRole,
                Operator = IISRequestRuleOperator.IsNotMemberOf,
                Value = Guid.NewGuid().ToString()
            };

            Assert.IsNotNull( IISRequestRuleConditionMatcher.Validate( roleConditionWithTextOperator, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsNotNull( IISRequestRuleConditionMatcher.Validate( roleConditionWithInvalidGuid, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsNotNull( IISRequestRuleConditionMatcher.Validate( pathConditionWithRoleOperator, IISRequestRuleStage.PostAuthentication ) );
            Assert.IsNull( IISRequestRuleConditionMatcher.Validate( validRoleCondition, IISRequestRuleStage.PostAuthentication ) );
        }

        [TestMethod]
        public void RuleSupportsAllAndAnyConditionLogic()
        {
            var snapshot = new IISRequestRuleSnapshot();
            snapshot.SetValue( IISRequestRuleField.HttpMethod, "GET" );
            snapshot.SetValue( IISRequestRuleField.Path, "/api/people" );

            var conditions = new List<IISRequestRuleCondition>
            {
                new IISRequestRuleCondition { Field = IISRequestRuleField.HttpMethod, Operator = IISRequestRuleOperator.Equal, Value = "GET", IgnoreCase = true },
                new IISRequestRuleCondition { Field = IISRequestRuleField.Path, Operator = IISRequestRuleOperator.StartsWith, Value = "/admin", IgnoreCase = true }
            };
            var matchers = new List<IISRequestRuleConditionMatcher>
                {
                    new IISRequestRuleConditionMatcher( conditions[0] ),
                    new IISRequestRuleConditionMatcher( conditions[1] )
                };
            var allRule = CreateRule( IISRequestRuleConditionLogic.All, conditions, matchers );
            var anyRule = CreateRule( IISRequestRuleConditionLogic.Any, conditions, matchers );

            Assert.IsFalse( allRule.IsMatch( snapshot ) );
            Assert.IsTrue( anyRule.IsMatch( snapshot ) );
        }

        [TestMethod]
        public void InvalidStageAndHeaderConditionsAreRejected()
        {
            var responseCondition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.ResponseStatusCode,
                Operator = IISRequestRuleOperator.Equal,
                Value = "500"
            };
            var headerCondition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.RequestHeader,
                Operator = IISRequestRuleOperator.Exists
            };
            var responseHeaderCondition = new IISRequestRuleCondition
            {
                Field = IISRequestRuleField.ResponseHeader,
                Operator = IISRequestRuleOperator.Exists
            };

            Assert.IsNotNull( IISRequestRuleConditionMatcher.Validate( responseCondition, IISRequestRuleStage.PreAuthentication ) );
            Assert.IsNotNull( IISRequestRuleConditionMatcher.Validate( headerCondition, IISRequestRuleStage.PreAuthentication ) );
            Assert.IsNotNull( IISRequestRuleConditionMatcher.Validate( responseHeaderCondition, IISRequestRuleStage.EndRequest ) );
        }

        [TestMethod]
        public void ResponseStreamCountsBytesWithoutChangingContent()
        {
            var innerStream = new MemoryStream();
            var countingStream = new ResponseByteCountingStream( innerStream );
            var first = new byte[] { 1, 2, 3 };
            var second = new byte[] { 4, 5 };

            countingStream.Write( first, 0, first.Length );
            countingStream.WriteAsync( second, 0, second.Length, CancellationToken.None ).GetAwaiter().GetResult();

            Assert.AreEqual( 5L, countingStream.BytesWritten );
            CollectionAssert.AreEqual( new byte[] { 1, 2, 3, 4, 5 }, innerStream.ToArray() );
        }

        private static IISRealtimeRule CreateRule(
            IISRequestRuleConditionLogic conditionLogic,
            IEnumerable<IISRequestRuleCondition> conditions,
            IEnumerable<IISRequestRuleConditionMatcher> matchers )
        {
            return new IISRealtimeRule(
                1,
                "Test Rule",
                IISRequestRuleStage.PreAuthentication,
                conditionLogic,
                string.Empty,
                string.Empty,
                1,
                false,
                403,
                string.Empty,
                false,
                60,
                false,
                conditions,
                matchers );
        }
    }
}
