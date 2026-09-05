using System;
using System.Linq;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security.Blocks.Blocks;

using Rock.Model;
using Rock.Rest.Filters;
using Rock.Security;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class RestActionSecurityPolicyTests
    {
        [DataTestMethod]
        [DataRow( "GET", "View" )]
        [DataRow( "POST", "Edit" )]
        [DataRow( "DELETE", "Edit" )]
        public void PlainSecuredMarkerUsesHttpVerb( string verb, string expectedAction )
        {
            var action = CreateAction<TestController>( nameof( TestController.Secured ), verb );
            CollectionAssert.AreEqual( new[] { expectedAction }, RestActionSecurityPolicy.GetEnforcedActions( action ) );
        }

        [TestMethod]
        public void ExplicitSecuredMarkerUsesItsAction()
        {
            var action = CreateAction<TestController>( nameof( TestController.CustomSecured ) );
            CollectionAssert.AreEqual( new[] { Authorization.EXECUTE }, RestActionSecurityPolicy.GetEnforcedActions( action ) );
        }

        [TestMethod]
        public void EndpointWithoutMarkerIsInsecurable()
        {
            var action = CreateAction<TestController>( nameof( TestController.Unsecured ) );
            Assert.AreEqual( 0, RestActionSecurityPolicy.GetEnforcedActions( action ).Count );
        }

        [TestMethod]
        public void InheritedMethodRetainsSecuredMarker()
        {
            var action = CreateAction<DerivedController>( nameof( TestController.Secured ) );
            CollectionAssert.AreEqual( new[] { Authorization.VIEW }, RestActionSecurityPolicy.GetEnforcedActions( action ) );
        }

        [TestMethod]
        public void ControllerMarkerSecuresItsEndpoints()
        {
            var action = CreateAction<SecuredController>( nameof( SecuredController.Endpoint ) );
            CollectionAssert.AreEqual( new[] { Authorization.VIEW }, RestActionSecurityPolicy.GetEnforcedActions( action ) );
        }

        [TestMethod]
        public void StableActionGuidStillMatchesAfterSignatureChanges()
        {
            var action = CreateAction<TestController>( nameof( TestController.CustomSecured ) );
            action.Guid = new Guid( "5789977C-7673-481A-9A65-03E5C9481B44" );
            action.ApiId = "old signature";
            CollectionAssert.AreEqual( new[] { Authorization.EXECUTE }, RestActionSecurityPolicy.GetEnforcedActions( action ) );
        }

        [TestMethod]
        public void MissingControllerOrMethodCannotBeSecured()
        {
            Assert.AreEqual( 0, RestActionSecurityPolicy.GetEnforcedActions( new RestAction() ).Count );
            var action = CreateAction<TestController>( nameof( TestController.Secured ) );
            action.ApiId = "missing endpoint";
            Assert.AreEqual( 0, RestActionSecurityPolicy.GetEnforcedActions( action ).Count );
        }

        [DataTestMethod]
        [DataRow( false, false, false )]
        [DataRow( false, true, false )]
        [DataRow( true, true, false )]
        [DataRow( true, false, true )]
        public void BulkActionOnlyChangesInsecureSecurableEndpoints( bool isSecurable, bool isSecured, bool expected )
        {
            Assert.AreEqual( expected, RestActionSecurityPolicy.ShouldSecure( isSecurable, isSecured ) );
        }

        [TestMethod]
        public void UnusedEndpointGetsAllUsersDenyAheadOfExistingRules()
        {
            var existingRule = new Auth { Id = 1, Order = -10, GroupId = 99, AllowOrDeny = "A" };
            var rules = RestActionSecurityPolicy.PrependRules( 12, 34, Authorization.VIEW, new int[0], new[] { existingRule } );

            Assert.AreEqual( 1, rules.Count );
            Assert.AreEqual( SpecialRole.AllUsers, rules[0].SpecialRole );
            Assert.AreEqual( "D", rules[0].AllowOrDeny );
            Assert.AreEqual( 0, rules[0].Order );
            Assert.IsNull( rules[0].GroupId );
            Assert.AreEqual( 1, existingRule.Order );
            Assert.AreEqual( "A", existingRule.AllowOrDeny );
            Assert.AreEqual( 99, existingRule.GroupId );
        }

        [TestMethod]
        public void RockEndpointAllowsRolesBeforeAllUsersDenyAndPreservesExistingOrder()
        {
            var existingRules = new[]
            {
                new Auth { Id = 9, Order = 0, AllowOrDeny = "D", GroupId = 30 },
                new Auth { Id = 2, Order = 0, AllowOrDeny = "A", PersonAliasId = 31 }
            };
            var rules = RestActionSecurityPolicy.PrependRules( 12, 34, Authorization.EDIT, new[] { 11, 22, 33 }, existingRules );

            CollectionAssert.AreEqual( new int?[] { 11, 22, 33, null }, rules.Select( rule => rule.GroupId ).ToArray() );
            CollectionAssert.AreEqual( new[] { "A", "A", "A", "D" }, rules.Select( rule => rule.AllowOrDeny ).ToArray() );
            CollectionAssert.AreEqual( new[] { 0, 1, 2, 3 }, rules.Select( rule => rule.Order ).ToArray() );
            Assert.AreEqual( SpecialRole.AllUsers, rules[3].SpecialRole );
            Assert.IsTrue( rules.All( rule => rule.EntityTypeId == 12 && rule.EntityId == 34 && rule.Action == Authorization.EDIT ) );
            Assert.IsTrue( rules.Take( 3 ).All( rule => rule.SpecialRole == SpecialRole.None && rule.PersonAliasId == null ) );
            Assert.AreEqual( 4, existingRules[1].Order );
            Assert.AreEqual( 5, existingRules[0].Order );
            Assert.AreEqual( 31, existingRules[1].PersonAliasId );
        }

        private static RestAction CreateAction<T>( string methodName, string verb = "GET" )
        {
            var type = typeof( T );
            return new RestAction
            {
                Guid = Guid.NewGuid(),
                Method = verb,
                ApiId = RestControllerService.GetApiId( type.GetMethod( methodName ), verb, type.Name, out _ ),
                Controller = new RestController { Name = type.Name, ClassName = type.FullName }
            };
        }

        public class TestController
        {
            [Secured]
            public void Secured() { }

            [Secured( Authorization.EXECUTE )]
            [Rock.SystemGuid.RestActionGuid( "5789977C-7673-481A-9A65-03E5C9481B44" )]
            public void CustomSecured() { }

            public void Unsecured() { }
        }

        public class DerivedController : TestController { }

        [Secured]
        public class SecuredController
        {
            public void Endpoint() { }
        }
    }
}
