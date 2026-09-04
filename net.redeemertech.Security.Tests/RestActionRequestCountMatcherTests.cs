using System.Collections.Generic;
using System.Diagnostics;

using Microsoft.VisualStudio.TestTools.UnitTesting;

using net.redeemertech.Security.Blocks.Blocks;

namespace net.redeemertech.Security.Tests
{
    [TestClass]
    public class RestActionRequestCountMatcherTests
    {
        [TestMethod]
        public void LiteralPathUsesMethodAndIgnoresUnspecifiedQueryParameters()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/people/search" ),
                Route( 1, "POST", "api/people/search" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "get", "/API/People/Search/", "term=ted" ) );
            Assert.AreEqual( 1, matcher.FindActionIndex( "POST", "api/people/search", null ) );
            Assert.IsNull( matcher.FindActionIndex( "DELETE", "api/people/search", null ) );
        }

        [TestMethod]
        public void LiteralPathWinsBeforeParameterizedPath()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/groups/{groupId}" ),
                Route( 1, "GET", "api/groups/search" ) );

            Assert.AreEqual( 1, matcher.FindActionIndex( "GET", "api/groups/search", null ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/groups/123", null ) );
        }

        [TestMethod]
        public void ParametersCanAppearBetweenLiteralSegments()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/groups/{groupId}/members/{personId}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/groups/123/members/456", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/groups/123/attendance/456", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/groups/123/members/456/edit", null ) );
        }

        [TestMethod]
        public void OptionalPathParameterDoesNotBecomeAQueryString()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/Badges/FamilyAttendance/{personId}/{monthCount}/{showAsIndividual?}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/Badges/FamilyAttendance/123/12", null ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/Badges/FamilyAttendance/123/12/true", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/Badges/FamilyAttendance/123", null ) );
        }

        [TestMethod]
        public void CatchAllParameterConsumesZeroOrMorePathSegments()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/docs/{*assetPath}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/docs", null ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/docs/css/site.css", null ) );
        }

        [TestMethod]
        public void KnownConstraintsNarrowOtherwiseEquivalentRoutes()
        {
            var guid = "4b59fe9c-9df9-4d23-8a7c-b43d1104c802";
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/prayerrequests/prayed/{id:int}" ),
                Route( 1, "GET", "api/prayerrequests/prayed/{id:guid}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/prayerrequests/prayed/42", null ) );
            Assert.AreEqual( 1, matcher.FindActionIndex( "GET", "api/prayerrequests/prayed/" + guid, null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/prayerrequests/prayed/not-an-id", null ) );
        }

        [TestMethod]
        public void CompositePathSegmentMatchesWithoutARegularExpression()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/people({key})" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/people(123)", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/people/123", null ) );
        }

        [TestMethod]
        public void QueryParametersAreMatchedIndependentlyOfPathSegmentsAndOrder()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/people/export?page={page}&pageSize={pageSize}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/people/export", "pageSize=100&page=2&sort=name" ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/people/export", "page=2" ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/people/export/2/100", null ) );
        }

        [TestMethod]
        public void QueryParameterNamesAndValuesAreUrlDecoded()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/search?term=hello world" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/search", "unused=x&term=hello+world" ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/search?term=hello%20world", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/search", "term=goodbye" ) );
        }

        [TestMethod]
        public void OptionalQueryParameterCanBeAbsent()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/search?term={term?}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/search", null ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/search", "term=ted" ) );
        }

        [TestMethod]
        public void OptionalPathMarkerAndQueryDelimiterAreParsedSeparately()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/people/{personId?}?format={format}" ) );

            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/people", "format=summary" ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/people/42", "format=summary" ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/people/42", null ) );
        }

        [TestMethod]
        public void MoreSpecificQueryTemplateWinsForTheSameLiteralPath()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/items" ),
                Route( 1, "GET", "api/items?type=special" ) );

            Assert.AreEqual( 1, matcher.FindActionIndex( "GET", "api/items", "type=special" ) );
            Assert.AreEqual( 0, matcher.FindActionIndex( "GET", "api/items", "type=ordinary" ) );
        }

        [TestMethod]
        public void FixedPrefixAndSegmentCountRejectUnrelatedShapes()
        {
            var matcher = CreateMatcher(
                Route( 0, "GET", "api/groups/{groupId}" ),
                Route( 1, "GET", "api/groups/{groupId}/members/{personId}" ),
                Route( 2, "GET", "api/people/{personId}" ) );

            Assert.AreEqual( 1, matcher.FindActionIndex( "GET", "api/groups/12/members/34", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/groups/12/members", null ) );
            Assert.IsNull( matcher.FindActionIndex( "GET", "api/unknown/12", null ) );
        }

        [TestMethod]
        public void IndexedMatcherHandlesProductionScaleSyntheticData()
        {
            const int routeCountPerKind = 1500;
            const int requestCount = 20000;
            var routes = new List<RestActionRouteDefinition>();

            for ( var i = 0; i < routeCountPerKind; i++ )
            {
                routes.Add( Route( i, "GET", "api/static/endpoint" + i ) );
                routes.Add( Route(
                    routeCountPerKind + i,
                    "GET",
                    "api/controller" + i + "/{id:int}/items?include={include}" ) );
            }

            var stopwatch = Stopwatch.StartNew();
            var matcher = new RestActionRequestCountMatcher( routes );
            var matches = 0;

            for ( var i = 0; i < requestCount; i++ )
            {
                var routeNumber = i % routeCountPerKind;
                var match = i % 2 == 0
                    ? matcher.FindActionIndex( "GET", "api/static/endpoint" + routeNumber, "tracking=value" )
                    : matcher.FindActionIndex( "GET", "api/controller" + routeNumber + "/42/items", "other=value&include=details" );

                if ( match.HasValue )
                {
                    matches++;
                }
            }

            stopwatch.Stop();

            Assert.AreEqual( requestCount, matches );
            Assert.IsTrue(
                stopwatch.Elapsed < System.TimeSpan.FromSeconds( 10 ),
                "Indexed matching took " + stopwatch.Elapsed + "." );
        }

        private static RestActionRequestCountMatcher CreateMatcher( params RestActionRouteDefinition[] routes )
        {
            return new RestActionRequestCountMatcher( routes );
        }

        private static RestActionRouteDefinition Route( int index, string method, string template )
        {
            return new RestActionRouteDefinition
            {
                ActionIndex = index,
                Method = method,
                RouteTemplate = template
            };
        }
    }
}
