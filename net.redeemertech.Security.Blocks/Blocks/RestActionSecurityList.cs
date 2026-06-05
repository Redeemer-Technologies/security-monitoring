using net.redeemertech.Security.Blocks.ViewModels;

using Rock;
using Rock.Attribute;
using Rock.Blocks;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Data.Entity;
using System.Linq;
using System.Text.RegularExpressions;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "REST Action Security List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists REST actions and whether their action-level permissions are secured." )]
    [SupportedSiteTypes( SiteType.Web )]
    [TextField( "Parquet Folder",
        "The folder containing parquet files created by Process IIS Logs. Relative paths are resolved under App_Data.",
        true,
        "IISLogParquet",
        key: AttributeKey.ParquetFolder,
        order: 0 )]
    [IntegerField( "Maximum Parquet Files",
        "The maximum number of parquet files to include when counting endpoint requests.",
        false,
        1000,
        key: AttributeKey.MaximumParquetFiles,
        order: 1 )]
    [IntegerField( "Timeout Length",
        "The amount of time in seconds to allow the endpoint request count query to run before timing out.",
        false,
        30,
        key: AttributeKey.Timeout,
        order: 2 )]
    [Rock.SystemGuid.EntityTypeGuid( "47c86a67-8e38-4431-a3ff-f0d4aaef0fc8" )]
    [Rock.SystemGuid.BlockTypeGuid( "5dd2882d-e30f-428a-adad-5412d6522f44" )]
    public class RestActionSecurityList : RockBlockType
    {
        private const string Last30DaysDateRange = "Last|30|Day||";

        private static class AttributeKey
        {
            public const string ParquetFolder = "ParquetFolder";
            public const string MaximumParquetFiles = "MaximumParquetFiles";
            public const string Timeout = "Timeout";
        }

        private static readonly string[] SecurityActionsToCheck =
        {
            Authorization.VIEW,
            Authorization.EDIT,
            Authorization.EXECUTE,
            Authorization.EXECUTE_READ,
            Authorization.EXECUTE_WRITE,
            Authorization.EXECUTE_UNRESTRICTED_READ,
            Authorization.EXECUTE_UNRESTRICTED_WRITE
        };

        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/restActionSecurityList.obs";

        public override object GetObsidianBlockInitialization()
        {
            if ( !CanView() )
            {
                return new RestActionSecurityInitializationBox
                {
                    ErrorMessage = "Not authorized to view REST action security."
                };
            }

            return new RestActionSecurityInitializationBox
            {
                RestActionEntityTypeGuid = EntityTypeCache.Get<RestAction>().Guid.ToString()
            };
        }

        [BlockAction]
        public BlockActionResult GetActions()
        {
            if ( !CanView() )
            {
                return ActionForbidden( "Not authorized to view REST action security." );
            }

            return ActionOk( GetActionSecurityBags() );
        }

        private List<RestActionSecurityBag> GetActionSecurityBags()
        {
            var allAuthenticatedUser = new Person
            {
                Id = 0,
                Guid = System.Guid.Empty
            };

            var actions = new RestActionService( RockContext )
                .Queryable()
                .Include( a => a.Controller )
                .OrderBy( a => a.Controller.Name )
                .ThenBy( a => a.Path )
                .ThenBy( a => a.Method )
                .ToList()
                .Select( a => ToSecurityBag( a, allAuthenticatedUser ) )
                .ToList();

            AddRequestCounts( actions );

            return actions;
        }

        private RestActionSecurityBag ToSecurityBag( RestAction action, Person allAuthenticatedUser )
        {
            var supportedActions = action.SupportedActions
                .Where( a => SecurityActionsToCheck.Contains( a.Key ) )
                .Select( a => a.Key )
                .ToList();

            var reasons = new List<string>();

            foreach ( var securityAction in supportedActions )
            {
                if ( Authorization.Authorized( action, securityAction, null ) )
                {
                    reasons.Add( string.Format( "All users can {0}.", securityAction ) );
                }

                if ( Authorization.Authorized( action, securityAction, allAuthenticatedUser ) )
                {
                    reasons.Add( string.Format( "All authenticated users can {0}.", securityAction ) );
                }
            }

            return new RestActionSecurityBag
            {
                IdKey = action.IdKey,
                Method = action.Method,
                Path = action.Path,
                ApiId = action.ApiId,
                ControllerName = action.Controller?.Name,
                ControllerClassName = action.Controller?.ClassName,
                RequestCountLast30Days = null,
                IsSecured = !reasons.Any(),
                SecurityStatus = reasons.Any() ? "Insecure" : "Secured",
                IsSecurityDisabled = !action.IsAuthorized( Authorization.ADMINISTRATE, RequestContext.CurrentPerson ),
                Reasons = reasons
            };
        }

        private void AddRequestCounts( List<RestActionSecurityBag> actions )
        {
            var endpointCounts = GetEndpointCountsLast30Days();
            if ( endpointCounts == null || !endpointCounts.Any() )
            {
                return;
            }

            foreach ( var action in actions )
            {
                if ( endpointCounts.TryGetValue( GetEndpointCountKey( action.Method, action.Path ), out var requestCount ) )
                {
                    action.RequestCountLast30Days = requestCount;
                    continue;
                }

                action.RequestCountLast30Days = endpointCounts
                    .Where( c => IsRouteMatch( action.Method, action.Path, c.Key ) )
                    .Sum( c => c.Value );
            }
        }

        private Dictionary<string, int> GetEndpointCountsLast30Days()
        {
            const string query = @"
SELECT
    UPPER(""cs-method"") AS method,
    REGEXP_REPLACE(COALESCE(""cs-uri-stem"", ''), '^/+', '') AS path,
    COUNT(*) AS request_count
FROM [[logs]]
WHERE ""cs-uri-stem"" IS NOT NULL
    AND (
        LOWER(""cs-uri-stem"") LIKE '/api/%'
        OR LOWER(""cs-uri-stem"") LIKE 'api/%'
    )
GROUP BY 1, 2";

            try
            {
                var dataTable = new IISLogDuckDbQuery().Execute(
                    query,
                    Last30DaysDateRange,
                    GetAttributeValue( AttributeKey.ParquetFolder ),
                    GetAttributeValue( AttributeKey.MaximumParquetFiles ).AsIntegerOrNull() ?? 1000,
                    GetAttributeValue( AttributeKey.Timeout ).AsIntegerOrNull() ?? 30 );

                return dataTable.Rows
                    .OfType<DataRow>()
                    .GroupBy( r => GetEndpointCountKey( r["method"].ToStringSafe(), r["path"].ToStringSafe() ), StringComparer.OrdinalIgnoreCase )
                    .ToDictionary(
                        g => g.Key,
                        g => g.Sum( r => Convert.ToInt32( r["request_count"] ) ),
                        StringComparer.OrdinalIgnoreCase );
            }
            catch
            {
                return null;
            }
        }

        private static bool IsRouteMatch( string method, string routeTemplate, string requestKey )
        {
            var keyParts = requestKey.Split( new[] { '|' }, 2 );
            if ( keyParts.Length != 2 || !keyParts[0].Equals( ( method ?? string.Empty ).Trim(), StringComparison.OrdinalIgnoreCase ) )
            {
                return false;
            }

            var requestPath = keyParts[1];
            routeTemplate = NormalizeApiPath( routeTemplate );
            requestPath = NormalizeApiPath( requestPath );

            if ( routeTemplate.IsNullOrWhiteSpace() || requestPath.IsNullOrWhiteSpace() )
            {
                return false;
            }

            var routeWithoutQuery = routeTemplate.Split( '?' ).FirstOrDefault();
            var requestWithoutQuery = requestPath.Split( '?' ).FirstOrDefault();
            var regexPattern = "^" + Regex.Escape( routeWithoutQuery )
                .Replace( "\\{", "{" )
                .Replace( "\\}", "}" );

            regexPattern = Regex.Replace( regexPattern, @"\{[^}/]+\}", @"[^/]+" ) + "$";
            return Regex.IsMatch( requestWithoutQuery, regexPattern, RegexOptions.IgnoreCase );
        }

        private static string GetEndpointCountKey( string method, string path )
        {
            return ( method ?? string.Empty ).Trim().ToUpperInvariant() + "|" + NormalizeApiPath( path );
        }

        private static string NormalizeApiPath( string path )
        {
            return ( path ?? string.Empty ).Trim().TrimStart( '/' );
        }

        private bool CanView()
        {
            return BlockCache.IsAuthorized( Authorization.VIEW, RequestContext.CurrentPerson );
        }

    }
}
