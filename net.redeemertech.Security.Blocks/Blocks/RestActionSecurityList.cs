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

        [BlockAction]
        public BlockActionResult SecureAction( string idKey )
        {
            if ( !CanView() )
            {
                return ActionForbidden( "Not authorized to view REST action security." );
            }

            if ( string.IsNullOrWhiteSpace( idKey ) )
            {
                return ActionBadRequest( "Select a REST action to secure." );
            }

            var action = new RestActionService( RockContext ).Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
            if ( action == null )
            {
                return ActionBadRequest( "The selected REST action no longer exists. Refresh the list and try again." );
            }

            RockContext.Entry( action ).Reference( a => a.Controller ).Load();

            var allAuthenticatedUser = new Person { Id = 0, Guid = Guid.Empty };
            var supportedActions = GetSupportedSecurityActions( action );
            var security = ToSecurityBag( action, allAuthenticatedUser, supportedActions );
            if ( !RestActionSecurityPolicy.ShouldSecure( security.IsSecurable, security.IsSecured ) )
            {
                return ActionOk( new { Status = "Skipped" } );
            }

            var allowedRoleIds = new List<int>();
            if ( security.IsNeededByRock )
            {
                allowedRoleIds = GetRockEndpointAllowedRoleIds();
                if ( allowedRoleIds == null )
                {
                    return ActionBadRequest( "Staff Workers, Staff Like Workers, and Rock Admins must all exist as active security roles before securing endpoints needed by Rock." );
                }
            }

            var authService = new AuthService( RockContext );
            foreach ( var securityAction in supportedActions )
            {
                var existingRules = authService.GetAuths( action.TypeId, action.Id, securityAction ).ToList();
                var rules = RestActionSecurityPolicy.PrependRules( action.TypeId, action.Id, securityAction, allowedRoleIds, existingRules );
                authService.AddRange( rules );
            }

            RockContext.SaveChanges();
            foreach ( var securityAction in supportedActions )
            {
                Authorization.RefreshAction( action.TypeId, action.Id, securityAction );
            }

            return ActionOk( new { Status = "Secured" } );
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

        private RestActionSecurityBag ToSecurityBag( RestAction action, Person allAuthenticatedUser, List<string> supportedActions = null )
        {
            var isNeededByRock = RockUiRestActionCatalog.IsNeededByRock( action.Controller?.ClassName, action.Method, action.Path );
            supportedActions = supportedActions ?? GetSupportedSecurityActions( action );
            var isSecurable = supportedActions.Any();
            List<string> reasons;
            bool isSecured;

            if ( !isSecurable )
            {
                reasons = new List<string> { "This endpoint has no [Secured] marker. Use the IIS rules function to secure this route to specific Rock roles." };
                isSecured = false;
            }
            else if ( isNeededByRock )
            {
                reasons = GetOpenAccessReasons( action, supportedActions, allAuthenticatedUser );
                isSecured = !reasons.Any();
            }
            else
            {
                reasons = GetMissingAllUsersDenyReasons( action, supportedActions );
                isSecured = !reasons.Any();
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
                IsNeededByRock = isNeededByRock,
                IsSecured = isSecured,
                IsSecurable = isSecurable,
                SecurityStatus = !isSecurable ? "Insecurable" : isSecured ? "Secured" : "Insecure",
                IsSecurityDisabled = !isSecurable,
                Reasons = reasons
            };
        }

        private static List<string> GetSupportedSecurityActions( RestAction action )
        {
            var enforcedActions = RestActionSecurityPolicy.GetEnforcedActions( action );
            if ( !enforcedActions.Any() )
            {
                return enforcedActions;
            }

            return action.SupportedActions
                .Where( a => SecurityActionsToCheck.Contains( a.Key ) )
                .Select( a => a.Key )
                .Union( enforcedActions, StringComparer.OrdinalIgnoreCase )
                .ToList();
        }

        private static List<string> GetOpenAccessReasons( RestAction action, List<string> supportedActions, Person allAuthenticatedUser )
        {
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

            return reasons;
        }

        private static List<string> GetMissingAllUsersDenyReasons( RestAction action, List<string> supportedActions )
        {
            var reasons = new List<string>();

            if ( !supportedActions.Any() )
            {
                reasons.Add( "This action has no REST security actions to deny." );
                return reasons;
            }

            var authorizations = Authorization.Get();
            var entityTypeId = action.TypeId;

            foreach ( var securityAction in supportedActions )
            {
                List<AuthRule> rules = null;
                if ( authorizations != null
                    && authorizations.ContainsKey( entityTypeId )
                    && authorizations[entityTypeId].ContainsKey( action.Id )
                    && authorizations[entityTypeId][action.Id].ContainsKey( securityAction ) )
                {
                    rules = authorizations[entityTypeId][action.Id][securityAction];
                }

                if ( rules == null || !rules.Any() )
                {
                    reasons.Add( string.Format( "{0} has no explicit Deny All Users rule.", securityAction ) );
                    continue;
                }

                var firstRule = rules[0];
                if ( firstRule.SpecialRole != SpecialRole.AllUsers || firstRule.AllowOrDeny != 'D' )
                {
                    reasons.Add( string.Format( "{0} does not have All Users as the first explicit deny rule.", securityAction ) );
                }
            }

            return reasons;
        }

        private void AddRequestCounts( List<RestActionSecurityBag> actions )
        {
            var endpointCounts = GetEndpointCountsLast30Days();
            if ( endpointCounts == null || !endpointCounts.Any() )
            {
                return;
            }

            var matcher = new RestActionRequestCountMatcher( actions.Select( ( action, index ) => new RestActionRouteDefinition
            {
                ActionIndex = index,
                Method = action.Method,
                RouteTemplate = action.Path
            } ) );
            var countsByActionIndex = new int[actions.Count];

            foreach ( var endpointCount in endpointCounts )
            {
                var actionIndex = matcher.FindActionIndex( endpointCount.Method, endpointCount.Path, endpointCount.Query );
                if ( actionIndex.HasValue )
                {
                    countsByActionIndex[actionIndex.Value] += endpointCount.Count;
                }
            }

            for ( var i = 0; i < actions.Count; i++ )
            {
                actions[i].RequestCountLast30Days = countsByActionIndex[i];
            }
        }

        private List<EndpointRequestCount> GetEndpointCountsLast30Days()
        {
            const string query = @"
SELECT
    UPPER(""cs-method"") AS method,
    REGEXP_REPLACE(COALESCE(""cs-uri-stem"", ''), '^/+', '') AS path,
    COALESCE(""cs-uri-query"", '') AS uri_query,
    COUNT(*) AS request_count
FROM [[logs]]
WHERE ""cs-uri-stem"" IS NOT NULL
    AND (
        LOWER(""cs-uri-stem"") LIKE '/api/%'
        OR LOWER(""cs-uri-stem"") LIKE 'api/%'
    )
GROUP BY 1, 2, 3";

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
                    .Select( r => new EndpointRequestCount
                    {
                        Method = r["method"].ToStringSafe(),
                        Path = r["path"].ToStringSafe(),
                        Query = r["uri_query"].ToStringSafe(),
                        Count = Convert.ToInt32( r["request_count"] )
                    } )
                    .ToList();
            }
            catch
            {
                return null;
            }
        }

        private sealed class EndpointRequestCount
        {
            public string Method { get; set; }
            public string Path { get; set; }
            public string Query { get; set; }
            public int Count { get; set; }
        }

        private List<int> GetRockEndpointAllowedRoleIds()
        {
            var roleGuids = new[]
            {
                Rock.SystemGuid.Group.GROUP_STAFF_MEMBERS.AsGuid(),
                Rock.SystemGuid.Group.GROUP_STAFF_LIKE_MEMBERS.AsGuid(),
                Rock.SystemGuid.Group.GROUP_ADMINISTRATORS.AsGuid()
            };
            var securityRoleTypeId = GroupTypeCache.Get( Rock.SystemGuid.GroupType.GROUPTYPE_SECURITY_ROLE.AsGuid() ).Id;
            var roles = new GroupService( RockContext ).Queryable()
                .Where( group => roleGuids.Contains( group.Guid ) && group.IsActive
                    && ( group.IsSecurityRole || group.GroupTypeId == securityRoleTypeId ) )
                .ToList();

            if ( roles.Count != roleGuids.Length )
            {
                return null;
            }

            return roleGuids.Select( guid => roles.Single( role => role.Guid == guid ).Id ).ToList();
        }

        private bool CanView()
        {
            return BlockCache.IsAuthorized( Authorization.VIEW, RequestContext.CurrentPerson );
        }

    }
}
