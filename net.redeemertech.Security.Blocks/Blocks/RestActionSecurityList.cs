using net.redeemertech.Security.Blocks.ViewModels;

using Rock;
using Rock.Attribute;
using Rock.Blocks;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;

using System.Collections.Generic;
using System.ComponentModel;
using System.Data.Entity;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "REST Action Security List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists REST actions and whether their action-level permissions are secured." )]
    [SupportedSiteTypes( SiteType.Web )]
    [Rock.SystemGuid.EntityTypeGuid( "47c86a67-8e38-4431-a3ff-f0d4aaef0fc8" )]
    [Rock.SystemGuid.BlockTypeGuid( "5dd2882d-e30f-428a-adad-5412d6522f44" )]
    public class RestActionSecurityList : RockBlockType
    {
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

            return new RestActionService( RockContext )
                .Queryable()
                .Include( a => a.Controller )
                .OrderBy( a => a.Controller.Name )
                .ThenBy( a => a.Path )
                .ThenBy( a => a.Method )
                .ToList()
                .Select( a => ToSecurityBag( a, allAuthenticatedUser ) )
                .ToList();
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
                IsSecured = !reasons.Any(),
                SecurityStatus = reasons.Any() ? "Insecure" : "Secured",
                IsSecurityDisabled = !action.IsAuthorized( Authorization.ADMINISTRATE, RequestContext.CurrentPerson ),
                Reasons = reasons
            };
        }

        private bool CanView()
        {
            return BlockCache.IsAuthorized( Authorization.VIEW, RequestContext.CurrentPerson );
        }
    }
}
