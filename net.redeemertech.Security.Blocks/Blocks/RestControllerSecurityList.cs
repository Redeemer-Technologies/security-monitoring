using net.redeemertech.Security.Blocks.ViewModels;

using Rock;
using Rock.Attribute;
using Rock.Blocks;
using Rock.Model;
using Rock.Security;
using Rock.Web.Cache;

using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "REST Controller Security List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists REST controllers and whether their controller-level permissions are secured." )]
    [SupportedSiteTypes( SiteType.Web )]
    [Rock.SystemGuid.EntityTypeGuid( "c1c0850f-8334-4dca-86db-23ea70ce4ebc" )]
    [Rock.SystemGuid.BlockTypeGuid( "5671e61e-3cf6-41ac-9dc8-529e27996735" )]
    public class RestControllerSecurityList : RockBlockType
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

        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/restControllerSecurityList.obs";

        public override object GetObsidianBlockInitialization()
        {
            if ( !CanView() )
            {
                return new RestControllerSecurityInitializationBox
                {
                    ErrorMessage = "Not authorized to view REST controller security."
                };
            }

            return new RestControllerSecurityInitializationBox
            {
                RestControllerEntityTypeGuid = EntityTypeCache.Get<RestController>().Guid.ToString()
            };
        }

        [BlockAction]
        public BlockActionResult GetControllers()
        {
            if ( !CanView() )
            {
                return ActionForbidden( "Not authorized to view REST controller security." );
            }

            return ActionOk( GetControllerSecurityBags() );
        }

        private List<RestControllerSecurityBag> GetControllerSecurityBags()
        {
            var allAuthenticatedUser = new Person
            {
                Id = 0,
                Guid = System.Guid.Empty
            };

            return new RestControllerService( RockContext )
                .Queryable()
                .OrderBy( c => c.Name )
                .ToList()
                .Select( c => ToSecurityBag( c, allAuthenticatedUser ) )
                .ToList();
        }

        private RestControllerSecurityBag ToSecurityBag( RestController controller, Person allAuthenticatedUser )
        {
            var supportedActions = controller.SupportedActions
                .Where( a => SecurityActionsToCheck.Contains( a.Key ) )
                .Select( a => a.Key )
                .ToList();

            var reasons = new List<string>();

            foreach ( var action in supportedActions )
            {
                if ( Authorization.Authorized( controller, action, null ) )
                {
                    reasons.Add( string.Format( "All users can {0}.", action ) );
                }

                if ( Authorization.Authorized( controller, action, allAuthenticatedUser ) )
                {
                    reasons.Add( string.Format( "All authenticated users can {0}.", action ) );
                }
            }

            return new RestControllerSecurityBag
            {
                IdKey = controller.IdKey,
                Name = controller.Name,
                ClassName = controller.ClassName,
                IsSecured = !reasons.Any(),
                SecurityStatus = reasons.Any() ? "Insecure" : "Secured",
                IsSecurityDisabled = !controller.IsAuthorized( Authorization.ADMINISTRATE, RequestContext.CurrentPerson ),
                Reasons = reasons
            };
        }

        private bool CanView()
        {
            return BlockCache.IsAuthorized( Authorization.VIEW, RequestContext.CurrentPerson );
        }
    }
}
