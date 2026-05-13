using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Attribute;
using Rock.Blocks;

using System.ComponentModel;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Alert List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists IIS alerts." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [LinkedPage( "Detail Page", "Page containing the IIS Alert Detail block.", true, key: AttributeKey.DetailPage )]
    [Rock.SystemGuid.EntityTypeGuid("1eb38156-8e6e-4d62-b7a0-6a3313b938b1")]
    [Rock.SystemGuid.BlockTypeGuid("49531c16-1f93-49d9-bcab-9e7fd889e1bf")]
    public class IISAlertList : RockBlockType
    {
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/iisAlertList.obs";
        private static class AttributeKey { public const string DetailPage = "DetailPage"; }

        public override object GetObsidianBlockInitialization()
        {
            if ( !CanView() )
            {
                return new IISAlertsInitializationBox { ErrorMessage = "Not authorized to view IIS alerts." };
            }

            return new IISAlertsInitializationBox
            {
                IsEditable = CanEdit(),
                DetailPageUrl = this.GetLinkedPageUrl( AttributeKey.DetailPage, "IISAlertId", "((IdKey))" ),
                Alerts = new IISAlertService( RockContext )
                    .Queryable()
                    .OrderBy( a => a.Name )
                    .ToList()
                    .Select( IISAlertBag.FromEntity )
                    .ToList()
            };
        }

        [BlockAction]
        public BlockActionResult DeleteAlert( string idKey )
        {
            if ( !CanEdit() )
            {
                return ActionForbidden( "Not authorized to edit IIS alerts." );
            }

            var service = new IISAlertService( RockContext );
            var alert = service.Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
            if ( alert == null )
            {
                return ActionNotFound( "IIS alert was not found." );
            }

            service.Delete( alert );
            RockContext.SaveChanges();
            return ActionOk();
        }

        private bool CanView() => new IISAlert { Id = 0 }.IsAuthorized( Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson );
        private bool CanEdit() => new IISAlert { Id = 0 }.IsAuthorized( Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson );
    }
}
