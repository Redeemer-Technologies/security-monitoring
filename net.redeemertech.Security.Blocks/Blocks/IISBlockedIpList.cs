using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Attribute;
using Rock.Blocks;

using System.ComponentModel;
using System.Data.Entity;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Blocked IP List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists IP addresses blocked by IIS alerts." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [LinkedPage( "History Detail Page", "Page containing the IIS Alert History Detail block.", false, key: AttributeKey.HistoryDetailPage )]
    [Rock.SystemGuid.EntityTypeGuid( "a2991b20-e33e-4b20-8a1c-bd37caf96cb5" )]
    [Rock.SystemGuid.BlockTypeGuid( "8deec723-675f-4999-9847-67a819bd01ab" )]
    public class IISBlockedIpList : RockBlockType
    {
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/iisBlockedIpList.obs";

        private static class AttributeKey
        {
            public const string HistoryDetailPage = "HistoryDetailPage";
        }

        public override object GetObsidianBlockInitialization()
        {
            if ( !CanView() )
            {
                return new IISAlertsInitializationBox { ErrorMessage = "Not authorized to view blocked IP addresses." };
            }

            return new IISAlertsInitializationBox
            {
                IsEditable = CanEdit(),
                HistoryDetailPageUrl = this.GetLinkedPageUrl( AttributeKey.HistoryDetailPage, "IISAlertHistoryId", "((IdKey))" ),
                BlockedIps = new IISAlertBlockedIpService( RockContext ).Queryable()
                    .Include( b => b.IISAlertHistory )
                    .OrderByDescending( b => b.ExpiresDateTime )
                    .ToList()
                    .Select( IISBlockedIpBag.FromEntity )
                    .ToList()
            };
        }

        [BlockAction]
        public BlockActionResult UnblockIp( string idKey )
        {
            if ( !CanEdit() )
            {
                return ActionForbidden( "Not authorized to edit blocked IP addresses." );
            }

            var service = new IISAlertBlockedIpService( RockContext );
            var blockedIp = service.Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
            if ( blockedIp == null )
            {
                return ActionNotFound( "Blocked IP address was not found." );
            }

            var ipAddress = blockedIp.IpAddress;
            service.Delete( blockedIp );
            RockContext.SaveChanges();
            IISAlertBlockedIpCache.RefreshIpAddress( ipAddress );

            return ActionOk();
        }

        private bool CanView() => new IISAlertBlockedIp { Id = 0 }.IsAuthorized( Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson );

        private bool CanEdit() => new IISAlertBlockedIp { Id = 0 }.IsAuthorized( Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson );
    }
}
