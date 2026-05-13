using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Attribute;
using Rock.Blocks;

using System.ComponentModel;
using System.Linq;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Alert History List" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Lists tripped IIS alert history records." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [LinkedPage( "Detail Page", "Page containing the IIS Alert History Detail block.", true, key: AttributeKey.DetailPage )]
    [Rock.SystemGuid.EntityTypeGuid("e7c4771f-c705-4632-8ffd-78084f2ca195")]
    [Rock.SystemGuid.BlockTypeGuid("655ca478-fdcf-4996-901c-6011b485e52b")]
    public class IISAlertHistoryList : RockBlockType
    {
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/iisAlertHistoryList.obs";
        private static class AttributeKey { public const string DetailPage = "DetailPage"; }

        public override object GetObsidianBlockInitialization()
        {
            if (!new IISAlertHistory { Id = 0 }.IsAuthorized(Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson))
            {
                return new IISAlertsInitializationBox { ErrorMessage = "Not authorized to view IIS alert history." };
            }
            var query = new IISAlertHistoryService( RockContext ).Queryable();

            var alert = GetContextAlert();
            if (alert != null)
            {
                query = query.Where(h => h.IISAlertId == alert.Id);
            }

            return new IISAlertsInitializationBox {
                HistoryDetailPageUrl = this.GetLinkedPageUrl( AttributeKey.DetailPage, "IISAlertHistoryId", "((IdKey))" ),
                Histories = query.OrderByDescending( h => h.TrippedDateTime )
                    .Take( 500 )
                    .ToList()
                    .Select( IISAlertHistoryBag.FromEntity )
                    .ToList()
            };
        }

        private IISAlert GetContextAlert()
        {
            var idKey = PageParameter( "IISAlertId" );
            return idKey.IsNullOrWhiteSpace() ? null : new IISAlertService( RockContext ).Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
        }
    }
}
