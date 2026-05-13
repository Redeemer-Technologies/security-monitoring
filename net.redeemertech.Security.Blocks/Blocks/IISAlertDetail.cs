using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Blocks;

using System.ComponentModel;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Alert Detail" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Edits a single IIS alert." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [Rock.SystemGuid.EntityTypeGuid("2069f66c-9dac-4250-a694-521e463adb4a")]
    [Rock.SystemGuid.BlockTypeGuid("c8032b08-fc23-479d-90d3-9ddf049a6a3c")]
    public class IISAlertDetail : RockBlockType
    {
        private const string DefaultQuery = "SELECT *\nFROM [[logs]]\nLIMIT 100";
        private const string DefaultSummaryLava = "IIS alert returned {{ results | Size }} row(s).";
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/iisAlertDetail.obs";

        public override object GetObsidianBlockInitialization()
        {
            var alert = GetAlert();

            if (alert == null)
            {
                return new IISAlertsInitializationBox { ErrorMessage = "IIS alert was not found." };
            }
            if (!alert.IsAuthorized(Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson))
            {
                return new IISAlertsInitializationBox { ErrorMessage = "Not authorized to view IIS alerts." };
            }

            return new IISAlertsInitializationBox
            {
                IsEditable = alert.IsAuthorized(Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson),
                Alert = IISAlertBag.FromEntity(alert),
                DefaultDateRange = IISLogDuckDbQuery.ToSlidingDateRangeBag(IISLogDuckDbQuery.DefaultDateRange)
            };
        }

        [BlockAction]
        public BlockActionResult SaveAlert(IISAlertBag bag)
        {
            var service = new IISAlertService(RockContext);
            var alert = bag.IdKey.IsNullOrWhiteSpace() ? new IISAlert() : service.Get(bag.IdKey, !PageCache.Layout.Site.DisablePredictableIds);
            if (alert == null)
            {
                return ActionNotFound("IIS alert was not found.");
            }

            if (!alert.IsAuthorized(Rock.Security.Authorization.EDIT, RequestContext.CurrentPerson))
            {
                return ActionForbidden("Not authorized to edit IIS alerts.");
            }

            alert.Name = bag.Name?.Trim();
            alert.Description = bag.Description;
            alert.IsActive = bag.IsActive;
            alert.Query = bag.Query;
            alert.SummaryLava = bag.SummaryLava;
            alert.DateRange = IISLogDuckDbQuery.ToDelimitedDateRange(bag.DateRange).IfEmpty(IISLogDuckDbQuery.DefaultDateRange);
            alert.NotificationEmails = bag.NotificationEmails;
            alert.EvaluationFrequencyMinutes = bag.EvaluationFrequencyMinutes < 1 ? 1 : bag.EvaluationFrequencyMinutes;
            if (alert.Name.IsNullOrWhiteSpace() || alert.Query.IsNullOrWhiteSpace())
            {
                return ActionBadRequest("Name and SQL query are required.");
            }

            if (alert.Id == 0)
            {
                service.Add(alert);
            }

            RockContext.SaveChanges();
            return ActionOk( IISAlertBag.FromEntity( alert ) );
        }

        private IISAlert GetNewAlert()
        {
            return new IISAlert {
                IsActive = true,
                Query = DefaultQuery,
                SummaryLava = DefaultSummaryLava,
                DateRange = IISLogDuckDbQuery.DefaultDateRange,
                EvaluationFrequencyMinutes = 60
            };
        }

        private IISAlert GetAlert()
        {
            var idKey = PageParameter( "IISAlertId" );
            return idKey.IsNullOrWhiteSpace() || idKey == "0" ? GetNewAlert() : new IISAlertService( RockContext ).Get( idKey, !PageCache.Layout.Site.DisablePredictableIds );
        }
    }
}
