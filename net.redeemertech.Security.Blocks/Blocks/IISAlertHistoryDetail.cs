using net.redeemertech.Security.Blocks.ViewModels;
using net.redeemertech.Security.Model;

using Rock;
using Rock.Blocks;

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Web;

namespace net.redeemertech.Security.Blocks.Blocks
{
    [DisplayName( "IIS Alert History Detail" )]
    [Category( "net_redeemertech > Security" )]
    [Description( "Displays one tripped IIS alert history record." )]
    [SupportedSiteTypes( Rock.Model.SiteType.Web )]
    [Rock.SystemGuid.EntityTypeGuid("d63b58d3-a198-4058-894a-2cb961ff0e1c")]
    [Rock.SystemGuid.BlockTypeGuid("da59b549-4345-408c-b5f7-5680328b46e7")]
    public class IISAlertHistoryDetail : RockBlockType
    {
        public override string ObsidianFileUrl => "/Plugins/net_redeemertech/Security/iisAlertHistoryDetail.obs";

        public override object GetObsidianBlockInitialization()
        {
            var history = GetHistory();

            if (history == null)
            {
                return new IISAlertHistoryBag { ErrorMessage = "IIS alert history was not found." };
            }

            if (!history.IsAuthorized(Rock.Security.Authorization.VIEW, RequestContext.CurrentPerson))
            {
                return new IISAlertHistoryBag { ErrorMessage = "Not authorized to view IIS alert history." };
            }

            return IISAlertHistoryBag.FromEntity(history);
        }

        private IISAlertHistory GetHistory()
        {
            var idKey = PageParameter("IISAlertHistoryId");
            return idKey.IsNullOrWhiteSpace() ? null : new IISAlertHistoryService(RockContext).Get(idKey, !PageCache.Layout.Site.DisablePredictableIds);
        }

        
    }
}
