using net.redeemertech.Security.Model;
using Rock;
using Rock.Model;
using Rock.ViewModels.Controls;
using System;
using System.Collections.Generic;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class IISAlertsInitializationBox
    {
        public bool IsEditable { get; set; }
        public string ErrorMessage { get; set; }
        public string DetailPageUrl { get; set; }
        public string HistoryDetailPageUrl { get; set; }
        public List<IISAlertBag> Alerts { get; set; }
        public IISAlertBag Alert { get; set; }
        public List<IISAlertHistoryListItemBag> Histories { get; set; }
        public List<IISBlockedIpBag> BlockedIps { get; set; }
        public SlidingDateRangeBag DefaultDateRange { get; set; }
    }
}
