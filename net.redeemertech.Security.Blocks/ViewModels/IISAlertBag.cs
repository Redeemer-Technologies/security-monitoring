using net.redeemertech.Security.Model;
using Rock;
using Rock.ViewModels.Controls;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class IISAlertBag
    {
        public string IdKey { get; set; }
        public string Name { get; set; }
        public string Description { get; set; }
        public bool IsActive { get; set; }
        public string Query { get; set; }
        public string SummaryLava { get; set; }
        public SlidingDateRangeBag DateRange { get; set; }
        public string NotificationEmails { get; set; }
        public int EvaluationFrequencyMinutes { get; set; }
        public string LastRunDateTime { get; set; }
        public bool BlockIpAddress { get; set; }
        public int? BlockIpAddressMinutes { get; set; }
        public bool LockOutUserAccounts { get; set; }

        public static IISAlertBag FromEntity(IISAlert alert)
        {
            return new IISAlertBag
            {
                IdKey = alert.Id == 0 ? null : alert.IdKey,
                Name = alert.Name,
                Description = alert.Description,
                IsActive = alert.IsActive,
                Query = alert.Query,
                SummaryLava = alert.SummaryLava,
                DateRange = IISLogDuckDbQuery.ToSlidingDateRangeBag(alert.DateRange.IfEmpty(IISLogDuckDbQuery.DefaultDateRange)),
                NotificationEmails = alert.NotificationEmails,
                EvaluationFrequencyMinutes = alert.EvaluationFrequencyMinutes < 1 ? 60 : alert.EvaluationFrequencyMinutes,
                LastRunDateTime = alert.LastRunDateTime?.ToString("g"),
                BlockIpAddress = alert.BlockIpAddress,
                BlockIpAddressMinutes = alert.BlockIpAddressMinutes,
                LockOutUserAccounts = alert.LockOutUserAccounts
            };
        }
    }
}
