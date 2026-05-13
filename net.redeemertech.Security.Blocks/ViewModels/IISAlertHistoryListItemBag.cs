using net.redeemertech.Security.Model;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class IISAlertHistoryListItemBag
    {
        public string IdKey { get; set; }
        public string AlertName { get; set; }
        public string TrippedDateTime { get; set; }
        public int ResultCount { get; set; }
        public string Summary { get; set; }

        public static IISAlertHistoryListItemBag FromEntity( IISAlertHistory history )
        {
            return new IISAlertHistoryListItemBag
            {
                IdKey = history.IdKey,
                AlertName = history.AlertName,
                TrippedDateTime = history.TrippedDateTime.ToString( "g" ),
                ResultCount = history.ResultCount,
                Summary = history.Summary
            };
        }
    }
}
