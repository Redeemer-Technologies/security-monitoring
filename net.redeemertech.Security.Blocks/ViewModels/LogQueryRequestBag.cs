using Rock.ViewModels.Controls;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class LogQueryRequestBag
    {
        public string Query { get; set; }

        public SlidingDateRangeBag DateRange { get; set; }

        public bool SaveUserPreference { get; set; }
    }
}
