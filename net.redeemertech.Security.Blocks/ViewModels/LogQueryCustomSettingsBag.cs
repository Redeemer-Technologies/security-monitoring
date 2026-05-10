using Rock.ViewModels.Controls;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class LogQueryCustomSettingsBag
    {
        public string Query { get; set; }

        public SlidingDateRangeBag DateRange { get; set; }

        public int? Timeout { get; set; }

        public string ResultsDisplayMode { get; set; }

        public string GridTitle { get; set; }

        public string SelectionUrl { get; set; }

        public string LavaTemplate { get; set; }

        public bool ShowQueryOnPage { get; set; }
    }
}
