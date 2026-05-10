using Rock.ViewModels.Blocks;
using Rock.ViewModels.Controls;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class LogQueryInitializationBox : BlockBox
    {
        public string DefaultQuery { get; set; }

        public string CurrentQuery { get; set; }

        public SlidingDateRangeBag DateRange { get; set; }

        public bool IsLavaTemplateDisplayMode { get; set; }

        public bool ShowQueryOnPage { get; set; }
    }
}
