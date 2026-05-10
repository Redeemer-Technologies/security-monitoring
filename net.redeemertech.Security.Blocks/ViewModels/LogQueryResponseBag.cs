using Rock.ViewModels.Blocks.Reporting.DynamicData;
using Rock.ViewModels.Core.Grid;

using System.Collections.Generic;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class LogQueryResponseBag
    {
        public GridResultsBag GridResults { get; set; }

        public GridDataBag GridData { get; set; }

        public LavaTemplateResultsBag LavaTemplateResults { get; set; }

        public Dictionary<string, string> NavigationUrls { get; set; }
    }
}
