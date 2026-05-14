namespace net.redeemertech.Security.Blocks.ViewModels
{
    using System.Collections.Generic;

    public class LavaApprovalContentBag
    {
        public string Content { get; set; }

        public string ContentHash { get; set; }

        public List<LavaApprovalBag> Sources { get; set; }
    }
}
