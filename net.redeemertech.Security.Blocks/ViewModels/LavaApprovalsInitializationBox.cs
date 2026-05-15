using System.Collections.Generic;

namespace net.redeemertech.Security.Blocks.ViewModels
{
    public class LavaApprovalsInitializationBox
    {
        public bool IsEditable { get; set; }

        public bool IsAIReviewConfigured { get; set; }

        public string ErrorMessage { get; set; }

        public List<LavaApprovalBag> Sources { get; set; }
    }
}
