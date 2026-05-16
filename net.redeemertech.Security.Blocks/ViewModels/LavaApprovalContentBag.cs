namespace net.redeemertech.Security.Blocks.ViewModels
{
    using System.Collections.Generic;

    public class LavaApprovalContentBag
    {
        public string Content { get; set; }

        public string ContentHash { get; set; }

        public bool? IsPublic { get; set; }

        public string AIReviewDetails { get; set; }

        public string AIRiskAssessment { get; set; }

        public bool? AIHasVulnerabilityConcerns { get; set; }

        public string AIReviewDateTime { get; set; }

        public List<LavaApprovalBag> Sources { get; set; }
    }
}
