import { LavaApprovalBag } from "./lavaApprovalBag";

export type LavaApprovalContentBag = {
    content?: string | null;
    contentHash?: string | null;
    aiReviewDetails?: string | null;
    aiRiskAssessment?: string | null;
    aiHasVulnerabilityConcerns?: boolean | null;
    aiReviewDateTime?: string | null;
    sources?: LavaApprovalBag[] | null;
};
