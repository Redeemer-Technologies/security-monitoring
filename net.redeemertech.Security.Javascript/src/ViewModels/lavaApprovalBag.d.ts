export type LavaApprovalBag = {
    idKey?: string | null;
    tableName?: string | null;
    columnName?: string | null;
    rowId: number;
    source?: string | null;
    contentHash?: string | null;
    contentPreview?: string | null;
    detectedDateTime?: string | null;
    lastScannedDateTime?: string | null;
    lastSeenDateTime?: string | null;
    matchingSourceCount: number;
    matchingSourceSortValue?: string | null;
    isApproved: boolean;
    isPublic?: boolean | null;
    aiReviewDateTime?: string | null;
    aiReviewProvider?: string | null;
    aiReviewModel?: string | null;
    aiHasVulnerabilityConcerns?: boolean | null;
    aiRiskAssessment?: string | null;
    aiRiskSortOrder: number;
    aiReviewDetails?: string | null;
    shortcodeAiRiskAssessment?: string | null;
    shortcodeAiRiskSortOrder: number;
    entityDetails?: LavaApprovalEntityDetailBag[] | null;
};

export type LavaApprovalEntityDetailBag = {
    label?: string | null;
    value?: string | null;
    url?: string | null;
};
