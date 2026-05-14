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
    isApproved: boolean;
};
