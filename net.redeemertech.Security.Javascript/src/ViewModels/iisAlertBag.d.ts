import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";

export type IisAlertBag = {
    idKey?: string | null;
    name?: string | null;
    description?: string | null;
    isActive: boolean;
    query?: string | null;
    summaryLava?: string | null;
    dateRange?: SlidingDateRangeBag | null;
    notificationEmails?: string | null;
    evaluationFrequencyMinutes: number;
    lastRunDateTime?: string | null;
    blockIpAddress: boolean;
    blockIpAddressMinutes?: number | null;
    lockOutUserAccounts: boolean;
};
