import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";
import { IisAlertConditionBag } from "./iisAlertConditionBag";

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
    matchCount: number;
    blockIpAddress: boolean;
    blockIpAddressMinutes?: number | null;
    lockOutUserAccounts: boolean;
    evaluationMode: string;
    requestStage: string;
    conditionLogic: string;
    conditions?: IisAlertConditionBag[] | null;
    blockRequest: boolean;
    blockResponseStatusCode?: number | null;
    blockResponseMessage?: string | null;
};
