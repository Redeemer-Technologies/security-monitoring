import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";
import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";
import { IisAlertBag } from "./iisAlertBag";
import { IisAlertHistoryListItemBag } from "./iisAlertHistoryListItemBag";
import { IisBlockedIpBag } from "./iisBlockedIpBag";

export type IisAlertsInitializationBag = BlockBox & {
    isEditable: boolean;
    errorMessage?: string | null;
    detailPageUrl?: string | null;
    historyDetailPageUrl?: string | null;
    alerts?: IisAlertBag[] | null;
    alert?: IisAlertBag | null;
    histories?: IisAlertHistoryListItemBag[] | null;
    blockedIps?: IisBlockedIpBag[] | null;
    defaultDateRange?: SlidingDateRangeBag | null;
};
