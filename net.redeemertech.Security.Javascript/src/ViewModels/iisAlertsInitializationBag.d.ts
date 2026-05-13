import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";
import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";
import { IisAlertBag } from "./iisAlertBag";
import { IisAlertHistoryBag } from "./iisAlertHistoryBag";

export type IisAlertsInitializationBag = BlockBox & {
    isEditable: boolean;
    errorMessage?: string | null;
    detailPageUrl?: string | null;
    historyDetailPageUrl?: string | null;
    alerts?: IisAlertBag[] | null;
    alert?: IisAlertBag | null;
    histories?: IisAlertHistoryBag[] | null;
    history?: IisAlertHistoryBag | null;
    defaultDateRange?: SlidingDateRangeBag | null;
};
