import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";

export type LogQueryRequestBag = {
    query?: string | null;
    dateRange?: SlidingDateRangeBag | null;
    saveUserPreference: boolean;
};
