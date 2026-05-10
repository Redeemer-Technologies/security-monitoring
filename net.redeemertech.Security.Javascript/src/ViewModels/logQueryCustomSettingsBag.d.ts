import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";

export type LogQueryCustomSettingsBag = {
    query?: string | null;
    queryParams?: string | null;
    dateRange?: SlidingDateRangeBag | null;
    timeout?: number | null;
    resultsDisplayMode?: string | null;
    gridTitle?: string | null;
    selectionUrl?: string | null;
    lavaTemplate?: string | null;
    showQueryOnPage: boolean;
};
