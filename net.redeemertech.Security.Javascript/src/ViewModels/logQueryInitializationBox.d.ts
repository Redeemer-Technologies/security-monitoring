import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";
import { SlidingDateRangeBag } from "@Obsidian/ViewModels/Controls/slidingDateRangeBag";

export type LogQueryInitializationBox = BlockBox & {
    errorMessage?: string | null;
    defaultQuery?: string | null;
    currentQuery?: string | null;
    dateRange?: SlidingDateRangeBag | null;
    isLavaTemplateDisplayMode: boolean;
    showQueryOnPage: boolean;
};
