import { GridResultsBag } from "@Obsidian/ViewModels/Blocks/Reporting/DynamicData/gridResultsBag";
import { LavaTemplateResultsBag } from "@Obsidian/ViewModels/Blocks/Reporting/DynamicData/lavaTemplateResultsBag";
import { GridDataBag } from "@Obsidian/ViewModels/Core/Grid/gridDataBag";

export type LogQueryResponseBag = {
    gridResults?: GridResultsBag | null;
    gridData?: GridDataBag | null;
    chartLavaTemplateResults?: LavaTemplateResultsBag | null;
    lavaTemplateResults?: LavaTemplateResultsBag | null;
    navigationUrls?: Record<string, string> | null;
};
