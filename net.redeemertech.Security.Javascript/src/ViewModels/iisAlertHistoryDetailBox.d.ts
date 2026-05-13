import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";
import { IisAlertHistoryBag } from "./iisAlertHistoryBag";

export type IisAlertHistoryDetailBox = BlockBox & {
    errorMessage?: string | null;
    history?: IisAlertHistoryBag | null;
};
