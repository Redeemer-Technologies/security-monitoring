import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";
import { LavaApprovalBag } from "./lavaApprovalBag";

export type LavaApprovalsInitializationBag = BlockBox & {
    isEditable: boolean;
    errorMessage?: string | null;
    sources?: LavaApprovalBag[] | null;
};
