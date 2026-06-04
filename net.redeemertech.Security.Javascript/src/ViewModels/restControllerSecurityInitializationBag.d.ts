import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";

export type RestControllerSecurityInitializationBag = BlockBox & {
    restControllerEntityTypeGuid?: string | null;
};
