import { BlockBox } from "@Obsidian/ViewModels/Blocks/blockBox";

export type RestActionSecurityInitializationBag = BlockBox & {
    restActionEntityTypeGuid?: string | null;
};
