import { LavaApprovalBag } from "./lavaApprovalBag";

export type LavaApprovalContentBag = {
    content?: string | null;
    contentHash?: string | null;
    sources?: LavaApprovalBag[] | null;
};
