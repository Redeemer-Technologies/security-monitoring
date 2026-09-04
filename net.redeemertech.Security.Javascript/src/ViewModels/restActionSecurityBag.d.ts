export type RestActionSecurityBag = {
    idKey: string;
    method: string;
    path: string;
    apiId: string;
    controllerName: string;
    controllerClassName: string;
    requestCountLast30Days?: number | null;
    isNeededByRock: boolean;
    isSecured: boolean;
    securityStatus: string;
    isSecurityDisabled: boolean;
    reasons: string[];
};
