export type RestActionSecurityBag = {
    idKey: string;
    method: string;
    path: string;
    apiId: string;
    controllerName: string;
    controllerClassName: string;
    requestCountLast30Days?: number | null;
    isSecured: boolean;
    securityStatus: string;
    isSecurityDisabled: boolean;
    reasons: string[];
};
