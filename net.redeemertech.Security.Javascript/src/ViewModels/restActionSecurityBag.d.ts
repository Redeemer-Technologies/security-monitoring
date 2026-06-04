export type RestActionSecurityBag = {
    idKey: string;
    method: string;
    path: string;
    apiId: string;
    controllerName: string;
    controllerClassName: string;
    isSecured: boolean;
    securityStatus: string;
    isSecurityDisabled: boolean;
    reasons: string[];
};
