export type RestControllerSecurityBag = {
    idKey: string;
    name: string;
    className: string;
    isSecured: boolean;
    securityStatus: string;
    isSecurityDisabled: boolean;
    reasons: string[];
};
