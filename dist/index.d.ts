/// <reference types="node" />
import * as tls from 'tls';
export declare const enum CertificateStatus {
    Good = "good",
    Revoked = "revoked",
    Unknown = "unknown",
    UnknownStatus = "(UNKNOWN)"
}
export declare const enum RevokedStatus {
    Unspecified = "unspecified",
    KeyCompromise = "keyCompromise",
    CACompromise = "cACompromise",
    AffiliationChanged = "affiliationChanged",
    Superseded = "superseded",
    CessationOfOperation = "cessationOfOperation",
    CertificateHold = "certificateHold",
    RemoveFromCRL = "removeFromCRL",
    UnknownStatus = "(UNKNOWN)"
}
interface ResponseCallback {
    status: number;
    statusStr: CertificateStatus;
    reason: number;
    reasonStr: RevokedStatus;
    thisUpdate: string;
    nextUpdate: string;
    revocationTime: string;
}
export declare const getRevocationStatusAsync: (socketCertificate: tls.DetailedPeerCertificate, cb: (err: Error, response?: ResponseCallback | undefined) => void) => void;
export declare const getRevocationStatusAsyncForTesting: (certPem: string, issuerPem: string, header: string, url: string, cb: (err: Error, response: ResponseCallback) => void) => void;
export {};
