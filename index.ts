import bindings = require('bindings');
import * as tls from 'tls';

const ocsp = bindings('ocsp');

const chunks = (s: string, chunkSize: number) => {
    const retval = [];
    for (let offset = 0; offset < s.length; offset += chunkSize) {
        retval.push(s.slice(offset, chunkSize + offset));
    }
    return retval;
};

// alternative https://stackoverflow.com/a/32028304/1435156
// but does not work with wikipedia.org or google.com
const derToPem = (buf: Buffer) =>
    [
        '-----BEGIN CERTIFICATE-----',
        ...chunks(buf.toString('base64'), 64),
        '-----END CERTIFICATE-----',
    ].join('\n');

export const enum CertificateStatus {
    // see https://github.com/openssl/openssl/blob/0c496700631d89a895617af005a338eb280095db/crypto/ocsp/ocsp_prn.c#L65-L67
    Good = 'good',
    Revoked = 'revoked',
    Unknown = 'unknown',
    // see https://github.com/openssl/openssl/blob/0c496700631d89a895617af005a338eb280095db/crypto/ocsp/ocsp_prn.c#L44
    UnknownStatus = '(UNKNOWN)',
}

export const enum RevokedStatus {
    // see https://github.com/openssl/openssl/blob/0c496700631d89a895617af005a338eb280095db/crypto/ocsp/ocsp_prn.c#L75-L82
    Unspecified = 'unspecified',
    KeyCompromise = 'keyCompromise',
    CACompromise = 'cACompromise',
    AffiliationChanged = 'affiliationChanged',
    Superseded = 'superseded',
    CessationOfOperation = 'cessationOfOperation',
    CertificateHold = 'certificateHold',
    RemoveFromCRL = 'removeFromCRL',
    // see https://github.com/openssl/openssl/blob/0c496700631d89a895617af005a338eb280095db/crypto/ocsp/ocsp_prn.c#L44
    UnknownStatus = '(UNKNOWN)',
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

export const getRevocationStatusAsync = (
    socketCertificate: tls.DetailedPeerCertificate,
    cb: (err: Error, response?: ResponseCallback) => void
) => {
    const certPem = derToPem(socketCertificate.raw);
    if (socketCertificate.issuerCertificate === undefined) {
        cb(new Error('Missing issuer certificate'));
        return;
    }
    const issuerPem = derToPem(socketCertificate.issuerCertificate.raw);
    const uris = socketCertificate.infoAccess['OCSP - URI'];
    let url = '';
    let header = '';
    try {
        // uris can have multiple values, should we only use the first one?
        url = uris![0];
        // Some OCSP responders require a Host header
        // see https://github.com/openssl/openssl/issues/1986
        header = `Host=${new URL(url).host}`;
    } catch (error) {
        cb(error);
        return;
    }

    ocsp.getRevocationStatusAsync(certPem, issuerPem, header, url, cb);
};

export const getRevocationStatusAsyncForTesting = (
    certPem: string,
    issuerPem: string,
    header: string,
    url: string,
    cb: (err: Error, response: ResponseCallback) => void
) => {
    ocsp.getRevocationStatusAsync(certPem, issuerPem, header, url, cb);
};
