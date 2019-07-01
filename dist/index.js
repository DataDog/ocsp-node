"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const bindings = require("bindings");
const ocsp = bindings('ocsp');
const chunks = (s, chunkSize) => {
    const retval = [];
    for (let offset = 0; offset < s.length; offset += chunkSize) {
        retval.push(s.slice(offset, chunkSize + offset));
    }
    return retval;
};
// alternative https://stackoverflow.com/a/32028304/1435156
// but does not work with wikipedia.org or google.com
const derToPem = (buf) => [
    '-----BEGIN CERTIFICATE-----',
    ...chunks(buf.toString('base64'), 64),
    '-----END CERTIFICATE-----',
].join('\n');
exports.getRevocationStatusAsync = (socketCertificate, cb) => {
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
        url = uris[0];
        // Some OCSP responders require a Host header
        // see https://github.com/openssl/openssl/issues/1986
        header = `Host=${new URL(url).host}`;
    }
    catch (error) {
        cb(error);
        return;
    }
    ocsp.getRevocationStatusAsync(certPem, issuerPem, header, url, cb);
};
exports.getRevocationStatusAsyncForTesting = (certPem, issuerPem, header, url, cb) => {
    ocsp.getRevocationStatusAsync(certPem, issuerPem, header, url, cb);
};
