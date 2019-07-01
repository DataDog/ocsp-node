/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

// g++ ocsp.cpp -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib/ -lcrypto
#include <sys/select.h>
#include <cstring>
#include <iostream>

#include <openssl/ocsp.h>

#include "ocsp.h"

# include <openssl/e_os2.h>
# include <openssl/crypto.h>
# include <openssl/err.h>
# include <openssl/ssl.h>
# include <openssl/evp.h>
# include <openssl/bn.h>
# include <openssl/x509v3.h>
# include <openssl/rand.h>

/* Maximum leeway in validity period: default 5 minutes */
# define MAX_VALIDITY_PERIOD    (5 * 60)

static int add_ocsp_cert(ocspCheck *retval, OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids);
static void print_ocsp_summary(ocspCheck *retval, BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage);

static OCSP_RESPONSE *query_responder(ocspCheck *retval, BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout);

ocspCheck verifyOCSP(const char* cert_local, const char* issuer_local, const char* header_local, const char* url_local, int timeout) {
    ocspCheck retval;
    BIO *bio_issuer_synthetics = NULL, *bio_cert_synthetics = NULL;

    BIO *out = NULL;
    const EVP_MD *cert_id_md = NULL;
    int trailing_md = 0;
    OCSP_BASICRESP *bs = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    STACK_OF(CONF_VALUE) *headers = NULL;
    STACK_OF(OCSP_CERTID) *ids = NULL;
    STACK_OF(OPENSSL_STRING) *reqnames = NULL;
    STACK_OF(X509) *sign_other = NULL, *verify_other = NULL;
    STACK_OF(X509) *issuers = NULL;
    X509 *issuer = NULL, *cert = NULL;
    X509_STORE *store = NULL;
    X509_VERIFY_PARAM *vpm = NULL;
    const char *CAfile = NULL, *CApath = NULL;
    char *header, *value;
    char *host = NULL, *port = NULL, *path = (char *)"/";
    char *thost = NULL, *tport = NULL, *tpath = NULL;
    int noCAfile = 0, noCApath = 0;
    int add_nonce = 1, noverify = 0, use_ssl = -1;
    int i, ignore_err = 0;
    int req_text = 0, resp_text = 0, ret = 1;
    int req_timeout = timeout;  // previous default was -1 i.e. no timeout
    long nsec = MAX_VALIDITY_PERIOD, maxage = -1;
    unsigned long verify_flags = 0;

    ids = sk_OCSP_CERTID_new_null();
    if (ids == NULL)
        goto end;

//     prog = opt_init(argc, argv, ocsp_options);
//     while ((o = opt_next()) != OPT_EOF) {
//         switch (o) {
//         case OPT_EOF:
//         case OPT_ERR:
//  opthelp:
//             BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
//             goto end;
//         case OPT_HELP:
//             ret = 0;
//             opt_help(ocsp_options);
//             goto end;
//         case OPT_OUTFILE:
//             outfile = opt_arg();
//             break;
//         case OPT_TIMEOUT:
// #ifndef OPENSSL_NO_SOCK
//             req_timeout = atoi(opt_arg());
// #endif
//             break;
//         case OPT_URL:
            OPENSSL_free(thost);
            OPENSSL_free(tport);
            OPENSSL_free(tpath);
            thost = tport = tpath = NULL;
            if (!OCSP_parse_url(url_local, &host, &port, &path, &use_ssl)) {
                // BIO_printf(bio_err, "%s Error parsing URL\n", "prog"); // BIO_printf(bio_err, "%s Error parsing URL\n", prog);
                retval.errorStr = "Error parsing URL";
                goto end;
            }
            thost = host;
            tport = port;
            tpath = path;
//             break;
//         case OPT_HOST:
//             host = opt_arg();
//             break;
//         case OPT_PORT:
//             port = opt_arg();
//             break;
//         case OPT_IGNORE_ERR:
//             ignore_err = 1;
//             break;
//         case OPT_NOVERIFY:
//             noverify = 1;
//             break;
//         case OPT_NONCE:
//             add_nonce = 2;
//             break;
//         case OPT_NO_NONCE:
//             add_nonce = 0;
//             break;
//         case OPT_RESP_NO_CERTS:
//             rflags |= OCSP_NOCERTS;
//             break;
//         case OPT_RESP_KEY_ID:
//             rflags |= OCSP_RESPID_KEY;
//             break;
//         case OPT_NO_CERTS:
//             sign_flags |= OCSP_NOCERTS;
//             break;
//         case OPT_NO_SIGNATURE_VERIFY:
//             verify_flags |= OCSP_NOSIGS;
//             break;
//         case OPT_NO_CERT_VERIFY:
//             verify_flags |= OCSP_NOVERIFY;
//             break;
//         case OPT_NO_CHAIN:
//             verify_flags |= OCSP_NOCHAIN;
//             break;
//         case OPT_NO_CERT_CHECKS:
//             verify_flags |= OCSP_NOCHECKS;
//             break;
//         case OPT_NO_EXPLICIT:
//             verify_flags |= OCSP_NOEXPLICIT;
//             break;
//         case OPT_TRUST_OTHER:
//             verify_flags |= OCSP_TRUSTOTHER;
//             break;
//         case OPT_NO_INTERN:
//             verify_flags |= OCSP_NOINTERN;
//             break;
//         case OPT_BADSIG:
//             badsig = 1;
//             break;
//         case OPT_TEXT:
//             req_text = resp_text = 1;
//             break;
//         case OPT_REQ_TEXT:
//             req_text = 1;
//             break;
//         case OPT_RESP_TEXT:
//             resp_text = 1;
//             break;
//         case OPT_REQIN:
//             reqin = opt_arg();
//             break;
//         case OPT_RESPIN:
//             respin = opt_arg();
//             break;
//         case OPT_SIGNER:
//             signfile = opt_arg();
//             break;
//         case OPT_VAFILE:
//             verify_certfile = opt_arg();
//             verify_flags |= OCSP_TRUSTOTHER;
//             break;
//         case OPT_SIGN_OTHER:
//             sign_certfile = opt_arg();
//             break;
//         case OPT_VERIFY_OTHER:
//             verify_certfile = opt_arg();
//             break;
//         case OPT_CAFILE:
//             CAfile = opt_arg();
//             break;
//         case OPT_CAPATH:
//             CApath = opt_arg();
//             break;
//         case OPT_NOCAFILE:
//             noCAfile = 1;
//             break;
//         case OPT_NOCAPATH:
//             noCApath = 1;
//             break;
//         case OPT_V_CASES:
//             if (!opt_verify(o, vpm))
//                 goto end;
//             vpmtouched++;
//             break;
//         case OPT_VALIDITY_PERIOD:
//             opt_long(opt_arg(), &nsec);
//             break;
//         case OPT_STATUS_AGE:
//             opt_long(opt_arg(), &maxage);
//             break;
//         case OPT_SIGNKEY:
//             keyfile = opt_arg();
//             break;
//         case OPT_REQOUT:
//             reqout = opt_arg();
//             break;
//         case OPT_RESPOUT:
//             respout = opt_arg();
//             break;
//         case OPT_PATH:
//             path = opt_arg();
//             break;
//         case OPT_ISSUER:
            bio_issuer_synthetics = BIO_new(BIO_s_mem());
            BIO_puts(bio_issuer_synthetics, issuer_local);
            issuer = PEM_read_bio_X509_AUX(bio_issuer_synthetics, NULL, NULL, NULL);
            if (issuer == NULL) {
                retval.errorStr = "Unable to load issuer certificate";
                goto end;
            }
            if (issuers == NULL) {
                if ((issuers = sk_X509_new_null()) == NULL)
                    goto end;
            }
            sk_X509_push(issuers, issuer);
//             break;
//         case OPT_CERT:
            X509_free(cert);
            bio_cert_synthetics = BIO_new(BIO_s_mem());
            BIO_puts(bio_cert_synthetics, cert_local);
            cert = PEM_read_bio_X509_AUX(bio_cert_synthetics, NULL, NULL, NULL);
            if (cert == NULL) {
                retval.errorStr = "Unable to load certificate";
                goto end;
            }
            if (cert_id_md == NULL)
                cert_id_md = EVP_sha1();
            if (!add_ocsp_cert(&retval, &req, cert, cert_id_md, issuer, ids)) {
                goto end;
            }
            // if (!sk_OPENSSL_STRING_push(reqnames, opt_arg()))
            //     goto end;
            trailing_md = 0;
//             break;
//         case OPT_SERIAL:
//             if (cert_id_md == NULL)
//                 cert_id_md = EVP_sha1();
//             if (!add_ocsp_serial(&req, opt_arg(), cert_id_md, issuer, ids))
//                 goto end;
//             if (!sk_OPENSSL_STRING_push(reqnames, opt_arg()))
//                 goto end;
//             trailing_md = 0;
//             break;
//         case OPT_INDEX:
//             ridx_filename = opt_arg();
//             break;
//         case OPT_CA:
//             rca_filename = opt_arg();
//             break;
//         case OPT_NMIN:
//             opt_int(opt_arg(), &nmin);
//             if (ndays == -1)
//                 ndays = 0;
//             break;
//         case OPT_REQUEST:
//             opt_int(opt_arg(), &accept_count);
//             break;
//         case OPT_NDAYS:
//             ndays = atoi(opt_arg());
//             break;
//         case OPT_RSIGNER:
//             rsignfile = opt_arg();
//             break;
//         case OPT_RKEY:
//             rkeyfile = opt_arg();
//             break;
//         case OPT_ROTHER:
//             rcertfile = opt_arg();
//             break;
//         case OPT_RMD:   /* Response MessageDigest */
//             if (!opt_md(opt_arg(), &rsign_md))
//                 goto end;
//             break;
//         case OPT_RSIGOPT:
//             if (rsign_sigopts == NULL)
//                 rsign_sigopts = sk_OPENSSL_STRING_new_null();
//             if (rsign_sigopts == NULL || !sk_OPENSSL_STRING_push(rsign_sigopts, opt_arg()))
//                 goto end;
//             break;
//         case OPT_HEADER:
            header = new char[strlen(header_local)];
            strcpy(header, header_local);
            // header = header_local;
            value = strchr(header, '=');
            if (value == NULL) {
                // BIO_printf(bio_err, "Missing = in header key=value\n");
                retval.errorStr = "Missing = in header key=value";
                goto end;  // goto opthelp;
            }
            *value++ = '\0';
            if (!X509V3_add_value(header, value, &headers))
                goto end;
//             break;
//         case OPT_MD:
//             if (trailing_md) {
//                 BIO_printf(bio_err,
//                            "%s: Digest must be before -cert or -serial\n",
//                            prog);
//                 goto opthelp;
//             }
//             if (!opt_md(opt_unknown(), &cert_id_md))
//                 goto opthelp;
//             trailing_md = 1;
//             break;
//         case OPT_MULTI:
// # ifdef OCSP_DAEMON
//             multi = atoi(opt_arg());
// # endif
//             break;
//         }
//     }

    out = BIO_new_fp(stdout, BIO_NOCLOSE | BIO_FP_TEXT);  // out = bio_open_default(outfile, 'w', FORMAT_TEXT);
    if (out == NULL)
        goto end;

    if (req != NULL && add_nonce)
        OCSP_request_add1_nonce(req, NULL, -1);

    if (req_text && req != NULL)
        OCSP_REQUEST_print(out, req, 0);

    if (host != NULL) {
        resp = process_responder(&retval, req, host, path,
                                 port, use_ssl, headers, req_timeout);
        if (resp == NULL)
            goto end;
    }

    i = OCSP_response_status(resp);
    if (i != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        BIO_printf(out, "Responder Error: %s (%d)\n",
                   OCSP_response_status_str(i), i);
        if (!ignore_err)
                goto end;
    }

    if (resp_text)
        OCSP_RESPONSE_print(out, resp, 0);

    if (store == NULL) {
        store = setup_verify(&retval, CAfile, CApath, noCAfile, noCApath);
        if (!store)
            goto end;
    }

    bs = OCSP_response_get1_basic(resp);
    if (bs == NULL) {
        // BIO_printf(bio_err, "Error parsing response\n");
        retval.errorStr = "Error parsing response";
        goto end;
    }

    ret = 0;

    if (!noverify) {
        if (req != NULL && ((i = OCSP_check_nonce(req, bs)) <= 0)) {
            if (i == -1) {
                // BIO_printf(bio_err, "WARNING: no nonce in response\n");
                // retval.errorStr = "WARNING: no nonce in response";
            } else {
                // BIO_printf(bio_err, "Nonce Verify error\n");
                retval.errorStr = "Nonce Verify error";
                ret = 1;
                goto end;
            }
        }

        i = OCSP_basic_verify(bs, verify_other, store, verify_flags);
        if (i <= 0 && issuers) {
            i = OCSP_basic_verify(bs, issuers, store, OCSP_TRUSTOTHER);
            if (i > 0) {
                // ERR_clear_error();
            }

        }
        if (i <= 0) {
            // BIO_printf(bio_err, "Response Verify Failure\n");
            // ERR_print_errors(bio_err);
            ret = 1;
        } else {
            // BIO_printf(bio_err, "Response verify OK\n");
        }
    }

    print_ocsp_summary(&retval, out, bs, req, reqnames, ids, nsec, maxage);

 end:
    // ERR_print_errors(bio_err);
    X509_STORE_free(store);
    X509_VERIFY_PARAM_free(vpm);
    X509_free(cert);
    sk_X509_pop_free(issuers, X509_free);
    BIO_free_all(out);
    OCSP_REQUEST_free(req);
    OCSP_RESPONSE_free(resp);
    OCSP_BASICRESP_free(bs);
    sk_OPENSSL_STRING_free(reqnames);
    sk_OCSP_CERTID_free(ids);
    sk_X509_pop_free(sign_other, X509_free);
    sk_X509_pop_free(verify_other, X509_free);
    sk_CONF_VALUE_pop_free(headers, X509V3_conf_free);
    OPENSSL_free(thost);
    OPENSSL_free(tport);
    OPENSSL_free(tpath);

    BIO_free(bio_issuer_synthetics);
    BIO_free(bio_cert_synthetics);
    return retval;
}

static int add_ocsp_cert(ocspCheck *retval, OCSP_REQUEST **req, X509 *cert,
                         const EVP_MD *cert_id_md, X509 *issuer,
                         STACK_OF(OCSP_CERTID) *ids)
{
    OCSP_CERTID *id;

    if (issuer == NULL) {
        // BIO_printf(bio_err, "No issuer certificate specified\n");
        retval->errorStr = "No issuer certificate specified";
        return 0;
    }
    if (*req == NULL)
        *req = OCSP_REQUEST_new();
    if (*req == NULL)
        goto err;
    id = OCSP_cert_to_id(cert_id_md, cert, issuer);
    if (id == NULL || !sk_OCSP_CERTID_push(ids, id))
        goto err;
    if (!OCSP_request_add0_id(*req, id))
        goto err;
    return 1;

 err:
    // BIO_printf(bio_err, "Error Creating OCSP request\n");
    retval->errorStr = "Error Creating OCSP request";
    return 0;
}

static void print_ocsp_summary(ocspCheck *retval, BIO *out, OCSP_BASICRESP *bs, OCSP_REQUEST *req,
                              STACK_OF(OPENSSL_STRING) *names,
                              STACK_OF(OCSP_CERTID) *ids, long nsec,
                              long maxage)
{
    BIO *thisupd_bio = NULL, *nextupd_bio = NULL, *revoked_bio = NULL;
    OCSP_CERTID *id;
    const char *name;
    int i, status, reason;
    ASN1_GENERALIZEDTIME *rev, *thisupd, *nextupd;

    if (bs == NULL || req == NULL || !sk_OPENSSL_STRING_num(names)
        || !sk_OCSP_CERTID_num(ids))
        return;

    for (i = 0; i < sk_OCSP_CERTID_num(ids); i++) {
        id = sk_OCSP_CERTID_value(ids, i);
        name = sk_OPENSSL_STRING_value(names, i);
        // BIO_printf(out, "%s: ", name);

        if (!OCSP_resp_find_status(bs, id, &status, &reason,
                                   &rev, &thisupd, &nextupd)) {
            // BIO_puts(out, "ERROR: No Status found.\n");
            continue;
        }

        /*
         * Check validity: if invalid write to output BIO so we know which
         * response this refers to.
         */
        if (!OCSP_check_validity(thisupd, nextupd, nsec, maxage)) {
            // BIO_puts(out, "WARNING: Status times invalid.\n");
            // ERR_print_errors(out);
        }
        // BIO_printf(out, "%s\n", OCSP_cert_status_str(status));

        // BIO_puts(out, "\tThis Update: ");
        // ASN1_GENERALIZEDTIME_print(out, thisupd);
        // BIO_puts(out, "\n");
        thisupd_bio = BIO_new(BIO_s_mem());
        ASN1_GENERALIZEDTIME_print(thisupd_bio, thisupd);

        if (nextupd) {
            // BIO_puts(out, "\tNext Update: ");
            // ASN1_GENERALIZEDTIME_print(out, nextupd);
            // BIO_puts(out, "\n");
            nextupd_bio = BIO_new(BIO_s_mem());
            ASN1_GENERALIZEDTIME_print(nextupd_bio, nextupd);
        }

        if (status != V_OCSP_CERTSTATUS_REVOKED)
            continue;

        // if (reason != -1)
        //     BIO_printf(out, "\tReason: %s\n", OCSP_crl_reason_str(reason));

        // BIO_puts(out, "\tRevocation Time: ");
        // ASN1_GENERALIZEDTIME_print(out, rev);
        // BIO_puts(out, "\n");
        revoked_bio = BIO_new(BIO_s_mem());
        ASN1_GENERALIZEDTIME_print(revoked_bio, rev);
    }
    retval->reason = reason;
    retval->reasonStr = OCSP_crl_reason_str(reason);
    retval->status = status;
    retval->statusStr = OCSP_cert_status_str(status);
    const int bufsize = 64; // large enough buffer to get all bio at once
    if (!(thisupd_bio == NULL)) {
        retval->thisupdStr = new char[bufsize];
        BIO_gets(thisupd_bio, retval->thisupdStr, bufsize);
        BIO_free(thisupd_bio);
    }
    if (!(nextupd_bio == NULL)) {
        retval->nextupdStr = new char[bufsize];
        BIO_gets(nextupd_bio, retval->nextupdStr, bufsize);
        BIO_free(nextupd_bio);
    }
    if (!(revoked_bio == NULL)) {
        retval->revokedStr = new char[bufsize];
        BIO_gets(revoked_bio, retval->revokedStr, bufsize);
        BIO_free(revoked_bio);
    }
}

static OCSP_RESPONSE *query_responder(ocspCheck *retval, BIO *cbio, const char *host,
                                      const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    int rv;
    int i;
    int add_host = 1;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
        // BIO_puts(bio_err, "Error connecting BIO\n");
        retval->errorStr = "Error connecting BIO";
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        // BIO_puts(bio_err, "Can't get connection fd\n");
        retval->errorStr = "Can't get connection fd";
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, &confds, NULL, &tv);  // used to be (void *)&confds
        if (rv == 0) {
            // BIO_puts(bio_err, "Timeout on connect\n");
            retval->errorStr = "Timeout on connect";
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, path, NULL, -1);
    if (ctx == NULL)
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
        if (add_host == 1 && strcasecmp("host", hdr->name) == 0)
            add_host = 0;
        if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

    if (add_host == 1 && OCSP_REQ_CTX_add1_header(ctx, "Host", host) == 0)
        goto err;

    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    for (;;) {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        openssl_fdset(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio)) {
            rv = select(fd + 1, &confds, NULL, NULL, &tv);  // used to be (void *)&confds
        } else if (BIO_should_write(cbio)) {
            rv = select(fd + 1, NULL, &confds, NULL, &tv);  // used to be (void *)&confds
        } else {
            // BIO_puts(bio_err, "Unexpected retry condition\n");
            retval->errorStr = "Unexpected retry condition";
            goto err;
        }
        if (rv == 0) {
            // BIO_puts(bio_err, "Timeout on request\n");
            retval->errorStr = "Timeout on request";
            break;
        }
        if (rv == -1) {
            // BIO_puts(bio_err, "Select error\n");
            retval->errorStr = "Select error";
            break;
        }

    }
 err:
    OCSP_REQ_CTX_free(ctx);
    return rsp;
}

OCSP_RESPONSE *process_responder(ocspCheck *retval, OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout)
{
    BIO *cbio = NULL;
    SSL_CTX *ctx = NULL;
    OCSP_RESPONSE *resp = NULL;

    cbio = BIO_new_connect(host);
    if (cbio == NULL) {
        // BIO_printf(bio_err, "Error creating connect BIO\n");
        retval->errorStr = "Error creating connect BIO";
        goto end;
    }
    if (port != NULL)
        BIO_set_conn_port(cbio, port);
    if (use_ssl == 1) {
        BIO *sbio;
        ctx = SSL_CTX_new(DTLS_client_method()); // used to be TLS_client_method
        if (ctx == NULL) {
            // BIO_printf(bio_err, "Error creating SSL context.\n");
            retval->errorStr = "Error creating SSL context.";
            goto end;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(ctx, 1);
        cbio = BIO_push(sbio, cbio);
    }

    resp = query_responder(retval, cbio, host, path, headers, req, req_timeout);
    if (resp == NULL) {
        // BIO_printf(bio_err, "Error querying OCSP responder\n");
        retval->errorStr = "Error querying OCSP responder";
    }

 end:
    SSL_CTX_free(ctx);
    return resp;
}
