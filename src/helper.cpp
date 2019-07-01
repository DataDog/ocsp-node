/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "helper.h"


// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/apps.c#L1223-L1264
X509_STORE *setup_verify(ocspCheck *retval, const char *CAfile, const char *CApath, int noCAfile, int noCApath)
{
    X509_STORE *store = X509_STORE_new();
    X509_LOOKUP *lookup;

    if (store == NULL)
        goto end;

    if (CAfile != NULL || !noCAfile) {
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
        if (lookup == NULL)
            goto end;
        if (CAfile) {
            if (!X509_LOOKUP_load_file(lookup, CAfile, X509_FILETYPE_PEM)) {
                // BIO_printf(bio_err, "Error loading file %s\n", CAfile);
                retval->errorStr = "Error loading file";
                goto end;
            }
        } else {
            X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    if (CApath != NULL || !noCApath) {
        lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            goto end;
        if (CApath) {
            if (!X509_LOOKUP_add_dir(lookup, CApath, X509_FILETYPE_PEM)) {
                // BIO_printf(bio_err, "Error loading directory %s\n", CApath);
                retval->errorStr = "Error loading directory";
                goto end;
            }
        } else {
            X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
        }
    }

    // ERR_clear_error();
    return store;
 end:
    X509_STORE_free(store);
    return NULL;
}
