/*
 * Copyright 2001-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ocsp.h>

#include "helper.h"

// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/apps.h#L33-L37
# if defined(OPENSSL_SYS_WIN32) || defined(OPENSSL_SYS_WINCE)
#  define openssl_fdset(a,b) FD_SET((unsigned int)a, b)
# else
#  define openssl_fdset(a,b) FD_SET(a, b)
# endif

// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/apps.h#L494-L498
OCSP_RESPONSE *process_responder(ocspCheck *retval, OCSP_REQUEST *req,
                                 const char *host, const char *path,
                                 const char *port, int use_ssl,
                                 STACK_OF(CONF_VALUE) *headers,
                                 int req_timeout);

ocspCheck verifyOCSP(const char* cert_local, const char* issuer_local, const char* header_local, const char* url_local, int timeout);
