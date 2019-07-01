struct ocspCheck {
    const char* statusStr = NULL;
    int status = -1;
    const char* reasonStr = NULL;
    int reason = -1;
    char* thisupdStr = NULL;
    char* nextupdStr = NULL;
    char* revokedStr = NULL;
    const char* errorStr = NULL;
};

// https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/apps.h#L473-L474
X509_STORE *setup_verify(ocspCheck *retval, const char *CAfile, const char *CApath,
                         int noCAfile, int noCApath);
