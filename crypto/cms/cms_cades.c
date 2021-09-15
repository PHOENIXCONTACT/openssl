/*
 * Copyright 2008-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/ess.h>
#include <openssl/ts.h>
#include <internal/sizes.h>
#include "crypto/ess.h"
#include "crypto/evp.h"
#include "crypto/x509.h"
#include "cms_local.h"

/* CAdES services */

/* extract the time of stamping from the timestamp token */
static int ossl_cms_cades_extract_timestamp(PKCS7 *token, time_t *stamp_time) {
    TS_TST_INFO *tst_info = PKCS7_to_TS_TST_INFO(token);
    const ASN1_GENERALIZEDTIME *atime = TS_TST_INFO_get_time(tst_info);
    struct tm tm;
    if (ASN1_TIME_to_tm(atime, &tm)) {
        *stamp_time = mktime(&tm);
        return 1;
    }
    return 0;
}

/* Calculate the hash over the provided object, which is the Signature within SignerInfo */
static int ossl_cms_cades_compute_imprint(PKCS7 *token, ASN1_OCTET_STRING *os, unsigned char **imprint, unsigned int *imprint_len) {
    TS_TST_INFO *tst_info = PKCS7_to_TS_TST_INFO(token);
    TS_MSG_IMPRINT *msg_imprint = TS_TST_INFO_get_msg_imprint(tst_info);
    X509_ALGOR *md_alg = TS_MSG_IMPRINT_get_algo(msg_imprint);
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    char name[OSSL_MAX_NAME_SIZE];

    OBJ_obj2txt(name, sizeof(name), md_alg->algorithm, 0);
    md = EVP_MD_fetch(NULL, name, NULL);

    *imprint = NULL;

    if (md == NULL)
	md = (EVP_MD *)EVP_get_digestbyname(name);

    if (md == NULL)
	goto err;

    *imprint_len = EVP_MD_get_size(md);
    if (*imprint_len < 0)
	goto err;
    if ((*imprint = OPENSSL_malloc(*imprint_len)) == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EVP_DigestInit(md_ctx, md))
        goto err;
    EVP_MD_free(md);
    md = NULL;
    if (!EVP_DigestUpdate(md_ctx, os->data, os->length))
	goto err;
    if (!EVP_DigestFinal(md_ctx, *imprint, NULL))
        goto err;
    EVP_MD_CTX_free(md_ctx);

    return 1;
err:
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(md);
    OPENSSL_free(*imprint);
    *imprint_len = 0;
    *imprint = NULL;
    return 0;
}

/* The Timestamp Token comes inside a (unsigned) X509 attribute of SignerInfo. */
/* The token is in PKCS7 format and needs to be converted from its still encoded form */
int ossl_cms_handle_CAdES_SignatureTimestampToken(X509_ATTRIBUTE *tsattr, X509_STORE *store, ASN1_OCTET_STRING *os, time_t *stamp_time) {
    int ret = 0, f = 0;
    TS_VERIFY_CTX *verify_ctx= NULL;
    ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(tsattr, 0);
    int tag = ASN1_TYPE_get(type);
    ASN1_OCTET_STRING *str = X509_ATTRIBUTE_get0_data(tsattr, 0, tag, NULL);
    PKCS7 *token = ASN1_item_unpack(str, ASN1_ITEM_rptr(PKCS7));
    unsigned char *imprint;
    unsigned int imprint_len = 0;

    if (!token) {
        fprintf(stderr, "Could not extract token\n");
	ERR_print_errors_fp(stderr);
	goto err;
    }

    f = TS_VFY_VERSION | TS_VFY_SIGNER;

    verify_ctx = TS_VERIFY_CTX_new();
    if (verify_ctx == NULL)
        goto err;

    if (!ossl_cms_cades_extract_timestamp(token, stamp_time)) {
        fprintf(stderr, "failed to extact stamping time\n");
        goto err;
    }

    f |= TS_VFY_IMPRINT;
    if (!ossl_cms_cades_compute_imprint(token, os, &imprint, &imprint_len))
	goto err;

    if (TS_VERIFY_CTX_set_imprint(verify_ctx, imprint, imprint_len) == NULL) {
        fprintf(stderr, "invalid digest string\n");
        goto err;
    }

    TS_VERIFY_CTX_add_flags(verify_ctx, f | TS_VFY_SIGNATURE);

    /* TS_VERIFY_CTX_free() will free the store, so we need to up the refcount here */
    X509_STORE_up_ref(store);
    if (TS_VERIFY_CTX_set_store(verify_ctx, store) == NULL) {
        fprintf(stderr, "cannot set store\n");
	goto err;
    };

    ret = TS_RESP_verify_token(verify_ctx, token);
    if (!ret)
	ERR_print_errors_fp(stderr);

err:
    TS_VERIFY_CTX_free(verify_ctx);
    return ret;
}
