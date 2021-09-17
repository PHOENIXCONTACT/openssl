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

/* The Archive Timestamp Token comes inside a (unsigned) X509 attribute of SignerInfo. */
/* The token is in PKCS7 format and needs to be converted from its still encoded form */
int ossl_cms_handle_CAdES_ArchiveTimestampV3Token(X509_ATTRIBUTE *tsattr, X509_STORE *store) {
    int ret = 0, f = 0;
    TS_VERIFY_CTX *verify_ctx= NULL;
    ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(tsattr, 0);
    int tag = ASN1_TYPE_get(type);
    ASN1_OCTET_STRING *str = X509_ATTRIBUTE_get0_data(tsattr, 0, tag, NULL);
    PKCS7 *token = ASN1_item_unpack(str, ASN1_ITEM_rptr(PKCS7));
    CMS_ContentInfo *cms = ASN1_item_unpack(str, ASN1_ITEM_rptr(CMS_ContentInfo));
    unsigned char *imprint;
    unsigned int imprint_len = 0;

    if (!token) {
        fprintf(stderr, "Could not extract token\n");
	ERR_print_errors_fp(stderr);
	goto err;
    }
    if (!cms) {
        fprintf(stderr, "Could not extract CMS\n");
	ERR_print_errors_fp(stderr);
	goto err;
    }

    /*
     * The archive timestamp token is of coursed signed with a digital signature
     * using a signerInfo structure with signed and unsigned attributes. Need to extract
     * the additional hash information from the unsigned attributes.
     * Note: Since this relies on CAdES background this work is done on CMS structures
     * instead of PKCS7 structures.
     */
    {
    int i, j, num;
    CMS_SignerInfo *si;
    STACK_OF(CMS_SignerInfo) *sinfos;
    CMS_ATSHashIndexV3 *hashindex;
#if 0
    sinfos = (STACK_OF(CMS_SignerInfo) *)PKCS7_get_signer_info(token);
#else
    sinfos = CMS_get0_SignerInfos(cms);
#endif
    if (!sinfos || !sk_CMS_SignerInfo_num(sinfos)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_SIGNATURES_ON_DATA);
        goto err;
    }
    for (i = 0; i < sk_CMS_SignerInfo_num(sinfos); i++) {
        si = sk_CMS_SignerInfo_value(sinfos, i);
        num = CMS_unsigned_get_attr_count(si);
        fprintf(stderr, "ArchiveTS: found %d unsigned attributes\n", num);
        if (num < 0)
            continue;
        for (j = 0; j < num; j++) {
            X509_ATTRIBUTE *attr = CMS_unsigned_get_attr(si, j);
            ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
            switch (OBJ_obj2nid(obj)) {
                case (NID_id_aa_ATSHashIndex_v3):
                    fprintf(stderr, "    ATSHashIndex-v3 found \n");
                    ASN1_TYPE *hi_type = X509_ATTRIBUTE_get0_type(attr, 0);
                    int hi_tag = ASN1_TYPE_get(hi_type);
                    ASN1_OCTET_STRING *hi_str = X509_ATTRIBUTE_get0_data(attr, 0, hi_tag, NULL);
		    hashindex = ASN1_item_unpack(hi_str, ASN1_ITEM_rptr(CMS_ATSHashIndexV3));
                    if (hashindex == NULL) {
                        fprintf(stderr, "    Failed to unpack ATSHashIndex-v3\n");
                        ERR_print_errors_fp(stderr);
                        goto err;
                    }
                    fprintf(stderr, "    hashindex available\n");
                    break;
                default:
                    ; /* don't care */
            }
        }
    }

    }

    f = TS_VFY_VERSION | TS_VFY_SIGNER;

    verify_ctx = TS_VERIFY_CTX_new();
    if (verify_ctx == NULL)
        goto err;
#if 0
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
#else
    ret = 1;
    fprintf(stderr, "In ArchiveTimetampToken\n");
#endif

err:
    TS_VERIFY_CTX_free(verify_ctx);
    return ret;
}
