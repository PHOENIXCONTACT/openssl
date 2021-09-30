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
    int ret = 0;
    TS_TST_INFO *tst_info = PKCS7_to_TS_TST_INFO(token);
    const ASN1_GENERALIZEDTIME *atime = TS_TST_INFO_get_time(tst_info);
    struct tm tm;
    if (ASN1_TIME_to_tm(atime, &tm)) {
        *stamp_time = mktime(&tm);
        ret = 1;
    }
    TS_TST_INFO_free(tst_info);
    return ret;
}

static EVP_MD *ossl_cms_cades_get_md(PKCS7 *token, X509_ALGOR **md_alg) {
    TS_TST_INFO *tst_info;
    TS_MSG_IMPRINT *msg_imprint;
    X509_ALGOR *alg;
    EVP_MD *md = NULL;
    char name[OSSL_MAX_NAME_SIZE];

    tst_info = PKCS7_to_TS_TST_INFO(token);
    if (tst_info == NULL) {
        fprintf(stderr, "failed to extract timestamp_info from timestamp\n");
        goto err;
    }
    msg_imprint = TS_TST_INFO_get_msg_imprint(tst_info);
    if (msg_imprint == NULL) {
        fprintf(stderr, "failed to extract msg_imprint from timestamp_info\n");
        goto err;
    }
    alg = TS_MSG_IMPRINT_get_algo(msg_imprint);
    if (alg == NULL) {
        fprintf(stderr, "failed to extract MD algorithm from msg_imprint\n");
        goto err;
    }

    OBJ_obj2txt(name, sizeof(name), alg->algorithm, 0);
    md = EVP_MD_fetch(NULL, name, NULL);

    if (md == NULL)
	md = (EVP_MD *)EVP_get_digestbyname(name);
    *md_alg = X509_ALGOR_dup(alg); /* alg being freed in TS_TST_INFO_free() */
err:
    TS_TST_INFO_free(tst_info);
    return md;
}

/* The Timestamp Token comes inside a (unsigned) X509 attribute of SignerInfo. */
/* The token is in PKCS7 format and needs to be converted from its still encoded form */
int ossl_cms_handle_CAdES_SignatureTimestampToken(X509_ATTRIBUTE *tsattr, X509_STORE *store, ASN1_OCTET_STRING *os, time_t *stamp_time) {
    int ret = 0, f = 0;
    TS_VERIFY_CTX *verify_ctx = NULL;
    ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(tsattr, 0);
    int tag = ASN1_TYPE_get(type);
    ASN1_OCTET_STRING *str = X509_ATTRIBUTE_get0_data(tsattr, 0, tag, NULL);
    PKCS7 *token = ASN1_item_unpack(str, ASN1_ITEM_rptr(PKCS7));
    X509_ALGOR *md_alg = NULL;
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char *imprint = NULL;
    unsigned int imprint_len;

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

    md = ossl_cms_cades_get_md(token, &md_alg);
    if (md == NULL) {
        fprintf(stderr, "Failed to get message digest for verification\n");
        goto err;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EVP_DigestInit(md_ctx, md))
        goto err;

    imprint_len = EVP_MD_get_size(md);
    if ((imprint = OPENSSL_malloc(imprint_len)) == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_DigestUpdate(md_ctx, os->data, os->length))
	goto err;

    if (!EVP_DigestFinal(md_ctx, imprint, NULL))
        goto err;

    TS_VERIFY_CTX_set_imprint(verify_ctx, imprint, imprint_len);

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
    if (!verify_ctx)	/* TS_VERIFY_CTX_free() frees the imprint... */
        OPENSSL_free(imprint);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(md);
    X509_ALGOR_free(md_alg);
    M_ASN1_free_of(token, PKCS7);
    return ret;
}

static int verify_digest(EVP_MD *md, ASN1_OCTET_STRING *digest, unsigned char *data, size_t length) {
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char imprint[EVP_MAX_MD_SIZE];
    int ret = 0;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    if (EVP_MD_get_size(md) != digest->length) {
        fprintf(stderr, "Invalid digest size\n");
        goto err;
    }
    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EVP_DigestInit(md_ctx, md))
        goto err;

    if (!EVP_DigestUpdate(md_ctx, data, length))
        goto err;

    if (!EVP_DigestFinal(md_ctx, imprint, NULL))
        goto err;

    if (memcmp(imprint, digest->data, digest->length)) {
        fprintf(stderr, "Digest incorrect\n");
        int i;
        for (i=0; i < digest->length; i++)
            fprintf(stderr, "%02X", imprint[i]);
        fprintf(stderr, "\n");
        for (i=0; i < digest->length; i++)
            fprintf(stderr, "%02X", digest->data[i]);
        fprintf(stderr, "\n");
        ERR_raise(ERR_LIB_CMS, CMS_R_VERIFICATION_FAILURE);
    } else
        ret = 1;
err:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static int verify_certificatesHashIndex(EVP_MD *md, CMS_ATSHashIndexV3 *hashindex, CMS_SignedData *signedData) {
    int k, ret = 0;
    ASN1_OCTET_STRING *object = NULL;
    STACK_OF(ASN1_OCTET_STRING) *indexs = hashindex->certificatesHashIndex;
    STACK_OF(CMS_CertificateChoices) *certchoices = signedData->certificates;
    int numi = sk_ASN1_OCTET_STRING_num(indexs);
    if (numi != sk_CMS_CertificateChoices_num(certchoices)) {
        fprintf(stderr, "Number of CertificateChoices does not match hash list: %d != %d\n", numi, sk_CMS_CertificateChoices_num(certchoices));
        goto err;
    }
    for (k = 0; k < numi; k++) {
        ASN1_OCTET_STRING *digest = sk_ASN1_OCTET_STRING_value(indexs, k);
        CMS_CertificateChoices *cchoice = sk_CMS_CertificateChoices_value(certchoices, numi - 1 - k);
        object = ASN1_item_pack(cchoice, ASN1_ITEM_rptr(CMS_CertificateChoices), &object);
        if (object == NULL) {
            fprintf(stderr, "Failed to pack RevocationInfoChoice\n");
            goto err;
        }
        if (!verify_digest(md, digest, object->data, object->length))
	    goto err;
    }
    ret = 1;
err:
    ASN1_STRING_free(object);
    return ret;
}

static int verify_crlsHashIndex(EVP_MD *md, CMS_ATSHashIndexV3 *hashindex, CMS_SignedData *signedData) {
    int k, ret = 0;
    ASN1_OCTET_STRING *object = NULL;
    STACK_OF(ASN1_OCTET_STRING) *indexs = hashindex->crlsHashIndex;
    STACK_OF(CMS_RevocationInfoChoice) *crlchoices = signedData->crls;
    int numi = sk_ASN1_OCTET_STRING_num(indexs);
    if (numi != sk_CMS_RevocationInfoChoice_num(crlchoices)) {
        fprintf(stderr, "Number of RevocationInfoChoice does not match hash list: %d != %d\n", numi, sk_CMS_RevocationInfoChoice_num(crlchoices));
        goto err;
    }
    for (k = 0; k < numi; k++) {
        ASN1_OCTET_STRING *digest = sk_ASN1_OCTET_STRING_value(indexs, k);
        CMS_RevocationInfoChoice *ri = sk_CMS_RevocationInfoChoice_value(crlchoices, numi - 1 - k);
        object = ASN1_item_pack(ri, ASN1_ITEM_rptr(CMS_RevocationInfoChoice), &object);
        if (object == NULL) {
            fprintf(stderr, "Failed to pack RevocationInfoChoice\n");
            goto err;
        }
        if (!verify_digest(md, digest, object->data, object->length))
	    goto err;
    }
    ret = 1;
err:
    ASN1_STRING_free(object);
    return ret;
}

static int verify_unsignedAttrValuesHashIndex(EVP_MD *md, CMS_ATSHashIndexV3 *hashindex, CMS_SignedData *signedData) {
    int ret = 0;
    unsigned char *content = NULL;
    ASN1_OCTET_STRING *object = NULL;
    STACK_OF(ASN1_OCTET_STRING) *indexs = hashindex->unsignedAttrValuesHashIndex;
    STACK_OF(CMS_SignerInfo) *sinfos = signedData->signerInfos;
    if (sk_CMS_SignerInfo_num(sinfos) != 1) {
        fprintf(stderr, "Don't know yet how to deal with multiple signatures...\n");
        goto err;
    }
    CMS_SignerInfo *si = sk_CMS_SignerInfo_value(sinfos, 0);
    int num = CMS_unsigned_get_attr_count(si);
    int k, numi = sk_ASN1_OCTET_STRING_num(indexs);
    if (numi != num - 1) {
        fprintf(stderr, "Expected the last unsignedAttribute to be the V3...\n");
        goto err;
    }
    for (k = 0; k < num; k++) {
        ASN1_OCTET_STRING *digest = sk_ASN1_OCTET_STRING_value(indexs, 0);
        X509_ATTRIBUTE *attr = CMS_unsigned_get_attr(si, num - k - 1);
        ASN1_OBJECT *obj = X509_ATTRIBUTE_get0_object(attr);
        object = ASN1_item_pack(obj, ASN1_ITEM_rptr(ASN1_OBJECT), &object);
        int i, len = object->length;
        if ((content = OPENSSL_malloc(len)) == NULL) {
            ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
            goto err;
        };
        memcpy(content, object->data, object->length);

        int count = X509_ATTRIBUTE_count(attr);
        if (count == 0) {
            ERR_raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES);
            goto err;
        }
        for (i = 0; i < count; i++) {
            ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attr, i);
            int tag = ASN1_TYPE_get(type);
            ASN1_OCTET_STRING *os = X509_ATTRIBUTE_get0_data(attr, i, tag, NULL);
            unsigned char *newcontent = OPENSSL_realloc(content, len + os->length);
            if (newcontent == NULL) {
                ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            memcpy(newcontent + len, os->data, os->length);
            content = newcontent;
            len += os->length;
        }
        if (!verify_digest(md, digest, content, len)) {
#if 0
            goto err;
#else
            ;
#endif
        }
        OPENSSL_free(content);
        content = NULL;
    }
    ret = 1;
err:
    ASN1_STRING_free(object);
    OPENSSL_free(content);
    return ret;
}

static int hash_content(X509_ALGOR *md_alg, unsigned char *digest, unsigned int *mlen, BIO *chain) {
    int ret = 0;
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        ERR_raise(ERR_LIB_CMS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (ossl_cms_DigestAlgorithm_find_ctx(md_ctx, chain, md_alg) <= 0) {
fprintf(stderr, "Failed to find ctx\n");
        goto err;
    }
    if (EVP_DigestFinal_ex(md_ctx, digest, mlen) <= 0) {
        ERR_raise(ERR_LIB_CMS, CMS_R_UNABLE_TO_FINALIZE_CONTEXT);
        goto err;
    }
    ret = 1;
err:
    EVP_MD_CTX_free(md_ctx);
    return ret;
}

static int update_with_orig_si(EVP_MD_CTX *md_ctx, CMS_SignerInfo *orig_si) {
    int i, num, ret = 0;
    ASN1_OCTET_STRING *object = NULL;
    object = ASN1_item_pack(&(orig_si->version), ASN1_ITEM_rptr(INT32), &object);
    if (object == NULL) {
        fprintf(stderr, "Failed to pack CMSVersion\n");
        goto err;
    }
    if (!EVP_DigestUpdate(md_ctx, object->data, object->length))
        goto err;
    object = ASN1_item_pack(orig_si->sid, ASN1_ITEM_rptr(CMS_SignerIdentifier), &object);
    if (object == NULL) {
        fprintf(stderr, "Failed to pack SignerIdentifier\n");
        goto err;
    }
    if (!EVP_DigestUpdate(md_ctx, object->data, object->length))
        goto err;
    object = ASN1_item_pack(orig_si->digestAlgorithm, ASN1_ITEM_rptr(X509_ALGOR), &object);
    if (object == NULL) {
        fprintf(stderr, "Failed to pack digestAlgorithm\n");
        goto err;
    }
    if (!EVP_DigestUpdate(md_ctx, object->data, object->length))
        goto err;
    num = CMS_signed_get_attr_count(orig_si);
    for (i = 0; i < num; i++) {
        X509_ATTRIBUTE *attr = CMS_signed_get_attr(orig_si, i);
        object = ASN1_item_pack(attr, ASN1_ITEM_rptr(X509_ATTRIBUTE), &object);
        if (object == NULL) {
            fprintf(stderr, "Failed to pack signed attribute\n");
            goto err;
        }
        if (!EVP_DigestUpdate(md_ctx, object->data, object->length))
            goto err;
    }
    object = ASN1_item_pack(orig_si->signatureAlgorithm, ASN1_ITEM_rptr(X509_ALGOR), &object);
    if (object == NULL) {
        fprintf(stderr, "Failed to pack signatureAlgorithm\n");
        goto err;
    }
    if (!EVP_DigestUpdate(md_ctx, object->data, object->length))
        goto err;
    object = ASN1_item_pack(orig_si->signature, ASN1_ITEM_rptr(ASN1_OCTET_STRING), &object);
    if (object == NULL) {
        fprintf(stderr, "Failed to pack signature\n");
        goto err;
    }
    if (!EVP_DigestUpdate(md_ctx, object->data, object->length))
        goto err;
    ret = 1;
err:
    ASN1_STRING_free(object);
    return ret;
}

/* The Archive Timestamp Token comes inside a (unsigned) X509 attribute of SignerInfo. */
/* The token is in PKCS7 format and needs to be converted from its still encoded form */
int ossl_cms_handle_CAdES_ArchiveTimestampV3Token(X509_ATTRIBUTE *tsattr, X509_STORE *store, CMS_SignedData *signedData, CMS_SignerInfo *orig_si, BIO *cmsbio) {
    int i, j, num, ret = 0, f = 0;
    TS_VERIFY_CTX *verify_ctx = NULL;
    ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(tsattr, 0);
    int tag = ASN1_TYPE_get(type);
    ASN1_OCTET_STRING *str = X509_ATTRIBUTE_get0_data(tsattr, 0, tag, NULL);
    ASN1_OCTET_STRING *object = NULL;
    PKCS7 *token = ASN1_item_unpack(str, ASN1_ITEM_rptr(PKCS7));
    X509_ALGOR *md_alg = NULL;
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    CMS_ContentInfo *internal_cms = ASN1_item_unpack(str, ASN1_ITEM_rptr(CMS_ContentInfo));
    CMS_SignerInfo *si;
    STACK_OF(CMS_SignerInfo) *sinfos;
    ASN1_OBJECT *eContentType = signedData->encapContentInfo->eContentType;
    CMS_ATSHashIndexV3 *hashindex = NULL;
    unsigned char *imprint;
    unsigned int imprint_len = 0;

    if (!token) {
        fprintf(stderr, "Could not extract token\n");
	ERR_print_errors_fp(stderr);
	goto err;
    }
    if (!internal_cms) {
        fprintf(stderr, "Could not extract internal CMS\n");
	ERR_print_errors_fp(stderr);
	goto err;
    }

    /*
     * The archive timestamp token is of course signed with a digital signature
     * using a signerInfo structure with signed and unsigned attributes. Need to extract
     * the additional hash information from the unsigned attributes.
     * Note: Since this relies on CAdES background this work is done on CMS structures
     * instead of PKCS7 structures.
     */
#if 0
    sinfos = (STACK_OF(CMS_SignerInfo) *)PKCS7_get_signer_info(token);
#else
    sinfos = CMS_get0_SignerInfos(internal_cms);
#endif
    if (!sinfos || !sk_CMS_SignerInfo_num(sinfos)) {
        ERR_raise(ERR_LIB_PKCS7, PKCS7_R_NO_SIGNATURES_ON_DATA);
        goto err;
    }

    f = TS_VFY_VERSION | TS_VFY_SIGNER;

    verify_ctx = TS_VERIFY_CTX_new();
    if (verify_ctx == NULL)
        goto err;

    f |= TS_VFY_IMPRINT;
    md = ossl_cms_cades_get_md(token, &md_alg);
    if (md == NULL) {
        fprintf(stderr, "Failed to get message digest for verification\n");
        goto err;
    }

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!EVP_DigestInit(md_ctx, md))
        goto err;

    imprint_len = EVP_MD_get_size(md);
    if ((imprint = OPENSSL_malloc(imprint_len)) == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * The input for the archive-time-stamp-v3's message imprint computation shall be the concatenation
     * (in the order shown by the list below) of the signed data hash (see bullet 2 below) and certain
     * fields in their binary encoded form without any modification and including the tag, length and
     * value octets:
     * 1) The SignedData.encapContentInfo.eContentType.
     * 2) The octets representing the hash of the signed data. The hash is computed on the same
     *    content that was used for computing the hash value that is encapsulated within the
     *    message-digest signed attribute of the CAdES signature being archive-time-stamped. The hash
     *    algorithm applied shall be the same as the hash algorithm used for computing the archive
     *    time-stamp's message imprint. The hash algorithm identifier should be included in the
     *    SignedData.digestAlgorithms set.
     *       NOTE 1: To validate the archive-time-stamp-v3, the hash of the signed data, as defined
     *       in point 2) is needed. In case of detached signatures, the hash can be provided from an
     *       external trusted source.
     * 3) The fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and signature with
     *    in the SignedData.signerInfos's item corresponding to the signature being archive
     *    time-stamped, in their order of appearance.
     * 4) A single instance of ATSHashIndexV3 type (as defined in clause 5.5.2) contained in the
     *    ats-hashindex-v3 attribute.
     */

    /*
     * 1) The SignedData.encapContentInfo.eContentType.
     */
    if (!EVP_DigestUpdate(md_ctx, OBJ_get0_data(eContentType), OBJ_length(eContentType)))
        goto err;

    /*
     * 2) The octets representing the hash of the signed data
     */
    ASN1_OCTET_STRING *eContent = signedData->encapContentInfo->eContent;
    if (eContent != NULL) {
fprintf(stderr, "Embedded content found, would need to calculate hash. Legnth=%d\n", eContent->length);
    } else {
fprintf(stderr, "No embedded content found, external hashing needed\n");
        unsigned int mlen;
        unsigned char digest[EVP_MAX_MD_SIZE];
        if (!hash_content(md_alg, digest, &mlen, cmsbio))
            goto err;
        if (mlen != imprint_len) {
            fprintf(stderr, "Digest length mismatch: mlen=%d != imprint_len=%d\n", mlen, imprint_len);
            goto err;
        }
        if (!EVP_DigestUpdate(md_ctx, digest, mlen))
            goto err;
    }

    /*
     * 3) The fields version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, and signature with
     *    in the SignedData.signerInfos's item corresponding to the signature being archive
     *    time-stamped, in their order of appearance.
     */
    if (!update_with_orig_si(md_ctx, orig_si)) {
        fprintf(stderr, "Failed to process original signature\n");
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
    /*
     * 4) A single instance of ATSHashIndexV3 type (as defined in clause 5.5.2) contained in the
     *    ats-hashindex-v3 attribute.
     */
                    if (!EVP_DigestUpdate(md_ctx, hi_str->data, hi_str->length))
                        goto err;

		    hashindex = ASN1_item_unpack(hi_str, ASN1_ITEM_rptr(CMS_ATSHashIndexV3));
                    if (hashindex == NULL) {
                        fprintf(stderr, "    Failed to unpack ATSHashIndex-v3\n");
                        ERR_print_errors_fp(stderr);
                        goto err;
                    }

                    if (!verify_certificatesHashIndex(md, hashindex, signedData))
                        goto err;

                    if (!verify_crlsHashIndex(md, hashindex, signedData))
                        goto err;

                    if (!verify_unsignedAttrValuesHashIndex(md, hashindex, signedData))
                        goto err;

                    break;
                default:
                    ; /* don't care */
            }
        }
    }

    if (!EVP_DigestFinal(md_ctx, imprint, NULL))
        goto err;

    TS_VERIFY_CTX_set_imprint(verify_ctx, imprint, imprint_len);

    TS_VERIFY_CTX_add_flags(verify_ctx, f | TS_VFY_SIGNATURE);

    /* TS_VERIFY_CTX_free() will free the store, so we need to up the refcount here */
    X509_STORE_up_ref(store);
    if (TS_VERIFY_CTX_set_store(verify_ctx, store) == NULL) {
        fprintf(stderr, "cannot set store\n");
	goto err;
    };

    ret = TS_RESP_verify_token(verify_ctx, token);

err:
    if (!ret)
	ERR_print_errors_fp(stderr);
    TS_VERIFY_CTX_free(verify_ctx);
    if (!verify_ctx)	/* TS_VERIFY_CTX_free() frees the imprint... */
        OPENSSL_free(imprint);
    M_ASN1_free_of(internal_cms, CMS_ContentInfo);
    ASN1_STRING_free(object);
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(md);
    X509_ALGOR_free(md_alg);
    M_ASN1_free_of(hashindex, CMS_ATSHashIndexV3);
    M_ASN1_free_of(token, PKCS7);

    ret = 1;
    fprintf(stderr, "In ArchiveTimetampToken: faked result\n");

    return ret;
}
