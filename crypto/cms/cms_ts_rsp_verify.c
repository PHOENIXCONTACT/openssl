/*
 * Copyright 2006-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/objects.h>
#include <openssl/ts.h>
#include <openssl/pkcs7.h>
#include <openssl/cms.h>
#include "internal/cryptlib.h"
#include "internal/sizes.h"
#include "crypto/ess.h"
#include "cms_local.h"
#include "cms_ts_local.h"

static int ts_verify_cert(X509_STORE *store, STACK_OF(X509) *untrusted,
                          X509 *signer, STACK_OF(X509) **chain);

static int int_ts_RESP_verify_token(TS_VERIFY_CTX *ctx,
                                    CMS_ContentInfo *cmstoken, TS_TST_INFO *tst_info);
static int ts_check_policy(const ASN1_OBJECT *req_oid,
                           const TS_TST_INFO *tst_info);
static int ts_compute_imprint(BIO *data, TS_TST_INFO *tst_info,
                              X509_ALGOR **md_alg,
                              unsigned char **imprint, unsigned *imprint_len);
static int ts_check_imprints(X509_ALGOR *algor_a,
                             const unsigned char *imprint_a, unsigned len_a,
                             TS_TST_INFO *tst_info);
static int ts_check_nonces(const ASN1_INTEGER *a, TS_TST_INFO *tst_info);
static int ts_check_signer_name(GENERAL_NAME *tsa_name, X509 *signer);
static int ts_find_name(STACK_OF(GENERAL_NAME) *gen_names,
                        GENERAL_NAME *name);

/*
 * This must be large enough to hold all values in ts_status_text (with
 * comma separator) or all text fields in ts_failure_info (also with comma).
 */
#define TS_STATUS_BUF_SIZE      256

/*-
 * This function carries out the following tasks:
 *      - Checks if there is one and only one signer.
 *      - Search for the signing certificate in 'certs' and in the response.
 *      - Check the extended key usage and key usage fields of the signer
 *      certificate (done by the path validation).
 *      - Build and validate the certificate path.
 *      - Check if the certificate path meets the requirements of the
 *      SigningCertificate ESS signed attribute.
 *      - Verify the signature value.
 *      - Returns the signer certificate in 'signer', if 'signer' is not NULL.
 */
static int cms_TS_RESP_verify_signature(CMS_ContentInfo *cmstoken, STACK_OF(X509) *certs,
                             X509_STORE *store, X509 **signer_out)
{
    STACK_OF(CMS_SignerInfo) *sinfos = NULL;
    CMS_SignerInfo *si;
    STACK_OF(X509) *untrusted = NULL;
    STACK_OF(X509) *signers = NULL;
    STACK_OF(X509) *cms_certs = NULL;
    X509 *signer = NULL;
    STACK_OF(X509) *chain = NULL;
    char buf[4096];
    int i, ret = 0;
    int scount = 0;
    BIO *cmsbio = NULL;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    /* Some sanity checks first. */
    if (!cmstoken) {
        ERR_raise(ERR_LIB_TS, TS_R_INVALID_NULL_POINTER);
        goto err;
    }
    if (OBJ_obj2nid(cmstoken->contentType) != NID_pkcs7_signed) {
        ERR_raise(ERR_LIB_TS, TS_R_WRONG_CONTENT_TYPE);
        goto err;
    }
    if (CMS_is_detached(cmstoken)) {
        ERR_raise(ERR_LIB_TS, TS_R_NO_CONTENT);
        goto err;
    }

    sinfos = CMS_get0_SignerInfos(cmstoken);
    if (!sinfos || sk_CMS_SignerInfo_num(sinfos) != 1) {
        ERR_raise(ERR_LIB_TS, TS_R_THERE_MUST_BE_ONE_SIGNER);
        goto err;
    }
    si = sk_CMS_SignerInfo_value(sinfos, 0);

    /*
     * Get hold of the signer certificate, search only internal certificates
     * if it was requested.
     */
    CMS_SignerInfo_get0_algs(si, NULL, &signer, NULL, NULL);
    if (signer)
        scount++;
    if (scount != sk_CMS_SignerInfo_num(sinfos))
        scount += CMS_set1_signers_certs(cmstoken, certs, 0);

    if (scount != sk_CMS_SignerInfo_num(sinfos)) {
        ERR_raise(ERR_LIB_CMS, CMS_R_SIGNER_CERTIFICATE_NOT_FOUND);
        goto err;
    }

    signers = CMS_get0_signers(cmstoken);
    if (!signers || sk_X509_num(signers) != 1) {
        fprintf(stderr, "signers = %p\n", signers);
        if (signers)
            fprintf(stderr, "Found %d entries in signers\n", sk_X509_num(signers));
        goto err;
    }
    signer = sk_X509_value(signers, 0);

    cms_certs = CMS_get1_certs(cmstoken);

    untrusted = sk_X509_new_reserve(NULL, sk_X509_num(certs)
                                    + sk_X509_num(cms_certs));
    if (untrusted == NULL
            || !X509_add_certs(untrusted, certs, 0)
            || !X509_add_certs(untrusted, cms_certs, 0))
        goto err;
    if (!ts_verify_cert(store, untrusted, signer, &chain))
        goto err;
    if (ossl_cms_check_signing_certs(si, chain) <= 0)
        goto err;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    cmsbio = CMS_dataInit(cmstoken, NULL);

    /* We now have to 'read' from p7bio to calculate digests etc. */
    while ((i = BIO_read(cmsbio, buf, sizeof(buf))) > 0)
        continue;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    if (CMS_SignerInfo_verify_content(si, cmsbio) <= 0) {
        ERR_raise(ERR_LIB_CMS, CMS_R_CONTENT_VERIFY_ERROR);
        goto err;
    }

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    if (signer_out) {
        *signer_out = signer;
        X509_up_ref(signer);
    }
    ret = 1;

 err:
    BIO_free_all(cmsbio);
    sk_X509_free(untrusted);
    sk_X509_pop_free(cms_certs, X509_free);
    sk_X509_pop_free(chain, X509_free);
    sk_X509_free(signers);

    return ret;
}

/*
 * The certificate chain is returned in chain. Caller is responsible for
 * freeing the vector.
 */
static int ts_verify_cert(X509_STORE *store, STACK_OF(X509) *untrusted,
                          X509 *signer, STACK_OF(X509) **chain)
{
    X509_STORE_CTX *cert_ctx = NULL;
    int i;
    int ret = 0;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    *chain = NULL;
    cert_ctx = X509_STORE_CTX_new();
    if (cert_ctx == NULL) {
        ERR_raise(ERR_LIB_TS, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    if (!X509_STORE_CTX_init(cert_ctx, store, signer, untrusted))
        goto end;
    X509_STORE_CTX_set_purpose(cert_ctx, X509_PURPOSE_TIMESTAMP_SIGN);
    i = X509_verify_cert(cert_ctx);
    if (i <= 0) {
        int j = X509_STORE_CTX_get_error(cert_ctx);
        ERR_raise_data(ERR_LIB_TS, TS_R_CERTIFICATE_VERIFY_ERROR,
                       "Verify error:%s", X509_verify_cert_error_string(j));
        goto err;
    }
    *chain = X509_STORE_CTX_get1_chain(cert_ctx);
    ret = 1;
    goto end;

err:
    ret = 0;

end:
    X509_STORE_CTX_free(cert_ctx);
    return ret;
}


/*
 * Tries to extract a TS_TST_INFO structure from the PKCS7 token and
 * calls the internal int_TS_RESP_verify_token function for verifying it.
 */
int cms_TS_RESP_verify_token(TS_VERIFY_CTX *ctx, CMS_ContentInfo *cmstoken)
{
    TS_TST_INFO *tst_info = CMS_to_TS_TST_INFO(cmstoken);
    int ret = 0;
    if (tst_info) {
        ret = int_ts_RESP_verify_token(ctx, cmstoken, tst_info);
        TS_TST_INFO_free(tst_info);
    }
    return ret;
}

/*-
 * Verifies whether the 'token' contains a valid time stamp token
 * with regards to the settings of the context. Only those checks are
 * carried out that are specified in the context:
 *      - Verifies the signature of the TS_TST_INFO.
 *      - Checks the version number of the response.
 *      - Check if the requested and returned policies math.
 *      - Check if the message imprints are the same.
 *      - Check if the nonces are the same.
 *      - Check if the TSA name matches the signer.
 *      - Check if the TSA name is the expected TSA.
 */
static int int_ts_RESP_verify_token(TS_VERIFY_CTX *ctx,
                                    CMS_ContentInfo *cmstoken, TS_TST_INFO *tst_info)
{
    X509 *signer = NULL;
    GENERAL_NAME *tsa_name = tst_info->tsa;
    X509_ALGOR *md_alg = NULL;
    unsigned char *imprint = NULL;
    unsigned imprint_len = 0;
    int ret = 0;
    int flags = ctx->flags;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    /* Some options require us to also check the signature */
    if (((flags & TS_VFY_SIGNER) && tsa_name != NULL)
            || (flags & TS_VFY_TSA_NAME)) {
        flags |= TS_VFY_SIGNATURE;
    }

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    if ((flags & TS_VFY_SIGNATURE)
        && !cms_TS_RESP_verify_signature(cmstoken, ctx->certs, ctx->store, &signer))
        goto err;

fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    if ((flags & TS_VFY_VERSION)
        && TS_TST_INFO_get_version(tst_info) != 1) {
        ERR_raise(ERR_LIB_TS, TS_R_UNSUPPORTED_VERSION);
        goto err;
    }
fprintf(stderr, "%s: %d\n", __FUNCTION__, __LINE__);
    if ((flags & TS_VFY_POLICY)
        && !ts_check_policy(ctx->policy, tst_info))
        goto err;
    if ((flags & TS_VFY_IMPRINT)
        && !ts_check_imprints(ctx->md_alg, ctx->imprint, ctx->imprint_len,
                              tst_info))
        goto err;
    if ((flags & TS_VFY_DATA)
        && (!ts_compute_imprint(ctx->data, tst_info,
                                &md_alg, &imprint, &imprint_len)
            || !ts_check_imprints(md_alg, imprint, imprint_len, tst_info)))
        goto err;
    if ((flags & TS_VFY_NONCE)
        && !ts_check_nonces(ctx->nonce, tst_info))
        goto err;
    if ((flags & TS_VFY_SIGNER)
        && tsa_name && !ts_check_signer_name(tsa_name, signer)) {
        ERR_raise(ERR_LIB_TS, TS_R_TSA_NAME_MISMATCH);
        goto err;
    }
    if ((flags & TS_VFY_TSA_NAME)
        && !ts_check_signer_name(ctx->tsa_name, signer)) {
        ERR_raise(ERR_LIB_TS, TS_R_TSA_UNTRUSTED);
        goto err;
    }
    ret = 1;

 err:
    X509_free(signer);
    X509_ALGOR_free(md_alg);
    OPENSSL_free(imprint);
    return ret;
}

static int ts_check_policy(const ASN1_OBJECT *req_oid,
                           const TS_TST_INFO *tst_info)
{
    const ASN1_OBJECT *resp_oid = tst_info->policy_id;

    if (OBJ_cmp(req_oid, resp_oid) != 0) {
        ERR_raise(ERR_LIB_TS, TS_R_POLICY_MISMATCH);
        return 0;
    }

    return 1;
}

static int ts_compute_imprint(BIO *data, TS_TST_INFO *tst_info,
                              X509_ALGOR **md_alg,
                              unsigned char **imprint, unsigned *imprint_len)
{
    TS_MSG_IMPRINT *msg_imprint = tst_info->msg_imprint;
    X509_ALGOR *md_alg_resp = msg_imprint->hash_algo;
    EVP_MD *md = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    unsigned char buffer[4096];
    char name[OSSL_MAX_NAME_SIZE];
    int length;

    *md_alg = NULL;
    *imprint = NULL;

    if ((*md_alg = X509_ALGOR_dup(md_alg_resp)) == NULL)
        goto err;

    OBJ_obj2txt(name, sizeof(name), md_alg_resp->algorithm, 0);

    (void)ERR_set_mark();
    md = EVP_MD_fetch(NULL, name, NULL);

    if (md == NULL)
        md = (EVP_MD *)EVP_get_digestbyname(name);

    if (md == NULL) {
        (void)ERR_clear_last_mark();
        goto err;
    }
    (void)ERR_pop_to_mark();

    length = EVP_MD_get_size(md);
    if (length < 0)
        goto err;
    *imprint_len = length;
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
    while ((length = BIO_read(data, buffer, sizeof(buffer))) > 0) {
        if (!EVP_DigestUpdate(md_ctx, buffer, length))
            goto err;
    }
    if (!EVP_DigestFinal(md_ctx, *imprint, NULL))
        goto err;
    EVP_MD_CTX_free(md_ctx);

    return 1;
 err:
    EVP_MD_CTX_free(md_ctx);
    EVP_MD_free(md);
    X509_ALGOR_free(*md_alg);
    *md_alg = NULL;
    OPENSSL_free(*imprint);
    *imprint_len = 0;
    *imprint = 0;
    return 0;
}

static int ts_check_imprints(X509_ALGOR *algor_a,
                             const unsigned char *imprint_a, unsigned len_a,
                             TS_TST_INFO *tst_info)
{
    TS_MSG_IMPRINT *b = tst_info->msg_imprint;
    X509_ALGOR *algor_b = b->hash_algo;
    int ret = 0;

    if (algor_a) {
        if (OBJ_cmp(algor_a->algorithm, algor_b->algorithm))
            goto err;

        /* The parameter must be NULL in both. */
        if ((algor_a->parameter
             && ASN1_TYPE_get(algor_a->parameter) != V_ASN1_NULL)
            || (algor_b->parameter
                && ASN1_TYPE_get(algor_b->parameter) != V_ASN1_NULL))
            goto err;
    }

    ret = len_a == (unsigned)ASN1_STRING_length(b->hashed_msg) &&
        memcmp(imprint_a, ASN1_STRING_get0_data(b->hashed_msg), len_a) == 0;
 err:
    if (!ret)
        ERR_raise(ERR_LIB_TS, TS_R_MESSAGE_IMPRINT_MISMATCH);
    return ret;
}

static int ts_check_nonces(const ASN1_INTEGER *a, TS_TST_INFO *tst_info)
{
    const ASN1_INTEGER *b = tst_info->nonce;

    if (!b) {
        ERR_raise(ERR_LIB_TS, TS_R_NONCE_NOT_RETURNED);
        return 0;
    }

    /* No error if a nonce is returned without being requested. */
    if (ASN1_INTEGER_cmp(a, b) != 0) {
        ERR_raise(ERR_LIB_TS, TS_R_NONCE_MISMATCH);
        return 0;
    }

    return 1;
}

/*
 * Check if the specified TSA name matches either the subject or one of the
 * subject alternative names of the TSA certificate.
 */
static int ts_check_signer_name(GENERAL_NAME *tsa_name, X509 *signer)
{
    STACK_OF(GENERAL_NAME) *gen_names = NULL;
    int idx = -1;
    int found = 0;

    if (tsa_name->type == GEN_DIRNAME
        && X509_name_cmp(tsa_name->d.dirn, X509_get_subject_name(signer)) == 0)
        return 1;
    gen_names = X509_get_ext_d2i(signer, NID_subject_alt_name, NULL, &idx);
    while (gen_names != NULL) {
        found = ts_find_name(gen_names, tsa_name) >= 0;
        if (found)
            break;
        /*
         * Get the next subject alternative name, although there should be no
         * more than one.
         */
        GENERAL_NAMES_free(gen_names);
        gen_names = X509_get_ext_d2i(signer, NID_subject_alt_name, NULL, &idx);
    }
    GENERAL_NAMES_free(gen_names);

    return found;
}

/* Returns 1 if name is in gen_names, 0 otherwise. */
static int ts_find_name(STACK_OF(GENERAL_NAME) *gen_names, GENERAL_NAME *name)
{
    int i, found;
    for (i = 0, found = 0; !found && i < sk_GENERAL_NAME_num(gen_names); ++i) {
        GENERAL_NAME *current = sk_GENERAL_NAME_value(gen_names, i);
        found = GENERAL_NAME_cmp(current, name) == 0;
    }
    return found ? i - 1 : -1;
}
