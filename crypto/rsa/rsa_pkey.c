/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include "crypto/bn.h"
#include "crypto/evp.h"
#include "crypto/rsa.h"
#include "rsa_local.h"

int RSA_pkey_ctx_ctrl(EVP_PKEY_CTX *ctx, int optype, int cmd, int p1, void *p2)
{
    /* If key type not RSA or RSA-PSS return error */
    if (ctx != NULL && ctx->pmeth != NULL
        && ctx->pmeth->pkey_id != EVP_PKEY_RSA
        && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;
     return EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2);
}

int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *ctx, int pad_mode)
{
    OSSL_PARAM pad_params[2], *p = pad_params;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            || ctx->op.ciph.ciphprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_RSA_PADDING,
                                 pad_mode, NULL);

    *p++ = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, &pad_mode);
    *p++ = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, pad_params);
}

int EVP_PKEY_CTX_get_rsa_padding(EVP_PKEY_CTX *ctx, int *pad_mode)
{
    OSSL_PARAM pad_params[2], *p = pad_params;

    if (ctx == NULL || pad_mode == NULL) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
            || ctx->op.ciph.ciphprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0,
                                 pad_mode);

    *p++ = OSSL_PARAM_construct_int(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, pad_mode);
    *p++ = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, pad_params))
        return 0;

    return 1;

}

int EVP_PKEY_CTX_set_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    const char *name;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.ciph.ciphprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                                 EVP_PKEY_CTRL_RSA_OAEP_MD, 0, (void *)md);

    name = (md == NULL) ? "" : EVP_MD_name(md);

    return EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, name, NULL);
}

int EVP_PKEY_CTX_set_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
                                      const char *mdprops)
{
    OSSL_PARAM rsa_params[3], *p = rsa_params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;


    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)mdname,
                                            strlen(mdname) + 1);
    if (mdprops != NULL) {
        *p++ = OSSL_PARAM_construct_utf8_string(
                    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
                    /*
                     * Cast away the const. This is read
                     * only so should be safe
                     */
                    (char *)mdprops,
                    strlen(mdprops) + 1);
    }
    *p++ = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, rsa_params);
}

int EVP_PKEY_CTX_get_rsa_oaep_md_name(EVP_PKEY_CTX *ctx, char *name,
                                      size_t namelen)
{
    OSSL_PARAM rsa_params[2], *p = rsa_params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
                                            name, namelen);
    *p++ = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, rsa_params))
        return -1;

    return 1;
}

int EVP_PKEY_CTX_get_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)
{
    /* 80 should be big enough */
    char name[80] = "";

    if (ctx == NULL || md == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.ciph.ciphprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                                 EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, (void *)md);

    if (EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx, name, sizeof(name)) <= 0)
        return -1;

    /* May be NULL meaning "unknown" */
    *md = EVP_get_digestbyname(name);

    return 1;
}

int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    const char *name;

    if (ctx == NULL
            || (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if ((EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && ctx->op.ciph.ciphprovctx == NULL)
            || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
                && ctx->op.sig.sigprovctx == NULL))
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA,
                                 EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
                                 EVP_PKEY_CTRL_RSA_MGF1_MD, 0, (void *)md);

    name = (md == NULL) ? "" : EVP_MD_name(md);

    return EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, name, NULL);
}

int EVP_PKEY_CTX_set_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, const char *mdname,
                                      const char *mdprops)
{
    OSSL_PARAM rsa_params[3], *p = rsa_params;

    if (ctx == NULL
            || mdname == NULL
            || (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (char *)mdname,
                                            strlen(mdname) + 1);
    if (mdprops != NULL) {
        *p++ = OSSL_PARAM_construct_utf8_string(
                    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS,
                    /*
                     * Cast away the const. This is read
                     * only so should be safe
                     */
                    (char *)mdprops,
                    strlen(mdprops) + 1);
    }
    *p++ = OSSL_PARAM_construct_end();

    return EVP_PKEY_CTX_set_params(ctx, rsa_params);
}

int EVP_PKEY_CTX_get_rsa_mgf1_md_name(EVP_PKEY_CTX *ctx, char *name,
                                      size_t namelen)
{
    OSSL_PARAM rsa_params[2], *p = rsa_params;

    if (ctx == NULL
            || (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST,
                                            name, namelen);
    *p++ = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, rsa_params))
        return -1;

    return 1;
}

int EVP_PKEY_CTX_get_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD **md)
{
    /* 80 should be big enough */
    char name[80] = "";

    if (ctx == NULL
            || (!EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && !EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx))) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA or RSA-PSS return error */
    if (ctx->pmeth != NULL
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA
            && ctx->pmeth->pkey_id != EVP_PKEY_RSA_PSS)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if ((EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)
                && ctx->op.ciph.ciphprovctx == NULL)
            || (EVP_PKEY_CTX_IS_SIGNATURE_OP(ctx)
                && ctx->op.sig.sigprovctx == NULL))
        return EVP_PKEY_CTX_ctrl(ctx, -1,
                                 EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT,
                                 EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, (void *)md);

    if (EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx, name, sizeof(name)) <= 0)
        return -1;

    /* May be NULL meaning "unknown" */
    *md = EVP_get_digestbyname(name);

    return 1;
}

int EVP_PKEY_CTX_set0_rsa_oaep_label(EVP_PKEY_CTX *ctx, void *label, int llen)
{
    OSSL_PARAM rsa_params[2], *p = rsa_params;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.ciph.ciphprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                                 EVP_PKEY_CTRL_RSA_OAEP_LABEL, llen,
                                 (void *)label);

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                            /*
                                             * Cast away the const. This is read
                                             * only so should be safe
                                             */
                                            (void *)label,
                                            (size_t)llen);
    *p++ = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_set_params(ctx, rsa_params))
        return 0;

    OPENSSL_free(label);
    return 1;
}

int EVP_PKEY_CTX_get0_rsa_oaep_label(EVP_PKEY_CTX *ctx, unsigned char **label)
{
    OSSL_PARAM rsa_params[3], *p = rsa_params;
    size_t labellen;

    if (ctx == NULL || !EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx)) {
        ERR_raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED);
        /* Uses the same return values as EVP_PKEY_CTX_ctrl */
        return -2;
    }

    /* If key type not RSA return error */
    if (ctx->pmeth != NULL && ctx->pmeth->pkey_id != EVP_PKEY_RSA)
        return -1;

    /* TODO(3.0): Remove this eventually when no more legacy */
    if (ctx->op.ciph.ciphprovctx == NULL)
        return EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT,
                                 EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, 0,
                                 (void *)label);

    *p++ = OSSL_PARAM_construct_octet_ptr(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL,
                                          (void **)label, 0);
    *p++ = OSSL_PARAM_construct_size_t(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL_LEN,
                                       &labellen);
    *p++ = OSSL_PARAM_construct_end();

    if (!EVP_PKEY_CTX_get_params(ctx, rsa_params))
        return -1;

    if (labellen > INT_MAX)
        return -1;

    return (int)labellen;
}
