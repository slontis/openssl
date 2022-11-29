/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdarg.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core.h>
#include <openssl/aead.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include "internal/nelem.h"
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"

static EVP_AEAD *evp_aead_new_from_cipher(EVP_CIPHER *cipher)
{
    EVP_AEAD *ret;

    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;
    ret->cipher = cipher;
    return ret;
}

static void evp_aead_free(EVP_AEAD *aead)
{
    if (aead == NULL)
        return;
    if (aead->cipher != NULL) {
        EVP_CIPHER_free(aead->cipher);
        /*
         * Don't try to use the cipher ref count here since internally
         * the internal store ref counts the cipher, so the aead
         * would not get freed.
         */
        OPENSSL_free(aead);
    }
}

EVP_AEAD_CTX *EVP_AEAD_CTX_new_from_cipher(OSSL_LIB_CTX *libctx, const char *alg,
                                           const char *propq)
{
    EVP_AEAD_CTX *ctx = NULL;
    EVP_CIPHER *cipher;

    cipher = EVP_CIPHER_fetch(libctx, alg, propq);
    if (cipher == NULL)
        return NULL;

    if ((EVP_CIPHER_get_flags(cipher) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0)
        goto err;

    ctx = OPENSSL_zalloc(sizeof(EVP_AEAD_CTX));
    if (ctx == NULL)
        goto err;

    ctx->ciphctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    ctx->meth = evp_aead_new_from_cipher(cipher);
    if (ctx->meth == NULL)
        goto err;
    ctx->taglen = EVP_AEAD_get_max_tag_len(ctx->meth);
    return ctx;
err:
    EVP_CIPHER_free(cipher);
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx->ciphctx);
        OPENSSL_free(ctx);
    }
    return NULL;
}

void EVP_AEAD_CTX_free(EVP_AEAD_CTX *ctx)
{
    if (ctx == NULL)
        return;
    evp_aead_free(ctx->meth);
    EVP_CIPHER_CTX_free(ctx->ciphctx);
    OPENSSL_free(ctx);
}

void EVP_AEAD_CTX_reset(EVP_AEAD_CTX *ctx)
{
    if (ctx == NULL || ctx->ciphctx != NULL)
        return;
    EVP_CIPHER_CTX_reset(ctx->ciphctx);
}

int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const unsigned char *key, size_t keylen)
{
    EVP_CIPHER_CTX *cctx = ctx->ciphctx;

    if (cctx == NULL)
        return 0;
    return EVP_EncryptInit_ex2(cctx, ctx->meth->cipher, key, NULL, NULL) > 0;
}

const EVP_AEAD *EVP_AEAD_CTX_get0_aead(EVP_AEAD_CTX *ctx)
{
    return ctx->meth;
}

const OSSL_PARAM *EVP_AEAD_CTX_settable_params(EVP_AEAD_CTX *ctx)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_size_t(OSSL_AEAD_PARAM_TAGLEN, 0),
        OSSL_PARAM_octet_string(OSSL_AEAD_PARAM_IV, NULL, 0),
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

int EVP_AEAD_CTX_set_params(EVP_AEAD_CTX *ctx, const OSSL_PARAM params[])
{
    EVP_CIPHER_CTX *cctx = ctx->ciphctx;

    if (params == NULL)
        return 1;

    if (ctx->ciphctx != NULL) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_AEAD_PARAM_TAGLEN);

        if (p != NULL) {
            if (!OSSL_PARAM_get_size_t(p, &ctx->taglen))
                return 0;
            if (ctx->taglen > EVP_AEAD_get_max_tag_len(ctx->meth))
                return 0;
        }
        p = OSSL_PARAM_locate_const(params, OSSL_AEAD_PARAM_IV);
        if (p != NULL) {
            if (p->data == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
                return 0;
            if (EVP_AEAD_get_nonce_length(ctx->meth) != p->data_size)
                return 0;
            memcpy(cctx->iv, p->data, p->data_size);
            cctx->iv_len = p->data_size;
        }
        return 1;
    }
    return 0;
}

int EVP_AEAD_CTX_seal(EVP_AEAD_CTX *ctx,
                      unsigned char *ct, size_t *ctlen,
                      const unsigned char *pt, size_t ptlen,
                      const unsigned char *aad, size_t aadlen,
                      const OSSL_PARAM *params)
{
    EVP_CIPHER_CTX *cctx = ctx->ciphctx;

    if (cctx != NULL) {
        int outlen = 0, tmplen = 0;
        OSSL_PARAM paramstag[2];

        if (ct == NULL || ctlen == NULL || pt == NULL)
            goto err;
        if (params != NULL && !EVP_AEAD_CTX_set_params(ctx, params))
            goto err;
        if (*ctlen < ptlen + ctx->taglen)
            goto err;
        if (!EVP_EncryptInit_ex2(cctx, NULL, NULL, cctx->iv, NULL))
            goto err;
        if (aad != NULL && aadlen != 0) {
            if (!EVP_EncryptUpdate(cctx, NULL, &outlen, aad, aadlen))
                goto err;
        }
        if (!EVP_EncryptUpdate(cctx, ct, &outlen, pt, ptlen))
            goto err;
        if (!EVP_EncryptFinal_ex(cctx, ct, &tmplen))
            goto err;

        paramstag[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                         ct + outlen, ctx->taglen);
        paramstag[1] = OSSL_PARAM_construct_end();
        if (!EVP_CIPHER_CTX_get_params(cctx, paramstag))
            goto err;
        *ctlen = outlen + ctx->taglen;
        return 1;
    }
err:
    return 0;
}

int EVP_AEAD_CTX_open(EVP_AEAD_CTX *ctx,
                      unsigned char *pt, size_t *ptlen,
                      const unsigned char *ct, size_t ctlen,
                      const unsigned char *aad, size_t aadlen,
                      const OSSL_PARAM *params)
{
    int ret = 0, outlen = 0;
    OSSL_PARAM paramstag[2];
    EVP_CIPHER_CTX *cctx = ctx->ciphctx;

    if (cctx == NULL || pt == NULL || ptlen == NULL || ct == NULL)
        return 0;

    if (params != NULL
            && !EVP_AEAD_CTX_set_params(ctx, params))
        return 0;

    if (ctlen <= ctx->taglen || (*ptlen + ctx->taglen < ctlen))
        return 0;

    if (cctx->iv_len != 0
            && !EVP_DecryptInit_ex2(cctx, NULL, NULL, cctx->iv, NULL))
        return 0;

    if ((aad != NULL && aadlen != 0)
            && !EVP_DecryptUpdate(cctx, NULL, &outlen, aad, aadlen))
            return 0;

    if (!EVP_DecryptUpdate(cctx, pt, &outlen, ct, ctlen - ctx->taglen))
        goto err;

    paramstag[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                     (void *)(ct + ctlen - ctx->taglen),
                                                     ctx->taglen);
    paramstag[1] = OSSL_PARAM_construct_end();
    if (!EVP_CIPHER_CTX_set_params(cctx, paramstag))
        goto err;

    ret = EVP_DecryptFinal_ex(cctx, pt, &outlen) > 0;
err:
    if (ret > 0)
        *ptlen = ctlen - ctx->taglen;
    else
        OPENSSL_cleanse(pt, *ptlen);
    return ret;
}

size_t EVP_AEAD_get_key_length(const EVP_AEAD *aead)
{
    return EVP_CIPHER_get_key_length(aead->cipher);
}

size_t EVP_AEAD_get_max_overhead(const EVP_AEAD *aead)
{
    return 16;
}

size_t EVP_AEAD_get_max_tag_len(const EVP_AEAD *aead)
{
    return 16;
}

size_t EVP_AEAD_get_nonce_length(const EVP_AEAD *aead)
{
    return EVP_CIPHER_get_iv_length(aead->cipher);
}
