/*
 * Copyright 2018-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2018-2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include "internal/cryptlib.h"
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/kdf.h>
#include "internal/asn1_int.h"
#include "internal/evp_int.h"
#include "internal/numbers.h"
#include "evp_locl.h"

/**
 * @ingroup CRYPTO_KDF_FUNCTIONS
 * @{
 */

/**
 *
 * Creates a new @ref EVP_KDF_CTX context using a @ref EVP_KDF object.
 *
 * @param kdf [in] A EVP_KDF object.
 * @retval The newly allocated EVP_KDF_CTX
 * @retval NULL if an error occurred.
 */
EVP_KDF_CTX *EVP_KDF_CTX_new(const EVP_KDF *kdf)
{
    EVP_KDF_CTX *ctx = NULL;

    if (kdf == NULL)
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(EVP_KDF_CTX));
    if (ctx == NULL || (ctx->impl = kdf->new()) == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTX_NEW, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ctx);
        ctx = NULL;
    } else {
        ctx->meth = kdf;
    }
    return ctx;
}

/**
 * Creates a new @ref EVP_KDF_CTX context using a @ref EVP_KDF numerical identity.
 *
 * @param id [in] A @ref EVP_KDF numerical identity.
 * @return The newly allocated @ref EVP_KDF_CTX or @b NULL if an error occurred.
 */
EVP_KDF_CTX *EVP_KDF_CTX_new_id(int id)
{
    const EVP_KDF *kdf = EVP_get_kdfbynid(id);

    return EVP_KDF_CTX_new(kdf);
}
/**
 * @param kdf [in] A @ref EVP_KDF object.
 * @return The numeric identity of the given @ref EVP_KDF implementation.
 */
int EVP_KDF_nid(const EVP_KDF *kdf)
{
    return kdf->type;
}

/**
 * @param ctx [in] The @ref EVP_KDF_CTX object.
 * @return The @ref EVP_KDF object associated with the @ref EVP_KDF_CTX.
 */
const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx)
{
    return ctx->meth;
}

/**
 * Frees up the @ref EVP_KDF_CTX.
 *
 * @param ctx [in] The @ref EVP_KDF_CTX to free. If @b NULL nothing is done.
 */
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    ctx->meth->free(ctx->impl);
    OPENSSL_free(ctx);
}

/**
 * Resets the @ref EVP_KDF_CTX to the default state as if the context
 * had just been created.
 *
 * @param ctx [in] The @ref EVP_KDF_CTX to reset. If @b NULL nothing is done.
 */
void EVP_KDF_reset(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return;

    if (ctx->meth->reset != NULL)
        ctx->meth->reset(ctx->impl);
}

/**
 * Used to provide inputs to the KDF algorithm prior to EVP_KDF_derive() being
 * called. The inputs that may be provided will vary depending on the KDF
 * algorithm or its implementation. This function takes variable arguments,
 * the expected arguments depend on "cmd".
 *
 * @param ctx [in] The @ref EVP_KDF_CTX to provide inputs to.
 * @param cmd [in] The command identifier. This determines what arguments are used.
 * @retval 1 for success
 * @retval <=0 for failure.
 * @retval -2 indicates the operation is not supported by the KDF algorithm.
 * @see CRYPTO_KDF_CTRLS
 */
int EVP_KDF_ctrl(EVP_KDF_CTX *ctx, int cmd, ...)
{
    int ret;
    va_list args;

    va_start(args, cmd);
    ret = EVP_KDF_vctrl(ctx, cmd, args);
    va_end(args);

    if (ret == -2)
        EVPerr(EVP_F_EVP_KDF_CTRL, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

/**
 * This is a variant of EVP_KDF_ctrl() that takes a @b va_list argument instead
 * of variadic arguments.
 *
 * @param ctx [in] The @ref EVP_KDF_CTX to provide inputs to.
 * @param cmd [in] The command identifier. This determines what arguments are used.
 * @param args [in] The va_list object contains arguments.
 * @retval 1 for success
 * @retval <=0 for failure.
 * @retval -2 indicates the operation is not supported by the KDF algorithm.
 * @see CRYPTO_KDF_CTRLS
 */
int EVP_KDF_vctrl(EVP_KDF_CTX *ctx, int cmd, va_list args)
{
    if (ctx == NULL)
        return 0;

    return ctx->meth->ctrl(ctx->impl, cmd, args);
}

/**
* Allows an application to send an algorithm specific control operation to a
* @ref EVP_KDF_CTX in string form.  This is intended to be used for
* options specified on the command line or in text files.
*
* @param ctx [in] The @ref EVP_KDF_CTX to provide inputs to.
* @param type [in] A key name.
* @param value [in] A value string associated with the key.
* @retval 1 For success
* @retval <=0 For failure.
* @retval -2 The operation is not supported by the KDF algorithm.
* @see CRYPTO_KDF_CTRLS
*/
int EVP_KDF_ctrl_str(EVP_KDF_CTX *ctx, const char *type, const char *value)
{
    int ret;

    if (ctx == NULL)
        return 0;

    if (ctx->meth->ctrl_str == NULL) {
        EVPerr(EVP_F_EVP_KDF_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);
        return -2;
    }

    ret = ctx->meth->ctrl_str(ctx->impl, type, value);
    if (ret == -2)
        EVPerr(EVP_F_EVP_KDF_CTRL_STR, EVP_R_COMMAND_NOT_SUPPORTED);

    return ret;
}

/**
 * @param ctx [in] The @ref EVP_KDF_CTX to get the size of.
 * @return the output size.  @c SIZE_MAX is returned to indicate that the
 *         algorithm produces a variable amount of output; 0 to indicate failure.
 */
size_t EVP_KDF_size(EVP_KDF_CTX *ctx)
{
    if (ctx == NULL)
        return 0;

    if (ctx->meth->size == NULL)
        return SIZE_MAX;

    return ctx->meth->size(ctx->impl);
}

/**
 * Derives 'keylen' bytes of key material and places it in the
 * 'key' buffer.  If the algorithm produces a fixed amount of output then an
 * error will occur unless the 'keylen' parameter is equal to that output size,
 * as returned by EVP_KDF_size().
 *
 * @param ctx [in] The @ref EVP_KDF_CTX used to derive key material.
 * @param key [in,out] The returned derived key material.
 * @param keylen [in] The size of the returned key material.
 * @retval 1 for success.
 * @retval <=0 for failure.
 */
int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen)
{
    if (ctx == NULL)
        return 0;

    return ctx->meth->derive(ctx->impl, key, keylen);
}

/** @} */
