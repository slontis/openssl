/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_AEAD_H
# define OPENSSL_AEAD_H
# pragma once

# include <stdarg.h>
# include <stddef.h>
# include <openssl/types.h>
# include <openssl/core.h>

# ifdef __cplusplus
extern "C" {
# endif

/* EVP_AEAD_CTX methods */

EVP_AEAD_CTX *EVP_AEAD_CTX_new_from_cipher(OSSL_LIB_CTX *libctx, const char *alg,
                                           const char *propq);
void EVP_AEAD_CTX_free(EVP_AEAD_CTX *ctx);
int EVP_AEAD_CTX_init(EVP_AEAD_CTX *ctx, const unsigned char *key, size_t keylen);
void EVP_AEAD_CTX_reset(EVP_AEAD_CTX *ctx);

int EVP_AEAD_CTX_seal(EVP_AEAD_CTX *ctx,
                      unsigned char *ct, size_t *ctlen,
                      const unsigned char *pt, size_t ptlen,
                      const unsigned char *aad, size_t aadlen,
                      const OSSL_PARAM *params);

int EVP_AEAD_CTX_open(EVP_AEAD_CTX *ctx,
                      unsigned char *pt, size_t *ptlen,
                      const unsigned char *ct, size_t ctlen,
                      const unsigned char *aad, size_t aadlen,
                      const OSSL_PARAM *params);

int EVP_AEAD_CTX_set_params(EVP_AEAD_CTX *ctx, const OSSL_PARAM params[]);
const OSSL_PARAM *EVP_AEAD_CTX_settable_params(EVP_AEAD_CTX *ctx);

const EVP_AEAD *EVP_AEAD_CTX_get0_aead(EVP_AEAD_CTX *ctx);

/* EVP_AEAD methods */
size_t EVP_AEAD_get_key_length(const EVP_AEAD *aead);
size_t EVP_AEAD_get_max_overhead(const EVP_AEAD *aead);
size_t EVP_AEAD_get_max_tag_len(const EVP_AEAD *aead);
size_t EVP_AEAD_get_nonce_length(const EVP_AEAD *aead);

# ifdef __cplusplus
}
# endif
#endif
