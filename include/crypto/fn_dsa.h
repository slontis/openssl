/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 */

/* Internal FN_DSA definitions for other submodules, not for application use. */
#ifndef OSSL_CRYPTO_FN_DSA_H
#define OSSL_CRYPTO_FN_DSA_H
#pragma once
#include <openssl/types.h>
#include <stddef.h>
#include <stdint.h>

/* Encoding proposal from draft-ietf-lamps-fn-dsa-certificates-00.
 * Section 6 explicitly treats the 32-byte private seed as provisional;
 * this is not a confirmed FIPS 206 key-generation interface.
 */
#define FN_DSA_SEED_BYTES 32
#define FN_DSA_512_PUB_LEN 897
#define FN_DSA_1024_PUB_LEN 1793
#define MAX_FN_DSA_PUB_LEN FN_DSA_1024_PUB_LEN
#define FN_DSA_MAX_CONTEXT_STRING_LEN 255
#define FN_DSA_TEST_ENTROPY_LEN 88

#define FN_DSA_KEY_PREFER_SEED (1 << 0)
#define FN_DSA_KEY_RETAIN_SEED (1 << 1)
#define FN_DSA_KEY_PROV_FLAGS_DEFAULT \
    (FN_DSA_KEY_PREFER_SEED | FN_DSA_KEY_RETAIN_SEED)

typedef struct fn_dsa_params_st {
    const char *alg;
    int evp_type;
    unsigned logn;
    size_t pk_len;
    size_t sk_len; /* Internal expanded-key cache, never the PKCS#8 payload. */
    size_t sig_len;
    unsigned bit_strength;
} FN_DSA_PARAMS;
typedef struct fn_dsa_key_st FN_DSA_KEY;

const FN_DSA_PARAMS *ossl_fn_dsa_params_get(int evp_type);
const FN_DSA_PARAMS *ossl_fn_dsa_key_params(const FN_DSA_KEY *key);
FN_DSA_KEY *ossl_fn_dsa_key_new(OSSL_LIB_CTX *libctx, const char *propq, int evp_type);
void ossl_fn_dsa_key_reset(FN_DSA_KEY *key);
void ossl_fn_dsa_key_free(FN_DSA_KEY *key);
FN_DSA_KEY *ossl_fn_dsa_key_dup(const FN_DSA_KEY *src, int selection);
int ossl_fn_dsa_key_has(const FN_DSA_KEY *key, int selection);
int ossl_fn_dsa_key_equal(const FN_DSA_KEY *a, const FN_DSA_KEY *b, int selection);
int ossl_fn_dsa_key_pairwise_check(const FN_DSA_KEY *key);
int ossl_fn_dsa_key_public_check(const FN_DSA_KEY *key);
int ossl_fn_dsa_set_prekey(FN_DSA_KEY *key, int flags_set, int flags_clr,
    const uint8_t *seed, size_t seed_len, const uint8_t *sk, size_t sk_len);
int ossl_fn_dsa_generate_key(FN_DSA_KEY *key);
int ossl_fn_dsa_pk_decode(FN_DSA_KEY *key, const uint8_t *in, size_t len);
int ossl_fn_dsa_sk_decode(FN_DSA_KEY *key, const uint8_t *in, size_t len);
const uint8_t *ossl_fn_dsa_key_get_pub(const FN_DSA_KEY *key);
const uint8_t *ossl_fn_dsa_key_get_priv(const FN_DSA_KEY *key);
const uint8_t *ossl_fn_dsa_key_get_seed(const FN_DSA_KEY *key);
int ossl_fn_dsa_key_get_prov_flags(const FN_DSA_KEY *key);
OSSL_LIB_CTX *ossl_fn_dsa_key_get0_libctx(const FN_DSA_KEY *key);
/* Pure message framing: 0x00 || one-byte context length || context || message.
 * This development profile adopts ML-DSA framing; FIPS 206 alignment is pending.
 */
int ossl_fn_dsa_sign(const FN_DSA_KEY *key, const char *propq,
    const uint8_t *context, size_t contextlen,
    const uint8_t *msg, size_t msglen, uint8_t *sig, size_t *siglen, size_t sigcap);
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
int ossl_fn_dsa_sign_test(const FN_DSA_KEY *key, const char *propq,
    const uint8_t *context, size_t contextlen,
    const uint8_t *msg, size_t msglen, const uint8_t *entropy, size_t entropylen,
    uint8_t *sig, size_t *siglen, size_t sigcap);
#endif
int ossl_fn_dsa_verify(const FN_DSA_KEY *key, const char *propq,
    const uint8_t *context, size_t contextlen,
    const uint8_t *msg, size_t msglen, const uint8_t *sig, size_t siglen);

#endif /* OSSL_CRYPTO_FN_DSA_H */
