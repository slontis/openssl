/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 */
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include "crypto/fn_dsa.h"
#include "fn_dsa_core.h"

static const FN_DSA_PARAMS params[] = {
    { "FN-DSA-512", EVP_PKEY_FN_DSA_512, 9, FN_DSA_512_PUB_LEN, 1281, 690, 128 },
    { "FN-DSA-1024", EVP_PKEY_FN_DSA_1024, 10, FN_DSA_1024_PUB_LEN, 2305, 1330, 256 }
};

struct fn_dsa_key_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    const FN_DSA_PARAMS *params;
    EVP_MD *shake256_md;
    unsigned char *seed;
    unsigned char *pub_encoding;
    unsigned char *priv_encoding;
    int prov_flags;
};

const FN_DSA_PARAMS *ossl_fn_dsa_params_get(int evp_type)
{
    if (evp_type == EVP_PKEY_FN_DSA_512)
        return &params[0];
    if (evp_type == EVP_PKEY_FN_DSA_1024)
        return &params[1];
    return NULL;
}

const FN_DSA_PARAMS *ossl_fn_dsa_key_params(const FN_DSA_KEY *key)
{
    return key->params;
}

FN_DSA_KEY *ossl_fn_dsa_key_new(OSSL_LIB_CTX *libctx, const char *propq, int evp_type)
{
    const FN_DSA_PARAMS *p = ossl_fn_dsa_params_get(evp_type);
    FN_DSA_KEY *key;

    if (p == NULL || (key = OPENSSL_zalloc(sizeof(*key))) == NULL)
        return NULL;
    key->params = p;
    key->libctx = libctx;
    key->prov_flags = FN_DSA_KEY_PROV_FLAGS_DEFAULT;
    if (propq != NULL && (key->propq = OPENSSL_strdup(propq)) == NULL)
        goto err;
    if ((key->shake256_md = EVP_MD_fetch(libctx, "SHAKE-256", propq)) == NULL)
        goto err;
    return key;
err:
    ossl_fn_dsa_key_free(key);
    return NULL;
}

void ossl_fn_dsa_key_reset(FN_DSA_KEY *key)
{
    if (key == NULL)
        return;
    OPENSSL_secure_clear_free(key->seed, FN_DSA_SEED_BYTES);
    OPENSSL_secure_clear_free(key->priv_encoding, key->params->sk_len);
    OPENSSL_free(key->pub_encoding);
    key->seed = key->priv_encoding = key->pub_encoding = NULL;
}

void ossl_fn_dsa_key_free(FN_DSA_KEY *key)
{
    if (key == NULL)
        return;
    ossl_fn_dsa_key_reset(key);
    EVP_MD_free(key->shake256_md);
    OPENSSL_free(key->propq);
    OPENSSL_free(key);
}

static unsigned char *secure_copy(const unsigned char *in, size_t len)
{
    unsigned char *out = OPENSSL_secure_malloc(len);

    if (out != NULL)
        memcpy(out, in, len);
    return out;
}

int ossl_fn_dsa_set_prekey(FN_DSA_KEY *key, int flags_set, int flags_clr,
    const uint8_t *seed, size_t seed_len, const uint8_t *sk, size_t sk_len)
{
    unsigned char *s = NULL, *k = NULL;

    if (key == NULL || key->pub_encoding != NULL || key->priv_encoding != NULL
        || key->seed != NULL || (seed == NULL && seed_len != 0)
        || (sk == NULL && sk_len != 0)
        || (seed != NULL && seed_len != FN_DSA_SEED_BYTES)
        || (sk != NULL && sk_len != key->params->sk_len))
        return 0;
    if (seed != NULL && (s = secure_copy(seed, seed_len)) == NULL)
        goto err;
    if (sk != NULL && (k = secure_copy(sk, sk_len)) == NULL)
        goto err;
    key->seed = s;
    key->priv_encoding = k;
    key->prov_flags = (key->prov_flags | flags_set) & ~flags_clr;
    return 1;
err:
    OPENSSL_secure_clear_free(s, seed_len);
    OPENSSL_secure_clear_free(k, sk_len);
    return 0;
}

/* The key owns an immutable fetched digest; each operation owns its context. */
static EVP_MD_CTX *new_hash_ctx(const FN_DSA_KEY *key, const char *propq)
{
    EVP_MD_CTX *ctx;

    if (propq != NULL
        && (key->propq == NULL || strcmp(propq, key->propq) != 0))
        return ossl_fn_dsa_core_new_hash_ctx(key->libctx, propq);
    ctx = EVP_MD_CTX_new();
    if (ctx != NULL && !EVP_DigestInit_ex2(ctx, key->shake256_md, NULL)) {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

int ossl_fn_dsa_generate_key(FN_DSA_KEY *key)
{
    unsigned char *pub = NULL, *priv = NULL;
    EVP_MD_CTX *mdctx = NULL;

    if (key == NULL || key->pub_encoding != NULL)
        return 0;
    if (key->seed == NULL) {
        if (key->priv_encoding != NULL
            || (key->seed = OPENSSL_secure_malloc(FN_DSA_SEED_BYTES)) == NULL)
            return 0;
        if (RAND_priv_bytes_ex(key->libctx, key->seed, FN_DSA_SEED_BYTES, 256) <= 0)
            goto err;
    }
    pub = OPENSSL_malloc(key->params->pk_len);
    priv = OPENSSL_secure_malloc(key->params->sk_len);
    if (pub == NULL || priv == NULL || (mdctx = new_hash_ctx(key, NULL)) == NULL
        || !ossl_fn_dsa_core_keygen_from_seed(mdctx, key->params->logn,
               key->seed, FN_DSA_SEED_BYTES, pub, priv))
        goto err;
    if (key->priv_encoding != NULL
        && CRYPTO_memcmp(priv, key->priv_encoding, key->params->sk_len) != 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
            "explicit %s private key does not match seed", key->params->alg);
        goto err;
    }
    OPENSSL_secure_clear_free(key->priv_encoding, key->params->sk_len);
    key->priv_encoding = priv;
    key->pub_encoding = pub;
    EVP_MD_CTX_free(mdctx);
    return 1;
err:
    EVP_MD_CTX_free(mdctx);
    OPENSSL_free(pub);
    OPENSSL_secure_clear_free(priv, key->params->sk_len);
    ossl_fn_dsa_key_reset(key);
    return 0;
}

int ossl_fn_dsa_pk_decode(FN_DSA_KEY *key, const uint8_t *in, size_t len)
{
    if (key == NULL || key->pub_encoding != NULL || key->seed != NULL
        || key->priv_encoding != NULL || len != key->params->pk_len
        || !ossl_fn_dsa_core_check_public(key->params->logn, in, len))
        return 0;
    key->pub_encoding = OPENSSL_memdup(in, len);
    return key->pub_encoding != NULL;
}

int ossl_fn_dsa_sk_decode(FN_DSA_KEY *key, const uint8_t *in, size_t len)
{
    unsigned char *pub = NULL, *priv = NULL;

    if (key == NULL || key->pub_encoding != NULL || key->seed != NULL
        || in == NULL || len != key->params->sk_len)
        return 0;
    pub = OPENSSL_malloc(key->params->pk_len);
    priv = secure_copy(in, len);
    if (pub == NULL || priv == NULL
        || !ossl_fn_dsa_core_public(key->params->logn, in, len, pub)) {
        OPENSSL_free(pub);
        OPENSSL_secure_clear_free(priv, len);
        return 0;
    }
    OPENSSL_secure_clear_free(key->priv_encoding, len);
    key->pub_encoding = pub;
    key->priv_encoding = priv;
    return 1;
}

int ossl_fn_dsa_key_has(const FN_DSA_KEY *key, int selection)
{
    return key != NULL
        && (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) || key->pub_encoding != NULL)
        && (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) || key->priv_encoding != NULL);
}

int ossl_fn_dsa_key_equal(const FN_DSA_KEY *a, const FN_DSA_KEY *b, int selection)
{
    if (a == NULL || b == NULL || a->params != b->params
        || !ossl_fn_dsa_key_has(a, selection) || !ossl_fn_dsa_key_has(b, selection))
        return 0;
    return (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
               || CRYPTO_memcmp(a->pub_encoding, b->pub_encoding, a->params->pk_len) == 0)
        && (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
               || CRYPTO_memcmp(a->priv_encoding, b->priv_encoding, a->params->sk_len) == 0);
}

FN_DSA_KEY *ossl_fn_dsa_key_dup(const FN_DSA_KEY *src, int selection)
{
    FN_DSA_KEY *out;

    if (src == NULL || (src->pub_encoding == NULL
                          && (src->seed != NULL || src->priv_encoding != NULL)))
        return NULL;
    if ((out = OPENSSL_zalloc(sizeof(*out))) == NULL)
        return NULL;
    out->libctx = src->libctx;
    out->params = src->params;
    out->prov_flags = src->prov_flags;
    if (!EVP_MD_up_ref(src->shake256_md))
        goto err;
    out->shake256_md = src->shake256_md;
    if (src->propq != NULL && (out->propq = OPENSSL_strdup(src->propq)) == NULL)
        goto err;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) && src->pub_encoding != NULL
        && (out->pub_encoding = OPENSSL_memdup(src->pub_encoding, src->params->pk_len)) == NULL)
        goto err;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (src->priv_encoding != NULL
            && (out->priv_encoding = secure_copy(src->priv_encoding, src->params->sk_len)) == NULL)
            goto err;
        if (src->seed != NULL
            && (out->seed = secure_copy(src->seed, FN_DSA_SEED_BYTES)) == NULL)
            goto err;
    }
    return out;
err:
    ossl_fn_dsa_key_free(out);
    return NULL;
}

int ossl_fn_dsa_key_pairwise_check(const FN_DSA_KEY *key)
{
    unsigned char pub[MAX_FN_DSA_PUB_LEN];

    return ossl_fn_dsa_key_has(key, OSSL_KEYMGMT_SELECT_KEYPAIR)
        && ossl_fn_dsa_core_public(key->params->logn,
               key->priv_encoding, key->params->sk_len, pub)
        && CRYPTO_memcmp(pub, key->pub_encoding, key->params->pk_len) == 0;
}

int ossl_fn_dsa_key_public_check(const FN_DSA_KEY *key)
{
    return key != NULL && ossl_fn_dsa_core_check_public(key->params->logn,
                              key->pub_encoding, key->params->pk_len);
}

const uint8_t *ossl_fn_dsa_key_get_pub(const FN_DSA_KEY *key) { return key->pub_encoding; }
const uint8_t *ossl_fn_dsa_key_get_priv(const FN_DSA_KEY *key) { return key->priv_encoding; }
const uint8_t *ossl_fn_dsa_key_get_seed(const FN_DSA_KEY *key) { return key->seed; }
int ossl_fn_dsa_key_get_prov_flags(const FN_DSA_KEY *key) { return key->prov_flags; }
OSSL_LIB_CTX *ossl_fn_dsa_key_get0_libctx(const FN_DSA_KEY *key) { return key->libctx; }

/* Keep message framing separate from the numerical signing backend. */
/*
 * FIPS 204, Algorithm 2: pure-signature framing 0x00 || len(ctx) || ctx.
 * This development FN-DSA profile adopts that framing by explicit choice.
 */
static size_t encode_message_prefix(uint8_t prefix[2 + FN_DSA_MAX_CONTEXT_STRING_LEN],
    const uint8_t *context, size_t contextlen)
{
    if (contextlen > FN_DSA_MAX_CONTEXT_STRING_LEN
        || (context == NULL && contextlen != 0))
        return 0;
    prefix[0] = 0;
    prefix[1] = (uint8_t)contextlen;
    if (contextlen != 0)
        memcpy(prefix + 2, context, contextlen);
    return 2 + contextlen;
}

int ossl_fn_dsa_sign(const FN_DSA_KEY *key, const char *propq,
    const uint8_t *context, size_t contextlen,
    const uint8_t *msg, size_t msglen, uint8_t *sig, size_t *siglen, size_t sigcap)
{
    uint8_t prefix[2 + FN_DSA_MAX_CONTEXT_STRING_LEN];
    size_t prefixlen = encode_message_prefix(prefix, context, contextlen);
    EVP_MD_CTX *mdctx;
    int ret;

    if (prefixlen == 0 || !ossl_fn_dsa_key_has(key, OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 0;
    if (sig == NULL)
        return ossl_fn_dsa_core_sign_ex(key->libctx, NULL, key->params->logn,
            key->priv_encoding, key->params->sk_len, prefix, prefixlen,
            msg, msglen, NULL, siglen, sigcap);
    if ((mdctx = new_hash_ctx(key, propq)) == NULL)
        return 0;
    ret = ossl_fn_dsa_core_sign_ex(key->libctx, mdctx, key->params->logn,
        key->priv_encoding, key->params->sk_len,
        prefix, prefixlen, msg, msglen, sig, siglen, sigcap);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
int ossl_fn_dsa_sign_test(const FN_DSA_KEY *key, const char *propq,
    const uint8_t *context, size_t contextlen,
    const uint8_t *msg, size_t msglen, const uint8_t *entropy, size_t entropylen,
    uint8_t *sig, size_t *siglen, size_t sigcap)
{
    uint8_t prefix[2 + FN_DSA_MAX_CONTEXT_STRING_LEN];
    size_t prefixlen = encode_message_prefix(prefix, context, contextlen);
    EVP_MD_CTX *mdctx;
    int ret;

    if (prefixlen == 0 || !ossl_fn_dsa_key_has(key, OSSL_KEYMGMT_SELECT_KEYPAIR)
        || entropy == NULL || entropylen != FN_DSA_TEST_ENTROPY_LEN)
        return 0;
    if (sig == NULL)
        return ossl_fn_dsa_core_sign_test_ex(NULL, key->params->logn,
            key->priv_encoding, key->params->sk_len, prefix, prefixlen,
            msg, msglen, entropy, NULL, siglen, sigcap);
    if ((mdctx = new_hash_ctx(key, propq)) == NULL)
        return 0;
    ret = ossl_fn_dsa_core_sign_test_ex(mdctx, key->params->logn,
        key->priv_encoding, key->params->sk_len,
        prefix, prefixlen, msg, msglen, entropy, sig, siglen, sigcap);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
#endif

int ossl_fn_dsa_verify(const FN_DSA_KEY *key, const char *propq,
    const uint8_t *context, size_t contextlen,
    const uint8_t *msg, size_t msglen, const uint8_t *sig, size_t siglen)
{
    uint8_t prefix[2 + FN_DSA_MAX_CONTEXT_STRING_LEN];
    size_t prefixlen = encode_message_prefix(prefix, context, contextlen);
    EVP_MD_CTX *mdctx;
    int ret;

    if (prefixlen == 0 || !ossl_fn_dsa_key_has(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 0;
    if ((mdctx = new_hash_ctx(key, propq)) == NULL)
        return 0;
    ret = ossl_fn_dsa_core_verify_ex(mdctx, key->params->logn,
        key->pub_encoding, key->params->pk_len,
        prefix, prefixlen, msg, msglen, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
