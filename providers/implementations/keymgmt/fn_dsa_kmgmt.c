/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 */
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include "crypto/fn_dsa.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

typedef struct {
    PROV_CTX *provctx;
    int evp_type;
    char *propq;
    unsigned char seed[FN_DSA_SEED_BYTES];
    int has_seed;
} FN_DSA_GEN_CTX;

static int get_params(void *vkey, OSSL_PARAM params[])
{
    FN_DSA_KEY *key = vkey;
    const FN_DSA_PARAMS *kp = ossl_fn_dsa_key_params(key);
    OSSL_PARAM *p;
    const unsigned char *data;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, (int)kp->pk_len * 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, (int)kp->bit_strength))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, kp->sig_len))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY)) != NULL) {
        data = ossl_fn_dsa_key_get_pub(key);
        if (data == NULL || !OSSL_PARAM_set_octet_string(p, data, kp->pk_len))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY)) != NULL) {
        data = ossl_fn_dsa_key_get_priv(key);
        if (data == NULL || !OSSL_PARAM_set_octet_string(p, data, kp->sk_len))
            return 0;
    }
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_FN_DSA_SEED)) != NULL) {
        data = ossl_fn_dsa_key_get_seed(key);
        if (data == NULL || !OSSL_PARAM_set_octet_string(p, data, FN_DSA_SEED_BYTES))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM key_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_size_t(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *gettable_params(void *provctx)
{
    (void)provctx;
    return key_params;
}

static int has(const void *key, int selection)
{
    return ossl_fn_dsa_key_has(key, selection);
}
static int match(const void *a, const void *b, int selection)
{
    return ossl_fn_dsa_key_equal(a, b, selection);
}
static void free_key(void *key) { ossl_fn_dsa_key_free(key); }
static void *dup_key(const void *key, int selection)
{
    return ossl_fn_dsa_key_dup(key, selection);
}

static int validate(const void *vkey, int selection, int check_type)
{
    const FN_DSA_KEY *key = vkey;

    (void)check_type;
    if (!has(key, selection))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        && !ossl_fn_dsa_key_public_check(key))
        return 0;
    return !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        || ossl_fn_dsa_key_pairwise_check(key);
}

static int octets(const OSSL_PARAM params[], const char *name,
    const unsigned char **data, size_t *len)
{
    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, name);

    *data = NULL;
    *len = 0;
    return p == NULL || (OSSL_PARAM_get_octet_string_ptr(p, (const void **)data, len)
                           && *data != NULL && *len != 0);
}

static int import_key(void *vkey, int selection, const OSSL_PARAM params[])
{
    FN_DSA_KEY *key = vkey;
    const FN_DSA_PARAMS *kp = ossl_fn_dsa_key_params(key);
    const unsigned char *pub = NULL, *priv = NULL, *seed = NULL;
    size_t publen = 0, privlen = 0, seedlen = 0;
    int include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY;

    if (!ossl_prov_is_running() || !(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        || ossl_fn_dsa_key_get_pub(key) != NULL)
        return 0;
    if (!octets(params, OSSL_PKEY_PARAM_PUB_KEY, &pub, &publen)
        || (include_private
            && (!octets(params, OSSL_PKEY_PARAM_PRIV_KEY, &priv, &privlen)
                || !octets(params, OSSL_PKEY_PARAM_FN_DSA_SEED, &seed, &seedlen))))
        goto err;
    if ((pub != NULL && publen != kp->pk_len)
        || (priv != NULL && privlen != kp->sk_len)
        || (seed != NULL && seedlen != FN_DSA_SEED_BYTES))
        goto err;
    if (seed != NULL && (priv == NULL
                           || (ossl_fn_dsa_key_get_prov_flags(key) & FN_DSA_KEY_PREFER_SEED))) {
        if (!ossl_fn_dsa_set_prekey(key, 0, 0, seed, seedlen, priv, privlen)
            || !ossl_fn_dsa_generate_key(key))
            goto err;
    } else if (priv != NULL) {
        if (!ossl_fn_dsa_sk_decode(key, priv, privlen))
            goto err;
    } else if (pub == NULL || !ossl_fn_dsa_pk_decode(key, pub, publen)) {
        goto err;
    }
    if (pub != NULL
        && CRYPTO_memcmp(pub, ossl_fn_dsa_key_get_pub(key), publen) != 0)
        goto err;
    return 1;
err:
    ossl_fn_dsa_key_reset(key);
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
    return 0;
}

static const OSSL_PARAM public_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0), OSSL_PARAM_END
};
static const OSSL_PARAM private_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, NULL, 0), OSSL_PARAM_END
};
static const OSSL_PARAM *key_types(int selection)
{
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return NULL;
    return selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? private_types : public_types;
}

static int export_key(void *vkey, int selection, OSSL_CALLBACK *cb, void *arg)
{
    const FN_DSA_KEY *key = vkey;
    const FN_DSA_PARAMS *kp = ossl_fn_dsa_key_params(key);
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    const unsigned char *seed = ossl_fn_dsa_key_get_seed(key);
    int ok = 0;

    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR) || !has(key, selection)
        || (bld = OSSL_PARAM_BLD_new()) == NULL)
        goto end;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        && !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
               ossl_fn_dsa_key_get_pub(key), kp->pk_len))
        goto end;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                ossl_fn_dsa_key_get_priv(key), kp->sk_len)
            || (seed != NULL && !OSSL_PARAM_BLD_push_octet_string(bld,
                                    OSSL_PKEY_PARAM_FN_DSA_SEED, seed, FN_DSA_SEED_BYTES)))
            goto end;
    }
    if ((params = OSSL_PARAM_BLD_to_param(bld)) != NULL)
        ok = cb(params, arg);
end:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return ok;
}

static void *load_key(const void *reference, size_t size)
{
    FN_DSA_KEY *key;

    if (!ossl_prov_is_running() || size != sizeof(key))
        return NULL;
    key = *(FN_DSA_KEY **)reference;
    *(FN_DSA_KEY **)reference = NULL;
    if (key == NULL || ossl_fn_dsa_key_get_pub(key) != NULL)
        return key;
    if (ossl_fn_dsa_generate_key(key))
        return key;
    ossl_fn_dsa_key_free(key);
    return NULL;
}

static int gen_set_params(void *vctx, const OSSL_PARAM params[])
{
    FN_DSA_GEN_CTX *ctx = vctx;
    const unsigned char *seed = NULL;
    size_t len = 0;
    const OSSL_PARAM *p, *seed_param;
    char *propq = NULL;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;
    seed_param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FN_DSA_SEED);
    if (seed_param != NULL
        && (!OSSL_PARAM_get_octet_string_ptr(seed_param, (const void **)&seed, &len)
            || (len != 0 && (seed == NULL || len != FN_DSA_SEED_BYTES)))) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES)) != NULL
        && !OSSL_PARAM_get_utf8_string(p, &propq, 0))
        return 0;
    if (propq != NULL) {
        OPENSSL_free(ctx->propq);
        ctx->propq = propq;
    }
    if (seed_param != NULL) {
        OPENSSL_cleanse(ctx->seed, sizeof(ctx->seed));
        if (len != 0)
            memcpy(ctx->seed, seed, len);
        ctx->has_seed = len != 0;
    }
    return 1;
}

static const OSSL_PARAM *gen_settable_params(void *genctx, void *provctx)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0), OSSL_PARAM_END
    };
    (void)genctx;
    (void)provctx;
    return types;
}
static void gen_cleanup(void *vctx)
{
    FN_DSA_GEN_CTX *ctx = vctx;

    if (ctx != NULL) {
        OPENSSL_free(ctx->propq);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}
static void *gen_init(void *provctx, int selection, const OSSL_PARAM params[], int type)
{
    FN_DSA_GEN_CTX *ctx;

    if (!ossl_prov_is_running() || !(selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        || (ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->provctx = provctx;
    ctx->evp_type = type;
    if (!gen_set_params(ctx, params)) {
        gen_cleanup(ctx);
        return NULL;
    }
    return ctx;
}
static void *generate(void *vctx, OSSL_CALLBACK *cb, void *arg)
{
    FN_DSA_GEN_CTX *ctx = vctx;
    FN_DSA_KEY *key;

    (void)cb;
    (void)arg;
    key = ossl_fn_dsa_key_new(PROV_LIBCTX_OF(ctx->provctx), ctx->propq, ctx->evp_type);
    if (key == NULL)
        return NULL;
    if ((ctx->has_seed && !ossl_fn_dsa_set_prekey(key, 0, 0,
                              ctx->seed, FN_DSA_SEED_BYTES, NULL, 0))
        || !ossl_fn_dsa_generate_key(key)) {
        ossl_fn_dsa_key_free(key);
        return NULL;
    }
    return key;
}

#define MAKE_FN_DSA_KEYMGMT(n) \
    static void *fn_dsa_##n##_new(void *provctx) \
    { return ossl_fn_dsa_key_new(PROV_LIBCTX_OF(provctx), NULL, EVP_PKEY_FN_DSA_##n); } \
    static void *fn_dsa_##n##_gen_init(void *provctx, int sel, const OSSL_PARAM p[]) \
    { return gen_init(provctx, sel, p, EVP_PKEY_FN_DSA_##n); } \
    const OSSL_DISPATCH ossl_fn_dsa_##n##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (OSSL_FUNC)fn_dsa_##n##_new }, \
        { OSSL_FUNC_KEYMGMT_FREE, (OSSL_FUNC)free_key }, \
        { OSSL_FUNC_KEYMGMT_DUP, (OSSL_FUNC)dup_key }, \
        { OSSL_FUNC_KEYMGMT_HAS, (OSSL_FUNC)has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (OSSL_FUNC)match }, \
        { OSSL_FUNC_KEYMGMT_VALIDATE, (OSSL_FUNC)validate }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (OSSL_FUNC)get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (OSSL_FUNC)gettable_params }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (OSSL_FUNC)import_key }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (OSSL_FUNC)key_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (OSSL_FUNC)export_key }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (OSSL_FUNC)key_types }, \
        { OSSL_FUNC_KEYMGMT_LOAD, (OSSL_FUNC)load_key }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (OSSL_FUNC)fn_dsa_##n##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (OSSL_FUNC)gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (OSSL_FUNC)gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (OSSL_FUNC)generate }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (OSSL_FUNC)gen_cleanup }, \
        OSSL_DISPATCH_END \
    }
MAKE_FN_DSA_KEYMGMT(512);
MAKE_FN_DSA_KEYMGMT(1024);
