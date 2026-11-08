/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 * Licensed under the Apache License 2.0; see LICENSE.txt.
 *
 * Provider operations for the fixed-point paper profile. Registration must
 * agree with the selected message/signature profile; these operations do not
 * by themselves establish conformance with a future normative FN-DSA revision.
 */
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include "crypto/fn_dsa.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"

typedef struct {
    FN_DSA_KEY *key; /* Borrowed; EVP retains the owning EVP_PKEY. */
    int evp_type;
    int operation; /* 1: sign, 2: verify, 0: not initialized. */
    char *propq;
    unsigned char *aid;
    int aidlen;
    unsigned char context_string[FN_DSA_MAX_CONTEXT_STRING_LEN];
    size_t context_string_len;
    int message_started;
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
    unsigned char test_entropy[FN_DSA_TEST_ENTROPY_LEN];
    size_t test_entropy_len;
#endif
    unsigned char *message;
    size_t msglen, capacity;
    unsigned char *verify_sig;
    size_t verify_siglen;
    int finalized;
} FN_DSA_SIG_CTX;

static void freectx(void *vctx)
{
    FN_DSA_SIG_CTX *ctx = vctx;

    if (ctx != NULL) {
        OPENSSL_free(ctx->propq);
        OPENSSL_free(ctx->aid);
        OPENSSL_clear_free(ctx->message, ctx->capacity);
        OPENSSL_free(ctx->verify_sig);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

static void *newctx(void *provctx, const char *propq, int evp_type)
{
    FN_DSA_SIG_CTX *ctx;
    X509_ALGOR *alg = NULL;

    (void)provctx;
    if (!ossl_prov_is_running()
        || (ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL)
        return NULL;
    ctx->evp_type = evp_type;
    if ((propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL)
        || (alg = X509_ALGOR_new()) == NULL)
        goto err;
    if (!X509_ALGOR_set0(alg, OBJ_nid2obj(evp_type), V_ASN1_UNDEF, NULL)
        || (ctx->aidlen = i2d_X509_ALGOR(alg, &ctx->aid)) <= 0)
        goto err;
    X509_ALGOR_free(alg);
    return ctx;
err:
    X509_ALGOR_free(alg);
    freectx(ctx);
    return NULL;
}

static void *dupctx(void *vctx)
{
    FN_DSA_SIG_CTX *src = vctx, *dst;

    if (src == NULL || !ossl_prov_is_running()
        || (dst = OPENSSL_memdup(src, sizeof(*src))) == NULL)
        return NULL;
    dst->propq = NULL;
    dst->aid = NULL;
    dst->message = NULL;
    dst->capacity = 0;
    dst->verify_sig = NULL;
    if ((src->propq != NULL && (dst->propq = OPENSSL_strdup(src->propq)) == NULL)
        || (src->aid != NULL
            && (dst->aid = OPENSSL_memdup(src->aid, (size_t)src->aidlen)) == NULL)) {
        freectx(dst);
        return NULL;
    }
    if (src->msglen != 0) {
        dst->message = OPENSSL_memdup(src->message, src->msglen);
        if (dst->message == NULL)
            goto err;
        dst->capacity = src->msglen;
    }
    if (src->verify_sig != NULL
        && (dst->verify_sig = OPENSSL_memdup(src->verify_sig, src->verify_siglen)) == NULL)
        goto err;
    return dst;
err:
    freectx(dst);
    return NULL;
}

static int set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;
    const char *digest;
    const OSSL_PARAM *signature = NULL, *context = NULL;
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
    const OSSL_PARAM *entropy = NULL;
#endif
    FN_DSA_SIG_CTX *ctx = vctx;

    if (vctx == NULL)
        return 0;
    if (params == NULL)
        return 1;
    for (p = params; p->key != NULL; p++) {
        if (strcmp(p->key, OSSL_SIGNATURE_PARAM_DIGEST) == 0) {
            if (!OSSL_PARAM_get_utf8_string_ptr(p, &digest)
                || digest == NULL || digest[0] != '\0') {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
                return 0;
            }
        } else if (strcmp(p->key, OSSL_SIGNATURE_PARAM_CONTEXT_STRING) == 0) {
            if (ctx->message_started || ctx->finalized
                || p->data_type != OSSL_PARAM_OCTET_STRING
                || p->data_size > sizeof(ctx->context_string)
                || (p->data == NULL && p->data_size != 0)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
                return 0;
            }
            context = p;
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
        } else if (strcmp(p->key, OSSL_SIGNATURE_PARAM_TEST_ENTROPY) == 0) {
            if (ctx->operation != 1 || ctx->message_started || ctx->finalized
                || p->data_type != OSSL_PARAM_OCTET_STRING || p->data == NULL
                || p->data_size != sizeof(ctx->test_entropy)) {
                ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
                return 0;
            }
            entropy = p;
#endif
        } else if (strcmp(p->key, OSSL_SIGNATURE_PARAM_SIGNATURE) == 0) {
            if (ctx->operation != 2 || p->data_type != OSSL_PARAM_OCTET_STRING
                || p->data == NULL || p->data_size == 0
                || p->data_size > ossl_fn_dsa_params_get(ctx->evp_type)->sig_len)
                return 0;
            signature = p;
        } else {
            ERR_raise_data(ERR_LIB_PROV, ERR_R_UNSUPPORTED,
                "unsupported signature parameter: %s", p->key);
            return 0;
        }
    }
    if (signature != NULL) {
        unsigned char *copy = OPENSSL_memdup(signature->data, signature->data_size);

        if (copy == NULL)
            return 0;
        OPENSSL_free(ctx->verify_sig);
        ctx->verify_sig = copy;
        ctx->verify_siglen = signature->data_size;
    }
    if (context != NULL) {
        if (context->data_size != 0)
            memcpy(ctx->context_string, context->data, context->data_size);
        ctx->context_string_len = context->data_size;
    }
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
    if (entropy != NULL) {
        memcpy(ctx->test_entropy, entropy->data, sizeof(ctx->test_entropy));
        ctx->test_entropy_len = sizeof(ctx->test_entropy);
    }
#endif
    return 1;
}

static int init(void *vctx, void *vkey, const OSSL_PARAM params[], int operation)
{
    FN_DSA_SIG_CTX *ctx = vctx;
    FN_DSA_KEY *key;
    int selection = operation == 1 ? OSSL_KEYMGMT_SELECT_KEYPAIR
                                  : OSSL_KEYMGMT_SELECT_PUBLIC_KEY;

    if (ctx == NULL || !ossl_prov_is_running())
        return 0;
    key = vkey == NULL ? ctx->key : vkey;
    ctx->key = NULL;
    ctx->operation = 0;
    OPENSSL_clear_free(ctx->message, ctx->capacity);
    ctx->message = NULL;
    ctx->msglen = ctx->capacity = 0;
    OPENSSL_free(ctx->verify_sig);
    ctx->verify_sig = NULL;
    ctx->verify_siglen = 0;
    ctx->finalized = 0;
    ctx->message_started = 0;
    if (!ossl_fn_dsa_key_has(key, selection)
        || ossl_fn_dsa_key_params(key)->evp_type != ctx->evp_type)
        return 0;
    ctx->key = key;
    ctx->operation = operation;
    if (!set_ctx_params(ctx, params)) {
        ctx->key = NULL;
        ctx->operation = 0;
        return 0;
    }
    return 1;
}
static int sign_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return init(ctx, key, params, 1);
}
static int verify_init(void *ctx, void *key, const OSSL_PARAM params[])
{
    return init(ctx, key, params, 2);
}
static int digest_init(void *ctx, const char *mdname, void *key,
    const OSSL_PARAM params[], int operation)
{
    if (mdname != NULL && mdname[0] != '\0') {
        FN_DSA_SIG_CTX *c = ctx;

        if (c != NULL) {
            c->key = NULL;
            c->operation = 0;
        }
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);
        return 0;
    }
    return init(ctx, key, params, operation);
}
static int digest_sign_init(void *ctx, const char *mdname, void *key,
    const OSSL_PARAM params[])
{
    return digest_init(ctx, mdname, key, params, 1);
}
static int digest_verify_init(void *ctx, const char *mdname, void *key,
    const OSSL_PARAM params[])
{
    return digest_init(ctx, mdname, key, params, 2);
}

static int sign(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize,
    const unsigned char *msg, size_t msglen)
{
    FN_DSA_SIG_CTX *ctx = vctx;
    size_t max;

    if (ctx == NULL || ctx->operation != 1 || ctx->key == NULL || siglen == NULL
        || ctx->finalized
        || !ossl_prov_is_running() || (msg == NULL && msglen != 0))
        return 0;
    max = ossl_fn_dsa_key_params(ctx->key)->sig_len;
    if (sig == NULL) {
        *siglen = max;
        return 1;
    }
    if (sigsize < max) {
        *siglen = max;
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
    if (ctx->test_entropy_len != 0)
        return ossl_fn_dsa_sign_test(ctx->key, ctx->propq,
            ctx->context_string, ctx->context_string_len, msg, msglen,
            ctx->test_entropy, ctx->test_entropy_len, sig, siglen, sigsize);
#endif
    return ossl_fn_dsa_sign(ctx->key, ctx->propq,
        ctx->context_string, ctx->context_string_len,
        msg, msglen, sig, siglen, sigsize);
}
static int verify(void *vctx, const unsigned char *sig, size_t siglen,
    const unsigned char *msg, size_t msglen)
{
    FN_DSA_SIG_CTX *ctx = vctx;

    return ctx != NULL && ctx->operation == 2 && ctx->key != NULL && !ctx->finalized
        && ossl_prov_is_running()
        && ossl_fn_dsa_verify(ctx->key, ctx->propq,
            ctx->context_string, ctx->context_string_len, msg, msglen, sig, siglen);
}

/* The backend hashes nonce || encoded_message. Verification learns the nonce
 * from the final signature, so update/final retains the message until final.
 */
static int update(void *vctx, const unsigned char *data, size_t len)
{
    FN_DSA_SIG_CTX *ctx = vctx;
    unsigned char *p;
    size_t needed, capacity;

    if (ctx == NULL || ctx->operation == 0 || ctx->key == NULL || ctx->finalized
        || !ossl_prov_is_running())
        return 0;
    if ((data == NULL && len != 0) || len > SIZE_MAX - ctx->msglen)
        goto err;
    needed = ctx->msglen + len;
    if (needed > ctx->capacity) {
        capacity = ctx->capacity <= SIZE_MAX / 2 ? ctx->capacity * 2 : needed;
        if (capacity < needed)
            capacity = needed;
        p = OPENSSL_clear_realloc(ctx->message, ctx->capacity, capacity);
        if (p == NULL)
            goto err;
        ctx->message = p;
        ctx->capacity = capacity;
    }
    if (len != 0)
        memcpy(ctx->message + ctx->msglen, data, len);
    ctx->msglen = needed;
    ctx->message_started = 1;
    return 1;
err:
    ctx->finalized = 1;
    return 0;
}
static int sign_final(void *vctx, unsigned char *sig, size_t *siglen, size_t sigsize)
{
    FN_DSA_SIG_CTX *ctx = vctx;
    int ok;

    if (ctx == NULL)
        return 0;
    ok = sign(ctx, sig, siglen, sigsize, ctx->message, ctx->msglen);
    if (ok && sig != NULL)
        ctx->finalized = 1;
    return ok;
}
static int verify_final(void *vctx, const unsigned char *sig, size_t siglen)
{
    FN_DSA_SIG_CTX *ctx = vctx;
    int ok;

    if (ctx == NULL)
        return 0;
    ok = verify(ctx, sig, siglen, ctx->message, ctx->msglen);
    ctx->finalized = 1;
    return ok;
}
static int verify_message_final(void *vctx)
{
    FN_DSA_SIG_CTX *ctx = vctx;

    return ctx != NULL && verify_final(ctx, ctx->verify_sig, ctx->verify_siglen);
}

static int get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    FN_DSA_SIG_CTX *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    return p == NULL || OSSL_PARAM_set_octet_string(p, ctx->aid, (size_t)ctx->aidlen);
}
static const OSSL_PARAM *gettable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0), OSSL_PARAM_END
    };
    (void)ctx;
    (void)provctx;
    return params;
}
static const OSSL_PARAM *settable_ctx_params(void *ctx, void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
#endif
        OSSL_PARAM_END
    };
    static const OSSL_PARAM verify_params[] = {
        OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, NULL, 0), OSSL_PARAM_END
    };
    FN_DSA_SIG_CTX *c = ctx;

    (void)provctx;
    return c != NULL && c->operation == 2 ? verify_params : params;
}

#define MAKE_FN_DSA_SIGNATURE(n) \
    static void *fn_dsa_##n##_newctx(void *provctx, const char *propq) \
    { return newctx(provctx, propq, EVP_PKEY_FN_DSA_##n); } \
    const OSSL_DISPATCH ossl_fn_dsa_##n##_signature_functions[] = { \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (OSSL_FUNC)fn_dsa_##n##_newctx }, \
        { OSSL_FUNC_SIGNATURE_FREECTX, (OSSL_FUNC)freectx }, \
        { OSSL_FUNC_SIGNATURE_DUPCTX, (OSSL_FUNC)dupctx }, \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT, (OSSL_FUNC)sign_init }, \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_INIT, (OSSL_FUNC)sign_init }, \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_UPDATE, (OSSL_FUNC)update }, \
        { OSSL_FUNC_SIGNATURE_SIGN_MESSAGE_FINAL, (OSSL_FUNC)sign_final }, \
        { OSSL_FUNC_SIGNATURE_SIGN, (OSSL_FUNC)sign }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (OSSL_FUNC)verify_init }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT, (OSSL_FUNC)verify_init }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_UPDATE, (OSSL_FUNC)update }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_FINAL, (OSSL_FUNC)verify_message_final }, \
        { OSSL_FUNC_SIGNATURE_VERIFY, (OSSL_FUNC)verify }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (OSSL_FUNC)digest_sign_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (OSSL_FUNC)sign }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (OSSL_FUNC)update }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (OSSL_FUNC)sign_final }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (OSSL_FUNC)digest_verify_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (OSSL_FUNC)verify }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE, (OSSL_FUNC)update }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL, (OSSL_FUNC)verify_final }, \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (OSSL_FUNC)get_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (OSSL_FUNC)gettable_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (OSSL_FUNC)set_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (OSSL_FUNC)settable_ctx_params }, \
        OSSL_DISPATCH_END \
    }
MAKE_FN_DSA_SIGNATURE(512);
MAKE_FN_DSA_SIGNATURE(1024);
