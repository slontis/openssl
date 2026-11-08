/* FN-DSA uses the shared DER-to-key decoder and keymgmt load operation. */
#ifndef OPENSSL_NO_FN_DSA
#include <limits.h>
#include "prov/fn_dsa_codecs.h"

static void fn_dsa_free_key(void *key) { ossl_fn_dsa_key_free(key); }
static void *fn_dsa_d2i_PKCS8(const unsigned char **der, long len,
    struct der2key_ctx_st *ctx)
{
    FN_DSA_KEY *key;

    if (len < 0 || len > INT_MAX)
        return NULL;
    key = ossl_fn_dsa_d2i_PKCS8(*der, (int)len, ctx->desc->evp_type,
        ctx->provctx, ctx->propq);
    if (key != NULL)
        *der += len;
    return key;
}
static void *fn_dsa_d2i_PUBKEY(const unsigned char **der, long len,
    struct der2key_ctx_st *ctx)
{
    FN_DSA_KEY *key;

    if (len < 0 || len > INT_MAX)
        return NULL;
    key = ossl_fn_dsa_d2i_PUBKEY(*der, (int)len, ctx->desc->evp_type,
        ctx->provctx, ctx->propq);
    if (key != NULL)
        *der += len;
    return key;
}
#define fn_dsa_512_evp_type EVP_PKEY_FN_DSA_512
#define fn_dsa_512_d2i_private_key NULL
#define fn_dsa_512_d2i_public_key NULL
#define fn_dsa_512_d2i_key_params NULL
#define fn_dsa_512_d2i_PUBKEY fn_dsa_d2i_PUBKEY
#define fn_dsa_512_d2i_PKCS8 fn_dsa_d2i_PKCS8
#define fn_dsa_512_free fn_dsa_free_key
#define fn_dsa_512_check NULL
#define fn_dsa_512_adjust NULL
#define fn_dsa_1024_evp_type EVP_PKEY_FN_DSA_1024
#define fn_dsa_1024_d2i_private_key NULL
#define fn_dsa_1024_d2i_public_key NULL
#define fn_dsa_1024_d2i_key_params NULL
#define fn_dsa_1024_d2i_PUBKEY fn_dsa_d2i_PUBKEY
#define fn_dsa_1024_d2i_PKCS8 fn_dsa_d2i_PKCS8
#define fn_dsa_1024_free fn_dsa_free_key
#define fn_dsa_1024_check NULL
#define fn_dsa_1024_adjust NULL
MAKE_DECODER("FN-DSA-512", fn_dsa_512, fn_dsa_512, PrivateKeyInfo);
MAKE_DECODER("FN-DSA-512", fn_dsa_512, fn_dsa_512, SubjectPublicKeyInfo);
MAKE_DECODER("FN-DSA-1024", fn_dsa_1024, fn_dsa_1024, PrivateKeyInfo);
MAKE_DECODER("FN-DSA-1024", fn_dsa_1024, fn_dsa_1024, SubjectPublicKeyInfo);
#endif
