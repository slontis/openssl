/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * at https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include "crypto/fn_dsa.h"
#include "prov/fn_dsa_codecs.h"
#include "fn_dsa_core.h"
#include "testutil.h"

static const int types[] = { EVP_PKEY_FN_DSA_512, EVP_PKEY_FN_DSA_1024 };

static EVP_PKEY *from_seed(const char *name, unsigned char *seed, size_t len,
    const unsigned char *pub, size_t publen, const unsigned char *priv, size_t privlen)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[4];
    size_t n = 0;

    params[n++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, seed, len);
    if (pub != NULL)
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)pub, publen);
    if (priv != NULL)
        params[n++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, (void *)priv, privlen);
    params[n] = OSSL_PARAM_construct_end();
    if (ctx != NULL && EVP_PKEY_fromdata_init(ctx) > 0
        && EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_KEYPAIR, params) <= 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int test_key_seed(int idx)
{
    FN_DSA_KEY *a = NULL, *b = NULL, *copy = NULL, *public = NULL, *decoded = NULL;
    const FN_DSA_PARAMS *p = ossl_fn_dsa_params_get(types[idx]);
    unsigned char seed[FN_DSA_SEED_BYTES], changed[FN_DSA_SEED_BYTES];
    unsigned char *der = NULL, sig[FN_DSA_MAX_SIG];
    size_t siglen = 0;
    int len, ok = 0;

    memset(seed, idx + 9, sizeof(seed));
    memcpy(changed, seed, sizeof(seed));
    changed[0] ^= 1;
    if (!TEST_ptr(a = ossl_fn_dsa_key_new(NULL, NULL, types[idx]))
        || !TEST_false(ossl_fn_dsa_set_prekey(a, 0, 0, seed, sizeof(seed) - 1, NULL, 0))
        || !TEST_true(ossl_fn_dsa_set_prekey(a, 0, 0, seed, sizeof(seed), NULL, 0))
        || !TEST_ptr_null(ossl_fn_dsa_key_dup(a, EVP_PKEY_KEYPAIR))
        || !TEST_true(ossl_fn_dsa_generate_key(a))
        || !TEST_mem_eq(ossl_fn_dsa_key_get_seed(a), sizeof(seed), seed, sizeof(seed))
        || !TEST_true(ossl_fn_dsa_key_pairwise_check(a))
        || !TEST_false(ossl_fn_dsa_set_prekey(a, 0, 0, seed, sizeof(seed), NULL, 0))
        || !TEST_false(ossl_fn_dsa_generate_key(a)))
        goto end;
    if (!TEST_ptr(copy = ossl_fn_dsa_key_dup(a, EVP_PKEY_KEYPAIR))
        || !TEST_true(ossl_fn_dsa_key_equal(a, copy, EVP_PKEY_KEYPAIR))
        || !TEST_ptr_ne(ossl_fn_dsa_key_get_seed(copy), ossl_fn_dsa_key_get_seed(a))
        || !TEST_ptr(public = ossl_fn_dsa_key_dup(a, EVP_PKEY_PUBLIC_KEY))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_seed(public))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_priv(public))
        || !TEST_true(ossl_fn_dsa_key_public_check(public)))
        goto end;
    if (!TEST_int_gt(len = ossl_fn_dsa_i2d_PKCS8_data(seed, sizeof(seed), p->logn, &der), 0)
        || !TEST_ptr(decoded = ossl_fn_dsa_d2i_PKCS8(der, len, types[idx], NULL, NULL))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_pub(decoded))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_priv(decoded))
        || !TEST_true(ossl_fn_dsa_generate_key(decoded))
        || !TEST_true(ossl_fn_dsa_key_equal(a, decoded, EVP_PKEY_KEYPAIR)))
        goto end;
    if (!TEST_true(ossl_fn_dsa_core_sign(NULL, p->logn, ossl_fn_dsa_key_get_priv(decoded),
                       p->sk_len, (const unsigned char *)"seed", 4, sig, &siglen, sizeof(sig)))
        || !TEST_true(ossl_fn_dsa_core_verify(NULL, p->logn, ossl_fn_dsa_key_get_pub(a),
                         p->pk_len, (const unsigned char *)"seed", 4, sig, siglen)))
        goto end;
    if (!TEST_ptr(b = ossl_fn_dsa_key_new(NULL, NULL, types[idx]))
        || !TEST_true(ossl_fn_dsa_set_prekey(b, 0, 0, changed, sizeof(changed),
                         ossl_fn_dsa_key_get_priv(a), p->sk_len))
        || !TEST_false(ossl_fn_dsa_generate_key(b))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_seed(b))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_priv(b))
        || !TEST_ptr_null(ossl_fn_dsa_key_get_pub(b)))
        goto end;
    ERR_clear_error();
    ossl_fn_dsa_key_reset(copy);
    if (!TEST_ptr_null(ossl_fn_dsa_key_get_seed(copy))
        || !TEST_true(ossl_fn_dsa_sk_decode(copy, ossl_fn_dsa_key_get_priv(a), p->sk_len))
        || !TEST_true(ossl_fn_dsa_key_equal(a, copy, EVP_PKEY_KEYPAIR))
        || !TEST_int_eq(ossl_fn_dsa_i2d_prvkey(copy, NULL), 0))
        goto end;
    ERR_clear_error();
    if (!TEST_ptr_null(ossl_fn_dsa_key_new(NULL, "provider=unavailable", types[idx])))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    ossl_fn_dsa_key_free(a);
    ossl_fn_dsa_key_free(b);
    ossl_fn_dsa_key_free(copy);
    ossl_fn_dsa_key_free(public);
    ossl_fn_dsa_key_free(decoded);
    OPENSSL_clear_free(der, der == NULL ? 0 : (size_t)len);
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(changed, sizeof(changed));
    return ok;
}

static int evp_roundtrip(EVP_PKEY *key, const char *format, const char *structure,
    int selection, int encrypt)
{
    OSSL_ENCODER_CTX *enc = NULL;
    OSSL_DECODER_CTX *dec = NULL;
    EVP_PKEY *recovered = NULL;
    unsigned char *data = NULL;
    const unsigned char *at;
    size_t len = 0, left;
    int ok = 0;

    enc = OSSL_ENCODER_CTX_new_for_pkey(key, selection, format, structure, NULL);
    if (!TEST_ptr(enc)
        || (encrypt && (!TEST_true(OSSL_ENCODER_CTX_set_cipher(enc, "AES-256-CBC", NULL))
                           || !TEST_true(OSSL_ENCODER_CTX_set_passphrase(enc,
                                            (const unsigned char *)"test", 4))))
        || !TEST_true(OSSL_ENCODER_to_data(enc, &data, &len)))
        goto end;
    dec = OSSL_DECODER_CTX_new_for_pkey(&recovered, format, NULL,
        EVP_PKEY_get0_type_name(key), selection, NULL, NULL);
    if (!TEST_ptr(dec))
        goto end;
    if (encrypt) {
        if (!TEST_true(OSSL_DECODER_CTX_set_passphrase(dec, (const unsigned char *)"wrong", 5)))
            goto end;
        at = data;
        left = len;
        if (!TEST_false(OSSL_DECODER_from_data(dec, &at, &left)) || !TEST_ptr_null(recovered))
            goto end;
        ERR_clear_error();
        if (!TEST_true(OSSL_DECODER_CTX_set_passphrase(dec, (const unsigned char *)"test", 4)))
            goto end;
    }
    at = data;
    left = len;
    if (!TEST_true(OSSL_DECODER_from_data(dec, &at, &left))
        || !TEST_size_t_eq(left, 0) || !TEST_ptr(recovered)
        || !TEST_int_eq(EVP_PKEY_eq(key, recovered), 1))
        goto end;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        unsigned char original[FN_DSA_SEED_BYTES], restored[FN_DSA_SEED_BYTES];
        size_t n, m;
        if (!TEST_true(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_FN_DSA_SEED, original, sizeof(original), &n))
            || !TEST_true(EVP_PKEY_get_octet_string_param(recovered, OSSL_PKEY_PARAM_FN_DSA_SEED, restored, sizeof(restored), &m))
            || !TEST_mem_eq(original, n, restored, m))
            goto end;
        OPENSSL_cleanse(original, sizeof(original));
        OPENSSL_cleanse(restored, sizeof(restored));
    } else {
        size_t n;
        if (!TEST_false(EVP_PKEY_get_octet_string_param(recovered, OSSL_PKEY_PARAM_FN_DSA_SEED, NULL, 0, &n)))
            goto end;
        ERR_clear_error();
    }
    ok = 1;
end:
    OSSL_ENCODER_CTX_free(enc);
    OSSL_DECODER_CTX_free(dec);
    EVP_PKEY_free(recovered);
    OPENSSL_clear_free(data, len);
    return ok;
}

static int test_evp_seed(int idx)
{
    const FN_DSA_PARAMS *p = ossl_fn_dsa_params_get(types[idx]);
    EVP_PKEY *key = NULL, *same = NULL, *copy = NULL, *bad = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *exported = NULL;
    OSSL_ENCODER_CTX *enc = NULL;
    unsigned char *unexpected = NULL;
    size_t unexpected_len = 0, seedlen;
    const OSSL_PARAM *pub, *priv;
    unsigned char seed[FN_DSA_SEED_BYTES];
    OSSL_PARAM params[2];
    int ok = 0;

    memset(seed, idx + 9, sizeof(seed));
    if (!TEST_ptr(key = from_seed(p->alg, seed, sizeof(seed), NULL, 0, NULL, 0))
        || !TEST_ptr(copy = EVP_PKEY_dup(key)) || !TEST_int_eq(EVP_PKEY_eq(key, copy), 1)
        || !TEST_true(EVP_PKEY_todata(copy, EVP_PKEY_KEYPAIR, &exported))
        || !TEST_ptr(OSSL_PARAM_locate_const(exported, OSSL_PKEY_PARAM_FN_DSA_SEED))
        || !TEST_ptr(pub = OSSL_PARAM_locate_const(exported, OSSL_PKEY_PARAM_PUB_KEY))
        || !TEST_ptr(priv = OSSL_PARAM_locate_const(exported, OSSL_PKEY_PARAM_PRIV_KEY)))
        goto end;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, idx == 0 ? "id-alg-fndsa512" : "FNDSA1024", NULL);
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, seed, sizeof(seed));
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(ctx) || !TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_params(ctx, params), 0)
        || !TEST_int_gt(EVP_PKEY_generate(ctx, &same), 0)
        || !TEST_int_eq(EVP_PKEY_eq(key, same), 1))
        goto end;
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (!TEST_ptr(ctx) || !TEST_int_gt(EVP_PKEY_pairwise_check(ctx), 0)
        || !TEST_true(evp_roundtrip(key, "DER", "PrivateKeyInfo", EVP_PKEY_KEYPAIR, 0))
        || !TEST_true(evp_roundtrip(key, "PEM", "PrivateKeyInfo", EVP_PKEY_KEYPAIR, 0))
        || !TEST_true(evp_roundtrip(key, "DER", "EncryptedPrivateKeyInfo", EVP_PKEY_KEYPAIR, 1))
        || !TEST_true(evp_roundtrip(key, "PEM", "EncryptedPrivateKeyInfo", EVP_PKEY_KEYPAIR, 1))
        || !TEST_true(evp_roundtrip(key, "DER", "SubjectPublicKeyInfo", EVP_PKEY_PUBLIC_KEY, 0)))
        goto end;
    seed[0] ^= 1;
    if (!TEST_ptr_null(bad = from_seed(p->alg, seed, sizeof(seed), pub->data, pub->data_size, NULL, 0)))
        goto end;
    ERR_clear_error();
    if (!TEST_ptr_null(bad = from_seed(p->alg, seed, sizeof(seed), NULL, 0, priv->data, priv->data_size)))
        goto end;
    ERR_clear_error();
    if (!TEST_ptr_null(bad = from_seed(p->alg, seed, sizeof(seed) - 1, NULL, 0, NULL, 0)))
        goto end;
    ERR_clear_error();
    OSSL_PARAM_free(exported);
    exported = NULL;
    if (!TEST_true(EVP_PKEY_todata(key, EVP_PKEY_PUBLIC_KEY, &exported))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(exported, OSSL_PKEY_PARAM_FN_DSA_SEED))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(exported, OSSL_PKEY_PARAM_PRIV_KEY)))
        goto end;
    enc = OSSL_ENCODER_CTX_new_for_pkey(key, EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", NULL);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_OUTPUT_FORMATS,
        "priv-only", 0);
    if (!TEST_ptr(enc) || !TEST_true(OSSL_ENCODER_CTX_set_params(enc, params))
        || !TEST_false(OSSL_ENCODER_to_data(enc, &unexpected, &unexpected_len))
        || !TEST_ptr_null(unexpected))
        goto end;
    ERR_clear_error();
    EVP_PKEY_free(same);
    same = EVP_PKEY_Q_keygen(NULL, NULL, p->alg);
    if (!TEST_ptr(same)
        || !TEST_true(EVP_PKEY_get_octet_string_param(same, OSSL_PKEY_PARAM_FN_DSA_SEED,
                         seed, sizeof(seed), &seedlen))
        || !TEST_size_t_eq(seedlen, sizeof(seed)))
        goto end;
    EVP_PKEY_free(copy);
    copy = from_seed(p->alg, seed, seedlen, NULL, 0, NULL, 0);
    if (!TEST_ptr(copy) || !TEST_int_eq(EVP_PKEY_eq(same, copy), 1))
        goto end;
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_PKEY_free(same);
    EVP_PKEY_free(copy);
    EVP_PKEY_free(bad);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(exported);
    OSSL_ENCODER_CTX_free(enc);
    OPENSSL_clear_free(unexpected, unexpected_len);
    OPENSSL_cleanse(seed, sizeof(seed));
    return ok;
}

static int private_equal(EVP_PKEY *a, EVP_PKEY *b)
{
    unsigned char first[2305], second[2305];
    size_t n = 0, m = 0;
    int ok = EVP_PKEY_get_octet_string_param(a, OSSL_PKEY_PARAM_PRIV_KEY, first, sizeof(first), &n) > 0
        && EVP_PKEY_get_octet_string_param(b, OSSL_PKEY_PARAM_PRIV_KEY, second, sizeof(second), &m) > 0
        && n == m && CRYPTO_memcmp(first, second, n) == 0;

    OPENSSL_cleanse(first, sizeof(first));
    OPENSSL_cleanse(second, sizeof(second));
    return ok;
}

static int test_gen_seed(int idx)
{
    const FN_DSA_PARAMS *p = ossl_fn_dsa_params_get(types[idx]);
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *first = NULL, *second = NULL, *random = NULL, *changed = NULL;
    unsigned char seed[FN_DSA_SEED_BYTES + 1] = { 0 }, retained[FN_DSA_SEED_BYTES];
    OSSL_PARAM params[2];
    const OSSL_PARAM *settable;
    size_t n;
    int ok = 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, seed, FN_DSA_SEED_BYTES);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, p->alg, NULL))
        || !TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        || !TEST_ptr(settable = EVP_PKEY_CTX_settable_params(ctx))
        || !TEST_ptr(OSSL_PARAM_locate_const(settable, OSSL_PKEY_PARAM_FN_DSA_SEED))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_DETERMINISTIC))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_TEST_ENTROPY))
        || !TEST_int_gt(EVP_PKEY_CTX_set_params(ctx, params), 0))
        goto end;
    seed[0] = 1; /* The generator must have copied the supplied all-zero seed. */
    if (!TEST_int_gt(EVP_PKEY_generate(ctx, &first), 0)
        || !TEST_true(EVP_PKEY_get_octet_string_param(first, OSSL_PKEY_PARAM_FN_DSA_SEED,
                         retained, sizeof(retained), &n))
        || !TEST_size_t_eq(n, FN_DSA_SEED_BYTES)
        || !TEST_uchar_eq(retained[0], 0)
        || !TEST_int_gt(EVP_PKEY_generate(ctx, &second), 0)
        || !TEST_int_eq(EVP_PKEY_eq(first, second), 1)
        || !TEST_true(private_equal(first, second)))
        goto end;
    params[0].data_size = FN_DSA_SEED_BYTES - 1;
    if (!TEST_int_le(EVP_PKEY_CTX_set_params(ctx, params), 0))
        goto end;
    params[0].data_size = FN_DSA_SEED_BYTES + 1;
    if (!TEST_int_le(EVP_PKEY_CTX_set_params(ctx, params), 0))
        goto end;
    EVP_PKEY_free(second);
    second = NULL;
    if (!TEST_int_gt(EVP_PKEY_generate(ctx, &second), 0)
        || !TEST_true(private_equal(first, second)))
        goto end;
    params[0].data_size = FN_DSA_SEED_BYTES;
    if (!TEST_int_gt(EVP_PKEY_CTX_set_params(ctx, params), 0)
        || !TEST_int_gt(EVP_PKEY_generate(ctx, &changed), 0)
        || !TEST_int_eq(EVP_PKEY_eq(first, changed), 0))
        goto end;
    /* Like ML-DSA, an empty generation seed restores random generation. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_FN_DSA_SEED, NULL, 0);
    if (!TEST_int_gt(EVP_PKEY_CTX_set_params(ctx, params), 0)
        || !TEST_int_gt(EVP_PKEY_generate(ctx, &random), 0)
        || !TEST_int_eq(EVP_PKEY_eq(changed, random), 0))
        goto end;
    EVP_PKEY_free(second);
    second = NULL;
    if (!TEST_int_gt(EVP_PKEY_generate(ctx, &second), 0)
        || !TEST_int_eq(EVP_PKEY_eq(random, second), 0)
        || !TEST_true(EVP_PKEY_get_octet_string_param(random, OSSL_PKEY_PARAM_FN_DSA_SEED,
                         retained, sizeof(retained), &n)))
        goto end;
    EVP_PKEY_free(second);
    second = from_seed(p->alg, retained, n, NULL, 0, NULL, 0);
    if (!TEST_ptr(second) || !TEST_true(private_equal(random, second)))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(first);
    EVP_PKEY_free(second);
    EVP_PKEY_free(random);
    EVP_PKEY_free(changed);
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(retained, sizeof(retained));
    return ok;
}

static const char *names[] = { "FN-DSA-512", "FN-DSA-1024" };
static const unsigned char message[] = "64.64 fixed-point Gaussian signing";

static int verify_once(EVP_MD_CTX *ctx, EVP_PKEY *key,
    const unsigned char *sig, size_t siglen, const unsigned char *msg, size_t msglen)
{
    if (!EVP_MD_CTX_reset(ctx)
        || EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, key, NULL) <= 0)
        return -1;
    return EVP_DigestVerify(ctx, sig, siglen, msg, msglen);
}

static int test_signature(int idx)
{
    EVP_PKEY *key = NULL, *pub = NULL, *wrong = NULL;
    EVP_MD_CTX *s = NULL, *v = NULL, *bad = NULL;
    EVP_PKEY_CTX *ps = NULL, *pv = NULL;
    EVP_SIGNATURE *alg = NULL, *other = NULL;
    unsigned char sig[1330], second[1330], aid[32], small[8], sentinel[8];
    unsigned char *spki = NULL;
    const unsigned char *at;
    X509_ALGOR *aid_alg = NULL;
    const ASN1_OBJECT *oid;
    OSSL_PARAM params[2];
    size_t siglen = sizeof(sig), secondlen = sizeof(second), n;
    int spkilen, ptype, ok = 0;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, names[idx]))
        || !TEST_ptr(wrong = EVP_PKEY_Q_keygen(NULL, NULL, names[idx]))
        || !TEST_int_eq(EVP_PKEY_eq(key, wrong), 0)
        || !TEST_int_gt(spkilen = i2d_PUBKEY(key, &spki), 0))
        goto end;
    at = spki;
    if (!TEST_ptr(pub = d2i_PUBKEY(NULL, &at, spkilen))
        || !TEST_ptr(s = EVP_MD_CTX_new()) || !TEST_ptr(v = EVP_MD_CTX_new())
        || !TEST_ptr(bad = EVP_MD_CTX_new())
        || !TEST_int_gt(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, NULL), 0))
        goto end;
    n = 0;
    if (!TEST_int_gt(EVP_DigestSign(s, NULL, &n, message, sizeof(message) - 1), 0)
        || !TEST_size_t_eq(n, (size_t)EVP_PKEY_get_size(key))
        || !TEST_int_gt(EVP_DigestSign(s, sig, &siglen, message, sizeof(message) - 1), 0)
        || !TEST_int_gt(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, NULL), 0)
        || !TEST_int_gt(EVP_DigestSign(s, second, &secondlen, message, sizeof(message) - 1), 0)
        || !TEST_true(siglen != secondlen || CRYPTO_memcmp(sig, second, siglen) != 0)
        || !TEST_int_eq(verify_once(v, pub, sig, siglen, message, sizeof(message) - 1), 1)
        || !TEST_int_eq(verify_once(v, pub, second, secondlen, message, sizeof(message) - 1), 1)
        || !TEST_int_eq(verify_once(v, pub, sig, siglen, message, sizeof(message) - 2), 0))
        goto end;
    sig[0] ^= 1;
    if (!TEST_int_eq(verify_once(v, pub, sig, siglen, message, sizeof(message) - 1), 0))
        goto end;
    sig[0] ^= 1;
    if (!TEST_int_eq(verify_once(v, pub, sig, siglen - 1, message, sizeof(message) - 1), 0)
        || !TEST_int_eq(verify_once(v, wrong, sig, siglen, message, sizeof(message) - 1), 0))
        goto end;
    ERR_clear_error();
    if (!TEST_int_le(EVP_DigestSignInit_ex(bad, NULL, NULL, NULL, NULL, pub, NULL), 0)
        || !TEST_true(EVP_MD_CTX_reset(bad))
        || !TEST_int_le(EVP_DigestSignInit_ex(bad, NULL, "SHA256", NULL, NULL, key, NULL), 0))
        goto end;
    ERR_clear_error();
    if (!TEST_ptr(ps = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL))
        || !TEST_ptr(pv = EVP_PKEY_CTX_new_from_pkey(NULL, pub, NULL))
        || !TEST_ptr(alg = EVP_SIGNATURE_fetch(NULL,
                         idx == 0 ? "2.16.840.1.101.3.4.3.50" : "id-alg-fndsa1024", "provider=default"))
        || !TEST_int_gt(EVP_PKEY_sign_message_init(ps, alg, NULL), 0))
        goto end;
    memset(small, 0xa5, sizeof(small));
    memcpy(sentinel, small, sizeof(small));
    n = sizeof(small);
    if (!TEST_int_le(EVP_PKEY_sign(ps, small, &n, message, sizeof(message) - 1), 0)
        || !TEST_mem_eq(small, sizeof(small), sentinel, sizeof(sentinel)))
        goto end;
    ERR_clear_error();
    siglen = sizeof(sig);
    if (!TEST_int_gt(EVP_PKEY_sign(ps, sig, &siglen, message, sizeof(message) - 1), 0)
        || !TEST_int_gt(EVP_PKEY_verify_message_init(pv, alg, NULL), 0)
        || !TEST_int_eq(EVP_PKEY_verify(pv, sig, siglen, message, sizeof(message) - 1), 1))
        goto end;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, aid, sizeof(aid));
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_int_gt(EVP_PKEY_CTX_get_params(ps, params), 0))
        goto end;
    at = aid;
    if (!TEST_ptr(aid_alg = d2i_X509_ALGOR(NULL, &at, (long)params[0].return_size)))
        goto end;
    X509_ALGOR_get0(&oid, &ptype, NULL, aid_alg);
    if (!TEST_int_eq(OBJ_obj2nid(oid), idx == 0 ? EVP_PKEY_FN_DSA_512 : EVP_PKEY_FN_DSA_1024)
        || !TEST_int_eq(ptype, V_ASN1_UNDEF))
        goto end;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, aid, 256);
    if (!TEST_int_le(EVP_PKEY_CTX_set_params(ps, params), 0))
        goto end;
    ERR_clear_error();
    siglen = sizeof(sig);
    if (!TEST_int_gt(EVP_PKEY_sign_message_init(ps, alg, NULL), 0)
        || !TEST_int_gt(EVP_PKEY_sign(ps, sig, &siglen, NULL, 0), 0)
        || !TEST_int_gt(EVP_PKEY_verify_message_init(pv, alg, NULL), 0)
        || !TEST_int_eq(EVP_PKEY_verify(pv, sig, siglen, NULL, 0), 1))
        goto end;
    if (!TEST_ptr(other = EVP_SIGNATURE_fetch(NULL, names[1 - idx], NULL))
        || !TEST_int_le(EVP_PKEY_sign_message_init(ps, other, NULL), 0))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(wrong);
    EVP_MD_CTX_free(s);
    EVP_MD_CTX_free(v);
    EVP_MD_CTX_free(bad);
    EVP_PKEY_CTX_free(ps);
    EVP_PKEY_CTX_free(pv);
    EVP_SIGNATURE_free(alg);
    EVP_SIGNATURE_free(other);
    X509_ALGOR_free(aid_alg);
    OPENSSL_free(spki);
    return ok;
}

static int test_streaming(int idx)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *s = NULL, *copy = NULL, *v = NULL;
    EVP_PKEY_CTX *ps = NULL, *pv = NULL;
    EVP_SIGNATURE *alg = NULL;
    unsigned char sig[1330], second[1330];
    size_t siglen = sizeof(sig), secondlen = sizeof(second);
    OSSL_PARAM params[2];
    unsigned char context[] = { 's', 0, 't' };
    OSSL_PARAM context_params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, sizeof(context)),
        OSSL_PARAM_END
    };
    int ok = 0;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, names[idx]))
        || !TEST_ptr(s = EVP_MD_CTX_new()) || !TEST_ptr(copy = EVP_MD_CTX_new())
        || !TEST_ptr(v = EVP_MD_CTX_new())
        || !TEST_int_gt(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, context_params), 0)
        || !TEST_int_gt(EVP_DigestSignUpdate(s, message, 3), 0)
        || !TEST_int_gt(EVP_MD_CTX_copy_ex(copy, s), 0)
        || !TEST_int_le(EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(copy), context_params), 0)
        || !TEST_int_gt(EVP_DigestSignUpdate(s, message + 3, sizeof(message) - 4), 0)
        || !TEST_int_gt(EVP_DigestSignUpdate(copy, message + 3, sizeof(message) - 4), 0)
        || !TEST_int_gt(EVP_DigestSignFinal(s, sig, &siglen), 0)
        || !TEST_int_gt(EVP_DigestSignFinal(copy, second, &secondlen), 0)
        || !TEST_int_gt(EVP_DigestVerifyInit_ex(v, NULL, NULL, NULL, NULL, key, context_params), 0)
        || !TEST_int_gt(EVP_DigestVerifyUpdate(v, message, sizeof(message) - 1), 0)
        || !TEST_int_eq(EVP_DigestVerifyFinal(v, sig, siglen), 1)
        || !TEST_int_eq(EVP_DigestVerifyFinal(v, second, secondlen), 1))
        goto end;
    if (!TEST_ptr(alg = EVP_SIGNATURE_fetch(NULL, names[idx], NULL))
        || !TEST_ptr(ps = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL))
        || !TEST_ptr(pv = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL))
        || !TEST_int_gt(EVP_PKEY_sign_message_init(ps, alg, context_params), 0)
        || !TEST_int_gt(EVP_PKEY_sign_message_update(ps, message, sizeof(message) - 1), 0))
        goto end;
    siglen = sizeof(sig);
    if (!TEST_int_gt(EVP_PKEY_sign_message_final(ps, sig, &siglen), 0))
        goto end;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_SIGNATURE, sig, siglen);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_int_gt(EVP_PKEY_verify_message_init(pv, alg, context_params), 0)
        || !TEST_int_gt(EVP_PKEY_verify_message_update(pv, message, sizeof(message) - 1), 0)
        || !TEST_int_gt(EVP_PKEY_CTX_set_params(pv, params), 0)
        || !TEST_int_eq(EVP_PKEY_verify_message_final(pv), 1))
        goto end;
    if (!TEST_int_gt(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, NULL), 0)
        || !TEST_int_gt(EVP_DigestSignUpdate(s, message, 1), 0)
        || !TEST_int_le(EVP_DigestSignUpdate(s, message, SIZE_MAX), 0)
        || !TEST_int_le(EVP_DigestSignFinal(s, sig, &siglen), 0))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(s);
    EVP_MD_CTX_free(copy);
    EVP_MD_CTX_free(v);
    EVP_PKEY_CTX_free(ps);
    EVP_PKEY_CTX_free(pv);
    EVP_SIGNATURE_free(alg);
    return ok;
}

/* Check the framed bytes against the raw backend, independently of the
 * provider's matching signing/verification wrappers.
 */
static int test_message_encoding(int idx)
{
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *s = NULL, *v = NULL;
    unsigned char context[256], encoded[257 + sizeof(message) - 1];
    unsigned char pub[1793], sig[1330];
    const size_t lengths[] = { 0, 1, 255 };
    size_t publen, siglen, encodedlen, i, j, len;
    OSSL_PARAM params[2];
    int ok = 0;

    for (i = 0; i < sizeof(context); i++)
        context[i] = (unsigned char)i;
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, names[idx]))
        || !TEST_ptr(s = EVP_MD_CTX_new()) || !TEST_ptr(v = EVP_MD_CTX_new())
        || !TEST_int_gt(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                           pub, sizeof(pub), &publen), 0))
        goto end;
    for (j = 0; j < OSSL_NELEM(lengths); j++) {
        len = lengths[j];
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, len);
        siglen = sizeof(sig);
        if (!TEST_int_gt(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0)
            || !TEST_int_gt(EVP_DigestSign(s, sig, &siglen, message, sizeof(message) - 1), 0)
            || !TEST_int_gt(EVP_DigestVerifyInit_ex(v, NULL, NULL, NULL, NULL, key, params), 0)
            || !TEST_int_eq(EVP_DigestVerify(v, sig, siglen, message, sizeof(message) - 1), 1))
            goto end;
        encoded[0] = 0;
        encoded[1] = (unsigned char)len;
        memcpy(encoded + 2, context, len);
        memcpy(encoded + 2 + len, message, sizeof(message) - 1);
        encodedlen = 2 + len + sizeof(message) - 1;
        if (!TEST_int_eq(ossl_fn_dsa_core_verify(NULL, 9 + idx, pub, publen,
                             encoded, encodedlen, sig, siglen), 1)
            || !TEST_int_eq(ossl_fn_dsa_core_verify(NULL, 9 + idx, pub, publen,
                                message, sizeof(message) - 1, sig, siglen), 0))
            goto end;
        encoded[0] = 1;
        if (!TEST_int_eq(ossl_fn_dsa_core_verify(NULL, 9 + idx, pub, publen,
                             encoded, encodedlen, sig, siglen), 0))
            goto end;
        encoded[0] = 0;
        encoded[1] ^= 1;
        if (!TEST_int_eq(ossl_fn_dsa_core_verify(NULL, 9 + idx, pub, publen,
                             encoded, encodedlen, sig, siglen), 0))
            goto end;
        context[0] ^= 1;
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, len == 0 ? 1 : len);
        if (!TEST_int_gt(EVP_DigestVerifyInit_ex(v, NULL, NULL, NULL, NULL, key, params), 0)
            || !TEST_int_eq(EVP_DigestVerify(v, sig, siglen, message, sizeof(message) - 1), 0))
            goto end;
        context[0] ^= 1;
    }
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, sizeof(context));
    if (!TEST_int_le(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0)
        || !TEST_int_le(EVP_DigestVerifyInit_ex(v, NULL, NULL, NULL, NULL, key, params), 0))
        goto end;
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (char *)context, 1);
    if (!TEST_int_le(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0))
        goto end;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 1);
    if (!TEST_int_le(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_MD_CTX_free(s);
    EVP_MD_CTX_free(v);
    return ok;
}

#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
static int sign_with_params(EVP_MD_CTX *ctx, EVP_PKEY *key, OSSL_PARAM params[],
    int stream, const unsigned char *msg, size_t msglen,
    unsigned char *sig, size_t *siglen)
{
    size_t n = 0;

    if (!EVP_MD_CTX_reset(ctx)
        || EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, key, params) <= 0)
        return 0;
    if (stream)
        return EVP_DigestSignUpdate(ctx, msg, msglen / 2) > 0
            && EVP_DigestSignUpdate(ctx, msg + msglen / 2, msglen - msglen / 2) > 0
            && EVP_DigestSignFinal(ctx, NULL, &n) > 0
            && n == (size_t)EVP_PKEY_get_size(key)
            && EVP_DigestSignFinal(ctx, sig, siglen) > 0;
    return EVP_DigestSign(ctx, NULL, &n, msg, msglen) > 0
        && n == (size_t)EVP_PKEY_get_size(key)
        && EVP_DigestSign(ctx, sig, siglen, msg, msglen) > 0;
}

static int test_entropy(int idx)
{
    EVP_PKEY *key = NULL, *copy = NULL, *restored = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    EVP_MD_CTX *s = NULL, *v = NULL;
    unsigned char sig[1330], second[1330], entropy[89], context[] = { 'c', 0, 'x' };
    size_t siglen = sizeof(sig), secondlen, i;
    int ok = 0;
    OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, sizeof(context)),
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, 88),
        OSSL_PARAM_END
    };
    OSSL_PARAM verify_params[] = {
        OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, sizeof(context)),
        OSSL_PARAM_END
    };

    for (i = 0; i < sizeof(entropy); i++)
        entropy[i] = (unsigned char)i;
    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, names[idx]))
        || !TEST_ptr(copy = EVP_PKEY_dup(key))
        || !TEST_ptr(p8 = EVP_PKEY2PKCS8(key))
        || !TEST_ptr(restored = EVP_PKCS82PKEY(p8))
        || !TEST_ptr(s = EVP_MD_CTX_new()) || !TEST_ptr(v = EVP_MD_CTX_new())
        || !TEST_true(sign_with_params(s, key, params, 0, message, sizeof(message) - 1, sig, &siglen))
        || !TEST_mem_eq(sig + 1, 40, entropy, 40))
        goto end;
    for (i = 0; i < 3; i++) {
        secondlen = sizeof(second);
        if (!TEST_true(sign_with_params(s, i == 0 ? key : i == 1 ? copy : restored,
                           params, i != 0, message, sizeof(message) - 1, second, &secondlen))
            || !TEST_mem_eq(sig, siglen, second, secondlen))
            goto end;
    }
    if (!TEST_int_gt(EVP_DigestVerifyInit_ex(v, NULL, NULL, NULL, NULL, key, verify_params), 0)
        || !TEST_int_eq(EVP_DigestVerify(v, sig, siglen, message, sizeof(message) - 1), 1))
        goto end;
    entropy[40] ^= 1; /* Change the private sampler seed, keeping the nonce. */
    secondlen = sizeof(second);
    if (!TEST_true(sign_with_params(s, key, params, 0, message, sizeof(message) - 1, second, &secondlen))
        || !TEST_true(siglen != secondlen || CRYPTO_memcmp(sig, second, siglen) != 0)
        || !TEST_mem_eq(second + 1, 40, entropy, 40)
        || !TEST_true(EVP_MD_CTX_reset(v))
        || !TEST_int_gt(EVP_DigestVerifyInit_ex(v, NULL, NULL, NULL, NULL, key, verify_params), 0)
        || !TEST_int_eq(EVP_DigestVerify(v, second, secondlen, message, sizeof(message) - 1), 1))
        goto end;
    for (i = 87; i <= 89; i += 2) {
        params[1].data_size = i;
        if (!TEST_true(EVP_MD_CTX_reset(s))
            || !TEST_int_le(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0))
            goto end;
    }
    params[1] = OSSL_PARAM_construct_utf8_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, "bad", 0);
    if (!TEST_true(EVP_MD_CTX_reset(s))
        || !TEST_int_le(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0))
        goto end;
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, 88);
    if (!TEST_true(EVP_MD_CTX_reset(s))
        || !TEST_int_gt(EVP_DigestSignInit_ex(s, NULL, NULL, NULL, NULL, key, params), 0)
        || !TEST_int_gt(EVP_DigestSignUpdate(s, message, 1), 0)
        || !TEST_int_le(EVP_PKEY_CTX_set_params(EVP_MD_CTX_get_pkey_ctx(s), params), 0))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_PKEY_free(copy);
    EVP_PKEY_free(restored);
    PKCS8_PRIV_KEY_INFO_free(p8);
    EVP_MD_CTX_free(s);
    EVP_MD_CTX_free(v);
    OPENSSL_cleanse(entropy, sizeof(entropy));
    return ok;
}
#endif

static int test_signing_controls(int idx)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *alg = NULL;
    const OSSL_PARAM *settable;
    unsigned char entropy[88] = { 0 };
    int deterministic = 1, ok = 0;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &deterministic);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, names[idx]))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL))
        || !TEST_ptr(alg = EVP_SIGNATURE_fetch(NULL, names[idx], NULL))
        || !TEST_int_gt(EVP_PKEY_sign_message_init(ctx, alg, NULL), 0)
        || !TEST_ptr(settable = EVP_PKEY_CTX_settable_params(ctx))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_DETERMINISTIC))
        || !TEST_int_le(EVP_PKEY_CTX_set_params(ctx, params), 0))
        goto end;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, entropy, sizeof(entropy));
#ifdef OPENSSL_NO_FN_DSA_TEST_ENTROPY
    if (!TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_TEST_ENTROPY))
        || !TEST_int_le(EVP_PKEY_CTX_set_params(ctx, params), 0)
        || !TEST_int_le(EVP_PKEY_sign_message_init(ctx, alg, params), 0))
        goto end;
#else
    if (!TEST_ptr(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_TEST_ENTROPY)))
        goto end;
#endif
    if (!TEST_int_gt(EVP_PKEY_verify_message_init(ctx, alg, NULL), 0)
        || !TEST_ptr(settable = EVP_PKEY_CTX_settable_params(ctx))
        || !TEST_ptr_null(OSSL_PARAM_locate_const(settable, OSSL_SIGNATURE_PARAM_TEST_ENTROPY))
        || !TEST_int_le(EVP_PKEY_CTX_set_params(ctx, params), 0))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(alg);
    OPENSSL_cleanse(entropy, sizeof(entropy));
    return ok;
}

#define CODEC_CHECK(condition) \
    do { \
        if (!TEST_true(condition)) \
            goto end; \
    } while (0)

static int test_codecs(int idx)
{
    unsigned logn = 9 + idx;
    unsigned char pub[MAX_FN_DSA_PUB_LEN], decoded[MAX_FN_DSA_PUB_LEN];
    unsigned char seed[FN_DSA_SEED_BYTES], recovered[FN_DSA_SEED_BYTES];
    unsigned char *der = NULL, *private_der = NULL, *mutated = NULL;
    const unsigned char *at, *raw;
    PKCS8_PRIV_KEY_INFO *p8 = NULL, *decrypted = NULL;
    X509_SIG *encrypted = NULL;
    X509_PUBKEY *spki = NULL;
    X509_ALGOR *alg;
    ASN1_OBJECT *obj;
    int derlen = 0, private_len = 0, length, changed = 0, ret = 0;
    size_t publen = logn == 9 ? FN_DSA_512_PUB_LEN : FN_DSA_1024_PUB_LEN, i;
    for (i = 0; i < publen; i++)
        pub[i] = (unsigned char)(i * 3 + logn);
    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (unsigned char)(i * 7 + logn);
    CODEC_CHECK((derlen = ossl_fn_dsa_i2d_PUBKEY_data(pub, publen, logn, &der)) > 0);
    CODEC_CHECK(ossl_fn_dsa_d2i_PUBKEY_data(der, derlen, logn, decoded, publen));
    CODEC_CHECK(CRYPTO_memcmp(pub, decoded, publen) == 0);
    CODEC_CHECK(!ossl_fn_dsa_d2i_PUBKEY_data(der, derlen, logn == 9 ? 10 : 9, decoded,
                                  publen));
    for (i = 0; i < (size_t)derlen; i++)
        CODEC_CHECK(!ossl_fn_dsa_d2i_PUBKEY_data(der, (long)i, logn, decoded, publen));
    ERR_clear_error();
    mutated = OPENSSL_malloc((size_t)derlen + 1);
    CODEC_CHECK(mutated);
    memcpy(mutated, der, (size_t)derlen);
    mutated[derlen] = 0;
    CODEC_CHECK(!ossl_fn_dsa_d2i_PUBKEY_data(mutated, derlen + 1, logn, decoded, publen));
    mutated[derlen - (int)publen - 1] = 1;
    mutated[derlen - 1] &= 0xfe;
    CODEC_CHECK(!ossl_fn_dsa_d2i_PUBKEY_data(mutated, derlen, logn, decoded, publen));
    OPENSSL_free(mutated);
    mutated = NULL;
    at = der;
    spki = d2i_X509_PUBKEY(NULL, &at, derlen);
    CODEC_CHECK(spki);
    CODEC_CHECK(X509_PUBKEY_get0_param(&obj, NULL, NULL, &alg, spki));
    CODEC_CHECK(OBJ_obj2nid(obj) == (logn == 9 ? EVP_PKEY_FN_DSA_512
                                      : EVP_PKEY_FN_DSA_1024));
    X509_ALGOR_set0(alg, OBJ_dup(obj), V_ASN1_NULL, NULL);
    CODEC_CHECK((changed = i2d_X509_PUBKEY(spki, &mutated)) > 0);
    CODEC_CHECK(!ossl_fn_dsa_d2i_PUBKEY_data(mutated, changed, logn, decoded, publen));
    OPENSSL_free(mutated);
    mutated = NULL;
    CODEC_CHECK((private_len = ossl_fn_dsa_i2d_PKCS8_data(seed, sizeof(seed), logn,
                                               &private_der)) > 0);
    CODEC_CHECK(ossl_fn_dsa_d2i_PKCS8_data(private_der, private_len, logn, recovered,
                                sizeof(recovered)));
    CODEC_CHECK(CRYPTO_memcmp(seed, recovered, sizeof(seed)) == 0);
    CODEC_CHECK(!ossl_fn_dsa_d2i_PKCS8_data(private_der, private_len, logn == 9 ? 10 : 9,
                                 recovered, sizeof(recovered)));
    for (i = 0; i < (size_t)private_len; i++)
        CODEC_CHECK(!ossl_fn_dsa_d2i_PKCS8_data(private_der, (long)i, logn, recovered,
                                     sizeof(recovered)));
    ERR_clear_error();
    at = private_der;
    p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &at, private_len);
    CODEC_CHECK(p8);
    CODEC_CHECK(PKCS8_pkey_get0((const ASN1_OBJECT **)&obj, &raw, &length, NULL, p8)
          && length == 32);
    CODEC_CHECK(OBJ_obj2nid(obj) == (logn == 9 ? EVP_PKEY_FN_DSA_512
                                      : EVP_PKEY_FN_DSA_1024));
    CODEC_CHECK(CRYPTO_memcmp(raw, seed, 32) == 0);
    encrypted =
        PKCS8_encrypt(-1, EVP_aes_256_cbc(), "test", 4, NULL, 0, 10000, p8);
    CODEC_CHECK(encrypted);
    CODEC_CHECK(PKCS8_decrypt(encrypted, "wrong", 5) == NULL);
    ERR_clear_error();
    decrypted = PKCS8_decrypt(encrypted, "test", 4);
    CODEC_CHECK(decrypted);
    CODEC_CHECK(PKCS8_pkey_get0(NULL, &raw, &length, NULL, decrypted) &&
          length == 32);
    CODEC_CHECK(CRYPTO_memcmp(raw, seed, 32) == 0);
    /* Reject a nested seed OCTET STRING and an expanded FN-DSA private key. */
    {
        unsigned char legacy[2305] = {0};
        ASN1_OBJECT *oid;
        const X509_ALGOR *palg;
        CODEC_CHECK(
            PKCS8_pkey_get0((const ASN1_OBJECT **)&obj, NULL, NULL, &palg, p8));
        oid = OBJ_dup(obj);
        CODEC_CHECK(oid);
        CODEC_CHECK(PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL,
                              OPENSSL_memdup(legacy, logn == 9 ? 1281 : 2305),
                              logn == 9 ? 1281 : 2305));
        CODEC_CHECK((changed = i2d_PKCS8_PRIV_KEY_INFO(p8, &mutated)) > 0);
        CODEC_CHECK(!ossl_fn_dsa_d2i_PKCS8_data(mutated, changed, logn, recovered,
                                     sizeof(recovered)));
    }
    ERR_clear_error();
    fprintf(
        stderr,
        "PASS FN-DSA-%u raw public / seed PKCS8 codecs and malformed input\n",
        1u << logn);
    ret = 1;
end:
    OPENSSL_free(der);
    OPENSSL_clear_free(private_der, private_len > 0 ? (size_t)private_len : 0);
    OPENSSL_clear_free(mutated, mutated != NULL ? (size_t)changed : 0);
    X509_PUBKEY_free(spki);
    PKCS8_PRIV_KEY_INFO_free(p8);
    PKCS8_PRIV_KEY_INFO_free(decrypted);
    X509_SIG_free(encrypted);
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(recovered, sizeof(recovered));
    return ret;
}

/* Reuse fetched SHAKE after defaults change; explicit overrides still apply. */
static int test_digest_reuse(int idx)
{
    OSSL_LIB_CTX *libctx = NULL;
    FN_DSA_KEY *key = NULL, *copy = NULL, *regenerated = NULL;
    unsigned char seed[FN_DSA_SEED_BYTES], sig[FN_DSA_MAX_SIG];
    size_t siglen = sizeof(sig);
    int ok = 0;

    memset(seed, 0x51 + idx, sizeof(seed));
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(key = ossl_fn_dsa_key_new(libctx, NULL, types[idx]))
        || !TEST_true(ossl_fn_dsa_set_prekey(key, 0, 0, seed, sizeof(seed), NULL, 0))
        || !TEST_true(ossl_fn_dsa_generate_key(key))
        || !TEST_true(ossl_fn_dsa_sign(key, NULL, NULL, 0,
            message, sizeof(message) - 1, sig, &siglen, sizeof(sig)))
        || !TEST_true(EVP_set_default_properties(libctx, "provider=unavailable")))
        goto end;
    if (!TEST_true(ossl_fn_dsa_verify(key, NULL, NULL, 0,
            message, sizeof(message) - 1, sig, siglen))
        || !TEST_true(ossl_fn_dsa_key_pairwise_check(key))
        || !TEST_ptr(copy = ossl_fn_dsa_key_dup(key, EVP_PKEY_KEYPAIR))
        || !TEST_true(ossl_fn_dsa_verify(copy, NULL, NULL, 0,
            message, sizeof(message) - 1, sig, siglen))
        || !TEST_ptr(regenerated = ossl_fn_dsa_key_dup(key, 0))
        || !TEST_true(ossl_fn_dsa_set_prekey(regenerated, 0, 0,
            seed, sizeof(seed), NULL, 0))
        || !TEST_true(ossl_fn_dsa_generate_key(regenerated))
        || !TEST_true(ossl_fn_dsa_key_equal(key, regenerated, EVP_PKEY_KEYPAIR))
        || !TEST_false(ossl_fn_dsa_verify(key, "provider=unavailable", NULL, 0,
            message, sizeof(message) - 1, sig, siglen)))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    ossl_fn_dsa_key_free(regenerated);
    ossl_fn_dsa_key_free(copy);
    ossl_fn_dsa_key_free(key);
    OSSL_LIB_CTX_free(libctx);
    OPENSSL_cleanse(seed, sizeof(seed));
    return ok;
}

static int check_text(BIO *out, const char *algorithm, int private, int seed)
{
    char heading[80], *bytes, *text = NULL;
    long len;
    int ok = 0;

    snprintf(heading, sizeof(heading), "%s %s-Key:", algorithm,
        private ? "Private" : "Public");
    if (!TEST_long_gt(len = BIO_get_mem_data(out, &bytes), 0)
        || !TEST_ptr(text = OPENSSL_strndup(bytes, (size_t)len)))
        goto end;
    ok = TEST_ptr(strstr(text, heading))
        && TEST_ptr(strstr(text, "pub:"))
        && TEST_int_eq(strstr(text, "priv:") != NULL, private)
        && TEST_int_eq(strstr(text, "seed:") != NULL, seed);
end:
    OPENSSL_clear_free(text, text == NULL ? 0 : (size_t)len + 1);
    return ok;
}

static int test_text_encoder(int idx)
{
    EVP_PKEY *key = NULL, *public = NULL;
    FN_DSA_KEY *cached = NULL, *empty = NULL;
    OSSL_ENCODER_CTX *encoder = NULL;
    BIO *out = NULL;
    unsigned char seed[FN_DSA_SEED_BYTES], priv[2305], *der = NULL;
    const unsigned char *p;
    size_t privlen;
    int derlen, ok = 0;

    memset(seed, 0x35 + idx, sizeof(seed));
    if (!TEST_ptr(key = from_seed(names[idx], seed, sizeof(seed), NULL, 0, NULL, 0))
        || !TEST_ptr(out = BIO_new(BIO_s_mem()))
        || !TEST_int_gt(EVP_PKEY_print_private(out, key, 0, NULL), 0)
        || !check_text(out, names[idx], 1, 1)
        || !TEST_int_gt(BIO_reset(out), 0)
        || !TEST_int_gt(EVP_PKEY_print_public(out, key, 0, NULL), 0)
        || !check_text(out, names[idx], 0, 0))
        goto end;
    if (!TEST_int_gt(derlen = i2d_PUBKEY(key, &der), 0))
        goto end;
    p = der;
    if (!TEST_ptr(public = d2i_PUBKEY(NULL, &p, derlen))
        || !TEST_int_gt(BIO_reset(out), 0)
        || !TEST_int_gt(EVP_PKEY_print_public(out, public, 0, NULL), 0)
        || !check_text(out, names[idx], 0, 0)
        || !TEST_int_gt(BIO_reset(out), 0)
        || !TEST_int_le(EVP_PKEY_print_private(out, public, 0, NULL), 0))
        goto end;
    ERR_clear_error();
    if (!TEST_ptr(encoder = OSSL_ENCODER_CTX_new_for_pkey(key,
            EVP_PKEY_PUBLIC_KEY, "TEXT", NULL, NULL))
        || !TEST_int_gt(OSSL_ENCODER_CTX_get_num_encoders(encoder), 0)
        || !TEST_int_gt(BIO_reset(out), 0)
        || !TEST_true(OSSL_ENCODER_to_bio(encoder, out))
        || !check_text(out, names[idx], 0, 0)
        || !TEST_true(EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY,
            priv, sizeof(priv), &privlen))
        || !TEST_ptr(cached = ossl_fn_dsa_key_new(NULL, NULL, types[idx]))
        || !TEST_true(ossl_fn_dsa_sk_decode(cached, priv, privlen))
        || !TEST_int_gt(BIO_reset(out), 0)
        || !TEST_true(ossl_fn_dsa_key_to_text(out, cached, EVP_PKEY_KEYPAIR))
        || !check_text(out, names[idx], 1, 0)
        || !TEST_ptr(empty = ossl_fn_dsa_key_new(NULL, NULL, types[idx]))
        || !TEST_int_gt(BIO_reset(out), 0)
        || !TEST_false(ossl_fn_dsa_key_to_text(out, empty, EVP_PKEY_KEYPAIR))
        || !TEST_long_eq(BIO_ctrl_pending(out), 0)
        || !TEST_false(ossl_fn_dsa_key_to_text(out, cached, 0))
        || !TEST_false(ossl_fn_dsa_key_to_text(NULL, cached, EVP_PKEY_KEYPAIR)))
        goto end;
    ERR_clear_error();
    ok = 1;
end:
    ossl_fn_dsa_key_free(empty);
    ossl_fn_dsa_key_free(cached);
    OSSL_ENCODER_CTX_free(encoder);
    EVP_PKEY_free(public);
    EVP_PKEY_free(key);
    BIO_free(out);
    OPENSSL_free(der);
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(priv, sizeof(priv));
    return ok;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_key_seed, 2);
    ADD_ALL_TESTS(test_evp_seed, 2);
    ADD_ALL_TESTS(test_gen_seed, 2);
    ADD_ALL_TESTS(test_signature, 2);
    ADD_ALL_TESTS(test_streaming, 2);
    ADD_ALL_TESTS(test_message_encoding, 2);
    ADD_ALL_TESTS(test_signing_controls, 2);
    ADD_ALL_TESTS(test_codecs, 2);
    ADD_ALL_TESTS(test_digest_reuse, 2);
    ADD_ALL_TESTS(test_text_encoder, 2);
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
    ADD_ALL_TESTS(test_entropy, 2);
#endif
    return 1;
}
