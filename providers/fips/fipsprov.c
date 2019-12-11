/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

/* TODO(3.0): Needed for dummy_evp_call(). To be removed */
#include <openssl/sha.h>
#include <openssl/rand_drbg.h>
#include <openssl/ec.h>
#include <openssl/fips_names.h>

#include "internal/cryptlib.h"
#include "internal/property.h"
#include "internal/constant_time.h"
#include "crypto/evp.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "selftest.h"

extern OSSL_core_thread_start_fn *c_thread_start;

/*
 * TODO(3.0): Should these be stored in the provider side provctx? Could they
 * ever be different from one init to the next? Unfortunately we can't do this
 * at the moment because c_put_error/c_add_error_vdata do not provide
 * us with the OPENSSL_CTX as a parameter.
 */

static SELF_TEST_POST_PARAMS selftest_params;

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params;
static OSSL_core_get_params_fn *c_get_params;
OSSL_core_thread_start_fn *c_thread_start;
static OSSL_core_new_error_fn *c_new_error;
static OSSL_core_set_error_debug_fn *c_set_error_debug;
static OSSL_core_clear_last_error_consttime_fn *c_clear_last_error_consttime;
static OSSL_core_vset_error_fn *c_vset_error;
static OSSL_CRYPTO_malloc_fn *c_CRYPTO_malloc;
static OSSL_CRYPTO_zalloc_fn *c_CRYPTO_zalloc;
static OSSL_CRYPTO_free_fn *c_CRYPTO_free;
static OSSL_CRYPTO_clear_free_fn *c_CRYPTO_clear_free;
static OSSL_CRYPTO_realloc_fn *c_CRYPTO_realloc;
static OSSL_CRYPTO_clear_realloc_fn *c_CRYPTO_clear_realloc;
static OSSL_CRYPTO_secure_malloc_fn *c_CRYPTO_secure_malloc;
static OSSL_CRYPTO_secure_zalloc_fn *c_CRYPTO_secure_zalloc;
static OSSL_CRYPTO_secure_free_fn *c_CRYPTO_secure_free;
static OSSL_CRYPTO_secure_clear_free_fn *c_CRYPTO_secure_clear_free;
static OSSL_CRYPTO_secure_allocated_fn *c_CRYPTO_secure_allocated;
static OSSL_CRYPTO_mem_ctrl_fn *c_CRYPTO_mem_ctrl;

typedef struct fips_global_st {
    const OSSL_PROVIDER *prov;
} FIPS_GLOBAL;

static void *fips_prov_ossl_ctx_new(OPENSSL_CTX *libctx)
{
    FIPS_GLOBAL *fgbl = OPENSSL_zalloc(sizeof(*fgbl));

    return fgbl;
}

static void fips_prov_ossl_ctx_free(void *fgbl)
{
    OPENSSL_free(fgbl);
}

static const OPENSSL_CTX_METHOD fips_prov_ossl_ctx_method = {
    fips_prov_ossl_ctx_new,
    fips_prov_ossl_ctx_free,
};


/* Parameters we provide to the core */
static const OSSL_PARAM fips_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_END
};

/*
 * Parameters to retrieve from the core provider - required for self testing.
 * NOTE: inside core_get_params() these will be loaded from config items
 * stored inside prov->parameters (except for OSSL_PROV_PARAM_MODULE_FILENAME).
 */
static OSSL_PARAM core_params[] =
{
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_MODULE_FILENAME,
                        selftest_params.module_filename,
                        sizeof(selftest_params.module_filename)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_MODULE_MAC,
                        selftest_params.module_checksum_data,
                        sizeof(selftest_params.module_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_MAC,
                        selftest_params.indicator_checksum_data,
                        sizeof(selftest_params.indicator_checksum_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_STATUS,
                        selftest_params.indicator_data,
                        sizeof(selftest_params.indicator_data)),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_FIPS_PARAM_INSTALL_VERSION,
                        selftest_params.indicator_version,
                        sizeof(selftest_params.indicator_version)),
    OSSL_PARAM_END
};

/* TODO(3.0): To be removed */
static int dummy_evp_call(void *provctx)
{
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_MD *sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_PBKDF2, NULL);
    char msg[] = "Hello World!";
    OSSL_PARAM params[16];
    const unsigned char exptd[] = {
        0x7f, 0x83, 0xb1, 0x65, 0x7f, 0xf1, 0xfc, 0x53, 0xb9, 0x2d, 0xc1, 0x81,
        0x48, 0xa1, 0xd6, 0x5d, 0xfc, 0x2d, 0x4b, 0x1f, 0xa3, 0xd6, 0x77, 0x28,
        0x4a, 0xdd, 0xd2, 0x00, 0x12, 0x6d, 0x90, 0x69
    };
    unsigned int dgstlen = 0;
    unsigned char dgst[SHA256_DIGEST_LENGTH];
    int ret = 0;
    BN_CTX *bnctx = NULL;
    BIGNUM *a = NULL, *b = NULL;
    unsigned char randbuf[128];
    RAND_DRBG *drbg = OPENSSL_CTX_get0_public_drbg(libctx);
#ifndef OPENSSL_NO_EC
    EC_KEY *key = NULL;
#endif
    int n = 0;

    if (ctx == NULL || sha256 == NULL || drbg == NULL || kdf == NULL)
        goto err;

    if (!EVP_DigestInit_ex(ctx, sha256, NULL))
        goto err;
    if (!EVP_DigestUpdate(ctx, msg, sizeof(msg) - 1))
        goto err;
    if (!EVP_DigestFinal(ctx, dgst, &dgstlen))
        goto err;
    if (dgstlen != sizeof(exptd) || memcmp(dgst, exptd, sizeof(exptd)) != 0)
        goto err;

    bnctx = BN_CTX_new_ex(libctx);
    if (bnctx == NULL)
        goto err;
    BN_CTX_start(bnctx);
    a = BN_CTX_get(bnctx);
    b = BN_CTX_get(bnctx);
    if (b == NULL)
        goto err;
    BN_zero(a);
    if (!BN_one(b)
        || !BN_add(a, a, b)
        || BN_cmp(a, b) != 0)
        goto err;

    if (RAND_DRBG_bytes(drbg, randbuf, sizeof(randbuf)) <= 0)
        goto err;

    if (!BN_rand_ex(a, 256, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, bnctx))
        goto err;

#ifndef OPENSSL_NO_EC
    /* Do some dummy EC calls */
    key = EC_KEY_new_by_curve_name_ex(libctx, NID_X9_62_prime256v1);
    if (key == NULL)
        goto err;

    if (!EC_KEY_generate_key(key))
        goto err;
#endif

    {
        EVP_PKEY_CTX *pctx = NULL;
        EVP_PKEY *pkey = NULL;
        unsigned char out[64];
        size_t outlen;
        //int pad = RSA_OAEP_PADDING;

        /* RSA key data */
        static unsigned char rsa_2048_n[] = {
            0xDB, 0x10, 0x1A, 0xC2, 0xA3, 0xF1, 0xDC, 0xFF, 0x13, 0x6B, 0xED, 0x44,
            0xDF, 0xF0, 0x02, 0x6D, 0x13, 0xC7, 0x88, 0xDA, 0x70, 0x6B, 0x54, 0xF1,
            0xE8, 0x27, 0xDC, 0xC3, 0x0F, 0x99, 0x6A, 0xFA, 0xC6, 0x67, 0xFF, 0x1D,
            0x1E, 0x3C, 0x1D, 0xC1, 0xB5, 0x5F, 0x6C, 0xC0, 0xB2, 0x07, 0x3A, 0x6D,
            0x41, 0xE4, 0x25, 0x99, 0xAC, 0xFC, 0xD2, 0x0F, 0x02, 0xD3, 0xD1, 0x54,
            0x06, 0x1A, 0x51, 0x77, 0xBD, 0xB6, 0xBF, 0xEA, 0xA7, 0x5C, 0x06, 0xA9,
            0x5D, 0x69, 0x84, 0x45, 0xD7, 0xF5, 0x05, 0xBA, 0x47, 0xF0, 0x1B, 0xD7,
            0x2B, 0x24, 0xEC, 0xCB, 0x9B, 0x1B, 0x10, 0x8D, 0x81, 0xA0, 0xBE, 0xB1,
            0x8C, 0x33, 0xE4, 0x36, 0xB8, 0x43, 0xEB, 0x19, 0x2A, 0x81, 0x8D, 0xDE,
            0x81, 0x0A, 0x99, 0x48, 0xB6, 0xF6, 0xBC, 0xCD, 0x49, 0x34, 0x3A, 0x8F,
            0x26, 0x94, 0xE3, 0x28, 0x82, 0x1A, 0x7C, 0x8F, 0x59, 0x9F, 0x45, 0xE8,
            0x5D, 0x1A, 0x45, 0x76, 0x04, 0x56, 0x05, 0xA1, 0xD0, 0x1B, 0x8C, 0x77,
            0x6D, 0xAF, 0x53, 0xFA, 0x71, 0xE2, 0x67, 0xE0, 0x9A, 0xFE, 0x03, 0xA9,
            0x85, 0xD2, 0xC9, 0xAA, 0xBA, 0x2A, 0xBC, 0xF4, 0xA0, 0x08, 0xF5, 0x13,
            0x98, 0x13, 0x5D, 0xF0, 0xD9, 0x33, 0x34, 0x2A, 0x61, 0xC3, 0x89, 0x55,
            0xF0, 0xAE, 0x1A, 0x9C, 0x22, 0xEE, 0x19, 0x05, 0x8D, 0x32, 0xFE, 0xEC,
            0x9C, 0x84, 0xBA, 0xB7, 0xF9, 0x6C, 0x3A, 0x4F, 0x07, 0xFC, 0x45, 0xEB,
            0x12, 0xE5, 0x7B, 0xFD, 0x55, 0xE6, 0x29, 0x69, 0xD1, 0xC2, 0xE8, 0xB9,
            0x78, 0x59, 0xF6, 0x79, 0x10, 0xC6, 0x4E, 0xEB, 0x6A, 0x5E, 0xB9, 0x9A,
            0xC7, 0xC4, 0x5B, 0x63, 0xDA, 0xA3, 0x3F, 0x5E, 0x92, 0x7A, 0x81, 0x5E,
            0xD6, 0xB0, 0xE2, 0x62, 0x8F, 0x74, 0x26, 0xC2, 0x0C, 0xD3, 0x9A, 0x17,
            0x47, 0xE6, 0x8E, 0xAB
        };

        static unsigned char rsa_2048_e[] = { 0x01, 0x00, 0x01 };
        static unsigned char rsa_2048_d[] = {
            0x52, 0x41, 0xF4, 0xDA, 0x7B, 0xB7, 0x59, 0x55, 0xCA, 0xD4, 0x2F, 0x0F,
            0x3A, 0xCB, 0xA4, 0x0D, 0x93, 0x6C, 0xCC, 0x9D, 0xC1, 0xB2, 0xFB, 0xFD,
            0xAE, 0x40, 0x31, 0xAC, 0x69, 0x52, 0x21, 0x92, 0xB3, 0x27, 0xDF, 0xEA,
            0xEE, 0x2C, 0x82, 0xBB, 0xF7, 0x40, 0x32, 0xD5, 0x14, 0xC4, 0x94, 0x12,
            0xEC, 0xB8, 0x1F, 0xCA, 0x59, 0xE3, 0xC1, 0x78, 0xF3, 0x85, 0xD8, 0x47,
            0xA5, 0xD7, 0x02, 0x1A, 0x65, 0x79, 0x97, 0x0D, 0x24, 0xF4, 0xF0, 0x67,
            0x6E, 0x75, 0x2D, 0xBF, 0x10, 0x3D, 0xA8, 0x7D, 0xEF, 0x7F, 0x60, 0xE4,
            0xE6, 0x05, 0x82, 0x89, 0x5D, 0xDF, 0xC6, 0xD2, 0x6C, 0x07, 0x91, 0x33,
            0x98, 0x42, 0xF0, 0x02, 0x00, 0x25, 0x38, 0xC5, 0x85, 0x69, 0x8A, 0x7D,
            0x2F, 0x95, 0x6C, 0x43, 0x9A, 0xB8, 0x81, 0xE2, 0xD0, 0x07, 0x35, 0xAA,
            0x05, 0x41, 0xC9, 0x1E, 0xAF, 0xE4, 0x04, 0x3B, 0x19, 0xB8, 0x73, 0xA2,
            0xAC, 0x4B, 0x1E, 0x66, 0x48, 0xD8, 0x72, 0x1F, 0xAC, 0xF6, 0xCB, 0xBC,
            0x90, 0x09, 0xCA, 0xEC, 0x0C, 0xDC, 0xF9, 0x2C, 0xD7, 0xEB, 0xAE, 0xA3,
            0xA4, 0x47, 0xD7, 0x33, 0x2F, 0x8A, 0xCA, 0xBC, 0x5E, 0xF0, 0x77, 0xE4,
            0x97, 0x98, 0x97, 0xC7, 0x10, 0x91, 0x7D, 0x2A, 0xA6, 0xFF, 0x46, 0x83,
            0x97, 0xDE, 0xE9, 0xE2, 0x17, 0x03, 0x06, 0x14, 0xE2, 0xD7, 0xB1, 0x1D,
            0x77, 0xAF, 0x51, 0x27, 0x5B, 0x5E, 0x69, 0xB8, 0x81, 0xE6, 0x11, 0xC5,
            0x43, 0x23, 0x81, 0x04, 0x62, 0xFF, 0xE9, 0x46, 0xB8, 0xD8, 0x44, 0xDB,
            0xA5, 0xCC, 0x31, 0x54, 0x34, 0xCE, 0x3E, 0x82, 0xD6, 0xBF, 0x7A, 0x0B,
            0x64, 0x21, 0x6D, 0x88, 0x7E, 0x5B, 0x45, 0x12, 0x1E, 0x63, 0x8D, 0x49,
            0xA7, 0x1D, 0xD9, 0x1E, 0x06, 0xCD, 0xE8, 0xBA, 0x2C, 0x8C, 0x69, 0x32,
            0xEA, 0xBE, 0x60, 0x71
        };
        static unsigned char rsa_2048_p[] = {
            0xFA, 0xAC, 0xE1, 0x37, 0x5E, 0x32, 0x11, 0x34, 0xC6, 0x72, 0x58, 0x2D,
            0x91, 0x06, 0x3E, 0x77, 0xE7, 0x11, 0x21, 0xCD, 0x4A, 0xF8, 0xA4, 0x3F,
            0x0F, 0xEF, 0x31, 0xE3, 0xF3, 0x55, 0xA0, 0xB9, 0xAC, 0xB6, 0xCB, 0xBB,
            0x41, 0xD0, 0x32, 0x81, 0x9A, 0x8F, 0x7A, 0x99, 0x30, 0x77, 0x6C, 0x68,
            0x27, 0xE2, 0x96, 0xB5, 0x72, 0xC9, 0xC3, 0xD4, 0x42, 0xAA, 0xAA, 0xCA,
            0x95, 0x8F, 0xFF, 0xC9, 0x9B, 0x52, 0x34, 0x30, 0x1D, 0xCF, 0xFE, 0xCF,
            0x3C, 0x56, 0x68, 0x6E, 0xEF, 0xE7, 0x6C, 0xD7, 0xFB, 0x99, 0xF5, 0x4A,
            0xA5, 0x21, 0x1F, 0x2B, 0xEA, 0x93, 0xE8, 0x98, 0x26, 0xC4, 0x6E, 0x42,
            0x21, 0x5E, 0xA0, 0xA1, 0x2A, 0x58, 0x35, 0xBB, 0x10, 0xE7, 0xBA, 0x27,
            0x0A, 0x3B, 0xB3, 0xAF, 0xE2, 0x75, 0x36, 0x04, 0xAC, 0x56, 0xA0, 0xAB,
            0x52, 0xDE, 0xCE, 0xDD, 0x2C, 0x28, 0x77, 0x03
        };
        static unsigned char rsa_2048_q[] = {
            0xDF, 0xB7, 0x52, 0xB6, 0xD7, 0xC0, 0xE2, 0x96, 0xE7, 0xC9, 0xFE, 0x5D,
            0x71, 0x5A, 0xC4, 0x40, 0x96, 0x2F, 0xE5, 0x87, 0xEA, 0xF3, 0xA5, 0x77,
            0x11, 0x67, 0x3C, 0x8D, 0x56, 0x08, 0xA7, 0xB5, 0x67, 0xFA, 0x37, 0xA8,
            0xB8, 0xCF, 0x61, 0xE8, 0x63, 0xD8, 0x38, 0x06, 0x21, 0x2B, 0x92, 0x09,
            0xA6, 0x39, 0x3A, 0xEA, 0xA8, 0xB4, 0x45, 0x4B, 0x36, 0x10, 0x4C, 0xE4,
            0x00, 0x66, 0x71, 0x65, 0xF8, 0x0B, 0x94, 0x59, 0x4F, 0x8C, 0xFD, 0xD5,
            0x34, 0xA2, 0xE7, 0x62, 0x84, 0x0A, 0xA7, 0xBB, 0xDB, 0xD9, 0x8A, 0xCD,
            0x05, 0xE1, 0xCC, 0x57, 0x7B, 0xF1, 0xF1, 0x1F, 0x11, 0x9D, 0xBA, 0x3E,
            0x45, 0x18, 0x99, 0x1B, 0x41, 0x64, 0x43, 0xEE, 0x97, 0x5D, 0x77, 0x13,
            0x5B, 0x74, 0x69, 0x73, 0x87, 0x95, 0x05, 0x07, 0xBE, 0x45, 0x07, 0x17,
            0x7E, 0x4A, 0x69, 0x22, 0xF3, 0xDB, 0x05, 0x39
        };

        static unsigned char rsa_2048_dmp1[] = {
            0x5E, 0xD8, 0xDC, 0xDA, 0x53, 0x44, 0xC4, 0x67, 0xE0, 0x92, 0x51, 0x34,
            0xE4, 0x83, 0xA5, 0x4D, 0x3E, 0xDB, 0xA7, 0x9B, 0x82, 0xBB, 0x73, 0x81,
            0xFC, 0xE8, 0x77, 0x4B, 0x15, 0xBE, 0x17, 0x73, 0x49, 0x9B, 0x5C, 0x98,
            0xBC, 0xBD, 0x26, 0xEF, 0x0C, 0xE9, 0x2E, 0xED, 0x19, 0x7E, 0x86, 0x41,
            0x1E, 0x9E, 0x48, 0x81, 0xDD, 0x2D, 0xE4, 0x6F, 0xC2, 0xCD, 0xCA, 0x93,
            0x9E, 0x65, 0x7E, 0xD5, 0xEC, 0x73, 0xFD, 0x15, 0x1B, 0xA2, 0xA0, 0x7A,
            0x0F, 0x0D, 0x6E, 0xB4, 0x53, 0x07, 0x90, 0x92, 0x64, 0x3B, 0x8B, 0xA9,
            0x33, 0xB3, 0xC5, 0x94, 0x9B, 0x4C, 0x5D, 0x9C, 0x7C, 0x46, 0xA4, 0xA5,
            0x56, 0xF4, 0xF3, 0xF8, 0x27, 0x0A, 0x7B, 0x42, 0x0D, 0x92, 0x70, 0x47,
            0xE7, 0x42, 0x51, 0xA9, 0xC2, 0x18, 0xB1, 0x58, 0xB1, 0x50, 0x91, 0xB8,
            0x61, 0x41, 0xB6, 0xA9, 0xCE, 0xD4, 0x7C, 0xBB
        };
        static unsigned char rsa_2048_dmq1[] = {
            0x54, 0x09, 0x1F, 0x0F, 0x03, 0xD8, 0xB6, 0xC5, 0x0C, 0xE8, 0xB9, 0x9E,
            0x0C, 0x38, 0x96, 0x43, 0xD4, 0xA6, 0xC5, 0x47, 0xDB, 0x20, 0x0E, 0xE5,
            0xBD, 0x29, 0xD4, 0x7B, 0x1A, 0xF8, 0x41, 0x57, 0x49, 0x69, 0x9A, 0x82,
            0xCC, 0x79, 0x4A, 0x43, 0xEB, 0x4D, 0x8B, 0x2D, 0xF2, 0x43, 0xD5, 0xA5,
            0xBE, 0x44, 0xFD, 0x36, 0xAC, 0x8C, 0x9B, 0x02, 0xF7, 0x9A, 0x03, 0xE8,
            0x19, 0xA6, 0x61, 0xAE, 0x76, 0x10, 0x93, 0x77, 0x41, 0x04, 0xAB, 0x4C,
            0xED, 0x6A, 0xCC, 0x14, 0x1B, 0x99, 0x8D, 0x0C, 0x6A, 0x37, 0x3B, 0x86,
            0x6C, 0x51, 0x37, 0x5B, 0x1D, 0x79, 0xF2, 0xA3, 0x43, 0x10, 0xC6, 0xA7,
            0x21, 0x79, 0x6D, 0xF9, 0xE9, 0x04, 0x6A, 0xE8, 0x32, 0xFF, 0xAE, 0xFD,
            0x1C, 0x7B, 0x8C, 0x29, 0x13, 0xA3, 0x0C, 0xB2, 0xAD, 0xEC, 0x6C, 0x0F,
            0x8D, 0x27, 0x12, 0x7B, 0x48, 0xB2, 0xDB, 0x31
        };
        static unsigned char rsa_2048_iqmp[] = {
            0x8D, 0x1B, 0x05, 0xCA, 0x24, 0x1F, 0x0C, 0x53, 0x19, 0x52, 0x74, 0x63,
            0x21, 0xFA, 0x78, 0x46, 0x79, 0xAF, 0x5C, 0xDE, 0x30, 0xA4, 0x6C, 0x20,
            0x38, 0xE6, 0x97, 0x39, 0xB8, 0x7A, 0x70, 0x0D, 0x8B, 0x6C, 0x6D, 0x13,
            0x74, 0xD5, 0x1C, 0xDE, 0xA9, 0xF4, 0x60, 0x37, 0xFE, 0x68, 0x77, 0x5E,
            0x0B, 0x4E, 0x5E, 0x03, 0x31, 0x30, 0xDF, 0xD6, 0xAE, 0x85, 0xD0, 0x81,
            0xBB, 0x61, 0xC7, 0xB1, 0x04, 0x5A, 0xC4, 0x6D, 0x56, 0x1C, 0xD9, 0x64,
            0xE7, 0x85, 0x7F, 0x88, 0x91, 0xC9, 0x60, 0x28, 0x05, 0xE2, 0xC6, 0x24,
            0x8F, 0xDD, 0x61, 0x64, 0xD8, 0x09, 0xDE, 0x7E, 0xD3, 0x4A, 0x61, 0x1A,
            0xD3, 0x73, 0x58, 0x4B, 0xD8, 0xA0, 0x54, 0x25, 0x48, 0x83, 0x6F, 0x82,
            0x6C, 0xAF, 0x36, 0x51, 0x2A, 0x5D, 0x14, 0x2F, 0x41, 0x25, 0x00, 0xDD,
            0xF8, 0xF3, 0x95, 0xFE, 0x31, 0x25, 0x50, 0x12
        };

        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, rsa_2048_n, sizeof(rsa_2048_n));
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, rsa_2048_e, sizeof(rsa_2048_e));
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_D, rsa_2048_d, sizeof(rsa_2048_d));
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR, rsa_2048_p, sizeof(rsa_2048_p)); //P
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_FACTOR, rsa_2048_q, sizeof(rsa_2048_q)); //Q
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, rsa_2048_dmp1, sizeof(rsa_2048_dmp1)); //DP
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_EXPONENT, rsa_2048_dmq1, sizeof(rsa_2048_dmq1)); //DQ
        params[n++] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT, rsa_2048_iqmp, sizeof(rsa_2048_iqmp)); //QINV
        params[n++] = OSSL_PARAM_construct_end();

        pctx = EVP_PKEY_CTX_new_provided(libctx, "RSA", "");
        EVP_PKEY_key_fromdata_init(pctx);
        EVP_PKEY_fromdata(pctx, &pkey, params);

        EVP_PKEY_encrypt_init(pctx);
        //EVP_PKEY_CTX_set_rsa_padding(cctx, RSA_OAEP_PADDING);
        EVP_PKEY_encrypt(pctx, out, &outlen, (const unsigned char *)msg, sizeof(msg));
    }

    ret = 1;
 err:
    BN_CTX_end(bnctx);
    BN_CTX_free(bnctx);

    EVP_KDF_free(kdf);
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(sha256);

#ifndef OPENSSL_NO_EC
    EC_KEY_free(key);
#endif
    return ret;
}

static const OSSL_PARAM *fips_gettable_params(const OSSL_PROVIDER *prov)
{
    return fips_param_types;
}

static int fips_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL FIPS Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

/* FIPS specific version of the function of the same name in provlib.c */
const char *ossl_prov_util_nid_to_name(int nid)
{
    /* We don't have OBJ_nid2n() in FIPS_MODE so we have an explicit list */

    switch (nid) {
    /* Digests */
    case NID_sha1:
        return "SHA1";
    case NID_sha224:
        return "SHA-224";
    case NID_sha256:
        return "SHA-256";
    case NID_sha384:
        return "SHA-384";
    case NID_sha512:
        return "SHA-512";
    case NID_sha512_224:
        return "SHA-512/224";
    case NID_sha512_256:
        return "SHA-512/256";
    case NID_sha3_224:
        return "SHA3-224";
    case NID_sha3_256:
        return "SHA3-256";
    case NID_sha3_384:
        return "SHA3-384";
    case NID_sha3_512:
        return "SHA3-512";

    /* Ciphers */
    case NID_aes_256_ecb:
        return "AES-256-ECB";
    case NID_aes_192_ecb:
        return "AES-192-ECB";
    case NID_aes_128_ecb:
        return "AES-128-ECB";
    case NID_aes_256_cbc:
        return "AES-256-CBC";
    case NID_aes_192_cbc:
        return "AES-192-CBC";
    case NID_aes_128_cbc:
        return "AES-128-CBC";
    case NID_aes_256_ctr:
        return "AES-256-CTR";
    case NID_aes_192_ctr:
        return "AES-192-CTR";
    case NID_aes_128_ctr:
        return "AES-128-CTR";
    case NID_aes_256_xts:
        return "AES-256-XTS";
    case NID_aes_128_xts:
        return "AES-128-XTS";
    case NID_aes_256_gcm:
        return "AES-256-GCM";
    case NID_aes_192_gcm:
        return "AES-192-GCM";
    case NID_aes_128_gcm:
        return "AES-128-GCM";
    case NID_aes_256_ccm:
        return "AES-256-CCM";
    case NID_aes_192_ccm:
        return "AES-192-CCM";
    case NID_aes_128_ccm:
        return "AES-128-CCM";
    case NID_id_aes256_wrap:
        return "AES-256-WRAP";
    case NID_id_aes192_wrap:
        return "AES-192-WRAP";
    case NID_id_aes128_wrap:
        return "AES-128-WRAP";
    case NID_id_aes256_wrap_pad:
        return "AES-256-WRAP-PAD";
    case NID_id_aes192_wrap_pad:
        return "AES-192-WRAP-PAD";
    case NID_id_aes128_wrap_pad:
        return "AES-128-WRAP-PAD";
    case NID_des_ede3_ecb:
        return "DES-EDE3";
    case NID_des_ede3_cbc:
        return "DES-EDE3-CBC";
    default:
        break;
    }

    return NULL;
}

/*
 * For the algorithm names, we use the following formula for our primary
 * names:
 *
 *     ALGNAME[VERSION?][-SUBNAME[VERSION?]?][-SIZE?][-MODE?]
 *
 *     VERSION is only present if there are multiple versions of
 *     an alg (MD2, MD4, MD5).  It may be omitted if there is only
 *     one version (if a subsequent version is released in the future,
 *     we can always change the canonical name, and add the old name
 *     as an alias).
 *
 *     SUBNAME may be present where we are combining multiple
 *     algorithms together, e.g. MD5-SHA1.
 *
 *     SIZE is only present if multiple versions of an algorithm exist
 *     with different sizes (e.g. AES-128-CBC, AES-256-CBC)
 *
 *     MODE is only present where applicable.
 *
 * We add diverse other names where applicable, such as the names that
 * NIST uses, or that are used for ASN.1 OBJECT IDENTIFIERs, or names
 * we have used historically.
 */
static const OSSL_ALGORITHM fips_digests[] = {
    /* Our primary name:NiST name[:our older names] */
    { "SHA1:SHA-1", "fips=yes", sha1_functions },
    { "SHA2-224:SHA-224:SHA224", "fips=yes", sha224_functions },
    { "SHA2-256:SHA-256:SHA256", "fips=yes", sha256_functions },
    { "SHA2-384:SHA-384:SHA384", "fips=yes", sha384_functions },
    { "SHA2-512:SHA-512:SHA512", "fips=yes", sha512_functions },
    { "SHA2-512/224:SHA-512/224:SHA512-224", "fips=yes",
      sha512_224_functions },
    { "SHA2-512/256:SHA-512/256:SHA512-256", "fips=yes",
      sha512_256_functions },

    /* We agree with NIST here, so one name only */
    { "SHA3-224", "fips=yes", sha3_224_functions },
    { "SHA3-256", "fips=yes", sha3_256_functions },
    { "SHA3-384", "fips=yes", sha3_384_functions },
    { "SHA3-512", "fips=yes", sha3_512_functions },
    /*
     * KECCAK-KMAC-128 and KECCAK-KMAC-256 as hashes are mostly useful for
     * KMAC128 and KMAC256.
     */
    { "KECCAK-KMAC-128:KECCAK-KMAC128", "fips=yes", keccak_kmac_128_functions },
    { "KECCAK-KMAC-256:KECCAK-KMAC256", "fips=yes", keccak_kmac_256_functions },

    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_ciphers[] = {
    /* Our primary name[:ASN.1 OID name][:our older names] */
    { "AES-256-ECB", "fips=yes", aes256ecb_functions },
    { "AES-192-ECB", "fips=yes", aes192ecb_functions },
    { "AES-128-ECB", "fips=yes", aes128ecb_functions },
    { "AES-256-CBC", "fips=yes", aes256cbc_functions },
    { "AES-192-CBC", "fips=yes", aes192cbc_functions },
    { "AES-128-CBC", "fips=yes", aes128cbc_functions },
    { "AES-256-CTR", "fips=yes", aes256ctr_functions },
    { "AES-192-CTR", "fips=yes", aes192ctr_functions },
    { "AES-128-CTR", "fips=yes", aes128ctr_functions },
    { "AES-256-XTS", "fips=yes", aes256xts_functions },
    { "AES-128-XTS", "fips=yes", aes128xts_functions },
    { "AES-256-GCM:id-aes256-GCM", "fips=yes", aes256gcm_functions },
    { "AES-192-GCM:id-aes192-GCM", "fips=yes", aes192gcm_functions },
    { "AES-128-GCM:id-aes128-GCM", "fips=yes", aes128gcm_functions },
    { "AES-256-CCM:id-aes256-CCM", "fips=yes", aes256ccm_functions },
    { "AES-192-CCM:id-aes192-CCM", "fips=yes", aes192ccm_functions },
    { "AES-128-CCM:id-aes128-CCM", "fips=yes", aes128ccm_functions },
    { "AES-256-WRAP:id-aes256-wrap:AES256-WRAP", "fips=yes",
      aes256wrap_functions },
    { "AES-192-WRAP:id-aes192-wrap:AES192-WRAP", "fips=yes",
      aes192wrap_functions },
    { "AES-128-WRAP:id-aes128-wrap:AES128-WRAP", "fips=yes",
      aes128wrap_functions },
    { "AES-256-WRAP-PAD:id-aes256-wrap-pad:AES256-WRAP-PAD", "fips=yes",
      aes256wrappad_functions },
    { "AES-192-WRAP-PAD:id-aes192-wrap-pad:AES192-WRAP-PAD", "fips=yes",
      aes192wrappad_functions },
    { "AES-128-WRAP-PAD:id-aes128-wrap-pad:AES128-WRAP-PAD", "fips=yes",
      aes128wrappad_functions },
#ifndef OPENSSL_NO_DES
    { "DES-EDE3-ECB:DES-EDE3", "fips=yes", tdes_ede3_ecb_functions },
    { "DES-EDE3-CBC:DES3", "fips=yes", tdes_ede3_cbc_functions },
#endif  /* OPENSSL_NO_DES */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_macs[] = {
#ifndef OPENSSL_NO_CMAC
    { "CMAC", "fips=yes", cmac_functions },
#endif
    { "GMAC", "fips=yes", gmac_functions },
    { "HMAC", "fips=yes", hmac_functions },
    { "KMAC-128:KMAC128", "fips=yes", kmac128_functions },
    { "KMAC-256:KMAC256", "fips=yes", kmac256_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_kdfs[] = {
    { "HKDF", "fips=yes", kdf_hkdf_functions },
    { "SSKDF", "fips=yes", kdf_sskdf_functions },
    { "PBKDF2", "fips=yes", kdf_pbkdf2_functions },
    { "TLS1-PRF", "fips=yes", kdf_tls1_prf_functions },
    { "KBKDF", "fips=yes", kdf_kbkdf_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keyexch[] = {
#ifndef OPENSSL_NO_DH
    { "DH:dhKeyAgreement", "fips=yes", dh_keyexch_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_signature[] = {
#ifndef OPENSSL_NO_DSA
    { "DSA:dsaEncryption", "fips=yes", dsa_signature_functions },
#endif
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_keymgmt[] = {
#ifndef OPENSSL_NO_DH
    { "DH", "fips=yes", dh_keymgmt_functions },
#endif
#ifndef OPENSSL_NO_DSA
    { "DSA", "fips=yes", dsa_keymgmt_functions },
#endif
    { "RSA", "fips=yes", rsa_keymgmt_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM fips_asym_cipher[] = {
    { "RSA:rsaEncryption", "fips=yes", rsa_asym_cipher_functions },
    { NULL, NULL, NULL }
};


static const OSSL_ALGORITHM *fips_query(OSSL_PROVIDER *prov,
                                         int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        return fips_digests;
    case OSSL_OP_CIPHER:
        return fips_ciphers;
    case OSSL_OP_MAC:
        return fips_macs;
    case OSSL_OP_KDF:
        return fips_kdfs;
    case OSSL_OP_KEYMGMT:
        return fips_keymgmt;
    case OSSL_OP_KEYEXCH:
        return fips_keyexch;
    case OSSL_OP_SIGNATURE:
        return fips_signature;
    case OSSL_OP_ASYM_CIPHER:
        return fips_asym_cipher;
    }
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fips_dispatch_table[] = {
    /*
     * To release our resources we just need to free the OPENSSL_CTX so we just
     * use OPENSSL_CTX_free directly as our teardown function
     */
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OPENSSL_CTX_free },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))fips_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))fips_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};

/* Functions we provide to ourself */
static const OSSL_DISPATCH intern_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fips_query },
    { 0, NULL }
};


int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    FIPS_GLOBAL *fgbl;
    OPENSSL_CTX *ctx;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_get_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_get_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_THREAD_START:
            c_thread_start = OSSL_get_core_thread_start(in);
            break;
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_get_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_get_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_get_core_vset_error(in);
            break;
        case OSSL_FUNC_CORE_CLEAR_LAST_ERROR_CONSTTIME:
            c_clear_last_error_consttime =
                OSSL_get_core_clear_last_error_consttime(in);
            break;
        case OSSL_FUNC_CRYPTO_MALLOC:
            c_CRYPTO_malloc = OSSL_get_CRYPTO_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_ZALLOC:
            c_CRYPTO_zalloc = OSSL_get_CRYPTO_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_FREE:
            c_CRYPTO_free = OSSL_get_CRYPTO_free(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_FREE:
            c_CRYPTO_clear_free = OSSL_get_CRYPTO_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_REALLOC:
            c_CRYPTO_realloc = OSSL_get_CRYPTO_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_CLEAR_REALLOC:
            c_CRYPTO_clear_realloc = OSSL_get_CRYPTO_clear_realloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_MALLOC:
            c_CRYPTO_secure_malloc = OSSL_get_CRYPTO_secure_malloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ZALLOC:
            c_CRYPTO_secure_zalloc = OSSL_get_CRYPTO_secure_zalloc(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_FREE:
            c_CRYPTO_secure_free = OSSL_get_CRYPTO_secure_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_CLEAR_FREE:
            c_CRYPTO_secure_clear_free = OSSL_get_CRYPTO_secure_clear_free(in);
            break;
        case OSSL_FUNC_CRYPTO_SECURE_ALLOCATED:
            c_CRYPTO_secure_allocated = OSSL_get_CRYPTO_secure_allocated(in);
            break;
        case OSSL_FUNC_CRYPTO_MEM_CTRL:
            c_CRYPTO_mem_ctrl = OSSL_get_CRYPTO_mem_ctrl(in);
            break;
        case OSSL_FUNC_BIO_NEW_FILE:
            selftest_params.bio_new_file_cb = OSSL_get_BIO_new_file(in);
            break;
        case OSSL_FUNC_BIO_NEW_MEMBUF:
            selftest_params.bio_new_buffer_cb = OSSL_get_BIO_new_membuf(in);
            break;
        case OSSL_FUNC_BIO_READ_EX:
            selftest_params.bio_read_ex_cb = OSSL_get_BIO_read_ex(in);
            break;
        case OSSL_FUNC_BIO_FREE:
            selftest_params.bio_free_cb = OSSL_get_BIO_free(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (!c_get_params(provider, core_params))
        return 0;

    /*  Create a context. */
    if ((ctx = OPENSSL_CTX_new()) == NULL)
        return 0;
    if ((fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                     &fips_prov_ossl_ctx_method)) == NULL) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    fgbl->prov = provider;

    selftest_params.libctx = PROV_LIBRARY_CONTEXT_OF(ctx);
    if (!SELF_TEST_post(&selftest_params, 0)) {
        OPENSSL_CTX_free(ctx);
        return 0;
    }

    *out = fips_dispatch_table;
    *provctx = ctx;

    /*
     * TODO(3.0): Remove me. This is just a dummy call to demonstrate making
     * EVP calls from within the FIPS module.
     */
    if (!dummy_evp_call(*provctx)) {
        OPENSSL_CTX_free(*provctx);
        *provctx = NULL;
        return 0;
    }

    return 1;
}

/*
 * The internal init function used when the FIPS module uses EVP to call
 * another algorithm also in the FIPS module. This is a recursive call that has
 * been made from within the FIPS module itself. To make this work, we populate
 * the provider context of this inner instance with the same library context
 * that was used in the EVP call that initiated this recursive call.
 */
OSSL_provider_init_fn fips_intern_provider_init;
int fips_intern_provider_init(const OSSL_PROVIDER *provider,
                              const OSSL_DISPATCH *in,
                              const OSSL_DISPATCH **out,
                              void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        default:
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *provctx = c_get_libctx(provider);

    /*
     * Safety measure...  we should get the library context that was
     * created up in OSSL_provider_init().
     */
    if (*provctx == NULL)
        return 0;

    *out = intern_dispatch_table;
    return 1;
}

void ERR_new(void)
{
    c_new_error(NULL);
}

void ERR_set_debug(const char *file, int line, const char *func)
{
    c_set_error_debug(NULL, file, line, func);
}

void ERR_set_error(int lib, int reason, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
    va_end(args);
}

void ERR_vset_error(int lib, int reason, const char *fmt, va_list args)
{
    c_vset_error(NULL, ERR_PACK(lib, 0, reason), fmt, args);
}

void err_clear_last_constant_time(int clear)
{
    c_clear_last_error_consttime(clear);
}

const OSSL_PROVIDER *FIPS_get_provider(OPENSSL_CTX *ctx)
{
    FIPS_GLOBAL *fgbl = openssl_ctx_get_data(ctx, OPENSSL_CTX_FIPS_PROV_INDEX,
                                             &fips_prov_ossl_ctx_method);

    if (fgbl == NULL)
        return NULL;

    return fgbl->prov;
}

void *CRYPTO_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_malloc(num, file, line);
}

void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_zalloc(num, file, line);
}

void CRYPTO_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_free(ptr, file, line);
}

void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_clear_free(ptr, num, file, line);
}

void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line)
{
    return c_CRYPTO_realloc(addr, num, file, line);
}

void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
                           const char *file, int line)
{
    return c_CRYPTO_clear_realloc(addr, old_num, num, file, line);
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_malloc(num, file, line);
}

void *CRYPTO_secure_zalloc(size_t num, const char *file, int line)
{
    return c_CRYPTO_secure_zalloc(num, file, line);
}

void CRYPTO_secure_free(void *ptr, const char *file, int line)
{
    c_CRYPTO_secure_free(ptr, file, line);
}

void CRYPTO_secure_clear_free(void *ptr, size_t num, const char *file, int line)
{
    c_CRYPTO_secure_clear_free(ptr, num, file, line);
}

int CRYPTO_secure_allocated(const void *ptr)
{
    return c_CRYPTO_secure_allocated(ptr);
}

int CRYPTO_mem_ctrl(int mode)
{
    return c_CRYPTO_mem_ctrl(mode);
}
