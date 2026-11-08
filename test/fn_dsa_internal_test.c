/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * at https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "internal/nelem.h"
#include "fn_dsa_core.h"
#include "fn_dsa_fxp.h"
#include "testutil.h"
#include "fn_dsa_internal_test.h"

static const char *data_dir;
#define ARITH_TEST_FN test_arithmetic_64
#define ARITH_WORDS 2
#define ARITH_VECTORS "arithmetic-128.bin"
#include "fn_dsa_arithmetic_test.inc"

#define CHECK(condition) \
    do { \
        if (!TEST_true(condition)) \
            goto end; \
    } while (0)

static int load_vector(unsigned logn, unsigned id, const char *prefix,
    const char *ext, unsigned char *out, size_t cap, size_t *len)
{
    char name[80], *path = NULL;
    FILE *f = NULL;
    int ok = 0;

    snprintf(name, sizeof(name), "%s%u-%u.%s", prefix, 1u << logn, id, ext);
    if (!TEST_ptr(path = test_mk_file_path(data_dir, name))
        || !TEST_ptr(f = fopen(path, "rb")))
        goto end;
    *len = fread(out, 1, cap, f);
    ok = TEST_int_eq(fgetc(f), EOF) && TEST_int_eq(ferror(f), 0);
end:
    if (f != NULL)
        fclose(f);
    OPENSSL_free(path);
    return ok;
}

static int test_core_vector(int idx)
{
    unsigned logn = 9 + idx / 4, id = idx % 4, i;
    unsigned char pk[1793], sk[2305], epk[1793], esk[2305], msg[4096];
    unsigned char sig[1331], esig[1331], seed[48], nonce[40], derived[1793];
    unsigned char expected[2305];
    size_t ml, sl, el, pklen, sklen, expected_len;
    int ok = 0;

    CHECK(load_vector(logn, id, "", "pk", epk, sizeof(epk), &pklen));
    CHECK(load_vector(logn, id, "", "sk", esk, sizeof(esk), &sklen));
    CHECK(load_vector(logn, id, "", "msg", msg, sizeof(msg), &ml));
    CHECK(load_vector(logn, id, "", "sig", esig, sizeof(esig), &el));
    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (unsigned char)(id * 17 + i);
    CHECK(fn_dsa_keygen_seed(NULL, logn, seed, pk, sk));
    memcpy(derived, pk, pklen);
    CHECK(ossl_fn_dsa_core_public(logn, sk, sklen, pk));
    CHECK(TEST_mem_eq(pk, pklen, derived, pklen));
    CHECK(ossl_fn_dsa_core_verify(NULL, logn, epk, pklen, msg, ml, esig, el));
    for (i = 0; i < sizeof(nonce); i++)
        nonce[i] = (unsigned char)(id * 17 + 71 + i);
    for (i = 0; i < sizeof(seed); i++)
        seed[i] = (unsigned char)(id * 17 + 142 + i);
    CHECK(fn_dsa_sign_seed(NULL, logn, sk, sklen, msg, ml, nonce, seed,
        sig, &sl, sizeof(sig)));
    CHECK(load_vector(logn, id, "fixed/", "pk", expected, sizeof(expected), &expected_len));
    CHECK(TEST_mem_eq(pk, pklen, expected, expected_len));
    CHECK(load_vector(logn, id, "fixed/", "sk", expected, sizeof(expected), &expected_len));
    CHECK(TEST_mem_eq(sk, sklen, expected, expected_len));
    CHECK(load_vector(logn, id, "fixed/", "sig", expected, sizeof(expected), &expected_len));
    CHECK(TEST_mem_eq(sig, sl, expected, expected_len));
    /* Independently produced fixtures also exercise any admitted private key. */
    if (ossl_fn_dsa_core_public(logn, esk, sklen, derived)) {
        size_t katlen;

        CHECK(fn_dsa_sign_seed(NULL, logn, esk, sklen, msg, ml, nonce,
            seed, esig, &katlen, sizeof(esig)));
        CHECK(ossl_fn_dsa_core_verify(NULL, logn, epk, pklen, msg, ml, esig, katlen));
    }
    CHECK(ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
    if (ml != 0) {
        msg[0] ^= 1;
        CHECK(!ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
        msg[0] ^= 1;
    }
    sig[sl / 2] ^= 1;
    CHECK(!ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
    sig[sl / 2] ^= 1;
    for (i = 0; i < sl; i++)
        CHECK(!ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, i));
    sig[sl] = 0;
    CHECK(!ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl + 1));
    CHECK(!ossl_fn_dsa_core_sign(NULL, logn, sk, sklen, msg, ml, sig, &sl, 1));
    CHECK(ossl_fn_dsa_core_sign(NULL, logn, sk, sklen, msg, ml, sig, &sl, sizeof(sig)));
    CHECK(ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
    ok = 1;
end:
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(esk, sizeof(esk));
    OPENSSL_cleanse(expected, sizeof(expected));
    return ok;
}

static uint32_t next_word(uint32_t *state)
{
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

static int test_core_stress(int idx)
{
    unsigned logn = 9 + idx, k, i, j;
    uint32_t state = 1531 + idx;
    unsigned char pk[1793], sk[2305], bad[2305], seed[48], msg[2048];
    unsigned char sig[1331], nonce[40];
    size_t sl, ml = 0, pklen = ossl_fn_dsa_core_pk_size(logn);
    size_t sklen = ossl_fn_dsa_core_sk_size(logn);
    int ok = 0;

    for (k = 0; k < 8; k++) {
        for (i = 0; i < sizeof(seed); i++)
            seed[i] = (unsigned char)next_word(&state);
        CHECK(fn_dsa_keygen_seed(NULL, logn, seed, pk, sk));
        for (j = 0; j < 3; j++) {
            ml = next_word(&state) % sizeof(msg);
            for (i = 0; i < ml; i++)
                msg[i] = (unsigned char)next_word(&state);
            for (i = 0; i < sizeof(nonce); i++)
                nonce[i] = (unsigned char)next_word(&state);
            CHECK(fn_dsa_sign_seed(NULL, logn, sk, sklen, msg, ml, nonce,
                seed, sig, &sl, sizeof(sig)));
            CHECK(ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
            i = next_word(&state) % sl;
            sig[i] ^= 1u << (next_word(&state) % 8);
            CHECK(!ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
        }
        /* Check the integer NTRU equation, rather than only congruence mod q. */
        memcpy(bad, sk, sklen);
        memset(bad + sklen - ((size_t)1 << logn), 0, (size_t)1 << logn);
        CHECK(!ossl_fn_dsa_core_public(logn, bad, sklen, pk));
        CHECK(!ossl_fn_dsa_core_sign(NULL, logn, bad, sklen, msg, ml, sig, &sl, sizeof(sig)));
    }
    for (k = 0; k < 256; k++) {
        sl = next_word(&state) % (ossl_fn_dsa_core_sig_size(logn) + 1);
        for (i = 0; i < sl; i++)
            sig[i] = (unsigned char)next_word(&state);
        if (sl != 0)
            sig[0] = (unsigned char)(0x30 + logn);
        CHECK(!ossl_fn_dsa_core_verify(NULL, logn, pk, pklen, msg, ml, sig, sl));
    }
    ok = 1;
end:
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(bad, sizeof(bad));
    return ok;
}
static int get32(FILE *f, uint32_t *v)
{
    unsigned i;
    *v = 0;
    for (i = 0; i < 4; i++) {
        int c = fgetc(f);
        if (c == EOF)
            return 0;
        *v |= (uint32_t)c << (8 * i);
    }
    return 1;
}
static int test_keygen_scaling(void)
{
    FILE *f = NULL;
    char *path = test_mk_file_path(data_dir, "scaling-32.bin");
    uint32_t count, c, h[5], i, lo, hi;
    int32_t *limbs = NULL;
    int64_t *out = NULL;
    int ret = 0;
    if (!TEST_ptr(path) || !TEST_ptr(f = fopen(path, "rb")))
        goto end;
    if (!get32(f, &count))
        goto end;
    for (c = 0; c < count; c++) {
        size_t n, words;
        for (i = 0; i < 5; i++)
            if (!get32(f, &h[i]))
                goto end;
        if (h[0] == 0 || h[0] > 209 || h[1] < h[0] || h[1] > 211 || h[2] > 10 ||
            h[3] > 7000)
            goto end;
        n = (size_t)1 << h[2];
        words = n * h[1];
        limbs = OPENSSL_malloc(words * sizeof(*limbs));
        out = OPENSSL_malloc(n * sizeof(*out));
        if (limbs == NULL || out == NULL)
            goto end;
        for (i = 0; i < words; i++) {
            if (!get32(f, &lo))
                goto end;
            limbs[i] = (int32_t)lo;
        }
        if (fn_dsa_keygen_max_bits_test(limbs, (int)h[0], (int)h[1],
                                        (int)h[2]) != (int)h[4])
            goto end;
        fn_dsa_keygen_scaled_test(out, limbs, (int)h[0], (int)h[1], (int)h[2],
                                  (int)h[3]);
        for (i = 0; i < n; i++) {
            if (!get32(f, &lo) || !get32(f, &hi) ||
                (uint64_t)out[i] != ((uint64_t)hi << 32 | lo)) {
                fprintf(stderr, "Scaling case %u coefficient %u failed\n", c,
                        i);
                goto end;
            }
        }
        OPENSSL_free(limbs);
        OPENSSL_free(out);
        limbs = NULL;
        out = NULL;
    }
    if (fgetc(f) != EOF)
        goto end;
    fprintf(stderr, "PASS %u exact scaled-polynomial cases\n", count);
    ret = 1;
end:
    OPENSSL_free(limbs);
    OPENSSL_free(out);
    if (f != NULL)
        fclose(f);
    OPENSSL_free(path);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(data_dir = test_get_argument(0)))
        return 0;
    ADD_TEST(test_arithmetic_64);
    ADD_TEST(test_keygen_scaling);
    ADD_ALL_TESTS(test_core_vector, 8);
    ADD_ALL_TESTS(test_core_stress, 2);
    return setup_fn_dsa_internal32_tests(data_dir);
}
