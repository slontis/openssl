/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy
 * at https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include "internal/nelem.h"
#include "fn_dsa_keygen_fxp.h"
#include "testutil.h"
#include "fn_dsa_internal_test.h"

static const char *data_dir;
#define ARITH_TEST_FN test_arithmetic_32
#define ARITH_WORDS 1
#define ARITH_VECTORS "arithmetic-64.bin"
#include "fn_dsa_arithmetic_test.inc"

static int get128(FILE *f, __uint128_t *out, unsigned bytes)
{
    unsigned i;
    *out = 0;
    for (i = 0; i < bytes; i++) {
        int c = fgetc(f);
        if (c == EOF)
            return 0;
        *out |= (__uint128_t)(unsigned)c << (8 * i);
    }
    return 1;
}
static int test_product_quotients(void)
{
    FILE *f = NULL;
    char *path = test_mk_file_path(data_dir, "products-32.bin");
    int ret = 0;
    __uint128_t count, i, numerator, denominator, expected, valid;
    if (!TEST_ptr(path) || !TEST_ptr(f = fopen(path, "rb")))
        goto end;
    if (!get128(f, &count, 4) || count > 10000)
        goto end;
    for (i = 0; i < count; i++) {
        int ok = 1;
        int64_t result;
        if (!get128(f, &numerator, 16) || !get128(f, &denominator, 16) ||
            !get128(f, &expected, 8) || !get128(f, &valid, 1))
            goto end;
        result = fxr_div_products((__int128)numerator, denominator, &ok);
        if (ok != (int)valid || (ok && (uint64_t)result != (uint64_t)expected)) {
            fprintf(stderr, "Product quotient case %u failed\n", (unsigned)i);
            goto end;
        }
    }
    if (fgetc(f) != EOF)
        goto end;
    fprintf(stderr, "PASS %u exact product quotients and overflow checks\n",
            (unsigned)count);
    ret = 1;
end:
    if (f != NULL)
        fclose(f);
    OPENSSL_free(path);
    return ret;
}


int setup_fn_dsa_internal32_tests(const char *directory)
{
    data_dir = directory;
    ADD_TEST(test_arithmetic_32);
    ADD_TEST(test_product_quotients);
    return 1;
}
