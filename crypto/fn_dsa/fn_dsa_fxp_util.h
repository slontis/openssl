/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#ifndef OSSL_FN_DSA_FXP_UTIL_H
#define OSSL_FN_DSA_FXP_UTIL_H

#include <stdint.h>

/* floor(log2(x)), for x != 0: six steps, no table or leading-zero intrinsic. */
static inline unsigned fxr_log2_u64(uint64_t x)
{
    unsigned result = 0, shift, step;

    for (step = 32; step != 0; step >>= 1) {
        shift = step & (0u - (unsigned)((x >> step) != 0));
        x >>= shift;
        result |= shift;
    }
    return result;
}
#endif
