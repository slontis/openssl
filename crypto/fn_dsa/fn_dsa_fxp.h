/*
 * Uniform 64.64 format: ePrint 2026/1531, Sections 3.4 and 6 (Type 1).
 * https://eprint.iacr.org/2026/1531
 * Products and quotients use nearest rounding, with ties to even.
 */
#ifndef OSSL_FN_DSA_FXP_H
#define OSSL_FN_DSA_FXP_H
#include <stdint.h>
#include "fn_dsa_fxp_util.h"
typedef __int128 FN_DSA_REAL;
typedef __uint128_t FN_DSA_UREAL;
static inline FN_DSA_REAL fxr_add(FN_DSA_REAL a, FN_DSA_REAL b)
{
    return (FN_DSA_REAL)((FN_DSA_UREAL)a + (FN_DSA_UREAL)b);
}
static inline FN_DSA_REAL fxr_sub(FN_DSA_REAL a, FN_DSA_REAL b)
{
    return (FN_DSA_REAL)((FN_DSA_UREAL)a - (FN_DSA_UREAL)b);
}
static inline FN_DSA_REAL fxr_neg(FN_DSA_REAL a)
{
    return (FN_DSA_REAL)(0 - (FN_DSA_UREAL)a);
}
static inline FN_DSA_UREAL fxr_abs(FN_DSA_REAL a)
{
    FN_DSA_UREAL m = 0 - ((FN_DSA_UREAL)a >> 127);
    return ((FN_DSA_UREAL)a ^ m) + (m & 1);
}
static inline FN_DSA_REAL fxr_of(int64_t a)
{
    return (FN_DSA_REAL)((FN_DSA_UREAL)(uint64_t)a << 64);
}
static inline int fxr_lt(FN_DSA_REAL a, FN_DSA_REAL b) { return a < b; }
static inline int fxr_gt(FN_DSA_REAL a, FN_DSA_REAL b) { return a > b; }
static inline int fxr_le(FN_DSA_REAL a, FN_DSA_REAL b) { return a <= b; }
static inline int fxr_ge(FN_DSA_REAL a, FN_DSA_REAL b) { return a >= b; }
static inline int fxr_eq(FN_DSA_REAL a, FN_DSA_REAL b) { return a == b; }
static inline int fxr_ne(FN_DSA_REAL a, FN_DSA_REAL b) { return a != b; }
static inline FN_DSA_REAL fxr_mul(FN_DSA_REAL a, FN_DSA_REAL b)
{
    FN_DSA_UREAL x = fxr_abs(a), y = fxr_abs(b), p0, p1, p2, p3, m, z, sign;
    uint64_t lo, up;
    p0 = (FN_DSA_UREAL)(uint64_t)x * (uint64_t)y;
    p1 = (FN_DSA_UREAL)(uint64_t)x * (uint64_t)(y >> 64);
    p2 = (FN_DSA_UREAL)(uint64_t)(x >> 64) * (uint64_t)y;
    p3 = (FN_DSA_UREAL)(uint64_t)(x >> 64) * (uint64_t)(y >> 64);
    m = (p0 >> 64) + (uint64_t)p1 + (uint64_t)p2;
    z = (p3 + (p1 >> 64) + (p2 >> 64) + (m >> 64)) << 64 | (uint64_t)m;
    lo = (uint64_t)p0;
    up = (lo > UINT64_C(0x8000000000000000)) |
         ((lo == UINT64_C(0x8000000000000000)) & ((uint64_t)z & 1));
    z += up;
    sign = 0 - (((FN_DSA_UREAL)a ^ (FN_DSA_UREAL)b) >> 127);
    return (FN_DSA_REAL)((z ^ sign) + (sign & 1));
}
/* Fixed iteration count: no hardware integer division, including compiler
 * helpers. */
static inline FN_DSA_REAL fxr_div(FN_DSA_REAL a, FN_DSA_REAL b)
{
    FN_DSA_UREAL x = fxr_abs(a), y = fxr_abs(b), r = 0, q = 0, ge, sign;
    unsigned i;
    uint64_t up;
    for (i = 192; i-- > 0;) {
        FN_DSA_UREAL bit = i >= 64 ? (x >> (i - 64)) & 1 : 0;
        ge = r >> 127;
        r = (r << 1) | bit;
        ge |= (r >= y);
        r -= y & (0 - ge);
        q = (q << 1) | ge;
    }
    up = ((r << 1) > y) | (((r << 1) == y) & (q & 1));
    q += up;
    sign = 0 - (((FN_DSA_UREAL)a ^ (FN_DSA_UREAL)b) >> 127);
    return (FN_DSA_REAL)((q ^ sign) + (sign & 1));
}
/* Truncated Q2.126 product from four 64-bit limb products. */
static inline __uint128_t fxr_sqrt_mul(__uint128_t a, __uint128_t b)
{
    __uint128_t lo = (__uint128_t)(uint64_t)a * (uint64_t)b;
    __uint128_t cross0 = (__uint128_t)(uint64_t)a * (uint64_t)(b >> 64);
    __uint128_t cross1 = (__uint128_t)(uint64_t)(a >> 64) * (uint64_t)b;
    __uint128_t high = (__uint128_t)(uint64_t)(a >> 64) * (uint64_t)(b >> 64);
    __uint128_t middle = (lo >> 64) + (uint64_t)cross0 + (uint64_t)cross1;

    high += (cross0 >> 64) + (cross1 >> 64) + (middle >> 64);
    return (high << 2) | ((uint64_t)middle >> 62);
}
/*
 * ePrint 2026/1531, Section 3.4: y <- y * (3 - x*y*y) / 2.
 * Normalize x to [1, 4) in Q2.126; 6 fixed steps give enough precision
 * to recover the correctly rounded result. See doc/designs/fn-dsa.md.
 */
static inline FN_DSA_REAL fxr_sqrt(FN_DSA_REAL a)
{
    __uint128_t raw = (__uint128_t)a, nonzero = raw != 0;
    __uint128_t x = raw | (1 ^ nonzero), y;
    __uint128_t root, square, factor;
    __int128 remainder;
    uint64_t high = (uint64_t)(x >> 64), mask = 0 - (uint64_t)(high != 0);
    uint64_t word = (high & mask) | ((uint64_t)x & ~mask);
    unsigned exponent = (fxr_log2_u64(word)
                         + (64 & (unsigned)mask)) & ~1u, i;

    x <<= 126 - exponent;
    /* Linear seed (35 - 5*x) / 32 has relative error below 1/8. */
    y = ((__uint128_t)35 << 121) - (x >> 3) - (x >> 5);
    for (i = 0; i < 6; i++) {
        square = fxr_sqrt_mul(y, y);
        factor = (((__uint128_t)3 << 126) - fxr_sqrt_mul(x, square)) >> 1;
        y = fxr_sqrt_mul(y, factor);
    }
    root = fxr_sqrt_mul(x, y) >> (94 - exponent / 2);
    /* Before truncation, the approximation is within 1/4 ulp. This low-word
     * subtraction recovers the exact remainder; only rounding up is needed. */
    remainder = (__int128)((raw << 64) - root * root);
    root += remainder > (__int128)root;
    return (__int128)(root & (0 - nonzero));
}
static inline int64_t fxr_trunc(FN_DSA_REAL a)
{
    uint64_t x = (uint64_t)(fxr_abs(a) >> 64),
             sign = (uint64_t)((FN_DSA_UREAL)a >> 127);
    return (int64_t)((x ^ (0 - sign)) + sign);
}
static inline int64_t fxr_floor(FN_DSA_REAL a)
{
    return (int64_t)((FN_DSA_UREAL)a >> 64);
}
static inline int64_t fxr_rint(FN_DSA_REAL a)
{
    FN_DSA_UREAL x = fxr_abs(a);
    uint64_t n = x >> 64, f = (uint64_t)x, sign = (FN_DSA_UREAL)a >> 127;
    n += (f > UINT64_C(0x8000000000000000)) |
         ((f == UINT64_C(0x8000000000000000)) & (n & 1));
    return (int64_t)((n ^ (0 - sign)) + sign);
}
static inline uint64_t fxr_q63(FN_DSA_REAL a)
{
    return (uint64_t)((FN_DSA_UREAL)a >> 1);
}
#endif
