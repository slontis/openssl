/*
 * Signed 32.32 key-generation arithmetic; fixed-point notation follows
 * ePrint 2026/1531, Section 3.4: https://eprint.iacr.org/2026/1531
 * Products and quotients use nearest rounding, with ties to even.
 */
#ifndef OSSL_FN_DSA_KEYGEN_FXP_H
#define OSSL_FN_DSA_KEYGEN_FXP_H
#include <stdint.h>
#include "fn_dsa_fxp_util.h"
typedef int64_t FN_DSA_REAL;
typedef uint64_t FN_DSA_UREAL;
static inline FN_DSA_REAL fxr_add(FN_DSA_REAL a, FN_DSA_REAL b)
{
    return (int64_t)((uint64_t)a + (uint64_t)b);
}
static inline FN_DSA_REAL fxr_sub(FN_DSA_REAL a, FN_DSA_REAL b)
{
    return (int64_t)((uint64_t)a - (uint64_t)b);
}
static inline FN_DSA_REAL fxr_neg(FN_DSA_REAL a)
{
    return (int64_t)(0 - (uint64_t)a);
}
static inline uint64_t fxr_abs(FN_DSA_REAL a)
{
    uint64_t mask = 0 - ((uint64_t)a >> 63);
    return ((uint64_t)a ^ mask) + (mask & 1);
}
static inline FN_DSA_REAL fxr_of(int64_t a)
{
    return (int64_t)((uint64_t)a << 32);
}
static inline int fxr_lt(FN_DSA_REAL a, FN_DSA_REAL b) { return a < b; }
static inline int fxr_gt(FN_DSA_REAL a, FN_DSA_REAL b) { return a > b; }
static inline int fxr_le(FN_DSA_REAL a, FN_DSA_REAL b) { return a <= b; }
static inline int fxr_ge(FN_DSA_REAL a, FN_DSA_REAL b) { return a >= b; }
static inline int fxr_eq(FN_DSA_REAL a, FN_DSA_REAL b) { return a == b; }
static inline int fxr_ne(FN_DSA_REAL a, FN_DSA_REAL b) { return a != b; }
static inline FN_DSA_REAL fxr_mul(FN_DSA_REAL a, FN_DSA_REAL b)
{
    __uint128_t p = (__uint128_t)fxr_abs(a) * fxr_abs(b);
    uint64_t q = (uint64_t)(p >> 32), r = (uint32_t)p;
    uint64_t mask = 0 - (((uint64_t)a ^ (uint64_t)b) >> 63);
    q += (r > UINT64_C(0x80000000)) | ((r == UINT64_C(0x80000000)) & (q & 1));
    return (int64_t)((q ^ mask) + (mask & 1));
}
static inline FN_DSA_REAL fxr_div(FN_DSA_REAL a, FN_DSA_REAL b)
{
    uint64_t x = fxr_abs(a), y = fxr_abs(b), r = 0, q = 0, ge, mask;
    unsigned i;
    for (i = 96; i-- > 0;) {
        uint64_t bit = i >= 32 ? (x >> (i - 32)) & 1 : 0;
        r = (r << 1) | bit;
        ge = r >= y;
        r -= y & (0 - ge);
        q = (q << 1) | ge;
    }
    q += ((r << 1) > y) | (((r << 1) == y) & (q & 1));
    mask = 0 - (((uint64_t)a ^ (uint64_t)b) >> 63);
    return (int64_t)((q ^ mask) + (mask & 1));
}
/* Divide the unrounded 128-bit product accumulator by its Gram norm.
 * Both accumulators have 64 fractional bits; the result has 32. This keeps
 * small Gram norms from vanishing when products are rounded individually. */
static inline FN_DSA_REAL fxr_div_products(__int128 numerator,
                                           __uint128_t denominator, int *ok)
{
    __uint128_t sign = 0 - ((__uint128_t)numerator >> 127);
    __uint128_t x = ((__uint128_t)numerator ^ sign) + (sign & 1);
    __uint128_t r = 0, ge;
    uint64_t q = 0, overflow = 0;
    unsigned i;
    for (i = 160; i-- > 0;) {
        __uint128_t bit = i >= 32 ? (x >> (i - 32)) & 1 : 0;
        ge = r >> 127;
        r = (r << 1) | bit;
        ge |= r >= denominator;
        r -= denominator & (0 - ge);
        overflow |= q >> 63;
        q = (q << 1) | (uint64_t)ge;
    }
    {
        uint64_t up =
            ((r << 1) > denominator) | (((r << 1) == denominator) & (q & 1));
        overflow |= up & (q == UINT64_MAX);
        q += up;
    }
    overflow |= q > (UINT64_C(0x7fffffffffffffff) + (uint64_t)(sign & 1));
    *ok &= (overflow == 0) & (denominator != 0);
    return (int64_t)((q ^ (uint64_t)sign) + ((uint64_t)sign & 1));
}
/* Truncated Q2.62 product of normalized square-root intermediates. */
static inline uint64_t fxr_sqrt_mul(uint64_t a, uint64_t b)
{
    return (uint64_t)(((__uint128_t)a * b) >> 62);
}
/*
 * ePrint 2026/1531, Section 3.4: y <- y * (3 - x*y*y) / 2.
 * Normalize x to [1, 4) in Q2.62; 5 fixed steps give enough precision
 * to recover the correctly rounded result. See doc/designs/fn-dsa.md.
 */
static inline FN_DSA_REAL fxr_sqrt(FN_DSA_REAL a)
{
    uint64_t raw = (uint64_t)a, nonzero = raw != 0;
    uint64_t x = raw | (1 ^ nonzero), y;
    uint64_t root, square, factor;
    int64_t remainder;
    unsigned exponent = fxr_log2_u64(x) & ~1u, i;

    x <<= 62 - exponent;
    /* Linear seed (35 - 5*x) / 32 has relative error below 1/8. */
    y = (UINT64_C(35) << 57) - (x >> 3) - (x >> 5);
    for (i = 0; i < 5; i++) {
        square = fxr_sqrt_mul(y, y);
        factor = ((UINT64_C(3) << 62) - fxr_sqrt_mul(x, square)) >> 1;
        y = fxr_sqrt_mul(y, factor);
    }
    root = fxr_sqrt_mul(x, y) >> (46 - exponent / 2);
    /* Before truncation, the approximation is within 1/4 ulp. This low-word
     * subtraction recovers the exact remainder; only rounding up is needed. */
    remainder = (int64_t)((raw << 32) - root * root);
    root += remainder > (int64_t)root;
    return (int64_t)(root & (0 - nonzero));
}
static inline int64_t fxr_trunc(FN_DSA_REAL a)
{
    uint64_t x = fxr_abs(a) >> 32, sign = (uint64_t)a >> 63;
    return (int64_t)((x ^ (0 - sign)) + sign);
}
static inline int64_t fxr_floor(FN_DSA_REAL a) { return a >> 32; }
static inline int64_t fxr_rint(FN_DSA_REAL a)
{
    uint64_t x = fxr_abs(a), n = x >> 32, r = (uint32_t)x;
    uint64_t sign = (uint64_t)a >> 63;
    n += (r > UINT64_C(0x80000000)) | ((r == UINT64_C(0x80000000)) & (n & 1));
    return (int64_t)((n ^ (0 - sign)) + sign);
}
static inline uint64_t fxr_q63(FN_DSA_REAL a) { return (uint64_t)a << 31; }
#endif
