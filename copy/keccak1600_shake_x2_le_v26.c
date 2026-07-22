#include "keccak1600_shake_x2_le_v26.h"

#include <string.h>

#if !defined(OSSL_SHAKE_X2_TEST_PORTABLE)
# if !defined(__aarch64__) && !defined(__arm64__) && !defined(_M_ARM64)
#  error "This implementation requires AArch64"
# endif
# if defined(__AARCH64EB__) || defined(__ARMEB__) || \
     (defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) && \
      __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#  error "This implementation requires little-endian AArch64"
# endif
# include "arch/arm_arch.h"
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(uint64_t) == 8, "64-bit uint64_t required");
_Static_assert(_Alignof(OSSL_SHAKE_X2_CTX) >= 16,
               "context must be 16-byte aligned");
#endif

static const uint64_t keccak_iotas[24] = {
    UINT64_C(0x0000000000000001), UINT64_C(0x0000000000008082),
    UINT64_C(0x800000000000808a), UINT64_C(0x8000000080008000),
    UINT64_C(0x000000000000808b), UINT64_C(0x0000000080000001),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008009),
    UINT64_C(0x000000000000008a), UINT64_C(0x0000000000000088),
    UINT64_C(0x0000000080008009), UINT64_C(0x000000008000000a),
    UINT64_C(0x000000008000808b), UINT64_C(0x800000000000008b),
    UINT64_C(0x8000000000008089), UINT64_C(0x8000000000008003),
    UINT64_C(0x8000000000008002), UINT64_C(0x8000000000000080),
    UINT64_C(0x000000000000800a), UINT64_C(0x800000008000000a),
    UINT64_C(0x8000000080008081), UINT64_C(0x8000000000008080),
    UINT64_C(0x0000000080000001), UINT64_C(0x8000000080008008)
};

/* Indexed as rho[x][y]. */
static const unsigned char keccak_rho[25] = {
     0, 36,  3, 41, 18,
     1, 44, 10, 45,  2,
    62,  6, 43, 15, 61,
    28, 55, 25, 21, 56,
    27, 20, 39,  8, 14
};

static void cleanse(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;

    while (n-- != 0)
        *q++ = 0;
}

static int armv8_sha3_available(void)
{
#if defined(OSSL_SHAKE_X2_TEST_PORTABLE)
    return 0;
#else
    return (OPENSSL_armcap_P & ARMV8_SHA3) != 0;
#endif
}

static uint64_t rol64(uint64_t value, unsigned int count)
{
    return count == 0 ? value
                      : (value << count) | (value >> (64u - count));
}

static void keccak1600_permute_c(uint64_t state[OSSL_KECCAK1600_LANES])
{
    uint64_t column[5];
    uint64_t permuted[OSSL_KECCAK1600_LANES];
    size_t round;
    size_t x;
    size_t y;

    for (round = 0; round < 24; ++round) {
        for (x = 0; x < 5; ++x) {
            column[x] = state[x] ^ state[5 + x] ^ state[10 + x]
                      ^ state[15 + x] ^ state[20 + x];
        }

        for (x = 0; x < 5; ++x) {
            uint64_t correction = column[(x + 4) % 5]
                                ^ rol64(column[(x + 1) % 5], 1);

            for (y = 0; y < 5; ++y)
                state[5 * y + x] ^= correction;
        }

        for (x = 0; x < 5; ++x) {
            for (y = 0; y < 5; ++y) {
                size_t dst_x = y;
                size_t dst_y = (2 * x + 3 * y) % 5;

                permuted[5 * dst_y + dst_x] =
                    rol64(state[5 * y + x], keccak_rho[5 * x + y]);
            }
        }

        for (y = 0; y < 5; ++y) {
            for (x = 0; x < 5; ++x) {
                state[5 * y + x] = permuted[5 * y + x]
                    ^ ((~permuted[5 * y + ((x + 1) % 5)])
                       & permuted[5 * y + ((x + 2) % 5)]);
            }
        }

        state[0] ^= keccak_iotas[round];
    }
}

static void keccak1600_2x_permute_c(uint64_t state[OSSL_KECCAK1600_X2_WORDS])
{
    uint64_t state_a[OSSL_KECCAK1600_LANES];
    uint64_t state_b[OSSL_KECCAK1600_LANES];
    size_t lane;

    for (lane = 0; lane < OSSL_KECCAK1600_LANES; ++lane) {
        state_a[lane] = state[2 * lane];
        state_b[lane] = state[2 * lane + 1];
    }

    keccak1600_permute_c(state_a);
    keccak1600_permute_c(state_b);

    for (lane = 0; lane < OSSL_KECCAK1600_LANES; ++lane) {
        state[2 * lane] = state_a[lane];
        state[2 * lane + 1] = state_b[lane];
    }

    cleanse(state_a, sizeof(state_a));
    cleanse(state_b, sizeof(state_b));
}

static void interleave_block(uint64_t *dst, const uint8_t *a,
                             const uint8_t *b, size_t rate)
{
    size_t lane;

    for (lane = 0; lane < rate / 8; ++lane) {
        memcpy(&dst[2 * lane], a + 8 * lane, sizeof(uint64_t));
        memcpy(&dst[2 * lane + 1], b + 8 * lane, sizeof(uint64_t));
    }
}

static void absorb_block_c(uint64_t *state, const uint64_t *interleaved,
                           size_t rate, int xor_existing)
{
    size_t words = 2 * (rate / 8);
    size_t i;

    if (!xor_existing)
        memset(state, 0, OSSL_KECCAK1600_X2_WORDS * sizeof(*state));

    for (i = 0; i < words; ++i) {
        if (xor_existing)
            state[i] ^= interleaved[i];
        else
            state[i] = interleaved[i];
    }

    keccak1600_2x_permute_c(state);
}

static void absorb_block(OSSL_SHAKE_X2_CTX *ctx, const uint8_t *a,
                         const uint8_t *b)
{
    _Alignas(16) uint64_t interleaved[2 * (OSSL_SHAKE128_RATE / 8)];
    int xor_existing = ctx->initialized != 0;

    interleave_block(interleaved, a, b, ctx->rate);

#if !defined(OSSL_SHAKE_X2_TEST_PORTABLE)
    if (ctx->use_armv8_sha3) {
        if (ctx->variant == OSSL_SHAKE_X2_128) {
            if (xor_existing)
                ossl_shake128_x2_absorb_update_armv8(ctx->state,
                                                     interleaved);
            else
                ossl_shake128_x2_absorb_init_armv8(ctx->state,
                                                   interleaved);
        } else {
            if (xor_existing)
                ossl_shake256_x2_absorb_update_armv8(ctx->state,
                                                     interleaved);
            else
                ossl_shake256_x2_absorb_init_armv8(ctx->state,
                                                   interleaved);
        }
    } else
#endif
    {
        absorb_block_c(ctx->state, interleaved, ctx->rate, xor_existing);
    }

    ctx->initialized = 1;
    cleanse(interleaved, sizeof(interleaved));
}

int ossl_shake_x2_init(OSSL_SHAKE_X2_CTX *ctx, OSSL_SHAKE_X2_VARIANT variant)
{
    if (ctx == NULL || (variant != OSSL_SHAKE_X2_128
                        && variant != OSSL_SHAKE_X2_256))
        return 0;

    memset(ctx, 0, sizeof(*ctx));
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->variant = variant;
    ctx->rate = variant == OSSL_SHAKE_X2_128 ? OSSL_SHAKE128_RATE
                                             : OSSL_SHAKE256_RATE;
    ctx->use_armv8_sha3 = (unsigned int)armv8_sha3_available();
    return 1;
}

int ossl_shake_x2_update(OSSL_SHAKE_X2_CTX *ctx,
                         const uint8_t *in_a, const uint8_t *in_b, size_t len)
{
    size_t take;

    if (ctx == NULL || ctx->finalized
        || (len != 0 && (in_a == NULL || in_b == NULL)))
        return 0;

    while (len != 0) {
        take = ctx->rate - ctx->used;
        if (take > len)
            take = len;

        memcpy(ctx->block + ctx->used, in_a, take);
        memcpy(ctx->block + ctx->rate + ctx->used, in_b, take);
        ctx->used += take;
        in_a += take;
        in_b += take;
        len -= take;

        if (ctx->used == ctx->rate) {
            absorb_block(ctx, ctx->block, ctx->block + ctx->rate);
            ctx->used = 0;
        }
    }
    return 1;
}

int ossl_shake_x2_final(OSSL_SHAKE_X2_CTX *ctx)
{
    uint8_t *a;
    uint8_t *b;

    if (ctx == NULL || ctx->finalized)
        return 0;

    a = ctx->block;
    b = ctx->block + ctx->rate;
    memset(a + ctx->used, 0, ctx->rate - ctx->used);
    memset(b + ctx->used, 0, ctx->rate - ctx->used);

    a[ctx->used] ^= 0x1f;
    b[ctx->used] ^= 0x1f;
    a[ctx->rate - 1] ^= 0x80;
    b[ctx->rate - 1] ^= 0x80;
    absorb_block(ctx, a, b);

    ctx->used = 0;
    ctx->squeeze_pos = 0;
    ctx->finalized = 1;
    cleanse(ctx->block, sizeof(ctx->block));
    return 1;
}

static void extract_rate_block(const OSSL_SHAKE_X2_CTX *ctx,
                               uint8_t *a, uint8_t *b)
{
    size_t lane;

    for (lane = 0; lane < ctx->rate / 8; ++lane) {
        memcpy(a + 8 * lane, &ctx->state[2 * lane], sizeof(uint64_t));
        memcpy(b + 8 * lane, &ctx->state[2 * lane + 1], sizeof(uint64_t));
    }
}

static void permute_x2(OSSL_SHAKE_X2_CTX *ctx)
{
#if !defined(OSSL_SHAKE_X2_TEST_PORTABLE)
    if (ctx->use_armv8_sha3) {
        keccak1600_2x_permute_armv8(ctx->state);
        return;
    }
#endif
    keccak1600_2x_permute_c(ctx->state);
}

int ossl_shake_x2_squeeze(OSSL_SHAKE_X2_CTX *ctx,
                          uint8_t *out_a, uint8_t *out_b, size_t len)
{
    _Alignas(16) uint8_t a[OSSL_SHAKE128_RATE];
    _Alignas(16) uint8_t b[OSSL_SHAKE128_RATE];
    size_t take;

    if (ctx == NULL || !ctx->finalized
        || (len != 0 && (out_a == NULL || out_b == NULL)))
        return 0;

    while (len != 0) {
        if (ctx->squeeze_pos == ctx->rate) {
            permute_x2(ctx);
            ctx->squeeze_pos = 0;
        }

        extract_rate_block(ctx, a, b);
        take = ctx->rate - ctx->squeeze_pos;
        if (take > len)
            take = len;
        memcpy(out_a, a + ctx->squeeze_pos, take);
        memcpy(out_b, b + ctx->squeeze_pos, take);
        out_a += take;
        out_b += take;
        len -= take;
        ctx->squeeze_pos += take;
    }

    cleanse(a, sizeof(a));
    cleanse(b, sizeof(b));
    return 1;
}

void ossl_shake_x2_reset(OSSL_SHAKE_X2_CTX *ctx)
{
    if (ctx != NULL)
        cleanse(ctx, sizeof(*ctx));
}
