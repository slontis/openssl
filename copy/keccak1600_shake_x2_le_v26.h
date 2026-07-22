#ifndef OSSL_KECCAK1600_SHAKE_X2_LE_V26_H
#define OSSL_KECCAK1600_SHAKE_X2_LE_V26_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
# define OSSL_SHAKE_X2_ALIGNAS(n) alignas(n)
#else
# define OSSL_SHAKE_X2_ALIGNAS(n) _Alignas(n)
#endif

#define OSSL_SHAKE128_RATE 168u
#define OSSL_SHAKE256_RATE 136u
#define OSSL_KECCAK1600_LANES 25u
#define OSSL_KECCAK1600_X2_WORDS 50u

typedef enum {
    OSSL_SHAKE_X2_128 = 128,
    OSSL_SHAKE_X2_256 = 256
} OSSL_SHAKE_X2_VARIANT;

typedef struct {
    OSSL_SHAKE_X2_ALIGNAS(16) uint64_t state[OSSL_KECCAK1600_X2_WORDS];
    OSSL_SHAKE_X2_ALIGNAS(16) uint8_t block[2 * OSSL_SHAKE128_RATE];
    size_t used;
    size_t squeeze_pos;
    size_t rate;
    OSSL_SHAKE_X2_VARIANT variant;
    unsigned int finalized;
    unsigned int initialized;
    unsigned int use_armv8_sha3;
} OSSL_SHAKE_X2_CTX;

void ossl_shake128_x2_absorb_init_armv8(
    uint64_t *state, const uint64_t *msg_interleaved);
void ossl_shake128_x2_absorb_update_armv8(
    uint64_t *state, const uint64_t *msg_interleaved);
void ossl_shake256_x2_absorb_init_armv8(
    uint64_t *state, const uint64_t *msg_interleaved);
void ossl_shake256_x2_absorb_update_armv8(
    uint64_t *state, const uint64_t *msg_interleaved);
void keccak1600_2x_permute_armv8(uint64_t *state);

int ossl_shake_x2_init(OSSL_SHAKE_X2_CTX *ctx,
                       OSSL_SHAKE_X2_VARIANT variant);
int ossl_shake_x2_update(OSSL_SHAKE_X2_CTX *ctx,
                         const uint8_t *in_a, const uint8_t *in_b,
                         size_t len);
int ossl_shake_x2_final(OSSL_SHAKE_X2_CTX *ctx);
int ossl_shake_x2_squeeze(OSSL_SHAKE_X2_CTX *ctx,
                          uint8_t *out_a, uint8_t *out_b, size_t len);
void ossl_shake_x2_reset(OSSL_SHAKE_X2_CTX *ctx);

#ifdef __cplusplus
}
#endif

#undef OSSL_SHAKE_X2_ALIGNAS
#endif
