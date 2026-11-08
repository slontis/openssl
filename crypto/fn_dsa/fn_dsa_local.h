/* Fixed-point arithmetic and workspace management for FN-DSA. */
#ifndef FN_DSA_LOCAL_H
#define FN_DSA_LOCAL_H
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef FN_DSA_KEYGEN
#include "fn_dsa_keygen_fxp.h"
#else
#include "fn_dsa_fxp.h"
#endif
#include "fn_dsa_exp.h"

typedef struct {
    unsigned char *mem;
    size_t used, capacity, highwater;
    int ok;
} FN_DSA_WORK;
typedef struct {
    EVP_MD_CTX *ctx;
} FN_DSA_XOF;
typedef struct {
    int8_t bd[512], sd[256];
    int32_t ptr, state[16];
} FN_DSA_RNG;
typedef struct {
    FN_DSA_REAL sigma_min;
    FN_DSA_RNG *p;
} FN_DSA_SAMPLER;
typedef struct {
    int32_t p, g, s;
} FN_DSA_PRIME;

static inline void *fn_dsa_alloc(FN_DSA_WORK *w, size_t n)
{
    void *p;
    n = (n + 15) & ~(size_t)15;
    if (!w->ok || n > w->capacity - w->used) {
        w->ok = 0;
        return NULL;
    }
    p = w->mem + w->used;
    memset(p, 0, n);
    w->used += n;
    if (w->used > w->highwater)
        w->highwater = w->used;
    return p;
}
static inline void fn_dsa_release(FN_DSA_WORK *w, size_t mark)
{
    OPENSSL_cleanse(w->mem + mark, w->used - mark);
    w->used = mark;
}
static inline int32_t fn_dsa_min32(int32_t a, int32_t b)
{
    return a < b ? a : b;
}
static inline int64_t fn_dsa_pack_littleEndianToLong(int8_t *p, int32_t off)
{
    uint64_t u = 0;
    unsigned i;
    for (i = 0; i < 8; ++i)
        u |= (uint64_t)(uint8_t)p[off + i] << (8 * i);
    return ((int64_t)(u));
}
static inline int32_t fn_dsa_pack_littleEndianToInt(int8_t *p, int32_t off)
{
    uint32_t u = 0;
    unsigned i;
    for (i = 0; i < 4; ++i)
        u |= (uint32_t)(uint8_t)p[off + i] << (8 * i);
    return ((int32_t)(u));
}
static inline void fn_dsa_pack_littleEndianToInts(int8_t *p, int32_t off,
                                                  int32_t *dst, int32_t pos,
                                                  int32_t n)
{
    int32_t i;
    for (i = 0; i < n; ++i)
        dst[pos + i] = fn_dsa_pack_littleEndianToInt(p, off + 4 * i);
}
static inline void fn_dsa_pack_intToLittleEndian(int32_t x, int8_t *p,
                                                 int32_t off)
{
    unsigned i;
    for (i = 0; i < 4; ++i)
        p[off + i] = ((int8_t)((uint8_t)((uint32_t)x >> (8 * i))));
}
static inline void fn_dsa_pack_longToLittleEndian(int64_t x, int8_t *p,
                                                  int32_t off)
{
    unsigned i;
    for (i = 0; i < 8; ++i)
        p[off + i] = ((int8_t)((uint8_t)((uint64_t)x >> (8 * i))));
}
static inline void fn_dsa_xof_out(FN_DSA_WORK *wk, FN_DSA_XOF *x, int8_t *out,
                                  int32_t off, int32_t n)
{
    if (!EVP_DigestSqueeze(x->ctx, (unsigned char *)out + off, (size_t)n))
        wk->ok = 0;
}
#endif
