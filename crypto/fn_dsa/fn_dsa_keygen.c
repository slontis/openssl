#define FN_DSA_KEYGEN
#include "fn_dsa_core.h"
#include "fn_dsa_fixed.inc"

#include <openssl/rand.h>

#define FN_DSA_WORK_CAPACITY (4 * 1024 * 1024)

static int start(FN_DSA_WORK *w)
{
    memset(w, 0, sizeof(*w));
    w->mem = OPENSSL_zalloc(FN_DSA_WORK_CAPACITY);
    if (w->mem == NULL)
        return 0;
    w->capacity = FN_DSA_WORK_CAPACITY;
    w->ok = 1;
    return 1;
}

static void finish(FN_DSA_WORK *w)
{
    OPENSSL_clear_free(w->mem, w->capacity);
}

static int xof_seed(FN_DSA_XOF *x, const unsigned char *seed, size_t len)
{
    return EVP_DigestInit_ex2(x->ctx, NULL, NULL) &&
           EVP_DigestUpdate(x->ctx, seed, len);
}

static int keygen_seed(EVP_MD_CTX *mdctx, unsigned l,
                       const unsigned char *seed, size_t seedlen,
                       unsigned char *pk, unsigned char *sk)
{
    FN_DSA_WORK w;
    FN_DSA_XOF x = { mdctx };
    int8_t *f, *g, *F;
    int16_t *h;
    size_t n, sksize = ossl_fn_dsa_core_sk_size(l), pksize = ossl_fn_dsa_core_pk_size(l);
    int32_t u, v;
    int ret = 0;
    if (mdctx == NULL || sksize == 0 || pk == NULL || sk == NULL || seed == NULL)
        return 0;
    n = (size_t)1 << l;
    if (!start(&w))
        goto end;
    f = fn_dsa_alloc(&w, n);
    g = fn_dsa_alloc(&w, n);
    F = fn_dsa_alloc(&w, n);
    h = fn_dsa_alloc(&w, 2 * n);
    if (!w.ok || !xof_seed(&x, seed, seedlen))
        goto end;
    fn_dsa_keygen(&w, &x, f, g, F, h, (int32_t)l);
    if (!w.ok)
        goto end;
    sk[0] = (unsigned char)(0x50 + l);
    u = 1;
    v = fn_dsa_trim_i8_encode(((int8_t *)sk + (u)), (int32_t)sksize - u, f,
                              (int32_t)l, fn_dsa_max_fg_bits[l]);
    if (v == 0)
        goto end;
    u += v;
    v = fn_dsa_trim_i8_encode(((int8_t *)sk + (u)), (int32_t)sksize - u, g,
                              (int32_t)l, fn_dsa_max_fg_bits[l]);
    if (v == 0)
        goto end;
    u += v;
    v = fn_dsa_trim_i8_encode(((int8_t *)sk + (u)), (int32_t)sksize - u, F,
                              (int32_t)l, fn_dsa_max_FG_bits[l]);
    if (v == 0 || (size_t)(u + v) != sksize)
        goto end;
    pk[0] = (unsigned char)l;
    ret = fn_dsa_modq_encode((int8_t *)pk, (int32_t)pksize - 1, h,
                             (int32_t)l) == (int32_t)pksize - 1 &&
          w.ok;
end:
    if (!ret) {
        OPENSSL_cleanse(sk, sksize);
        OPENSSL_cleanse(pk, pksize);
    }
    finish(&w);
    return ret;
}
int ossl_fn_dsa_core_keygen(OSSL_LIB_CTX *libctx, unsigned l, unsigned char *pk,
                       unsigned char *sk)
{
    unsigned char seed[48];
    EVP_MD_CTX *mdctx;
    int ret;
    if (RAND_priv_bytes_ex(libctx, seed, sizeof(seed), 256) <= 0)
        return 0;
    mdctx = ossl_fn_dsa_core_new_hash_ctx(libctx, NULL);
    ret = mdctx != NULL && keygen_seed(mdctx, l, seed, sizeof(seed), pk, sk);
    EVP_MD_CTX_free(mdctx);
    OPENSSL_cleanse(seed, sizeof(seed));
    return ret;
}

/* The development seed profile feeds 32 bytes directly to SHAKE-256.
 * The arithmetic and byte consumption are deterministic. This profile is
 * subject to alignment with the eventual normative FN-DSA KeyGen procedure.
 */
int ossl_fn_dsa_core_keygen_from_seed(EVP_MD_CTX *mdctx,
    unsigned l, const unsigned char *seed, size_t seedlen,
    unsigned char *pk, unsigned char *sk)
{
    if (seedlen != 32)
        return 0;
    return keygen_seed(mdctx, l, seed, seedlen, pk, sk);
}

#ifdef FN_DSA_TESTING
int fn_dsa_keygen_max_bits_test(const int32_t *f, int len, int stride, int logn)
{
    return fn_dsa_poly_max_bits(f, len, stride, logn);
}
void fn_dsa_keygen_scaled_test(int64_t *out, int32_t *f, int len, int stride,
                               int logn, int scale)
{
    fn_dsa_poly_big_to_fxp(out, f, len, stride, logn, scale);
}
int fn_dsa_keygen_seed(OSSL_LIB_CTX *c, unsigned l, const unsigned char s[48],
                       unsigned char *p, unsigned char *k)
{
    EVP_MD_CTX *mdctx = ossl_fn_dsa_core_new_hash_ctx(c, NULL);
    int ret;

    if (mdctx == NULL)
        return 0;
    ret = keygen_seed(mdctx, l, s, 48, p, k);
    EVP_MD_CTX_free(mdctx);
    return ret;
}

#endif
