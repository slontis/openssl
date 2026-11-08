#include "fn_dsa_core.h"
#include "fn_dsa_fixed.inc"

#include <openssl/rand.h>

size_t ossl_fn_dsa_core_pk_size(unsigned l)
{
    return l == 9 ? 897 : l == 10 ? 1793 : 0;
}
size_t ossl_fn_dsa_core_sk_size(unsigned l)
{
    return l == 9 ? 1281 : l == 10 ? 2305 : 0;
}
size_t ossl_fn_dsa_core_sig_size(unsigned l)
{
    return l == 9 ? 690 : l == 10 ? 1330 : 0;
}

int ossl_fn_dsa_core_check_public(unsigned l, const unsigned char *pk, size_t pklen)
{
    int16_t h[1024];

    return ossl_fn_dsa_core_pk_size(l) != 0 && pk != NULL
        && pklen == ossl_fn_dsa_core_pk_size(l) && pk[0] == l
        && fn_dsa_modq_decode(h, (int32_t)l, (int8_t *)pk + 1,
               (int32_t)pklen - 1) == (int32_t)pklen - 1;
}

/* Raw operation entry points use this once; native keys cache the EVP_MD. */
EVP_MD_CTX *ossl_fn_dsa_core_new_hash_ctx(OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_MD *md = EVP_MD_fetch(libctx, "SHAKE-256", propq);
    EVP_MD_CTX *ctx = NULL;

    if (md != NULL) {
        ctx = EVP_MD_CTX_new();
        if (ctx != NULL && !EVP_DigestInit_ex2(ctx, md, NULL)) {
            EVP_MD_CTX_free(ctx);
            ctx = NULL;
        }
    }
    EVP_MD_free(md);
    return ctx;
}

static int start(FN_DSA_WORK *w, size_t capacity)
{
    memset(w, 0, sizeof(*w));
    w->mem = OPENSSL_zalloc(capacity);
    if (w->mem == NULL)
        return 0;
    w->capacity = capacity;
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

static int private_equation(const int8_t *f, const int8_t *g, const int8_t *F,
                            const int8_t *G, size_t n)
{
    size_t i, j;
    uint32_t bad = 0;
    for (i = 0; i < n; i++) {
        int32_t sum = 0;
        for (j = 0; j < n; j++) {
            size_t k = (i + n - j) & (n - 1);
            int32_t z = (int32_t)f[j] * G[k] - (int32_t)g[j] * F[k];
            sum += j <= i ? z : -z;
        }
        bad |= (uint32_t)(sum - (i == 0 ? 12289 : 0));
    }
    return bad == 0;
}

static int decode_private(FN_DSA_WORK *w, unsigned l, const unsigned char *sk,
                          size_t sklen, int8_t *f, int8_t *g, int8_t *F,
                          int8_t *G, int16_t *tmp)
{
    int32_t u = 1, v;
    if (sk == NULL || sklen != ossl_fn_dsa_core_sk_size(l) || sk[0] != 0x50 + l)
        return 0;
    v = fn_dsa_trim_i8_decode(f, (int32_t)l, fn_dsa_max_fg_bits[l],
                              ((int8_t *)sk + (u)), (int32_t)sklen - u);
    if (v == 0)
        return 0;
    u += v;
    v = fn_dsa_trim_i8_decode(g, (int32_t)l, fn_dsa_max_fg_bits[l],
                              ((int8_t *)sk + (u)), (int32_t)sklen - u);
    if (v == 0)
        return 0;
    u += v;
    v = fn_dsa_trim_i8_decode(F, (int32_t)l, fn_dsa_max_FG_bits[l],
                              ((int8_t *)sk + (u)), (int32_t)sklen - u);
    if (v == 0 || (size_t)(u + v) != sklen)
        return 0;
    return fn_dsa_complete_private(G, f, g, F, (int32_t)l, tmp) && w->ok &&
           private_equation(f, g, F, G, (size_t)1 << l) &&
           fn_dsa_bounds_post(w, f, g, F, G, l);
}

int ossl_fn_dsa_core_public(unsigned l,
                       const unsigned char *sk, size_t sklen, unsigned char *pk)
{
    FN_DSA_WORK w;
    int8_t *f, *g, *F, *G;
    int16_t *h, *tmp;
    size_t n, pksize = ossl_fn_dsa_core_pk_size(l);
    int ret = 0;
    if (pksize == 0 || pk == NULL)
        return 0;
    n = (size_t)1 << l;
    if (!start(&w, 128 * 1024))
        goto end;
    f = fn_dsa_alloc(&w, n);
    g = fn_dsa_alloc(&w, n);
    F = fn_dsa_alloc(&w, n);
    G = fn_dsa_alloc(&w, n);
    h = fn_dsa_alloc(&w, 2 * n);
    tmp = fn_dsa_alloc(&w, 4 * n);
    if (!w.ok || !decode_private(&w, l, sk, sklen, f, g, F, G, tmp))
        goto end;
    if (!fn_dsa_compute_public((h + (0)), f, g, (int32_t)l, (tmp + (0))))
        goto end;
    pk[0] = (unsigned char)l;
    ret = fn_dsa_modq_encode((int8_t *)pk, (int32_t)pksize - 1, h,
                             (int32_t)l) == (int32_t)pksize - 1 &&
          w.ok;
end:
    finish(&w);
    return ret;
}

static int sign_seed(EVP_MD_CTX *mdctx, unsigned l, const unsigned char *sk,
                     size_t sklen, const unsigned char *prefix, size_t prefixlen,
                     const unsigned char *msg, size_t msglen,
                     const unsigned char nonce[40],
                     const unsigned char seed[48], unsigned char *sig,
                     size_t *siglen, size_t sigcap)
{
    FN_DSA_WORK w;
    FN_DSA_XOF x = { mdctx };
    int8_t *f, *g, *F, *G;
    int16_t *hm, *s, *tmp;
    FN_DSA_REAL *ftmp;
    size_t n, maxsig = ossl_fn_dsa_core_sig_size(l);
    int32_t v;
    int ret = 0;
    if (maxsig == 0 || siglen == NULL || sk == NULL ||
        (msg == NULL && msglen != 0) || (prefix == NULL && prefixlen != 0))
        return 0;
    if (sig == NULL) {
        *siglen = maxsig;
        return 1;
    }
    *siglen = 0;
    if (sigcap < maxsig || nonce == NULL || seed == NULL || mdctx == NULL)
        return 0;
    n = (size_t)1 << l;
    if (!start(&w, 512 * 1024))
        goto end;
    f = fn_dsa_alloc(&w, n);
    g = fn_dsa_alloc(&w, n);
    F = fn_dsa_alloc(&w, n);
    G = fn_dsa_alloc(&w, n);
    hm = fn_dsa_alloc(&w, 2 * n);
    s = fn_dsa_alloc(&w, 2 * n);
    tmp = fn_dsa_alloc(&w, 4 * n);
    ftmp = fn_dsa_alloc(&w, 16 * n * sizeof(*ftmp));
    if (!w.ok || !decode_private(&w, l, sk, sklen, f, g, F, G, tmp))
        goto end;
    if (!xof_seed(&x, nonce, 40)
        || (prefixlen != 0 && !EVP_DigestUpdate(x.ctx, prefix, prefixlen))
        || !EVP_DigestUpdate(x.ctx, msg, msglen))
        goto end;
    /* This hash depends only on the public nonce and message. */
    fn_dsa_hash_to_point_vartime(&w, &x, hm, (int32_t)l);
    if (!w.ok || !xof_seed(&x, seed, 48))
        goto end;
    /* Algorithm 7 also rejects vectors exceeding the compressed size bound. */
    do {
        fn_dsa_sign_dyn(&w, s, &x, f, g, F, G, hm, (int32_t)l, ftmp);
        if (!w.ok)
            goto end;
        v = fn_dsa_comp_encode((int8_t *)sig + 41, (int32_t)maxsig - 41, s,
                               (int32_t)l);
    } while (v == 0);
    sig[0] = (unsigned char)(0x30 + l);
    memcpy(sig + 1, nonce, 40);
    *siglen = 41 + (size_t)v;
    ret = 1;
end:
    if (!ret)
        OPENSSL_cleanse(sig, sigcap);
    finish(&w);
    return ret;
}
int ossl_fn_dsa_core_sign_ex(OSSL_LIB_CTX *libctx, EVP_MD_CTX *mdctx, unsigned l, const unsigned char *sk,
                     size_t sklen, const unsigned char *prefix, size_t prefixlen,
                     const unsigned char *msg, size_t msglen,
                     unsigned char *sig, size_t *siglen, size_t sigcap)
{
    unsigned char material[88];
    int ret = 0;

    if (ossl_fn_dsa_core_sk_size(l) == 0 || sk == NULL
        || sklen != ossl_fn_dsa_core_sk_size(l) || siglen == NULL
        || (prefix == NULL && prefixlen != 0) || (msg == NULL && msglen != 0))
        return 0;
    if (sig == NULL)
        return sign_seed(mdctx, l, sk, sklen, prefix, prefixlen, msg, msglen, NULL, NULL, sig,
                         siglen, sigcap);
    if (RAND_bytes_ex(libctx, material, 40, 256) <= 0
        || RAND_priv_bytes_ex(libctx, material + 40, 48, 256) <= 0)
        goto end;
    ret = sign_seed(mdctx, l, sk, sklen, prefix, prefixlen, msg, msglen,
                    material, material + 40, sig, siglen,
                    sigcap);
end:
    OPENSSL_cleanse(material, sizeof(material));
    return ret;
}
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
/* Only built with enable-fn-dsa-test-entropy; never a production signing mode. */
int ossl_fn_dsa_core_sign_test_ex(EVP_MD_CTX *mdctx, unsigned l,
    const unsigned char *sk, size_t sklen,
    const unsigned char *prefix, size_t prefixlen,
    const unsigned char *msg, size_t msglen, const unsigned char entropy[88],
    unsigned char *sig, size_t *siglen, size_t sigcap)
{
    if (entropy == NULL)
        return 0;
    return sign_seed(mdctx, l, sk, sklen, prefix, prefixlen, msg, msglen,
        entropy, entropy + 40, sig, siglen, sigcap);
}
#endif

int ossl_fn_dsa_core_verify_ex(EVP_MD_CTX *mdctx, unsigned l,
                       const unsigned char *pk, size_t pklen,
                       const unsigned char *prefix, size_t prefixlen,
                       const unsigned char *msg, size_t msglen,
                       const unsigned char *sig, size_t siglen)
{
    FN_DSA_WORK w;
    FN_DSA_XOF x = { mdctx };
    int16_t *h, *hm, *s, *tmp;
    size_t n, maxsig = ossl_fn_dsa_core_sig_size(l);
    int ret = 0;
    if (mdctx == NULL || maxsig == 0 || pk == NULL || sig == NULL ||
        (msg == NULL && msglen != 0) || (prefix == NULL && prefixlen != 0)
        || pklen != ossl_fn_dsa_core_pk_size(l) ||
        pk[0] != l || siglen <= 41 || siglen > maxsig || sig[0] != 0x30 + l)
        return 0;
    n = (size_t)1 << l;
    if (!start(&w, 16 * 1024))
        goto end;
    h = fn_dsa_alloc(&w, 2 * n);
    hm = fn_dsa_alloc(&w, 2 * n);
    s = fn_dsa_alloc(&w, 2 * n);
    tmp = fn_dsa_alloc(&w, 2 * n);
    if (!w.ok || fn_dsa_modq_decode(h, (int32_t)l, (int8_t *)pk + 1,
                                    (int32_t)pklen - 1) != (int32_t)pklen - 1)
        goto end;
    if (fn_dsa_comp_decode(s, (int32_t)l, (int8_t *)sig + 41,
                           (int32_t)siglen - 41) != (int32_t)siglen - 41)
        goto end;
    fn_dsa_to_ntt_monty(h, (int32_t)l);
    if (!xof_seed(&x, sig + 1, 40)
        || (prefixlen != 0 && !EVP_DigestUpdate(x.ctx, prefix, prefixlen))
        || !EVP_DigestUpdate(x.ctx, msg, msglen))
        goto end;
    fn_dsa_hash_to_point_vartime(&w, &x, hm, (int32_t)l);
    ret = fn_dsa_verify_raw(hm, s, h, (int32_t)l, tmp) != 0 && w.ok;
end:
    finish(&w);
    return ret;
}
int ossl_fn_dsa_core_sign(OSSL_LIB_CTX *libctx, unsigned l,
    const unsigned char *sk, size_t sklen, const unsigned char *msg, size_t msglen,
    unsigned char *sig, size_t *siglen, size_t sigcap)
{
    EVP_MD_CTX *mdctx;
    int ret;

    if (sig == NULL)
        return ossl_fn_dsa_core_sign_ex(libctx, NULL, l, sk, sklen, NULL, 0,
            msg, msglen, sig, siglen, sigcap);
    if ((mdctx = ossl_fn_dsa_core_new_hash_ctx(libctx, NULL)) == NULL)
        return 0;
    ret = ossl_fn_dsa_core_sign_ex(libctx, mdctx, l, sk, sklen, NULL, 0,
        msg, msglen, sig, siglen, sigcap);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
int ossl_fn_dsa_core_verify(OSSL_LIB_CTX *libctx, unsigned l,
    const unsigned char *pk, size_t pklen, const unsigned char *msg, size_t msglen,
    const unsigned char *sig, size_t siglen)
{
    EVP_MD_CTX *mdctx = ossl_fn_dsa_core_new_hash_ctx(libctx, NULL);
    int ret;

    if (mdctx == NULL)
        return 0;
    ret = ossl_fn_dsa_core_verify_ex(mdctx, l, pk, pklen, NULL, 0,
        msg, msglen, sig, siglen);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
#ifdef FN_DSA_TESTING
int fn_dsa_sign_seed(OSSL_LIB_CTX *c, unsigned l, const unsigned char *k,
                     size_t kl, const unsigned char *m, size_t ml,
                     const unsigned char n[40], const unsigned char s[48],
                     unsigned char *o, size_t *ol, size_t cap)
{
    EVP_MD_CTX *mdctx = ossl_fn_dsa_core_new_hash_ctx(c, NULL);
    int ret;

    if (mdctx == NULL)
        return 0;
    ret = sign_seed(mdctx, l, k, kl, NULL, 0, m, ml, n, s, o, ol, cap);
    EVP_MD_CTX_free(mdctx);
    return ret;
}
#endif
