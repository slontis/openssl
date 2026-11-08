/* Internal FN-DSA API. This is not an OpenSSL public header. */
#ifndef OSSL_FN_DSA_CORE_H
#define OSSL_FN_DSA_CORE_H
#include <openssl/types.h>
#include <stddef.h>
#define FN_DSA_MAX_PK 1793
#define FN_DSA_MAX_SK 2305
#define FN_DSA_MAX_SIG 1330
/* Caller owns the initialized SHAKE-256 context passed to *_ex and keygen. */
EVP_MD_CTX *ossl_fn_dsa_core_new_hash_ctx(OSSL_LIB_CTX *libctx, const char *propq);
size_t ossl_fn_dsa_core_pk_size(unsigned logn);
size_t ossl_fn_dsa_core_sk_size(unsigned logn);
size_t ossl_fn_dsa_core_sig_size(unsigned logn);
int ossl_fn_dsa_core_keygen(OSSL_LIB_CTX *libctx, unsigned logn, unsigned char *pk,
                       unsigned char *sk);
int ossl_fn_dsa_core_keygen_from_seed(EVP_MD_CTX *mdctx,
    unsigned logn, const unsigned char *seed, size_t seedlen,
    unsigned char *pk, unsigned char *sk);
int ossl_fn_dsa_core_check_public(unsigned logn, const unsigned char *pk, size_t pklen);
int ossl_fn_dsa_core_public(unsigned logn,
                       const unsigned char *sk, size_t sklen,
                       unsigned char *pk);
int ossl_fn_dsa_core_sign(OSSL_LIB_CTX *libctx, unsigned logn,
                     const unsigned char *sk, size_t sklen,
                     const unsigned char *msg, size_t msglen,
                     unsigned char *sig, size_t *siglen, size_t sigcap);
int ossl_fn_dsa_core_verify(OSSL_LIB_CTX *libctx, unsigned logn,
                       const unsigned char *pk, size_t pklen,
                       const unsigned char *msg, size_t msglen,
                       const unsigned char *sig, size_t siglen);
int ossl_fn_dsa_core_sign_ex(OSSL_LIB_CTX *libctx, EVP_MD_CTX *mdctx, unsigned logn,
    const unsigned char *sk, size_t sklen,
    const unsigned char *prefix, size_t prefixlen,
    const unsigned char *msg, size_t msglen,
    unsigned char *sig, size_t *siglen, size_t sigcap);
int ossl_fn_dsa_core_verify_ex(EVP_MD_CTX *mdctx, unsigned logn,
    const unsigned char *pk, size_t pklen,
    const unsigned char *prefix, size_t prefixlen,
    const unsigned char *msg, size_t msglen,
    const unsigned char *sig, size_t siglen);
#ifndef OPENSSL_NO_FN_DSA_TEST_ENTROPY
int ossl_fn_dsa_core_sign_test_ex(EVP_MD_CTX *mdctx, unsigned logn,
    const unsigned char *sk, size_t sklen,
    const unsigned char *prefix, size_t prefixlen,
    const unsigned char *msg, size_t msglen, const unsigned char entropy[88],
    unsigned char *sig, size_t *siglen, size_t sigcap);
#endif
/* Test-only deterministic entry points, absent from production builds. */
#ifdef FN_DSA_TESTING
#include <stdint.h>
int fn_dsa_keygen_max_bits_test(const int32_t *, int, int, int);
void fn_dsa_keygen_scaled_test(int64_t *, int32_t *, int, int, int, int);
int fn_dsa_keygen_seed(OSSL_LIB_CTX *, unsigned, const unsigned char[48],
                       unsigned char *, unsigned char *);
int fn_dsa_sign_seed(OSSL_LIB_CTX *, unsigned, const unsigned char *, size_t,
                     const unsigned char *, size_t, const unsigned char[40],
                     const unsigned char[48], unsigned char *, size_t *,
                     size_t);
#endif
#endif
