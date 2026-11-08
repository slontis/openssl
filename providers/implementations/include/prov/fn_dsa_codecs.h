/* Internal provisional FN-DSA encoding interfaces. */
#ifndef PROV_FN_DSA_CODECS_H
#define PROV_FN_DSA_CODECS_H
#pragma once
#include <openssl/types.h>
#include <stddef.h>
#include "crypto/fn_dsa.h"

#ifndef OPENSSL_NO_FN_DSA


#include "prov/provider_ctx.h"
FN_DSA_KEY *ossl_fn_dsa_d2i_PUBKEY(const uint8_t *der, int derlen,
    int evp_type, PROV_CTX *provctx, const char *propq);
FN_DSA_KEY *ossl_fn_dsa_d2i_PKCS8(const uint8_t *der, int derlen,
    int evp_type, PROV_CTX *provctx, const char *propq);
int ossl_fn_dsa_i2d_pubkey(const FN_DSA_KEY *key, unsigned char **out);
int ossl_fn_dsa_i2d_prvkey(const FN_DSA_KEY *key, unsigned char **out);

int ossl_fn_dsa_key_to_text(BIO *out, const FN_DSA_KEY *key, int selection);

/* Low-level framing helpers exercised by the integrated codec tests. */
int ossl_fn_dsa_d2i_PUBKEY_data(const unsigned char *der, long derlen, unsigned logn,
                           unsigned char *pub, size_t publen);
int ossl_fn_dsa_d2i_PKCS8_data(const unsigned char *der, long derlen, unsigned logn,
                          unsigned char *seed, size_t seedlen);
/* Payload helpers for the shared OpenSSL encoder framework. */
int ossl_fn_dsa_i2d_pubkey_data(const unsigned char *pub, size_t publen,
                           unsigned logn, unsigned char **out);
int ossl_fn_dsa_i2d_prvkey_data(const unsigned char *seed, size_t seedlen,
                           unsigned char **out);
/* Full wrappers, also used to test canonical DER independently of keygen. */
int ossl_fn_dsa_i2d_PUBKEY_data(const unsigned char *pub, size_t publen,
                           unsigned logn, unsigned char **out);
int ossl_fn_dsa_i2d_PKCS8_data(const unsigned char *seed, size_t seedlen,
                          unsigned logn, unsigned char **out);
#endif /* OPENSSL_NO_FN_DSA */
#endif /* PROV_FN_DSA_CODECS_H */
