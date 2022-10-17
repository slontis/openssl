/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_HPKE_H
# define OSSL_CRYPTO_HPKE_H
# pragma once

/* Constants from RFC 9180 Section 7.1 and 7.3 */
# define OSSL_HPKE_MAX_SECRET 64
# define OSSL_HPKE_MAX_PUBLIC 133
# define OSSL_HPKE_MAX_PRIVATE 66
# define OSSL_HPKE_MAX_NONCE 12
# define OSSL_HPKE_MAX_KDF_INPUTLEN 64

/*
 * @brief info about a KEM
 * Used to store constants from Section 7.1 "Table 2 KEM IDs"
 * and the bitmask for EC curves described in Section 7.1.3 DeriveKeyPair
 */
typedef struct {
    uint16_t       kem_id; /**< code point for key encipherment method */
    const char    *keytype; /**< string form of algtype "EC"/"X25519"/"X448" */
    const char    *groupname; /**< string form of EC group for NIST curves  */
    const char    *mdname; /**< hash alg name for the HKDF */
    size_t         Nsecret; /**< size of secrets */
    size_t         Nenc; /**< length of encapsulated key */
    size_t         Npk; /**< length of public key */
    size_t         Npriv; /**< length of raw private key */
    uint8_t        bitmask;
} OSSL_HPKE_KEM_INFO;

const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_curve(const char *curve);
const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_id(uint16_t kemid);
const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_random(OSSL_LIB_CTX *libctx);

int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
                          unsigned char *prk, size_t prklen,
                          const unsigned char *salt, size_t saltlen,
                          const unsigned char *ikm, size_t ikmlen);

int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
                         unsigned char *okm, size_t okmlen,
                         const unsigned char *prk, size_t prklen,
                         const unsigned char *info, size_t infolen);

int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
                              unsigned char *prk, size_t prklen,
                              const unsigned char *salt, size_t saltlen,
                              const char *protocol_label,
                              const unsigned char *suiteid, size_t suiteidlen,
                              const char *label,
                              const unsigned char *ikm, size_t ikmlen);
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
                             unsigned char *okm, size_t okmlen,
                             const unsigned char *prk, size_t prklen,
                             const char *protocol_label,
                             const unsigned char *suiteid, size_t suiteidlen,
                             const char *label,
                             const unsigned char *info, size_t infolen);

EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
                                 OSSL_LIB_CTX *libctx, const char *propq);

#endif
