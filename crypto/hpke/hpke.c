/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* An OpenSSL-based HPKE implementation of RFC9180 */

#include <string.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/hpke.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/hpke_util.h"
#include "internal/nelem.h"

/** default buffer size for keys and internal buffers we use */
#ifndef OSSL_HPKE_MAXSIZE
# define OSSL_HPKE_MAXSIZE 512
#endif

/* Define HPKE labels from RFC 9180 in hex for EBCDIC compatibility */
/**< "HPKE" - "suite_id" label for section 5.1 */
static const char OSSL_HPKE_SEC51LABEL[] = "\x48\x50\x4b\x45";
/**< "psk_id_hash" - in key_schedule_context */
static const char OSSL_HPKE_PSKIDHASH_LABEL[] = "\x70\x73\x6b\x5f\x69\x64\x5f\x68\x61\x73\x68";
/**<  "info_hash" - in key_schedule_context */
static const char OSSL_HPKE_INFOHASH_LABEL[] = "\x69\x6e\x66\x6f\x5f\x68\x61\x73\x68";
/**<  "base_nonce" - base nonce calc label */
static const char OSSL_HPKE_NONCE_LABEL[] = "\x62\x61\x73\x65\x5f\x6e\x6f\x6e\x63\x65";
/**<  "exp" - internal exporter secret generation label */
static const char OSSL_HPKE_EXP_LABEL[] = "\x65\x78\x70";
/**<  "sec" - external label for exporting secret */
static const char OSSL_HPKE_EXP_SEC_LABEL[] = "\x73\x65\x63";
/**<  "key" - label for use when generating key from shared secret */
static const char OSSL_HPKE_KEY_LABEL[] = "\x6b\x65\x79";
/**<  "psk_hash" - for hashing PSK */
static const char OSSL_HPKE_PSK_HASH_LABEL[] = "\x70\x73\x6b\x5f\x68\x61\x73\x68";
/**<  "secret" - for generating shared secret */
static const char OSSL_HPKE_SECRET_LABEL[] = "\x73\x65\x63\x72\x65\x74";

/* "strength" input to RAND_bytes_ex */
#define OSSL_HPKE_RSTRENGTH 10

/**
 * @brief sender or receiver context
 */
struct ossl_hpke_ctx_st
{
    OSSL_LIB_CTX *libctx; /**< library context */
    char *propq; /**< properties */
    int mode; /**< HPKE mode */
    OSSL_HPKE_SUITE suite; /**< suite */
    uint64_t seq; /**< sequence number */
    unsigned char *shared_secret;
    size_t shared_secretlen;
    unsigned char *key;
    size_t keylen;
    unsigned char *nonce;
    size_t noncelen;
    unsigned char *exportersec; /**< exporter secret */
    size_t exporterseclen;
    char *pskid; /**< PSK stuff */
    unsigned char *psk;
    size_t psklen;
    unsigned char *info;
    size_t infolen;
    unsigned char *ikme;
    size_t ikmelen;
    EVP_PKEY *authpriv; /**< sender's authentication private key */
    unsigned char *authpub; /**< auth public key */
    size_t authpublen;
};

/*
 * @brief check if KEM uses NIST curve or not
 * @param kem_id is the externally supplied kem_id
 * @return 1 for NIST, 0 for good-but-non-NIST, other otherwise
 */
static int hpke_kem_id_nist_curve(uint16_t kem_id)
{
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;

    kem_info = ossl_HPKE_KEM_INFO_find_id(kem_id);
    return kem_info != NULL && kem_info->groupname != NULL;
}

/*
 * @brief hpke wrapper to import NIST curve public key as easily as x25519/x448
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param gname is the curve groupname
 * @param buf is the binary buffer with the (uncompressed) public value
 * @param buflen is the length of the private key buffer
 * @return a working EVP_PKEY * or NULL
 */
static EVP_PKEY *EVP_PKEY_new_raw_nist_public_key(OSSL_LIB_CTX *libctx,
                                                  const char *propq,
                                                  const char *gname,
                                                  const unsigned char *buf,
                                                  size_t buflen)
{
    int erv = 0;
    OSSL_PARAM params[2];
    EVP_PKEY *ret = NULL;
    EVP_PKEY_CTX *cctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)gname, 0);
    params[1] = OSSL_PARAM_construct_end();
    if (cctx == NULL
        || EVP_PKEY_paramgen_init(cctx) <= 0
        || EVP_PKEY_CTX_set_params(cctx, params) <= 0
        || EVP_PKEY_paramgen(cctx, &ret) <= 0
        || EVP_PKEY_set1_encoded_public_key(ret, buf, buflen) != 1) {
        goto err;
    }
    erv = 1;

err:
    EVP_PKEY_CTX_free(cctx);
    if (erv == 1) {
        return ret;
    } else {
        EVP_PKEY_free(ret);
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
}

/*
 * @brief do the AEAD decryption
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param cipher is obvious
 * @param cipherlen is the ciphertext length
 * @param plain is an output
 * @param plainlen input/output, better be big enough on input, exact on output
 * @return 1 for good otherwise bad
 */
static int hpke_aead_dec(OSSL_LIB_CTX *libctx, const char *propq,
                         OSSL_HPKE_SUITE suite,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *cipher, size_t cipherlen,
                         unsigned char *plain, size_t *plainlen)
{
    int erv = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    size_t plaintextlen = 0;
    unsigned char *plaintext = NULL;
    size_t taglen;
    EVP_CIPHER *enc = NULL;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;

    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    taglen = aead_info->taglen;
    plaintext = OPENSSL_malloc(cipherlen);
    if (plaintext == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Create and initialise the context */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation */
    enc = EVP_CIPHER_fetch(libctx, aead_info->name, propq);
    if (enc == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_DecryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide AAD. */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len, cipher,
                          cipherlen - taglen) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    plaintextlen = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                             taglen, (void *)(cipher + cipherlen - taglen))) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Finalise decryption.  */
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (plaintextlen > *plainlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *plainlen = plaintextlen;
    memcpy(plain, plaintext, plaintextlen);

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    OPENSSL_clear_free(plaintext, plaintextlen);
    return erv;
}

/*
 * @brief do AEAD encryption as per the RFC
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the ciphersuite
 * @param key is the secret
 * @param keylen is the length of the secret
 * @param iv is the initialisation vector
 * @param ivlen is the length of the iv
 * @param aad is the additional authenticated data
 * @param aadlen is the length of the aad
 * @param plain is an output
 * @param plainlen is the length of plain
 * @param cipher is an output
 * @param cipherlen input/output, better be big enough on input, exact on output
 * @return 1 for good otherwise bad
 */
static int hpke_aead_enc(OSSL_LIB_CTX *libctx, const char *propq,
                         OSSL_HPKE_SUITE suite,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *iv, size_t ivlen,
                         const unsigned char *aad, size_t aadlen,
                         const unsigned char *plain, size_t plainlen,
                         unsigned char *cipher, size_t *cipherlen)
{
    int erv = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    size_t ciphertextlen;
    unsigned char *ciphertext = NULL;
    size_t taglen = 0;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;
    EVP_CIPHER *enc = NULL;
    unsigned char tag[16];

    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    taglen = aead_info->taglen;
    if (taglen != 16) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if ((taglen + plainlen) > *cipherlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /*
     * Allocate this much extra for ciphertext and check the AEAD
     * doesn't require more - If it does, we'll fail.
     */
    ciphertext = OPENSSL_malloc(plainlen + taglen);
    if (ciphertext == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise the encryption operation. */
    enc = EVP_CIPHER_fetch(libctx, aead_info->name, propq);
    if (enc == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_EncryptInit_ex(ctx, enc, NULL, NULL, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_CIPHER_free(enc);
    enc = NULL;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, ivlen, NULL) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Initialise key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* Provide any AAD data. */
    if (aadlen != 0 && aad != NULL) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aadlen) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plain, plainlen) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ciphertextlen = len;
    /* Finalise the encryption. */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ciphertextlen += len;
    /*
     * Get the tag This isn't a duplicate so needs to be added to the ciphertext
     */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen, tag) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    memcpy(ciphertext + ciphertextlen, tag, taglen);
    ciphertextlen += taglen;
    if (ciphertextlen > *cipherlen) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *cipherlen = ciphertextlen;
    memcpy(cipher, ciphertext, ciphertextlen);

err:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(enc);
    OPENSSL_free(ciphertext);
    return erv;
}

/*
 * @brief check mode is in-range and supported
 * @param mode is the caller's chosen mode
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_mode_check(unsigned int mode)
{
    switch (mode) {
    case OSSL_HPKE_MODE_BASE:
    case OSSL_HPKE_MODE_PSK:
    case OSSL_HPKE_MODE_AUTH:
    case OSSL_HPKE_MODE_PSKAUTH:
        break;
    default:
        return 0;
    }
    return 1;
}
/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, 0 otherwise
 */
static int hpke_suite_check(OSSL_HPKE_SUITE suite)
{
    /* check KEM, KDF and AEAD are supported here */
    if (ossl_HPKE_KEM_INFO_find_id(suite.kem_id) == NULL)
        return 0;
    if (ossl_HPKE_KDF_INFO_find_id(suite.kdf_id) == NULL)
        return 0;
    if (ossl_HPKE_AEAD_INFO_find_id(suite.aead_id) == NULL)
        return 0;
    return 1;
}

/*
 * @brief generate a key pair
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param mode is the mode (currently unused)
 * @param suite is the ciphersuite
 * @param ikmlen is the length of IKM, if supplied
 * @param ikm is IKM, if supplied
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key pointer
 * @return 1 for good (OpenSSL style), not 1 for error
 */
static int hpke_kg_evp(OSSL_LIB_CTX *libctx, const char *propq,
                       OSSL_HPKE_SUITE suite,
                       size_t ikmlen, const unsigned char *ikm,
                       size_t *publen, unsigned char *pub,
                       EVP_PKEY **priv)
{
    int erv = 1; /* Our error return value - 1 is success */
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *skR = NULL;
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    OSSL_PARAM params[3], *p = params;

    if (hpke_suite_check(suite) != 1)
        return 0;
    if (pub == NULL || publen == NULL || *publen == 0 || priv == NULL)
        return 0;
    if (ikmlen > 0 && ikm == NULL)
        return 0;
    if (ikmlen == 0 && ikm != NULL)
        return 0;
    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    if (kem_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (hpke_kem_id_nist_curve(suite.kem_id) == 1) {
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *)kem_info->groupname, 0);
        pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq);
    } else {
        pctx = EVP_PKEY_CTX_new_from_name(libctx, kem_info->keytype, propq);
    }
    if (pctx == NULL
        || EVP_PKEY_keygen_init(pctx) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ikm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM,
                                                 (char *)ikm, ikmlen);
    *p = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (EVP_PKEY_generate(pctx, &skR) <= 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    if (EVP_PKEY_get_octet_string_param(skR, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                        pub, *publen, publen) != 1) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *priv = skR;

err:
    if (erv != 1) { EVP_PKEY_free(skR); }
    EVP_PKEY_CTX_free(pctx);
    return erv;
}

/*
 * @brief randomly pick a suite
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the result
 * @return 1 for success, otherwise failure
 *
 * If you change the structure of the various *_tab arrays
 * then this code will also need change.
 */
static int hpke_random_suite(OSSL_LIB_CTX *libctx,
                             const char *propq,
                             OSSL_HPKE_SUITE *suite)
{
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;

    /* random kem, kdf and aead */
    kem_info = ossl_HPKE_KEM_INFO_find_random(libctx);
    if (kem_info == NULL)
        return 0;
    suite->kem_id = kem_info->kem_id;
    kdf_info = ossl_HPKE_KDF_INFO_find_random(libctx);
    if (kdf_info == NULL)
        return 0;
    suite->kdf_id = kdf_info->kdf_id;
    aead_info = ossl_HPKE_AEAD_INFO_find_random(libctx);
    if (aead_info == NULL)
        return 0;
    suite->aead_id = aead_info->aead_id;
    return 1;
}

/*
 * @brief return a (possibly) random suite, public key, ciphertext for GREASErs
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite-in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param ciphertext buffer with random value of the appropriate length
 * @param ciphertext_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
static int hpke_get_grease_value(OSSL_LIB_CTX *libctx, const char *propq,
                                 OSSL_HPKE_SUITE *suite_in,
                                 OSSL_HPKE_SUITE *suite,
                                 unsigned char *enc,
                                 size_t *enclen,
                                 unsigned char *ct,
                                 size_t ctlen)
{
    OSSL_HPKE_SUITE chosen;
    size_t plen = 0;
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;

    if (enc == NULL || !enclen
        || ct == NULL || ctlen == 0 || suite == NULL)
        return 0;
    if (suite_in == NULL) {
        /* choose a random suite */
        if (hpke_random_suite(libctx, propq, &chosen) != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        chosen = *suite_in;
    }
    kem_info = ossl_HPKE_KEM_INFO_find_id(chosen.kem_id);
    if (kem_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    aead_info = ossl_HPKE_AEAD_INFO_find_id(chosen.aead_id);
    if (aead_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hpke_suite_check(chosen) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *suite = chosen;
    /* make sure room for tag and one plaintext octet */
    if (aead_info->taglen >= ctlen) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    /* publen */
    plen = kem_info->Npk;
    if (plen > *enclen) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (RAND_bytes_ex(libctx, enc, plen, OSSL_HPKE_RSTRENGTH) <= 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *enclen = plen;
    /* if NIST curve chosen set 1st octet to 0x04 */
    if (hpke_kem_id_nist_curve(chosen.kem_id) == 1) {
        enc[0] = 0x04;
    }
    if (RAND_bytes_ex(libctx, ct, ctlen, OSSL_HPKE_RSTRENGTH) <= 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    return 1;
err:
    return 0;
}

/*
 * @brief tell the caller how big the ciphertext will be
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who knows what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given suite.
 *
 * @param suite is the suite to be used
 * @param enclen points to what'll be enc length
 * @param clearlen is the length of plaintext
 * @param cipherlen points to what'll be ciphertext length
 * @return 1 for success, otherwise failure
 */
static int hpke_expansion(OSSL_HPKE_SUITE suite,
                          size_t *enclen,
                          size_t clearlen,
                          size_t *cipherlen)
{
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;

    if (cipherlen == NULL || enclen == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (hpke_suite_check(suite) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    aead_info = ossl_HPKE_AEAD_INFO_find_id(suite.aead_id);
    if (aead_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *cipherlen = clearlen + aead_info->taglen;
    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    if (kem_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    *enclen = kem_info->Nenc;
    return 1;
}

static size_t hpke_seq2buf(uint64_t seq, unsigned char *buf, size_t blen)
{
    size_t i;

    if (blen < sizeof(seq))
        return 0;
    for (i = 1; i <= sizeof(seq); i++)
        buf[blen - i] = (seq >> (8 * (i - 1))) & 0xff;
    if (blen > sizeof(seq))
        memset(buf, 0, blen - sizeof(seq));
    return blen;
}

static int hpke_encap(OSSL_HPKE_CTX *ctx, unsigned char *enc, size_t *enclen,
                      const unsigned char *pub, size_t publen)
{
    int erv = 1;
    OSSL_PARAM params[3], *p = params;
    size_t lsslen = 0;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkR = NULL;
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;

    if (ctx == NULL || enc == NULL || enclen == NULL || *enclen == 0
        || pub == NULL || publen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->shared_secret != NULL) {
        /* only run the KEM once per OSSL_HPKE_CTX */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    kem_info = ossl_HPKE_KEM_INFO_find_id(ctx->suite.kem_id);
    if (kem_info == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (hpke_kem_id_nist_curve(ctx->suite.kem_id) == 1) {
        pkR = EVP_PKEY_new_raw_nist_public_key(ctx->libctx, ctx->propq,
                                               kem_info->groupname,
                                               pub, publen);
    } else {
        pkR = EVP_PKEY_new_raw_public_key_ex(ctx->libctx,
                                             kem_info->keytype,
                                             ctx->propq, pub, publen);
    }
    if (pkR == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, pkR, ctx->propq);
    if (pctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                            OSSL_KEM_PARAM_OPERATION_DHKEM,
                                            0);
    if (ctx->ikme != NULL) {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME,
                                                 ctx->ikme, ctx->ikmelen);
    }
    *p = OSSL_PARAM_construct_end();
    if (ctx->mode == OSSL_HPKE_MODE_AUTH
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        if (EVP_PKEY_auth_encapsulate_init(pctx, ctx->authpriv,
                                           params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        if (EVP_PKEY_encapsulate_init(pctx, params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    erv = EVP_PKEY_encapsulate(pctx, NULL, enclen, NULL, &lsslen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ctx->shared_secret = OPENSSL_malloc(lsslen);
    if (ctx->shared_secret == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ctx->shared_secretlen = lsslen;
    erv = EVP_PKEY_encapsulate(pctx, enc, enclen,
                               ctx->shared_secret,
                               &ctx->shared_secretlen);
    if (erv != 1) {
        ctx->shared_secretlen = 0;
        ctx->shared_secret = NULL;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(pkR);
    return erv;
}

static int hpke_decap(OSSL_HPKE_CTX *ctx,
                      const unsigned char *enc, size_t enclen,
                      EVP_PKEY *priv)
{
    int erv = 1;
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *spub = NULL;
    OSSL_PARAM params[3], *p = params;
    size_t lsslen = 0;
    unsigned char lss[OSSL_HPKE_MAXSIZE];

    if (ctx == NULL || enc == NULL || enclen == 0 || priv == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->shared_secret != NULL) {
        /* only run the KEM once per OSSL_HPKE_CTX */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, priv, ctx->propq);
    if (pctx == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KEM_PARAM_OPERATION,
                                            OSSL_KEM_PARAM_OPERATION_DHKEM,
                                            0);
    *p = OSSL_PARAM_construct_end();
    if (ctx->mode == OSSL_HPKE_MODE_AUTH
        || ctx->mode == OSSL_HPKE_MODE_PSKAUTH) {
        const OSSL_HPKE_KEM_INFO *kem_info = NULL;

        kem_info = ossl_HPKE_KEM_INFO_find_id(ctx->suite.kem_id);
        if (kem_info == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (hpke_kem_id_nist_curve(ctx->suite.kem_id) == 1) {
            spub = EVP_PKEY_new_raw_nist_public_key(ctx->libctx, ctx->propq,
                                                    kem_info->groupname,
                                                    ctx->authpub,
                                                    ctx->authpublen);
        } else {
            spub = EVP_PKEY_new_raw_public_key_ex(ctx->libctx,
                                                  kem_info->keytype,
                                                  ctx->propq,
                                                  ctx->authpub,
                                                  ctx->authpublen);
        }
        if (spub == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        if (EVP_PKEY_auth_decapsulate_init(pctx, spub, params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    } else {
        if (EVP_PKEY_decapsulate_init(pctx, params) != 1) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    erv = EVP_PKEY_decapsulate(pctx, NULL, &lsslen, enc, enclen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (lsslen > OSSL_HPKE_MAXSIZE) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = EVP_PKEY_decapsulate(pctx, lss, &lsslen, enc, enclen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;
    /* free shared_secret in case this is 2nd call */
    OPENSSL_clear_free(ctx->shared_secret, ctx->shared_secretlen);
    ctx->shared_secret = OPENSSL_malloc(lsslen);
    if (ctx->shared_secret == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ctx->shared_secretlen = lsslen;
    memcpy(ctx->shared_secret, lss, lsslen);

err:
    EVP_PKEY_CTX_free(pctx);
    EVP_PKEY_free(spub);
    OPENSSL_cleanse(lss, sizeof(lss));
    return erv;
}

static int hpke_do_rest(OSSL_HPKE_CTX *ctx,
                        const unsigned char *info, size_t infolen)
{
    int erv = 1;
    size_t ks_contextlen = OSSL_HPKE_MAXSIZE;
    unsigned char ks_context[OSSL_HPKE_MAXSIZE];
    size_t halflen = 0;
    size_t pskidlen = 0;
    size_t psk_hashlen = OSSL_HPKE_MAXSIZE;
    unsigned char psk_hash[OSSL_HPKE_MAXSIZE];
    const OSSL_HPKE_AEAD_INFO *aead_info = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;
    size_t secretlen = OSSL_HPKE_MAXSIZE;
    unsigned char secret[OSSL_HPKE_MAXSIZE];
    EVP_KDF_CTX *kctx = NULL;
    unsigned char suitebuf[6];
    const char *mdname = NULL;

    /* just do this once */
    if (ctx->exportersec != NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ossl_HPKE_KEM_INFO_find_id(ctx->suite.kem_id) == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    aead_info = ossl_HPKE_AEAD_INFO_find_id(ctx->suite.aead_id);
    if (aead_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    kdf_info = ossl_HPKE_KDF_INFO_find_id(ctx->suite.kdf_id);
    if (kdf_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    mdname = kdf_info->mdname;
    kctx = ossl_kdf_ctx_create("HKDF", mdname, ctx->libctx, ctx->propq);
    if (kctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* create key schedule context */
    memset(ks_context, 0, sizeof(ks_context));
    ks_context[0] = (unsigned char)(ctx->mode % 256);
    ks_contextlen--; /* remaining space */
    halflen = kdf_info->Nh;
    if ((2 * halflen) > ks_contextlen) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    pskidlen = (ctx->psk == NULL ? 0 : strlen(ctx->pskid));
    /* mode == FULL as per RFC9180 sec 5.1 */
    suitebuf[0] = ctx->suite.kem_id / 256;
    suitebuf[1] = ctx->suite.kem_id % 256;
    suitebuf[2] = ctx->suite.kdf_id / 256;
    suitebuf[3] = ctx->suite.kdf_id % 256;
    suitebuf[4] = ctx->suite.aead_id / 256;
    suitebuf[5] = ctx->suite.aead_id % 256;
    erv = ossl_hpke_labeled_extract(kctx, ks_context + 1, halflen,
                                    NULL, 0, OSSL_HPKE_SEC51LABEL,
                                    suitebuf, sizeof(suitebuf),
                                    OSSL_HPKE_PSKIDHASH_LABEL,
                                    (unsigned char *)ctx->pskid, pskidlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = ossl_hpke_labeled_extract(kctx, ks_context + 1 + halflen, halflen,
                                    NULL, 0, OSSL_HPKE_SEC51LABEL,
                                    suitebuf, sizeof(suitebuf),
                                    OSSL_HPKE_INFOHASH_LABEL,
                                    (unsigned char *)info, infolen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    ks_contextlen = 1 + 2 * halflen;
    /* Extract and Expand variously... */
    psk_hashlen = halflen;
    erv = ossl_hpke_labeled_extract(kctx, psk_hash, psk_hashlen,
                                    NULL, 0, OSSL_HPKE_SEC51LABEL,
                                    suitebuf, sizeof(suitebuf),
                                    OSSL_HPKE_PSK_HASH_LABEL,
                                    ctx->psk, ctx->psklen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    secretlen = kdf_info->Nh;
    if (secretlen > OSSL_HPKE_MAXSIZE) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = ossl_hpke_labeled_extract(kctx, secret, secretlen,
                                    ctx->shared_secret, ctx->shared_secretlen,
                                    OSSL_HPKE_SEC51LABEL,
                                    suitebuf, sizeof(suitebuf),
                                    OSSL_HPKE_SECRET_LABEL,
                                    ctx->psk, ctx->psklen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    if (ctx->suite.aead_id != OSSL_HPKE_AEAD_ID_EXPORTONLY) {
        /* we only need nonce/key for non export AEADs */
        ctx->noncelen = aead_info->Nn;
        ctx->nonce = OPENSSL_malloc(ctx->noncelen);
        if (ctx->nonce == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        erv = ossl_hpke_labeled_expand(kctx, ctx->nonce, ctx->noncelen,
                                       secret, secretlen, OSSL_HPKE_SEC51LABEL,
                                       suitebuf, sizeof(suitebuf),
                                       OSSL_HPKE_NONCE_LABEL,
                                       ks_context, ks_contextlen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        ctx->keylen = aead_info->Nk;
        ctx->key = OPENSSL_malloc(ctx->keylen);
        if (ctx->key == NULL) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        erv = ossl_hpke_labeled_expand(kctx, ctx->key, ctx->keylen,
                                       secret, secretlen, OSSL_HPKE_SEC51LABEL,
                                       suitebuf, sizeof(suitebuf),
                                       OSSL_HPKE_KEY_LABEL,
                                       ks_context, ks_contextlen);
        if (erv != 1) {
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }
    ctx->exporterseclen = kdf_info->Nh;
    ctx->exportersec = OPENSSL_malloc(ctx->exporterseclen);
    if (ctx->exportersec == NULL) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    erv = ossl_hpke_labeled_expand(kctx,
                                   ctx->exportersec, ctx->exporterseclen,
                                   secret, secretlen, OSSL_HPKE_SEC51LABEL,
                                   suitebuf, sizeof(suitebuf),
                                   OSSL_HPKE_EXP_LABEL,
                                   ks_context, ks_contextlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    }

err:
    OPENSSL_cleanse(ks_context, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(psk_hash, OSSL_HPKE_MAXSIZE);
    OPENSSL_cleanse(secret, OSSL_HPKE_MAXSIZE);
    EVP_KDF_CTX_free(kctx);
    return erv;
}

/* externally visible functions from below here */

/**
 * @brief contex creator
 * @param mode is the desired HPKE mode
 * @param suite specifies the KEM, KDF and AEAD to use
 * @param libctx is the context to use
 * @param propq is a properties string
 * @return pointer to new context or NULL if error
 */
OSSL_HPKE_CTX *OSSL_HPKE_CTX_new(int mode, OSSL_HPKE_SUITE suite,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    OSSL_HPKE_CTX *ctx = NULL;

    if (hpke_mode_check(mode) != 1)
        return NULL;
    if (hpke_suite_check(suite) != 1)
        return NULL;
    if (mode < 0 || mode > OSSL_HPKE_MODE_PSKAUTH)
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(OSSL_HPKE_CTX));
    if (ctx == NULL)
        return ctx;
    ctx->libctx = libctx;
    if (propq != NULL) {
        ctx->propq = OPENSSL_strdup(propq);
        if (ctx->propq == NULL)
            goto err;
    }
    ctx->mode = mode;
    ctx->suite = suite;
    return ctx;

err:
    OSSL_HPKE_CTX_free(ctx);
    return NULL;
}

/**
 * @brief free up storage for a HPKE context
 * @param ctx is the pointer to be free'd (can be NULL)
 */
void OSSL_HPKE_CTX_free(OSSL_HPKE_CTX *ctx)
{
    if (ctx == NULL)
        return;
    OPENSSL_free(ctx->propq);
    OPENSSL_clear_free(ctx->exportersec, ctx->exporterseclen);
    OPENSSL_free(ctx->pskid);
    OPENSSL_clear_free(ctx->psk, ctx->psklen);
    OPENSSL_clear_free(ctx->key, ctx->keylen);
    OPENSSL_clear_free(ctx->nonce, ctx->noncelen);
    OPENSSL_clear_free(ctx->shared_secret, ctx->shared_secretlen);
    OPENSSL_clear_free(ctx->ikme, ctx->ikmelen);
    EVP_PKEY_free(ctx->authpriv);
    OPENSSL_free(ctx->info);
    OPENSSL_free(ctx->authpub);

    OPENSSL_free(ctx);
    return;
}

/**
 * @brief set a PSK for an HPKE context
 * @param ctx is the pointer for the HPKE context
 * @param pskid is a string identifying the PSK
 * @param psk is the PSK buffer
 * @param psklen is the size of the PSK
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_psk(OSSL_HPKE_CTX *ctx,
                           const char *pskid,
                           const unsigned char *psk, size_t psklen)
{
    if (ctx == NULL || pskid == NULL || psk == NULL || psklen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->mode != OSSL_HPKE_MODE_PSK
        && ctx->mode != OSSL_HPKE_MODE_PSKAUTH) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* free previous value if any */
    OPENSSL_free(ctx->pskid);
    OPENSSL_clear_free(ctx->psk, ctx->psklen);
    ctx->pskid = OPENSSL_strdup(pskid);
    if (ctx->pskid == NULL)
        goto err;
    ctx->psk = OPENSSL_malloc(psklen);
    if (ctx->psk == NULL)
        goto err;
    memcpy(ctx->psk, psk, psklen);
    ctx->psklen = psklen;
    return 1;
err:
    /* zap any new or old psk */
    OPENSSL_free(ctx->pskid);
    OPENSSL_clear_free(ctx->psk, ctx->psklen);
    ctx->psklen = 0;
    return 0;
}

/**
 * @brief set a sender IKM for key DHKEM generation
 * @param ctx is the pointer for the HPKE context
 * @param ikme is a buffer for the IKM
 * @param ikmelen is the length of the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_ikme(OSSL_HPKE_CTX *ctx,
                            const unsigned char *ikme, size_t ikmelen)
{
    if (ctx == NULL || ikme == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    OPENSSL_clear_free(ctx->ikme, ctx->ikmelen);
    ctx->ikme = OPENSSL_malloc(ikmelen);
    if (ctx->ikme == NULL)
        return 0;
    memcpy(ctx->ikme, ikme, ikmelen);
    ctx->ikmelen = ikmelen;
    return 1;
}

/**
 * @brief set a private key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param privp is an EVP_PKEY form of the private key
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_authpriv(OSSL_HPKE_CTX *ctx, EVP_PKEY *priv)
{
    if (ctx == NULL || priv == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->mode != OSSL_HPKE_MODE_AUTH
        && ctx->mode != OSSL_HPKE_MODE_PSKAUTH) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->authpriv != NULL)
        EVP_PKEY_free(ctx->authpriv);
    ctx->authpriv = EVP_PKEY_dup(priv);
    if (ctx->authpriv == NULL)
        return 0;
    return 1;
}

/**
 * @brief set a public key for HPKE authenticated modes
 * @param ctx is the pointer for the HPKE context
 * @param pub is an buffer form of the public key
 * @param publen is the length of the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_CTX_set1_authpub(OSSL_HPKE_CTX *ctx,
                               const unsigned char *pub, size_t publen)
{
    if (ctx == NULL)
        return 0;
    if (ctx->authpub != NULL)
        OPENSSL_free(ctx->authpub);
    ctx->authpub = OPENSSL_malloc(publen);
    if (ctx->authpub == NULL)
        return 0;
    memcpy(ctx->authpub, pub, publen);
    ctx->authpublen = publen;
    return 1;
}

/**
 * @brief ask for the state of the sequence of seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @param seq returns the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The value returned is the most recent used when sealing
 * or opening (successfully)
 */
int OSSL_HPKE_CTX_get_seq(OSSL_HPKE_CTX *ctx, uint64_t *seq)
{
    if (ctx == NULL || seq == NULL)
        return 0;
    *seq = ctx->seq;
    return 1;
}

/**
 * @brief set the sequence value for seal/open calls
 * @param ctx is the pointer for the HPKE context
 * @param seq set the positive integer sequence number
 * @return 1 for success, 0 for error
 *
 * The value returned is the most recent used when sealing
 * or opening (successfully)
 */
int OSSL_HPKE_CTX_set_seq(OSSL_HPKE_CTX *ctx, uint64_t seq)
{
    if (ctx == NULL)
        return 0;
    ctx->seq = seq;
    return 1;
}

/**
 * @brief sender encapsulation function
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param pub is the recipient public key octets
 * @param publen is the size the above
 * @param info is the info parameter
 * @param infolen is the size the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_encap(OSSL_HPKE_CTX *ctx,
                    unsigned char *enc, size_t *enclen,
                    unsigned char *pub, size_t publen,
                    const unsigned char *info, size_t infolen)
{
    int erv = 1;

    if (ctx == NULL || enc == NULL || enclen == NULL || *enclen == 0
        || pub == NULL || publen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ctx->shared_secret != NULL || ctx->info != NULL) {
        /* only allow one encap per OSSL_HPKE_CTX */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    if (hpke_encap(ctx, enc, enclen, pub, publen) != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    erv = hpke_do_rest(ctx, info, infolen);
    return erv;
}

/**
 * @brief recipient decapsulation function
 * @param ctx is the pointer for the HPKE context
 * @param enc is the sender's ephemeral public value
 * @param enclen is the size the above
 * @param recippriv is the EVP_PKEY form of recipient private value
 * @param info is the info parameter
 * @param infolen is the size the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_decap(OSSL_HPKE_CTX *ctx,
                    const unsigned char *enc, size_t enclen,
                    EVP_PKEY *recippriv,
                    const unsigned char *info, size_t infolen)
{
    int erv = 1;

    if (ctx == NULL || enc == NULL || enclen == 0 || recippriv == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (ctx->shared_secret != NULL) {
        /* only allow one encap per OSSL_HPKE_CTX */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    erv = hpke_decap(ctx, enc, enclen, recippriv);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    erv = hpke_do_rest(ctx, info, infolen);
    return erv;
}

/**
 * @brief new sender seal function
 * @param ctx is the pointer for the HPKE context
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_seal(OSSL_HPKE_CTX *ctx,
                   unsigned char *ct, size_t *ctlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *pt, size_t ptlen)
{
    int erv = 1;
    unsigned char seqbuf[12];
    size_t seqlen = 0;
    unsigned char nonce[12];

    if (ctx == NULL || ct == NULL || ctlen == NULL || *ctlen == 0
        || pt == NULL || ptlen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (ctx->key == NULL || ctx->nonce == NULL) {
        /* need to have done an encap first, info can be NULL */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    if (ctx->noncelen > sizeof(nonce)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    seqlen = hpke_seq2buf(ctx->seq, seqbuf, sizeof(seqbuf));
    if (seqlen == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    } else {
        size_t sind;
        unsigned char cv;

        if (seqlen > ctx->noncelen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != ctx->noncelen; sind++) {
            nonce[ctx->noncelen - 1 - sind] =
                ctx->nonce[ctx->noncelen - 1 - sind];
            if (sind < seqlen) {
                cv = seqbuf[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[ctx->noncelen - 1 - sind] ^= cv;
        }
    }

    erv = hpke_aead_enc(ctx->libctx, ctx->propq, ctx->suite,
                        ctx->key, ctx->keylen, nonce, ctx->noncelen,
                        aad, aadlen, pt, ptlen, ct, ctlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    } else {
        ctx->seq++;
    }
err:
    OPENSSL_cleanse(nonce, ctx->noncelen);
    return 1;
}

/**
 * @brief new sender seal function
 * @param ctx is the pointer for the HPKE context
 * @param ct is the ciphertext output
 * @param ctlen is the size the above
 * @param aad is the aad parameter
 * @param aadlen is the size the above
 * @param pt is the plaintext
 * @param ptlen is the size the above
 * @return 1 for success, 0 for error
 */
int OSSL_HPKE_open(OSSL_HPKE_CTX *ctx,
                   unsigned char *pt, size_t *ptlen,
                   const unsigned char *aad, size_t aadlen,
                   const unsigned char *ct, size_t ctlen)
{
    int erv = 1;
    unsigned char seqbuf[12];
    size_t seqlen = 0;
    unsigned char nonce[12];

    if (ctx == NULL || pt == NULL || ptlen == NULL || *ptlen == 0
        || ct == NULL || ctlen == 0) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }
    if (ctx->key == NULL || ctx->nonce == NULL) {
        /* need to have done an encap first, info can be NULL */
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    if (ctx->noncelen > sizeof(nonce)) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }
    seqlen = hpke_seq2buf(ctx->seq, seqbuf, sizeof(seqbuf));
    if (seqlen == 0) {
        erv = 0;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        goto err;
    } else {
        size_t sind;
        unsigned char cv;

        if (seqlen > ctx->noncelen) {
            erv = 0;
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
            goto err;
        }
        /* non constant time - does it matter? maybe no */
        for (sind = 0; sind != ctx->noncelen; sind++) {
            nonce[ctx->noncelen - 1 - sind] =
                ctx->nonce[ctx->noncelen - 1 - sind];
            if (sind < seqlen) {
                cv = seqbuf[seqlen - 1 - (sind % seqlen)];
            } else {
                cv = 0x00;
            }
            nonce[ctx->noncelen - 1 - sind] ^= cv;
        }
    }
    erv = hpke_aead_dec(ctx->libctx, ctx->propq, ctx->suite,
                        ctx->key, ctx->keylen, nonce, ctx->noncelen,
                        aad, aadlen, ct, ctlen, pt, ptlen);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    } else {
        ctx->seq++;
    }
err:
    OPENSSL_cleanse(nonce, ctx->noncelen);
    return 1;
}

/**
 * @brief generate a given-length secret based on context and label
 * @param ctx is the HPKE context
 * @param secret is the resulting secret that will be of length...
 * @param secretlen is the desired output length
 * @param label is a buffer to provide separation between secrets
 * @param labellen is the length of the above
 * @return 1 for good, 0 for error
 */
int OSSL_HPKE_export(OSSL_HPKE_CTX *ctx,
                     unsigned char *secret, size_t secretlen,
                     const unsigned char *label, size_t labellen)
{
    int erv = 1;
    EVP_KDF_CTX *kctx = NULL;
    unsigned char suitebuf[6];
    const char *mdname = NULL;
    const OSSL_HPKE_KDF_INFO *kdf_info = NULL;

    if (ctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ctx->exportersec == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    kdf_info = ossl_HPKE_KDF_INFO_find_id(ctx->suite.kdf_id);
    if (kdf_info == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    mdname = kdf_info->mdname;
    kctx = ossl_kdf_ctx_create("HKDF", mdname, ctx->libctx, ctx->propq);
    if (kctx == NULL) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    /* mode == FULL as per RFC9180 sec 5.1 */
    suitebuf[0] = ctx->suite.kem_id / 256;
    suitebuf[1] = ctx->suite.kem_id % 256;
    suitebuf[2] = ctx->suite.kdf_id / 256;
    suitebuf[3] = ctx->suite.kdf_id % 256;
    suitebuf[4] = ctx->suite.aead_id / 256;
    suitebuf[5] = ctx->suite.aead_id % 256;
    erv = ossl_hpke_labeled_expand(kctx,
                                   secret, secretlen,
                                   ctx->exportersec, ctx->exporterseclen,
                                   OSSL_HPKE_SEC51LABEL,
                                   suitebuf, sizeof(suitebuf),
                                   OSSL_HPKE_EXP_SEC_LABEL,
                                   label, labellen);
    EVP_KDF_CTX_free(kctx);
    if (erv != 1) {
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return 1;
}

/*
 * @brief generate a key pair
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite is the ciphersuite (currently unused)
 * @param ikmlen is the length of IKM, if supplied
 * @param ikm is IKM, if supplied
 * @param publen is the size of the public key buffer (exact length on output)
 * @param pub is the public value
 * @param priv is the private key handle
 * @return 1 for good (OpenSSL style), not-1 for error
 */
int OSSL_HPKE_keygen(OSSL_LIB_CTX *libctx, const char *propq,
                     OSSL_HPKE_SUITE suite,
                     const unsigned char *ikm, size_t ikmlen,
                     unsigned char *pub, size_t *publen,
                     EVP_PKEY **priv)
{
    return hpke_kg_evp(libctx, propq, suite,
                       ikmlen, ikm, publen, pub, priv);
}

/**
 * @brief check if a suite is supported locally
 *
 * @param suite is the suite to check
 * @return 1 for good/supported, not-1 otherwise
 */
int OSSL_HPKE_suite_check(OSSL_HPKE_SUITE suite)
{
    return hpke_suite_check(suite);
}

/*
 * @brief get a (possibly) random suite, public key and ciphertext for GREASErs
 *
 * As usual buffers are caller allocated and lengths on input are buffer size.
 *
 * @param libctx is the context to use
 * @param propq is a properties string
 * @param suite_in specifies the preferred suite or NULL for a random choice
 * @param suite is the chosen or random suite
 * @param pub a random value of the appropriate length for a sender public value
 * @param pub_len is the length of pub (buffer size on input)
 * @param cipher is a random value of the appropriate length for a ciphertext
 * @param cipher_len is the length of cipher
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_get_grease_value(OSSL_LIB_CTX *libctx, const char *propq,
                               OSSL_HPKE_SUITE *suite_in,
                               OSSL_HPKE_SUITE *suite,
                               unsigned char *enc,
                               size_t *enclen,
                               unsigned char *ct,
                               size_t ctlen)
{
    return hpke_get_grease_value(libctx, propq, suite_in, suite,
                                 enc, enclen, ct, ctlen);
}

/*
 * @brief map a string to a HPKE suite
 * @param str is the string value
 * @param suite is the resulting suite
 * @return 1 for success, otherwise failure
 */
int OSSL_HPKE_str2suite(const char *str, OSSL_HPKE_SUITE *suite)
{
    return ossl_hpke_str2suite(str, suite);
}

/*
 * @brief tell the caller how big the ciphertext will be
 * @param suite is the suite to be used
 * @param clearlen is the length of plaintext
 * @return the length of the related ciphertext or zero on error
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 */
size_t OSSL_HPKE_get_ciphertext_size(OSSL_HPKE_SUITE suite, size_t clearlen)
{
    size_t enclen = 0;
    size_t cipherlen = 0;

    if (hpke_expansion(suite, &enclen, clearlen, &cipherlen) != 1)
        return 0;
    return cipherlen;
}

/*
 * @brief tell the caller how big the public value ``enc`` will be
 * @param suite is the suite to be used
 * @return size of public encap or zero on error
 *
 * AEAD algorithms add a tag for data authentication.
 * Those are almost always, but not always, 16 octets
 * long, and who know what'll be true in the future.
 * So this function allows a caller to find out how
 * much data expansion they'll see with a given
 * suite.
 */
size_t OSSL_HPKE_get_public_encap_size(OSSL_HPKE_SUITE suite)
{
    size_t enclen = 0;
    size_t cipherlen = 0;
    size_t clearlen = 16;

    if (hpke_expansion(suite, &enclen, clearlen, &cipherlen) != 1)
        return 0;
    return enclen;
}

/**
 * @brief recommend an IKM size in octets for a given suite
 * @param suite is the suite to be used
 * @return the recommended size or zero on error
 *
 * Today, this really only uses the KEM to recommend
 * the number of random octets to use based on the
 * size of a private value. In future, it could also
 * factor in e.g. the AEAD.
 */
size_t OSSL_HPKE_get_recommended_ikmelen(OSSL_HPKE_SUITE suite)
{
    const OSSL_HPKE_KEM_INFO *kem_info = NULL;

    if (hpke_suite_check(suite) != 1)
        return 0;
    kem_info = ossl_HPKE_KEM_INFO_find_id(suite.kem_id);
    return kem_info->Npriv;
}
