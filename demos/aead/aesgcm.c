/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/params.h>
#include <openssl/aead.h>
#include <openssl/core_names.h>

/* AES-GCM test data obtained from NIST public test vectors */

/* AES key */
static const unsigned char gcm_key[] = {
    0xee, 0xbc, 0x1f, 0x57, 0x48, 0x7f, 0x51, 0x92, 0x1c, 0x04, 0x65, 0x66,
    0x5f, 0x8a, 0xe6, 0xd1, 0x65, 0x8b, 0xb2, 0x6d, 0xe6, 0xf8, 0xa0, 0x69,
    0xa3, 0x52, 0x02, 0x93, 0xa5, 0x72, 0x07, 0x8f
};

/* Unique initialisation vector */
static const unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

/* Example plaintext to encrypt */
static const unsigned char gcm_pt[] = {
    0xf5, 0x6e, 0x87, 0x05, 0x5b, 0xc3, 0x2d, 0x0e, 0xeb, 0x31, 0xb2, 0xea,
    0xcc, 0x2b, 0xf2, 0xa5
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
static const unsigned char gcm_aad[] = {
    0x4d, 0x23, 0xc3, 0xce, 0xc3, 0x34, 0xb4, 0x9b, 0xdb, 0x37, 0x0c, 0x43,
    0x7f, 0xec, 0x78, 0xde
};

/* Expected ciphertext value */
static const unsigned char gcm_ct[] = {
    0xf7, 0x26, 0x44, 0x13, 0xa8, 0x4c, 0x0e, 0x7c, 0xd5, 0x36, 0x86, 0x7e,
    0xb9, 0xf2, 0x17, 0x36
};

/* Expected AEAD Tag value */
static const unsigned char gcm_tag[] = {
    0x67, 0xba, 0x05, 0x10, 0x26, 0x2a, 0xe4, 0x87, 0xd7, 0x37, 0xee, 0x62,
    0x98, 0xf7, 0x7e, 0x0c
};

/*
 * A library context and property query can be used to select & filter
 * algorithm implementations. If they are NULL then the default library
 * context and properties are used.
 */
OSSL_LIB_CTX *libctx = NULL;
const char *propq = NULL;

int aes_gcm_seal(unsigned char *ct, size_t *ctlen)
{
    int ret = 0;
    EVP_AEAD_CTX *sctx = NULL;
    int outlen, tmplen;
    OSSL_PARAM params[2];
    const unsigned char *pt = gcm_pt;
    size_t ptlen = sizeof(gcm_pt);

    printf("AES GCM Seal:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, pt, ptlen);

    /* Create a context for the seal operation */
    if ((sctx = EVP_AEAD_CTX_new_from_cipher(libctx, "AES-256-GCM", propq)) == NULL)
        goto err;

    if (!EVP_AEAD_CTX_init(sctx, gcm_key, sizeof(gcm_key)))
        goto err;

    /*
     * Optionally pass the IV.
     * In a compliant application the IV would be generated internally so the iv passed in
     * would be NULL, so this line would be omitted.
     */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_AEAD_PARAM_IV,
                                                  (void *)gcm_iv, sizeof(gcm_iv));
    /* Set this to optionally return a truncated taglen - The default size is used otherwise */
    //params[1] = OSSL_PARAM_construct_size_t(OSSL_AEAD_PARAM_TAGLEN, &taglen);
    params[1] = OSSL_PARAM_construct_end();


    if (!EVP_AEAD_CTX_seal(sctx, ct, ctlen, pt, ptlen, gcm_aad, sizeof(gcm_aad), params))
        goto err;

    /*
     * For demo purposes we print the actual ciphertext and tag separately,
     * Normally this is not required, since the ciphertext + tag can just be
     * passed to the open() to do an authenticated decrypt.
     */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ct, ptlen);

    if (memcmp(gcm_ct, ct, ptlen) != 0) {
        fprintf(stderr, "The cipher text does not match the expected value");
        goto err;
    }

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, ct + ptlen, *ctlen - ptlen);

    if (memcmp(gcm_tag, ct + ptlen, *ctlen - ptlen) != 0) {
        fprintf(stderr, "The tag does not match the expected value");
        goto err;
    }

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_AEAD_CTX_free(sctx);
    return ret;
}

int aes_gcm_open(const unsigned char *ct, size_t ctlen)
{
    int ret = 0;
    EVP_AEAD_CTX *octx = NULL;
    EVP_AEAD *aead = NULL;
    size_t gcm_ivlen = sizeof(gcm_iv);
    unsigned char pt[1024];
    size_t ptlen = sizeof(pt);
    OSSL_PARAM params[2];

    printf("AES GCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ct, ctlen);

    if ((octx = EVP_AEAD_CTX_new_from_cipher(libctx, "AES-256-GCM", propq)) == NULL)
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_AEAD_PARAM_IV,
                                                  (void *)gcm_iv, sizeof(gcm_iv));
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_AEAD_CTX_init(octx, gcm_key, sizeof(gcm_key)))
        goto err;

    if (!EVP_AEAD_CTX_open(octx, pt, &ptlen, ct, ctlen, gcm_aad, sizeof(gcm_aad), params))
        goto err;

    /* Output decrypted block */
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, pt, ptlen);

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_AEAD_CTX_free(octx);
    return ret;
}

int main(int argc, char **argv)
{
    unsigned char ct[1024];
    size_t ctlen = sizeof(ct); /* The max size of the buffer is passed to the seal */

    if (!aes_gcm_seal(ct, &ctlen))
        return 1;

    if (!aes_gcm_open(ct, ctlen))
        return 1;

    return 0;
}
