/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_RSA_H
# define OSSL_INTERNAL_RSA_H

#include <openssl/rsa.h>

RSA *rsa_new(OPENSSL_CTX *libctx);

int rsa_generate_key_int(OPENSSL_CTX *libctx, RSA *rsa, int bits, int primes,
                         BIGNUM *e_value, BN_GENCB *cb);

int rsa_public_encrypt_int(OPENSSL_CTX *libctx, int flen,
                           const unsigned char *from, unsigned char *to,
                           RSA *rsa, int padding);

int rsa_private_decrypt_int(OPENSSL_CTX *libctx, int flen,
                            const unsigned char *from, unsigned char *to,
                            RSA *rsa, int padding);

int rsa_set0_all_params(RSA *r, const STACK_OF(BIGNUM) *primes,
                        const STACK_OF(BIGNUM) *exps,
                        const STACK_OF(BIGNUM) *coeffs);
int rsa_get0_all_params(RSA *r, STACK_OF(BIGNUM_const) *primes,
                        STACK_OF(BIGNUM_const) *exps,
                        STACK_OF(BIGNUM_const) *coeffs);

int rsa_padding_add_PKCS1_type_2_int(OPENSSL_CTX *libctx, unsigned char *to,
                                     int tlen, const unsigned char *from,
                                     int flen);
int rsa_padding_add_PKCS1_OAEP_mgf1_int(OPENSSL_CTX *libctx,
                                        unsigned char *to, int tlen,
                                        const unsigned char *from, int flen,
                                        const unsigned char *param, int plen,
                                        const EVP_MD *md, const EVP_MD *mgf1md);
int rsa_padding_add_PKCS1_OAEP_int(OPENSSL_CTX *libctx,
                                   unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   const unsigned char *param, int plen);
int rsa_padding_add_SSLv23_int(OPENSSL_CTX *libctx, unsigned char *to, int tlen,
                               const unsigned char *from, int flen);
int rsa_padding_check_PKCS1_type_2_TLS(OPENSSL_CTX *libctx,
                                       unsigned char *to, size_t tlen,
                                       const unsigned char *from, size_t flen,
                                       int client_version, int alt_version);

#endif
