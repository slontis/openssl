/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "internal/thread_once.h"
#include "rand_lcl.h"

/* Called twice by SP800-90Ar1 10.1.2.2 HMAC_DRBG_Update_Process.
 * inbyte is 0x00 on the first call and 0x01 on the second call.
 */
static int do_hmac(RAND_DRBG_HMAC *hmac, unsigned char inbyte,
                   const unsigned char *in1, size_t in1len,
                   const unsigned char *in2, size_t in2len,
                   const unsigned char *in3, size_t in3len)
{
    HMAC_CTX *ctx = hmac->ctx;
           /* K = HMAC(K, V || inbyte || provived_data */
    return HMAC_Init_ex(ctx, hmac->K, hmac->blocklen, hmac->md, NULL)
           && HMAC_Update(ctx, hmac->V, hmac->blocklen)
           && HMAC_Update(ctx, &inbyte, 1)
           && (in1 == NULL || in1len == 0 || HMAC_Update(ctx, in1, in1len))
           && (in2 == NULL || in2len == 0 || HMAC_Update(ctx, in2, in2len))
           && (in3 == NULL || in3len == 0 || HMAC_Update(ctx, in3, in3len))
           && HMAC_Final(ctx, hmac->K, NULL)
           /* V = HMAC(K, V) */
           && HMAC_Init_ex(ctx, hmac->K, hmac->blocklen, hmac->md, NULL)
           && HMAC_Update(ctx, hmac->V, hmac->blocklen)
           && HMAC_Final(ctx, hmac->V, NULL);
}

/* SP800-90Ar1 10.1.2.2 HMAC_DRBG_Update_Process: */
static int drbg_hmac_update(RAND_DRBG *drbg,
                            const unsigned char *in1, size_t in1len,
                            const unsigned char *in2, size_t in2len,
                            const unsigned char *in3, size_t in3len)
{
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;
    /* (Steps 1-2) K = HMAC(K, V||0x00||provided_data). V = HMAC(K,V) */
    if (!do_hmac(hmac, 0x00, in1, in1len, in2, in2len, in3, in3len))
        return 0;
    /* (Step 3) If provided_data == NULL then return (K,V) */
    if (in1len == 0 && in2len == 0 && in3len == 0)
        return 1;
    /* (Steps 4-5) K = HMAC(K, V||0x01||provided_data). V = HMAC(K,V) */
    return do_hmac(hmac, 0x01, in1, in1len, in2, in2len, in3, in3len);
}

/* SP800-90Ar1 10.1.2.3 HMAC_DRBG_Instantiate_Process: */
static int drbg_hmac_instantiate(RAND_DRBG *drbg,
                                 const unsigned char *ent, size_t ent_len,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned char *pstr, size_t pstr_len)
{
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;
    /* (Step 2) Key = 0x00 00...00 */
    memset(hmac->K, 0x00, hmac->blocklen);
    /* (Step 3) V = 0x01 01...01 */
    memset(hmac->V, 0x01, hmac->blocklen);
    /* (Step 4) (K,V) = HMAC_DRBG_Update(entropy||nonce||pers string, K, V) */
    return drbg_hmac_update(drbg, ent, ent_len, nonce, nonce_len, pstr,
                            pstr_len);
}

/* SP800-90Ar1 10.1.2.4 HMAC_DRBG_Rseed_Process: */
static int drbg_hmac_reseed(RAND_DRBG *drbg,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    /* (Step 2) (K,V) = HMAC_DRBG_Update(entropy||additional_input, K, V) */
    return drbg_hmac_update(drbg, ent, ent_len, adin, adin_len, NULL, 0);
}

/* SP800-90Ar1 10.1.2.5 HMAC_DRBG_Generate_Process: */
static int drbg_hmac_generate(RAND_DRBG *drbg,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;
    HMAC_CTX *ctx = hmac->ctx;
    const unsigned char *temp = hmac->V;

    if (adin != NULL
            && adin_len > 0
            && !drbg_hmac_update(drbg, adin, adin_len, NULL, 0, NULL, 0))
        return 0;
    for (;;) {
        if (!HMAC_Init_ex(ctx, hmac->K, hmac->blocklen, hmac->md, NULL)
                || !HMAC_Update(ctx, temp, hmac->blocklen))
            return 0;

        if (outlen > hmac->blocklen) {
            if (!HMAC_Final(ctx, out, NULL))
                return 0;
            temp = out;
        } else {
            if (!HMAC_Final(ctx, hmac->V, NULL))
                return 0;
            memcpy(out, hmac->V, outlen);
            break;
        }
        out += hmac->blocklen;
        outlen -= hmac->blocklen;
    }
    if (!drbg_hmac_update(drbg, adin, adin_len, NULL, 0, NULL, 0))
        return 0;

    return 1;
}

static int drbg_hmac_uninstantiate(RAND_DRBG *drbg)
{
    HMAC_CTX_free(drbg->data.hmac.ctx);
    OPENSSL_cleanse(&drbg->data.hmac, sizeof(drbg->data.hmac));
    return 1;
}

static RAND_DRBG_METHOD drbg_hmac_meth = {
    drbg_hmac_instantiate,
    drbg_hmac_reseed,
    drbg_hmac_generate,
    drbg_hmac_uninstantiate
};

int drbg_hmac_init(RAND_DRBG *drbg)
{
    const EVP_MD *md = NULL;
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;

    /* Any approved digest is allowed - assume we pass digest (not NID_hmac*) */
    md = EVP_get_digestbynid(drbg->type);
    if (md == NULL)
        return 0;

    drbg->meth = &drbg_hmac_meth;

    if (hmac->ctx == NULL) {
        hmac->ctx = HMAC_CTX_new();
        if (hmac->ctx == NULL)
            return 0;
    }

    hmac->md = md;
    hmac->blocklen = EVP_MD_size(md);
    /* See SP800-57 Part1 Rev4 5.6.1 Table 3 */
    drbg->strength = 64 * (hmac->blocklen >> 3);
    if (drbg->strength > 256)
        drbg->strength = 256;
    drbg->seedlen = hmac->blocklen;

    drbg->min_entropylen = drbg->strength / 8;
    drbg->max_entropylen = DRBG_MINMAX_FACTOR * drbg->min_entropylen;

    drbg->min_noncelen = drbg->min_entropylen / 2;
    drbg->max_noncelen = DRBG_MINMAX_FACTOR * drbg->min_noncelen;

    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;

    drbg->max_request = 1 << 16;

    return 1;
}
