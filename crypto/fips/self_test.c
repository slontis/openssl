#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand_drbg.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <string.h>
#include "internal/nelem.h"
#include "crypto/rand/rand_lcl.h"
#include "self_test_lcl.h"
#include "self_test_data.c"

#define SELF_TEST_CALLBACK 1


/* Utility function to convert binary data to a BIGNUM */
static BIGNUM *TOBN(ST_ITEM item)
{
    return BN_bin2bn(item.data, item.len, NULL);
}

int test_kat_data(const unsigned char *data, size_t data_len,
                  const unsigned char *kat, size_t kat_len)
{
    return (data_len == kat_len && memcmp(data, kat, kat_len) == 0);
}

int test_kat(const unsigned char *data, int data_len, ST_ITEM kat)
{
    return (data_len == kat.len && memcmp(data, kat.data, data_len) == 0);
}

/* Load a EVP_PKEY from binary data */
static EVP_PKEY *pkey_from_binary(int nid, ST_ITEM *key)
{
    EVP_PKEY *pkey = EVP_PKEY_new();
    void *vkey = NULL;
    RSA *rsa = NULL;
    DSA *dsa = NULL;
    EC_KEY *ec = NULL;
    int type;

    if (pkey == NULL)
        goto err;
    switch (nid)
    {
    case NID_ecdsa_with_Specified:
        ec = EC_KEY_new_by_curve_name(OBJ_sn2nid((char *)key[EC_CURVE].data));
        if (ec == NULL
                || !EC_KEY_set_public_key_affine_coordinates(ec,
                                                             TOBN(key[EC_X]),
                                                             TOBN(key[EC_Y]))
                || !EC_KEY_set_private_key(ec, TOBN(key[EC_D]))) {
            EC_KEY_free(ec);
            goto err;
        }
        type = EVP_PKEY_EC;
        vkey = ec;
        break;
    case NID_rsa:
        rsa  = RSA_new();
        if (rsa == NULL
                || !RSA_set0_key(rsa, TOBN(key[RSA_N]), TOBN(key[RSA_E]),
                                 TOBN(key[RSA_D]))
                || !RSA_set0_factors(rsa, TOBN(key[RSA_P]), TOBN(key[RSA_Q]))
                || !RSA_set0_crt_params(rsa, TOBN(key[RSA_DMP1]),
                                        TOBN(key[RSA_DMQ1]),
                                        TOBN(key[RSA_IQMP]))) {
            RSA_free(rsa);
            goto err;
        }
        type = EVP_PKEY_RSA;
        vkey = rsa;
        break;
    case NID_dsa:
        dsa = DSA_new();
        if (dsa == NULL
            || !DSA_set0_pqg(dsa, TOBN(key[DSA_P]), TOBN(key[DSA_Q]),
                             TOBN(key[DSA_G]))
            || !DSA_set0_key(dsa, TOBN(key[DSA_PUB]), TOBN(key[DSA_PRIV]))) {
            DSA_free(dsa);
            goto err;
        }
        type = EVP_PKEY_DSA;
        vkey = dsa;
        break;
    default:
        goto err;
    }
    EVP_PKEY_assign(pkey, type, vkey);
    return pkey;
err:
    EVP_PKEY_free(pkey);
    return NULL;
}

/*
 * Helper function to setup a EVP_CipherInit
 * Used to hide the complexity of Authenticated ciphers.
 */
static int cipher_init(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
                       ST_CIPHER *t, int do_encrypt)
{
    int pad = ((t->flags & ST_FLAG_PAD) != 0) ? 1 : 0;

    /* Flag required for Key wrapping */
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (t->tag.data == NULL) {
        /* Use a normal cipher init */
        return EVP_CipherInit_ex(ctx, cipher, NULL, t->key.data, t->iv.data,
                                 do_encrypt)
               && EVP_CIPHER_CTX_set_padding(ctx, pad);
    } else {
        /* The authenticated cipher init */
        unsigned char *in_tag = NULL;
        int in_len = 0, in_tag_len = 0;
        int tmp;
        int is_ccm = ((t->flags & ST_FLAG_CCM) != 0);

        if (do_encrypt) {
            if (is_ccm) {
                in_len = t->pt.len;
                in_tag_len = 1;
            }
        } else {
            if (is_ccm)
                in_len = t->ct_ka.len;
            in_tag = (unsigned char *)t->tag.data;
        }
        return EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, do_encrypt)
               && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, t->iv.len,
                                      NULL)
               && ((in_tag == NULL && in_tag_len == 0)
                       || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                                              t->tag.len, in_tag))
               && EVP_CipherInit_ex(ctx, NULL, NULL, t->key.data, NULL, // t->iv.data,
                                    do_encrypt)
               && EVP_CIPHER_CTX_set_padding(ctx, pad)
               && (in_len == 0
                       || EVP_CipherUpdate(ctx, NULL, &tmp, NULL, in_len))
               && EVP_CipherUpdate(ctx, NULL, &tmp, t->add.data, t->add.len);
    }
}

int self_test_cipher(ST_CIPHER *t)
{
    unsigned char ct_buf[256] = { 0 };
    unsigned char pt_buf[256] = { 0 };
    int ret = 0;
    int len, ct_len, pt_len;
    int encrypt = 1;
    EVP_CIPHER_CTX *ctx = NULL;
    const EVP_CIPHER *cipher = NULL;
    const char *desc = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;
    cipher = EVP_get_cipherbynid(t->nid);
    if (cipher == NULL)
        goto err;
    desc = EVP_CIPHER_name(cipher);
    self_test_cb(ST_TYPE_CIPHER, desc, "start");

    /* Encrypt plaintext msg */
    if (!cipher_init(ctx, cipher, t, encrypt)
            || !EVP_CipherUpdate(ctx, ct_buf, &len, t->pt.data, t->pt.len)
            || !EVP_CipherFinal_ex(ctx, ct_buf + len, &ct_len))
        goto err;
    ct_len += len;

    if (!test_kat(ct_buf, ct_len, t->ct_ka))
        goto err;

    if (t->tag.data != NULL) {
        unsigned char tag[16] = { 0 };
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, t->tag.len, tag)
                || !test_kat(tag, t->tag.len, t->tag))
            goto err;
    }

#ifdef SELF_TEST_CALLBACK
    /* Optional corruption */
    if (self_test_is_corrupt_cb(ST_TYPE_CIPHER, desc))
        ct_buf[0] ^= 1;
#endif

    if (!cipher_init(ctx, cipher, t, !encrypt)
            || !EVP_CipherUpdate(ctx, pt_buf, &len, ct_buf, ct_len)
            || !EVP_CipherFinal_ex(ctx, pt_buf + len, &pt_len))
        goto err;
    pt_len += len;

    if (!test_kat(pt_buf, pt_len, t->pt))
        goto err;

    ret = 1;
err:
    self_test_cb(ST_TYPE_CIPHER, desc, ret ? "pass" : "fail");
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int self_test_digest(ST_DIGEST *t)
{
    int ret = 0;
    unsigned int out_len = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = EVP_get_digestbynid(t->nid);
    unsigned char out[EVP_MAX_MD_SIZE] = { 0 };
    const char *desc = NULL;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || md == NULL)
        goto err;

    desc = EVP_MD_name(md);
    self_test_cb(ST_TYPE_DIGEST, desc, "start");

    if (!EVP_DigestInit_ex(ctx, md, NULL)
            || !EVP_DigestUpdate(ctx, t->pt.data, t->pt.len)
            || !EVP_DigestFinal_ex(ctx, out, &out_len))
        goto err;

#ifdef SELF_TEST_CALLBACK
    /* Optional corruption */
    if (self_test_is_corrupt_cb(ST_TYPE_DIGEST, desc))
        out[0] ^= 1;
#endif

    if (!test_kat(out, (int)out_len, t->digest_ka))
        goto err;

    ret = 1;
err:
    self_test_cb(ST_TYPE_DIGEST, desc, ret ? "pass" : "fail");
    EVP_MD_CTX_free(ctx);
    return ret;
}

int self_test_sign(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md,
                   const unsigned char *msg, int msg_len,
                   unsigned char *out, size_t *out_len)
{
    return EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) == 1
            && EVP_DigestSignUpdate(ctx, msg, msg_len) == 1
            && EVP_DigestSignFinal(ctx, NULL, out_len) == 1
            && EVP_DigestSignFinal(ctx, out, out_len) == 1;
}

int self_test_signature(ST_SIGNATURE *t)
{
    int ret = 0;
    size_t out_len = 0;
    unsigned char out[256];
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = EVP_get_digestbynid(t->digest_nid);
    EVP_PKEY *pkey = pkey_from_binary(t->key_nid, t->key);
    const char *desc = t->name;

    self_test_cb(ST_TYPE_SIGNATURE, desc, "start");
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL || md == NULL)
        goto err;

    out_len = t->sig_ka.len;
    if (!self_test_sign(ctx, pkey, md, t->msg.data, t->msg.len, out, &out_len)
            || (t->sig_ka.data != NULL && !test_kat(out, out_len, t->sig_ka)))
        goto err;

#ifdef SELF_TEST_CALLBACK
    /* Optional corruption */
    if (self_test_is_corrupt_cb(ST_TYPE_SIGNATURE, desc))
        out[0] ^= 1;
#endif

    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey) != 1
            || EVP_DigestVerifyUpdate(ctx, t->msg.data, t->msg.len) != 1
            || EVP_DigestVerifyFinal(ctx, out, out_len) != 1)
        goto err;
    ret = 1;
err:
    self_test_cb(ST_TYPE_SIGNATURE, desc, ret ? "pass" : "fail");
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}


static int drbg_data_index = -1;

static size_t drbg_entropy_cb(RAND_DRBG *drbg, unsigned char **pout,
                              int entropy, size_t min_len, size_t max_len,
                              int prediction_resistance)
{
    ST_DRBG *t = (ST_DRBG *)RAND_DRBG_get_ex_data(drbg, drbg_data_index);
    if (prediction_resistance) {
        *pout = (unsigned char *)t->reseed_entropy.data;
        return t->reseed_entropy.len;
    } else {
        *pout = (unsigned char *)t->init_entropy.data;
        return t->init_entropy.len;
    }
}

#if 0
static int drbg_is_clear(unsigned char *data, unsigned int len)
{
    unsigned int i;
    for (i = 0; i < len; ++i) {
        if (data[i] != 0)
            return 0;
    }
    return 1;
}
#endif

static int self_test_DRBG(ST_DRBG *t)
{
    int ret = 0;
    RAND_DRBG *drbg = NULL;
    unsigned char out[16];
    static const int predict_resist = 1;
    const char *desc = t->name;
    int len;

    if (drbg_data_index == -1)
        drbg_data_index = RAND_DRBG_get_ex_new_index(0L, NULL, NULL, NULL, NULL);

    self_test_cb(ST_TYPE_DRBG, desc, "start");
    drbg = RAND_DRBG_new(t->nid, t->flags, NULL);
    if (drbg == NULL
            || !RAND_DRBG_set_ex_data(drbg, drbg_data_index, t)
            || !RAND_DRBG_set_callbacks(drbg, drbg_entropy_cb, NULL, NULL, NULL)
            || !RAND_DRBG_instantiate(drbg, t->pers_str.data, t->pers_str.len)
            || !RAND_DRBG_generate(drbg, out, t->gen_ka.len,!predict_resist,
                                   t->gen_addin.data, t->gen_addin.len)
            || !test_kat(out, t->gen_ka.len, t->gen_ka))
        goto err;
    len = t->reseed_addin.len;
#ifdef SELF_TEST_CALLBACK
    /* Optional corruption */
    if (self_test_is_corrupt_cb(ST_TYPE_DRBG, desc))
        len--;
#endif
    if (!RAND_DRBG_reseed(drbg, t->reseed_addin.data, len, predict_resist)
            || !RAND_DRBG_generate(drbg, out, t->reseed_ka.len, !predict_resist,
                                   t->reseed_addin.data, t->reseed_addin.len)
            || !test_kat(out, t->reseed_ka.len, t->reseed_ka)
            || !RAND_DRBG_uninstantiate(drbg))
        goto err;

#if 0
    if (!drbg_is_clear((unsigned char *)&drbg->data, sizeof(drbg->data)))
        goto err;
#endif

    ret = 1;
err:
    self_test_cb(ST_TYPE_DRBG, desc, ret ? "pass" : "fail");
    RAND_DRBG_free(drbg);
    return ret;
}

static int self_test_integrity(void)
{
    int ret = 0, st = 0;
    char *fail_reason = "fail";
    unsigned char checksum[EVP_MAX_MD_SIZE];
    unsigned char expected[EVP_MAX_MD_SIZE];
    size_t checksum_len = sizeof(checksum);
    int expected_len = sizeof(expected);
    ST_ITEM kat;

    self_test_cb(ST_TYPE_INTEGRITY, "", "start");

    if (getenv("OSSL_SELFTEST_INSTALL"))
        self_test_integrity_save(1);


    st = self_test_integrity_calculate(checksum, &checksum_len);
    if (st != 1) {
        if (st == -1)
            fail_reason = "Failed loading fips module file";
        else
            fail_reason = "Failed to calculate checksum";
        goto end;
    }

#ifdef SELF_TEST_CALLBACK
    /* Optional corruption */
    if (self_test_is_corrupt_cb(ST_TYPE_INTEGRITY, ""))
        checksum[0] ^= 1;
#endif
   if (!self_test_integrity_load(expected, &expected_len)) {
       fail_reason = "Failed to load verify checksum";
       goto end;
   }
   kat.data = expected;
   kat.len = expected_len;
   if (!test_kat(checksum, checksum_len, kat)) {
       fail_reason = "Verify failed";
       goto end;
   }
   ret = 1;
end:
    self_test_cb(ST_TYPE_INTEGRITY, "", ret ? "pass" : fail_reason);
    return ret;
}

int FIPS_self_test(int force_run_selftest)
{
    int self_test_failed = 0;
    unsigned int i;
    int has_run = 0;

    if (!self_test_integrity())
        self_test_failed = 1;

    has_run = self_test_runonce_check();
    if (force_run_selftest || has_run == 1)
    {
        for (i = 0; i < OSSL_NELEM(cipher_tests); ++i) {
            if (!self_test_cipher(&cipher_tests[i]))
                self_test_failed = 1;
        }

        for (i = 0; i < OSSL_NELEM(digest_tests); ++i) {
            if (!self_test_digest(&digest_tests[i]))
                self_test_failed = 1;
        }

        for (i = 0; i < OSSL_NELEM(signature_tests); ++i) {
            if (!self_test_signature(&signature_tests[i]))
                self_test_failed = 1;;
        }


        for (i = 0; i < OSSL_NELEM(drbg_tests); ++i) {
            if (!self_test_DRBG(&drbg_tests[i])) {
                self_test_failed = 1;
            }
        }

        /* On success only save the state if the file has not been corrupted */
        if (self_test_failed == 0 && has_run == 0)
            self_test_runonce_save();
    }
    return self_test_failed ? 0 : 1;
}
