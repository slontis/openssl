#ifndef SELF_TEST_LCL_H_
#define SELF_TEST_LCL_H_

#include <openssl/evp.h>

#define ST_TYPE_INTEGRITY "integrity_checksum"
#define ST_TYPE_CIPHER    "cipher"
#define ST_TYPE_DIGEST    "digest"
#define ST_TYPE_SIGNATURE "signature"
#define ST_TYPE_DRBG      "drbg"

#define ST_FLAG_NOPAD 0
#define ST_FLAG_PAD   1
#define ST_FLAG_CCM   2

/* Binary data */
typedef struct item_st {
    const unsigned char *data;
    int len;
} ST_ITEM;

/* Self test data for a cipher - last fields required for authenticated modes */
typedef struct st_cipher_st {
    int nid;
    int flags;
    ST_ITEM pt;
    ST_ITEM ct_ka;
    ST_ITEM key;
    ST_ITEM iv;
    ST_ITEM add;
    ST_ITEM tag;
} ST_CIPHER;

/* Self test data for a digest */
typedef struct st_digest_st {
    int nid;
    ST_ITEM pt;
    ST_ITEM digest_ka;
} ST_DIGEST;

/* Self test data for a signature */
typedef struct st_sig_st {
    const char *name;
    int key_nid;
    int digest_nid;
    ST_ITEM *key;
    ST_ITEM msg;
    ST_ITEM sig_ka;
} ST_SIGNATURE;

/* Self test data for a DRBG */
typedef struct st_drbg_st {
    const char *name;
    int nid;
    int flags;
    ST_ITEM init_entropy;
    ST_ITEM pers_str;
    ST_ITEM gen_addin;
    ST_ITEM gen_ka;
    ST_ITEM reseed_entropy;
    ST_ITEM reseed_addin;
    ST_ITEM reseed_ka;
} ST_DRBG;

char *self_test_file_path(const char *fname);

int self_test_runonce_check(void);
void self_test_runonce_save(void);

int self_test_integrity_calculate(unsigned char *out, size_t *out_len);
int self_test_integrity_load(unsigned char *out, int *out_len);
int self_test_integrity_save(int force);

int self_test_signature(ST_SIGNATURE *t);
int self_test_sign(EVP_MD_CTX *ctx, EVP_PKEY *pkey, const EVP_MD *md,
                   const unsigned char *msg, int msg_len,
                   unsigned char *out, size_t *out_len);
int self_test_digest(ST_DIGEST *t);
int self_test_cipher(ST_CIPHER *t);
int test_kat_data(const unsigned char *data, size_t data_len,
                  const unsigned char *kat, size_t kat_len);
int test_kat(const unsigned char *data, int data_len, ST_ITEM kat);

int self_test_is_corrupt_cb(const char *type, const char *desc);
void self_test_cb(const char *type, const char *desc, const char *state);

#endif /* SELF_TEST_LCL_H_ */
