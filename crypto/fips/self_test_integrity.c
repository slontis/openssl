#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "self_test_lcl.h"

/* Filename to save integrity datat into - used for verifying */
#define ST_INTEGRITY_FILENAME "fips_integrity.bin"
/* Platform specific name of FIPS MODULE LIBRARY */
#define ST_INTEGRITY_FIPS_LIB_FILENAME  "libcrypto.so"
#define ST_INTEGRITY_MD_NAME "SHA256"
#define ST_INTEGRITY_MSG_BUFFER_LEN (16*1024)


/* A fixed internal key for calculation of the POST integrity signature */
static unsigned char st_hmac_integrity_key_data[] = {
   0x6b, 0xe3, 0x18, 0x60, 0xca, 0x27, 0x1e, 0xf4,
   0x48, 0xde, 0x8f, 0x8d, 0x8b, 0x39, 0x34, 0x6d,
   0xaf, 0x4b, 0x81, 0xd7, 0xe9, 0x2d, 0x65, 0xb3
};

/*
 * Platform specific code to get the library path may be
 * required if accessing via a default entry point (DEP).
 */
static char *self_test_lib_file_path(void)
{
    return ".//";
}

/*
 * The returned path must be freed by the user.
 */
char *self_test_file_path(const char *fname)
{
    char *filename = NULL;
    char *path = self_test_lib_file_path();

    if (path == NULL)
        goto err;

    filename = malloc(1 + strlen(path) + strlen(fname));
    if (filename == NULL)
        goto err;
    sprintf(filename, "%s%s", path, fname);
err:
    return filename;
}

/*
 * Returns the calculated integrity checksum of the FIPS module library file.
 */
int self_test_integrity_calculate(unsigned char *out, size_t *out_len)
{
    int ret = 0;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = EVP_get_digestbyname(ST_INTEGRITY_MD_NAME);
    EVP_PKEY *pkey = NULL;
    unsigned char *msg = NULL;
    unsigned int msg_len;
    FILE *fp = NULL;
    char *filename = NULL;

    ctx = EVP_MD_CTX_new();
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                        st_hmac_integrity_key_data,
                                        sizeof(st_hmac_integrity_key_data));
    if (ctx == NULL || pkey == NULL || md == NULL)
        goto end;
    filename = self_test_file_path(ST_INTEGRITY_FIPS_LIB_FILENAME);
    if (filename == NULL) {
        ret = -1;
        goto end;
    }

    msg = malloc(ST_INTEGRITY_MSG_BUFFER_LEN);
    if (msg == NULL)
        goto end;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        ret = -1;
        goto end;
    }

    if (EVP_DigestSignInit(ctx, NULL, md, NULL, pkey) != 1)
        goto end;

    while (1) {
        msg_len = fread(msg, 1, sizeof(msg), fp);
        if (msg_len <= 0)
            break;
        if (EVP_DigestSignUpdate(ctx, msg, msg_len) != 1)
            goto end;
    }
    ret = EVP_DigestSignFinal(ctx, NULL, out_len) == 1
          && EVP_DigestSignFinal(ctx, out, out_len) == 1;
end:
    if (fp != NULL)
        fclose(fp);
    free(filename);
    free(msg);
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}

/*
 * Retrieve the stored integrity checksum from a file.
 * Returns 1 if successful, or 0 if there was a file error.
 */
int self_test_integrity_load(unsigned char *out, int *out_len)
{
    int ret = 0;
    int num;
    FILE *fp = NULL;
    char *filename = self_test_file_path(ST_INTEGRITY_FILENAME);
    if (filename == NULL)
        goto end;

    fp = fopen(filename, "rb");
    if (fp == NULL)
        goto end;

    num = fread(out, 1, *out_len, fp);
    if (num <= 0)
        goto end;
    ret = 1;
    *out_len = num;
end:
    if (fp != NULL)
        fclose(fp);
    free(filename);
    return ret;
}

/*
 * Write out the integrity checksum to a file.
 * If force=0 then it will fail if the file already exists.
 * Returns 1 if successful.
 */
int self_test_integrity_save(int force)
{
    int ret = 0;
    FILE *fp = NULL;
    char *filename = NULL;
    unsigned char out[EVP_MAX_MD_SIZE];
    size_t out_len = sizeof(out);

    filename = self_test_file_path(ST_INTEGRITY_FILENAME);
    if (filename == NULL)
        goto end;

    if (!force) {
        fp = fopen(filename, "rb");
        if (fp != NULL)
            goto end;
    }

    if (!self_test_integrity_calculate(out, &out_len))
        goto end;

    fp = fopen(filename, "wb");
    if (fp == NULL)
        goto end;
    if (fwrite(out, 1, out_len, fp) != out_len)
        goto end;

    ret = 1;
end:
    if (fp != NULL)
        fclose(fp);
    free(filename);
    return ret;
}

