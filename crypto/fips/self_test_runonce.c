#include <string.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "self_test_lcl.h"

/* Filename of run once file */
#define ST_RUN_ONCE_FILENAME "fips_selftest.bin"
#define ST_RUN_ONCE_MSG_MAX 256
#define ST_RUN_ONCE_SIG_MAX EVP_MAX_MD_SIZE
#define ST_RUN_ONCE_FILE_MAX (ST_RUN_ONCE_MSG_MAX + ST_RUN_ONCE_SIG_MAX)

#define ST_RUN_ONCE_MSG_FORMAT "Type=0\nStatus=1\nPlatform=%s\n%s"
#define ST_RUN_ONCE_MSG_SIG "Signature="
#define ST_RUN_ONCE_MD_NAME "SHA256"

/* A fixed internal key for calculation of the signature */
static unsigned char st_hmac_key_data[] = {
   0x6b, 0xe3, 0x18, 0x60, 0xca, 0x27, 0x1e, 0xf4,
   0x48, 0xde, 0x8f, 0x8d, 0x8b, 0x39, 0x34, 0x6d,
   0xaf, 0x4b, 0x81, 0xd7, 0xe9, 0x2d, 0x65, 0xb3
};

static int get_checksum_info_string(unsigned char *out, int *out_len)
{
    int bytes;
    bytes = snprintf((char *)out, *out_len, ST_RUN_ONCE_MSG_FORMAT,
                     OpenSSL_version(OPENSSL_PLATFORM), ST_RUN_ONCE_MSG_SIG);
    if (bytes <= 0 || bytes >= *out_len)
        return 0;
    *out_len = bytes;
    return 1;
}

static int calculate_self_test_checksum(unsigned char *out, size_t *out_len,
                                        unsigned char *msg, int msg_len)
{
    int ret = 0;
    const EVP_MD *md = EVP_get_digestbyname(ST_RUN_ONCE_MD_NAME);
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *ctx = NULL;

    ctx = EVP_MD_CTX_new();
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL,
                                        st_hmac_key_data,
                                        sizeof(st_hmac_key_data));
    if (ctx == NULL || pkey == NULL || md == NULL)
        goto end;

    if (!get_checksum_info_string(msg, &msg_len))
        goto end;

    if (!self_test_sign(ctx, pkey, md, msg, msg_len, out, out_len))
        goto end;

    ret = 1;
end:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int verify_runonce_checksum(unsigned char *sig, size_t sig_len)
{
    unsigned char kat[EVP_MAX_MD_SIZE];
    size_t kat_len = sizeof(kat);
    unsigned char msg[ST_RUN_ONCE_MSG_MAX];
    unsigned int msg_len = sizeof(msg);

    return calculate_self_test_checksum(kat, &kat_len, msg, msg_len)
           && test_kat_data(kat, kat_len, sig, sig_len);
}

/*
 * Returns 1 if the self tests have already run successfully, or 0 if the self
 * test have not run. -1 is returned if the file is corrupt.
 */
int self_test_runonce_check()
{
    int ret = 0;
    FILE *fp = NULL;
    char *filename = NULL;
    char data[ST_RUN_ONCE_FILE_MAX];
    char *str;
    size_t bytes;

    filename = self_test_file_path(ST_RUN_ONCE_FILENAME);
    if (filename == NULL)
        goto end;
    fp = fopen(filename, "rb");
    if (fp == NULL)
        goto end;

    ret = -1;
    bytes = fread(data, 1, ST_RUN_ONCE_FILE_MAX, fp);
    if (bytes <= 0 || bytes >= ST_RUN_ONCE_FILE_MAX)
        goto end;

    str = strstr(data, ST_RUN_ONCE_MSG_SIG);
    if (str != NULL) {
        str += (sizeof(ST_RUN_ONCE_MSG_SIG) - 1);
        if (!verify_runonce_checksum((unsigned char *)str,
                                      bytes - (str - data)))
            goto end;
    }
    ret = 1;
end:
    if (fp != NULL)
        fclose(fp);
    free(filename);
    return ret;

}

/*
 * Mark the self tests as being successfully run by writing to a file.
 * It saves an integrity value to the file as this is considered to be a
 * Critical Security Parameter.
 * This file can be loaded and validated on subsequent loads to avoid the
 * self tests having to run again.
 */
void self_test_runonce_save()
{
    FILE *fp = NULL;
    char *filename = NULL;
    unsigned char sig[ST_RUN_ONCE_SIG_MAX];
    size_t sig_len = sizeof(sig);
    unsigned char msg[ST_RUN_ONCE_MSG_MAX];
    int msg_len = sizeof(msg);

    if (!calculate_self_test_checksum(sig, &sig_len, msg, msg_len))
        goto end;

    filename = self_test_file_path(ST_RUN_ONCE_FILENAME);
    if (filename == NULL)
        goto end;
    fp = fopen(filename, "wb");
    if (fp == NULL)
        goto end;

    fputs((char *)msg, fp);
    fwrite(sig, 1, sig_len, fp);
end:
    if (fp != NULL)
        fclose(fp);
    free(filename);
}
