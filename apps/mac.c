/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "apps.h"
#include "progs.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/params.h>

#undef BUFSIZE
#define BUFSIZE 1024*8

typedef enum OPTION_choice {
    OPT_ERR = -1, OPT_EOF = 0, OPT_HELP,
    OPT_MACOPT, OPT_BIN, OPT_IN, OPT_OUT
} OPTION_CHOICE;

const OPTIONS mac_options[] = {
    {OPT_HELP_STR, 1, '-', "Usage: %s [options] mac_name\n"},
    {OPT_HELP_STR, 1, '-', "mac_name\t\t MAC algorithm (See list "
                           "-mac-algorithms)"},
    {"help", OPT_HELP, '-', "Display this summary"},
    {"macopt", OPT_MACOPT, 's', "MAC algorithm control parameters in n:v form. "
                                "See 'Supported Controls' in the EVP_MAC_ docs"},
    {"in", OPT_IN, '<', "Input file to MAC (default is stdin)"},
    {"out", OPT_OUT, '>', "Output to filename rather than stdout"},
    {"binary", OPT_BIN, '-', "Output in binary format (Default is hexadecimal "
                             "output)"},
    {NULL}
};

/*
static int mac_ctrl_string(EVP_MAC_CTX *ctx, const char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;

    stmp = OPENSSL_strdup(value);
    if (stmp == NULL)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp != NULL) {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_MAC_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}
*/

static int hex2param(OSSL_PARAM *p, const char *key, const char *hex,
                     unsigned char **out)
{
    long binlen = 0;
    unsigned char *bin = NULL;

    bin = OPENSSL_hexstr2buf(hex, &binlen);
    if (bin == NULL)
        return 0;
    if (binlen <= INT_MAX) {
        *p = OSSL_PARAM_construct_octet_ptr(key + 3, (void **)out, binlen, NULL);
        *out = bin;
        return 1;
    }
    OPENSSL_free(bin);
    return 0;
}

static int str2param(OSSL_PARAM *p, const char *key, char **value)
{
    size_t len;

    len = strlen(*value);
    if (len > INT_MAX)
        return 0;
    *p = OSSL_PARAM_construct_octet_ptr(key, (void **)value, len, NULL);
    return 1;
}

static int mac_set_params(EVP_MAC_CTX *ctx, STACK_OF(OPENSSL_STRING) *opts)
{
    int rv = 0, i;
    char *ktmp, *vtmp = NULL;
    size_t outlen = 0, n = 0;
    OSSL_PARAM params[5];
    unsigned char *tmp_key = NULL, *tmp_salt = NULL, *tmp_custom = NULL;

    for (i = 0; i < sk_OPENSSL_STRING_num(opts); i++) {
        char *opt = sk_OPENSSL_STRING_value(opts, i);

        rv = 0;
        ktmp = opt; /* OPENSSL_strdup(opt); */
        if (ktmp == NULL)
            goto err;
        vtmp = strchr(ktmp, ':');
        if (vtmp != NULL) {
            *vtmp = 0;
            vtmp++;
        }
        if (strcmp("key", ktmp) == 0) {
            rv = str2param(&params[n], ktmp, &vtmp);
            goto end;
        }
        if (strcmp("hexkey", ktmp) == 0) {
            rv = hex2param(&params[n], ktmp, vtmp, &tmp_key);
            goto end;
        }
        if (strcmp("custom", ktmp) == 0) {
            rv = str2param(&params[n], ktmp, &vtmp);
            goto end;
        }
        if (strcmp("hexcustom", ktmp) == 0) {
            rv = hex2param(&params[n], ktmp, vtmp, &tmp_custom);
            goto end;
        }
        if (strcmp("salt", ktmp) == 0) {
            rv = str2param(&params[n], ktmp, &vtmp);
            goto end;
        }
        if (strcmp("hexsalt", ktmp) == 0) {
            rv = hex2param(&params[n], ktmp, vtmp, &tmp_salt);
            goto end;
        }
        if (strcmp("outlen", ktmp) == 0) {
            outlen = (size_t)atoi(vtmp);
            params[n] = OSSL_PARAM_construct_size_t(ktmp, &outlen, NULL);
            goto end;
        }
end:
        /* OPENSSL_free(ktmp); */
        if (rv <= 0) {
            BIO_printf(bio_err, "MAC parameter error '%s'\n", opt);
            return rv;
        }
        n++;
        if ((n + 1) >= OSSL_NELEM(params))
            return 0;
    }
    params[n] = OSSL_PARAM_construct_end();
    rv = EVP_MAC_set_params(ctx, params);
err:
    OPENSSL_free(tmp_key);
    OPENSSL_free(tmp_salt);
    OPENSSL_free(tmp_custom);
    return rv;
}

int mac_main(int argc, char **argv)
{
    int ret = 1;
    char *prog;
    const EVP_MAC *mac = NULL;
    OPTION_CHOICE o;
    EVP_MAC_CTX *ctx = NULL;
    STACK_OF(OPENSSL_STRING) *opts = NULL;
    unsigned char *buf = NULL;
    size_t len;
    int i;
    BIO *in = NULL, *out = NULL;
    const char *outfile = NULL;
    const char *infile = NULL;
    int out_bin = 0;
    int inform = FORMAT_BINARY;

    prog = opt_init(argc, argv, mac_options);
    buf = app_malloc(BUFSIZE, "I/O buffer");
    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        default:
opthelp:
            BIO_printf(bio_err, "%s: Use -help for summary.\n", prog);
            goto err;
        case OPT_HELP:
            opt_help(mac_options);
            ret = 0;
            goto err;
        case OPT_BIN:
            out_bin = 1;
            break;
        case OPT_IN:
            infile = opt_arg();
            break;
        case OPT_OUT:
            outfile = opt_arg();
            break;
        case OPT_MACOPT:
            if (opts == NULL)
                opts = sk_OPENSSL_STRING_new_null();
            if (opts == NULL || !sk_OPENSSL_STRING_push(opts, opt_arg()))
                goto opthelp;
            break;
        }
    }

    argc = opt_num_rest();
    argv = opt_rest();

    if (argc != 1) {
        BIO_printf(bio_err, "Invalid number of extra arguments\n");
        goto opthelp;
    }

    mac = EVP_get_macbyname(argv[0]);
    if (mac == NULL) {
        BIO_printf(bio_err, "Invalid MAC name %s\n", argv[0]);
        goto opthelp;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto err;

    if (opts != NULL && mac_set_params(ctx, opts) <= 0)
        goto err;

    /* Use text mode for stdin */
    if (infile == NULL || strcmp(infile, "-") == 0)
        inform = FORMAT_TEXT;
    in = bio_open_default(infile, 'r', inform);
    if (in == NULL)
        goto err;

    out = bio_open_default(outfile, 'w', out_bin ? FORMAT_BINARY : FORMAT_TEXT);
    if (out == NULL)
        goto err;

    if (!EVP_MAC_init(ctx)) {
        BIO_printf(bio_err, "EVP_MAC_Init failed\n");
        goto err;
    }


    for (;;) {
        i = BIO_read(in, (char *)buf, BUFSIZE);
        if (i < 0) {
            BIO_printf(bio_err, "Read Error in '%s'\n", infile);
            goto err;
        }
        if (i == 0)
            break;
        if (!EVP_MAC_update(ctx, buf, i)) {
            BIO_printf(bio_err, "EVP_MAC_update failed\n");
            goto err;
        }
    }

    if (!EVP_MAC_final(ctx, NULL, &len)) {
        BIO_printf(bio_err, "EVP_MAC_final failed\n");
        goto err;
    }
    if (len > BUFSIZE) {
        BIO_printf(bio_err, "output len is too large\n");
        goto err;
    }

    if (!EVP_MAC_final(ctx, buf, &len)) {
        BIO_printf(bio_err, "EVP_MAC_final failed\n");
        goto err;
    }

    if (out_bin) {
        BIO_write(out, buf, len);
    } else {
        if (outfile == NULL)
            BIO_printf(out,"\n");
        for (i = 0; i < (int)len; ++i)
            BIO_printf(out, "%02X", buf[i]);
        if (outfile == NULL)
            BIO_printf(out,"\n");
    }

    ret = 0;
err:
    if (ret != 0)
        ERR_print_errors(bio_err);
    OPENSSL_clear_free(buf, BUFSIZE);
    sk_OPENSSL_STRING_free(opts);
    BIO_free(in);
    BIO_free(out);
    EVP_MAC_CTX_free(ctx);
    return ret;
}
