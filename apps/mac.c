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
#include <openssl/params.h>
#include "internal/param_build.h"

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

int mac_main(int argc, char **argv)
{
    int ret = 1;
    char *prog;
    EVP_MAC *mac = NULL;
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
    OSSL_PARAM_BLD param_build;

    ossl_param_bld_init(&param_build);

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

    mac = EVP_MAC_fetch(NULL, argv[0], NULL);
    if (mac == NULL) {
        BIO_printf(bio_err, "Invalid MAC name %s\n", argv[0]);
        goto opthelp;
    }

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        goto err;

    if (opts != NULL) {
        OSSL_PARAM *params;
        const OSSL_PARAM *paramdefs = EVP_MAC_CTX_settable_params(mac);
        size_t params_n;
        int ok = 1;

        for (params_n = 0; params_n < (size_t)sk_OPENSSL_STRING_num(opts);
             params_n++) {
            char *opt = sk_OPENSSL_STRING_value(opts, (int)params_n);
            char *stmp, *vtmp = NULL;

            if ((stmp = OPENSSL_strdup(opt)) == NULL
                || (vtmp = strchr(stmp, ':')) == NULL
                || (*vtmp++ = 0) /* Always zero */
                || !ossl_param_bld_push_from_text(&param_build, stmp, vtmp,
                                                  strlen(vtmp), paramdefs)) {
                BIO_printf(bio_err, "MAC parameter error '%s'\n", opt);
                ERR_print_errors(bio_err);
                ok = 0;
            }
            OPENSSL_free(stmp);
            if (!ok)
                break;
        }
        if (ok) {
            params = ossl_param_bld_to_param(&param_build);
            if (params == NULL)
                goto err;
            ok = EVP_MAC_CTX_set_params(ctx, params);
            ossl_param_bld_free(params);

            if (!ok) {
                BIO_printf(bio_err, "MAC parameter error\n");
                ERR_print_errors(bio_err);
                goto err;
            }
        }
    }

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

    if (!EVP_MAC_final(ctx, NULL, &len, 0)) {
        BIO_printf(bio_err, "EVP_MAC_final failed\n");
        goto err;
    }
    if (len > BUFSIZE) {
        BIO_printf(bio_err, "output len is too large\n");
        goto err;
    }

    if (!EVP_MAC_final(ctx, buf, &len, BUFSIZE)) {
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
    EVP_MAC_free(mac);
    return ret;
}
