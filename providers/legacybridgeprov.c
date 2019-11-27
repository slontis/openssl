/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/obj_mac.h>

/*
 * Currently this is just a dummy provider.
 * It could turn into something that handles fetching.
 * See legacy_bridge_query() below for some horrible code to return
 * engine algorithms.
 */
OSSL_provider_init_fn ossl_legacy_bridge_provider_init;
#define OSSL_provider_init ossl_legacy_bridge_provider_init


#if 0

/*
 * Commented out code.
 *
 * We dont know what engine algorithm we want so we have to return them all..
 * Note that this may also need to handle returning the non engine related
 * bridge functions.. for the EVP_MD_meth_get_init() on a legacy const EVP_MD*.
 */
static const OSSL_ALGORITHM *legacy_bridge_query(OSSL_PROVIDER *prov,
                                                int operation_id,
                                                int *no_cache)
{
    ENGINE *e;
    static OSSL_ALGORITHM algs[MAX_QUERY_ALGS];
    int i, j, sz = 0;
    const int *nids = NULL;
    const char *alg;
    char *tmp, *cur;
    int nid;
    const EVP_MD *default_md[128];
    int default_nids_count = 0;

    *no_cache = 1;
    switch (operation_id) {
    case OSSL_OP_DIGEST:
        for (i = 0; (cur = supported_digests[i]) != NULL; ++i) {
            /* Retrieve the last string */
            while (1) {
                tmp = strchr(cur, ':');
                if (tmp == NULL)
                    break;
                cur = ++tmp;
            }
            default_md[i] = NULL;
            /* For each algorithm is there a default? */
            nid = OBJ_sn2nid(cur);
            if (nid != NID_undef) {
                e = ENGINE_get_digest_engine(nid);
                if (e != NULL) {
                    const char *prop_def = engine_get_property_query(e);
                    default_md[default_nids_count++] = ENGINE_get_digest(e, nid);
                    algs[j].algorithm_names = OBJ_nid2sn(nid);
                    algs[j].property_definition = prop_def;
                    algs[i].implementation = legacy_bridge_digest_functions;
                }
            }
        }
        /*
         * Iterate through the engines and find all supported digests,
         * exclude any digest algorithms that have defaults assigned.
         * kill me now.
         */
        for (e = ENGINE_get_first(); e != NULL; e = ENGINE_get_next(e)) {
            ENGINE_DIGESTS_PTR fn = ENGINE_get_digests(e);
            const char *prop_def = engine_get_property_query(e);

            if (fn != NULL
                && (sz = fn(e, NULL, &nids, 0)) > 0) {
                for (i = 0; i < sz; ++i) {
                    if (!has_default(nids[i], default_md, default_nids_count)) {
                        algs[j].algorithm_names = OBJ_nid2sn(nids[i]);
                        algs[j].property_definition = prop_def;
                        algs[i].implementation = legacy_bridge_digest_functions;
                    }
                }
            }
        }
        /* Add NULL terminated entry */
        algs[i].algorithm_names = NULL;
        algs[i].implementation = NULL;
        algs[i].property_definition = NULL;
        return algs;
    default:
        break;
    }
    return NULL;
}

/* Functions provided by the core */
static OSSL_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_ITEM legacy_bridge_param_types[] = {
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_NAME },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_VERSION },
    { OSSL_PARAM_UTF8_PTR, OSSL_PROV_PARAM_BUILDINFO },
    { 0, NULL }
};

static const OSSL_ITEM *legacy_bridge_gettable_params(const OSSL_PROVIDER *prov)
{
    return legacy_bridge_param_types;
}

static int legacy_bridge_get_params(const OSSL_PROVIDER *prov, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL Legacy Engine Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;

    return 1;
}

#define MAX_EVP_MD 64
DEFINE_STACK_OF(EVP_MD)

static STACK_OF(EVP_MD) *digests;

int register_digest(EVP_MD *md)
{
    if (digests == NULL) {
        digests = sk_EVP_MD_new_null();
        if (digests == NULL)
            return 0;
    }
    return (sk_EVP_MD_push(digests, md) > 0);
}

void deregister_digest(EVP_MD *md)
{
    sk_EVP_MD_delete_ptr(digests, md);
}

static int digest_get_params_XXX(OSSL_PARAM params[])
{
    OSSL_PARAM *p = NULL;
    EVP_MD *md = md[XXX];

    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, blksz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, paramsz)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_FLAGS);
    if (p != NULL && !OSSL_PARAM_set_ulong(p, flags)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        return 0;
    }
    return 1;
}


const OSSL_DISPATCH legacy_bridge_digest_functions[] = {
    { OSSL_FUNC_DIGEST_LEGACYNEWCTX, (void (*)(void))ossl_lb_digest_prov2legacy_legacynewctx },
    { OSSL_FUNC_DIGEST_INIT, (void (*)(void)) ossl_lb_digest_prov2legacy_init },
    { OSSL_FUNC_DIGEST_UPDATE, (void (*)(void)) ossl_lb_digest_prov2legacy_update },
    { OSSL_FUNC_DIGEST_FINAL, (void (*)(void)) ossl_lb_digest_prov2legacy_final },
//    { OSSL_FUNC_DIGEST_DIGEST, (void (*)(void)) ossl_lb_digest_digest },
    { OSSL_FUNC_DIGEST_FREECTX, (void (*)(void)) ossl_lb_digest_prov2legacy_freectx },
//    { OSSL_FUNC_DIGEST_DUPCTX, (void (*)(void)) ossl_lb_digest_dupctx },
//    { OSSL_FUNC_DIGEST_GET_PARAMS, (void (*)(void)) ossl_lb_digest_get_params },
    { OSSL_FUNC_DIGEST_SET_CTX_PARAMS, (void (*)(void)) ossl_lb_digest_set_ctx_params },
    { OSSL_FUNC_DIGEST_GET_CTX_PARAMS, (void (*)(void)) ossl_lb_digest_get_ctx_params },
//    { OSSL_FUNC_DIGEST_GETTABLE_PARAMS, (void (*)(void)) ossl_lb_digest_gettable_params },
//    { OSSL_FUNC_DIGEST_SETTABLE_CTX_PARAMS, (void (*)(void)) ossl_lb_digest_settable_ctx_params},
//    { OSSL_FUNC_DIGEST_GETTABLE_CTX_PARAMS, (void (*)(void)) ossl_lb_digest_gettable_ctx_params },
    { 0, NULL }
};


/* Our primary name:NIST name[:our older names] */
static const char supported_digests[] = {
    "SHA1:SHA-1",
    "SHA2-224:SHA-224:SHA224",
    "SHA2-256:SHA-256:SHA256",
    "SHA2-384:SHA-384:SHA384",
    "SHA2-512:SHA-512:SHA512",
    "SHA2-512/224:SHA-512/224:SHA512-224",
    "SHA2-512/256:SHA-512/256:SHA512-256",
    "SHA3-224",
    "SHA3-256",
    "SHA3-384",
    "SHA3-512",
    "KECCAK_KMAC128",
    "KECCAK_KMAC256",
    "SHAKE-128:SHAKE128",
    "SHAKE-256:SHAKE256",
#ifndef OPENSSL_NO_BLAKE2
    "BLAKE2s-256:BLAKE2s256",
    "BLAKE2b-512:BLAKE2b512",
#endif /* OPENSSL_NO_BLAKE2 */
#ifndef OPENSSL_NO_SM3
    "SM3",
#endif /* OPENSSL_NO_SM3 */
#ifndef OPENSSL_NO_MD5
    "MD5",
    "MD5-SHA1",
#endif /* OPENSSL_NO_MD5 */
    NULL
};


static int has_default(int nid, const EVP_MD *md_list, int sz)
{
    int i;

    for (i = 0; i < sz; ++i) {
        if (md_list[i].type == nid)
            return 1;
    }
    return 0;
}



//static const OSSL_ALGORITHM *legacy_bridge_query(OSSL_PROVIDER *prov,
//                                                int operation_id,
//                                                int *no_cache)
//{
//    return 0;
//}

#endif

/* Functions we provide to the core */
static const OSSL_DISPATCH legacy_bridge_dispatch_table[] = {
    { 0, NULL }
};

int ossl_legacy_bridge_provider_init(const OSSL_PROVIDER *provider,
                                     const OSSL_DISPATCH *in,
                                     const OSSL_DISPATCH **out,
                                     void **provctx)
{
    OSSL_core_get_library_context_fn *c_get_libctx = NULL;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GET_LIBRARY_CONTEXT:
            c_get_libctx = OSSL_get_core_get_library_context(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    *out = legacy_bridge_dispatch_table;
    *provctx = c_get_libctx(provider);
    return 1;
}
