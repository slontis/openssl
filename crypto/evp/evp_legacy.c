/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
# include <openssl/provider.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include "crypto/evp.h"
#include "internal/provider.h"
#include "evp_local.h"
#include "internal/legacy_bridge.h"

static void set_lb_digest_dup_funcs(EVP_MD *md);

static OSSL_PROVIDER *prov = NULL;
OSSL_PROVIDER *ossl_legacy_bridge_provider()
{
    if (prov == NULL)
        prov = OSSL_PROVIDER_load(NULL, "legacybridge");
    return prov;
}

EVP_MD *EVP_MD_meth_new(int md_type, int pkey_type)
{
    EVP_MD *fetched = NULL;
    EVP_MD *md = NULL;

    /* Fetch the default md here */
    fetched = EVP_MD_fetch(NULL, OBJ_nid2sn(md_type), "");
    if (fetched == NULL)
        return NULL;

    md = evp_md_new();
    if (md != NULL) {
        CRYPTO_RWLOCK *lock = md->lock;

        memcpy(md, fetched, sizeof(*fetched));
        md->lock = lock;
        md->refcnt = 1;
        md->pkey_type = pkey_type;
        md->prov = ossl_legacy_bridge_provider();
        if (md->prov != NULL)
            ossl_provider_up_ref(md->prov);
        set_lb_digest_dup_funcs(md);
    }
    EVP_MD_free(fetched);
    return md;
}


EVP_MD *EVP_MD_meth_dup(const EVP_MD *md)
{
    EVP_MD *to = NULL;

//    if (md->prov != NULL)
//        return NULL; /* TODO - provider dup */

    to = EVP_MD_meth_new(md->type, md->pkey_type);
    if (to != NULL) {
        to->block_size = md->block_size;
        to->ctx_size = md->ctx_size;
        to->flags = md->flags;
        to->md_size = md->md_size;
        to->name_id = md->name_id;
    }
    return to;
}

int EVP_MD_meth_get_input_blocksize(const EVP_MD *md)
{
    return md->block_size;
}

int EVP_MD_meth_set_input_blocksize(EVP_MD *md, int blocksize)
{
//    if (md->block_size != 0)
//        return 0;

    md->block_size = blocksize;
    return 1;
}

int EVP_MD_meth_get_result_size(const EVP_MD *md)
{
    return md->md_size;
}

int EVP_MD_meth_set_result_size(EVP_MD *md, int resultsize)
{
    if (md->md_size != 0)
        return 0;

    md->md_size = resultsize;
    return 1;
}

int EVP_MD_meth_get_app_datasize(const EVP_MD *md)
{
    return md->ctx_size;
}

int EVP_MD_meth_set_app_datasize(EVP_MD *md, int datasize)
{
//    if (md->ctx_size != 0)
//        return 0;

    md->ctx_size = datasize;
    return 1;
}

unsigned long EVP_MD_meth_get_flags(const EVP_MD *md)
{
    return md->flags;
}

int EVP_MD_meth_set_flags(EVP_MD *md, unsigned long flags)
{
//    if (md->flags != 0)
//        return 0;

    md->flags = flags;
    return 1;
}

int (*EVP_MD_meth_get_init(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->init;
}

int EVP_MD_meth_set_init(EVP_MD *md, int (*init)(EVP_MD_CTX *ctx))
{
//    if (md->init != NULL)
//        return 0;

    md->init = init;
    return 1;
}

int (*EVP_MD_meth_get_update(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                                const void *data,
                                                size_t count)
{
    return md->update;
}

int EVP_MD_meth_set_update(EVP_MD *md, int (*update)(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count))
{
//    if (md->update != NULL)
//        return 0;

    md->update = update;
    return 1;
}

int (*EVP_MD_meth_get_final(const EVP_MD *md))(EVP_MD_CTX *ctx,
                                               unsigned char *md)
{
    return md->final;
}

int EVP_MD_meth_set_final(EVP_MD *md, int (*final)(EVP_MD_CTX *ctx,
                                                   unsigned char *md))
{
//    if (md->final != NULL)
//        return 0;

    md->final = final;
    return 1;
}

int (*EVP_MD_meth_get_copy(const EVP_MD *md))(EVP_MD_CTX *to,
                                              const EVP_MD_CTX *from)
{
    return md->copy;
}

int EVP_MD_meth_set_copy(EVP_MD *md, int (*copy)(EVP_MD_CTX *to,
                                                 const EVP_MD_CTX *from))
{
//    if (md->copy != NULL)
//        return 0;

    md->copy = copy;
    return 1;
}

int (*EVP_MD_meth_get_cleanup(const EVP_MD *md))(EVP_MD_CTX *ctx)
{
    return md->cleanup;
}

int EVP_MD_meth_set_cleanup(EVP_MD *md, int (*cleanup)(EVP_MD_CTX *ctx))
{
//    if (md->cleanup != NULL)
//        return 0;

    md->cleanup = cleanup;
    return 1;
}

int (*EVP_MD_meth_get_ctrl(const EVP_MD *md))(EVP_MD_CTX *ctx, int cmd,
                                              int p1, void *p2)
{
    return md->md_ctrl;
}

int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd,
                                                 int p1, void *p2))
{
//    if (md->md_ctrl != NULL)
//        return 0;

    md->md_ctrl = ctrl;
    return 1;
}


/* ------------------------------------- */

/* Not sure this is actually needed... */
static int digest_reset(EVP_MD_CTX *ctx)
{
   /*
    * Don't assume ctx->md_data was cleaned in EVP_Digest_Final, because
    * sometimes only copies of the context are ever finalised.
    */
   if (ctx->digest && ctx->digest->cleanup
       && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_CLEANED)) {
       ctx->digest->cleanup(ctx);
       EVP_MD_CTX_set_flags(ctx, EVP_MD_CTX_FLAG_CLEANED);
   }
   if (ctx->digest && ctx->digest->ctx_size && ctx->md_data
       && !EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_REUSE)) {
       OPENSSL_clear_free(ctx->md_data, ctx->digest->ctx_size);
   }
   /*
    * pctx should be freed by the user of EVP_MD_CTX
    * if EVP_MD_CTX_FLAG_KEEP_PKEY_CTX is set
    */
   if (!EVP_MD_CTX_test_flags(ctx, EVP_MD_CTX_FLAG_KEEP_PKEY_CTX))
       EVP_PKEY_CTX_free(ctx->pctx);

#ifndef OPENSSL_NO_ENGINE
   ENGINE_finish(ctx->engine);
#endif
   OPENSSL_cleanse(ctx, sizeof(*ctx));

   return 1;
}

static void ossl_lb_digest_prov2legacy_freectx(void *dctx)
{
   EVP_MD_CTX *ctx = dctx;

   digest_reset(ctx);
   OPENSSL_free(ctx);
}

static void *ossl_lb_digest_prov2legacy_newctx(void *provctx)
{
   const EVP_MD *method = provctx;
   EVP_MD_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

   if (ctx == NULL) {
       ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
       return NULL;
   }

   /*
    * There is already a pointer in the EVP_MD_CTX for the extra allocated data
    * so we just use that.
    */
   if (method->ctx_size > 0) {
       if ((ctx->md_data = OPENSSL_zalloc(method->ctx_size)) == NULL) {
           ossl_lb_digest_prov2legacy_freectx(ctx);
           ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
           return NULL;
       }
   }

   ctx->digest = method;
   ctx->update = method->update;
   return ctx;
}

static int ossl_lb_digest_prov2legacy_init(void *dctx)
{
    EVP_MD_CTX *ctx = dctx;

    return ctx->digest->init(ctx);
}

static int ossl_lb_digest_prov2legacy_update(void *dctx, const unsigned char *in,
                                             size_t inl)
{
   EVP_MD_CTX *ctx = dctx;

   return ctx->update(ctx, in, inl);
}

static int ossl_lb_digest_prov2legacy_final(void *dctx, unsigned char *out,
                                            size_t *outl, size_t outsz)
{
   EVP_MD_CTX *ctx = dctx;
   int ret;

   /*
    * EVP_DigestFinal_ex and EVP_DigestFinalXOF always pass the correct
    * size, as far as they can tell, so we should not need any extra
    * control here.
    */
   ret = ctx->digest->final(ctx, out);
   if (outl != NULL)
       *outl = outsz;
   if (ctx->digest->cleanup != NULL) {
       ctx->digest->cleanup(ctx);
       ctx->flags |= EVP_MD_CTX_FLAG_CLEANED;
   }
   OPENSSL_cleanse(ctx->md_data, ctx->digest->ctx_size);
   return ret;
}

/*
 * Default legacy EVP_MD functions.
 * Which just simply call the new provider functions from a
 * legacy function.
 */
static int ossl_lb_digest_default_legacy2prov_init(EVP_MD_CTX *ctx)
{
    const EVP_MD *md = EVP_MD_CTX_md(ctx);

    return md->dinit(ctx->provctx);
}

static int ossl_lb_digest_default_legacy2prov_update(EVP_MD_CTX *ctx,
                                                     const void *data,
                                                     size_t count)
{
    return ctx->update(ctx->provctx, data, count);
}

static int ossl_lb_digest_default_legacy2prov_final(EVP_MD_CTX *ctx,
                                                    unsigned char *out)
{
    const EVP_MD *md = EVP_MD_CTX_md(ctx);
    size_t mdsize = EVP_MD_size(md);

    OPENSSL_assert(mdsize <= EVP_MAX_MD_SIZE);
    return md->final(ctx, out);
}

static int ossl_lb_digest_default_legacy2prov_ctrl(EVP_MD_CTX *ctx, int cmd,
                                                   int p1, void *p2)
{
    return EVP_MD_CTX_ctrl(ctx, cmd, p1, p2);
}

/*
 * Stub legacy EVP_MD functions.
 * These are returned by EVP_MD_METH_get_XXX() only when the user creates a
 * non const EVP_MD* but does NOT not use EVP_MD_METH_set_XXX().
 * This is required because the user can get one of these legacy methods and
 * call it directly.
 */
static int ossl_lb_digest_init_stub(EVP_MD_CTX *ctx)
{
    int ret;
    EVP_MD *fetched = NULL;
    const EVP_MD *md = EVP_MD_CTX_md(ctx);

    fetched = EVP_MD_fetch(NULL, EVP_MD_name(md), "default=true");
    ret = fetched->dinit(ctx);
    EVP_MD_free(fetched);
    return ret;
}
static int ossl_lb_digest_update_stub(EVP_MD_CTX *ctx, const void *data,
                                      size_t count)
{
    int ret;
    EVP_MD *fetched = NULL;
    const EVP_MD *md = EVP_MD_CTX_md(ctx);

    fetched = EVP_MD_fetch(NULL, EVP_MD_name(md), "default=true");
    ret = fetched->dupdate(ctx, data, count);
    EVP_MD_free(fetched);
    return ret;
}

static int ossl_lb_digest_final_stub(EVP_MD_CTX *ctx, unsigned char *out)
{
    int ret;
    EVP_MD *fetched = NULL;
    const EVP_MD *md = EVP_MD_CTX_md(ctx);
    size_t mdsize = EVP_MD_size(md);

    fetched = EVP_MD_fetch(NULL, EVP_MD_name(md), "default=true");
    ret = fetched->dfinal(ctx, out, NULL, mdsize);
    EVP_MD_free(fetched);
    return ret;
}

static int ossl_lb_digest_ctrl_stub(EVP_MD_CTX *ctx, int cmd, int p1, void *p2)
{
    return EVP_MD_CTX_ctrl(ctx, cmd, p1, p2);
}

#if 0
static int ossl_lb_digest_get_params(void *provctx, OSSL_PARAM params[])
{
   EVP_MD *digest = provctx;
   OSSL_PARAM *p;

   if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, digest->block_size))
       return 0;
   if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, digest->md_size))
       return 0;
   if ((p = OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_FLAGS)) != NULL
        && !OSSL_PARAM_set_ulong(p, digest->flags))
       return 0;
   return 1;
}
#endif

static int ossl_lb_digest_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
   EVP_MD_CTX *ctx = vctx;
   const OSSL_PARAM *p;
   int ret = 1;

   for (p = params; p->key != NULL; p++) {
       int ok, cmd, p1;
       void *p2;
       size_t sz;

       if (strcmp(p->key, OSSL_DIGEST_PARAM_XOFLEN) == 0) {
           if (!OSSL_PARAM_get_size_t(p, &sz))
               return 0;
           cmd = EVP_MD_CTRL_XOF_LEN;
           p1 = (int)sz;
           p2 = NULL;
       } else if (strcmp(p->key, OSSL_DIGEST_PARAM_SSL3_MS) == 0) {
           if (!OSSL_PARAM_get_octet_string(p, &p2, 0, &sz))
               return 0;
           cmd = EVP_CTRL_SSL3_MASTER_SECRET;
           p1 = (int)sz;
       } else {
           continue;
       }
       ok = EVP_MD_CTX_ctrl(ctx, cmd, p1, p2);
       if (ok <= 0)
           ret = 0;
   }

   return ret;
}

/* There are no such controls that we know of */
static int ossl_lb_digest_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
   return 1;
}

void evp_md_set_lb_digest_default_funcs(EVP_MD *md)
{
    md->init = ossl_lb_digest_default_legacy2prov_init;
    md->update = ossl_lb_digest_default_legacy2prov_update;
    md->final = ossl_lb_digest_default_legacy2prov_final;
    md->md_ctrl = ossl_lb_digest_default_legacy2prov_ctrl;
}

static void set_lb_digest_dup_funcs(EVP_MD *md)
{
    md->init = ossl_lb_digest_init_stub;
    md->update = ossl_lb_digest_update_stub;
    md->final = ossl_lb_digest_final_stub;
    md->md_ctrl = ossl_lb_digest_ctrl_stub;

    md->has_legacybridge = 1;
    md->newctx = ossl_lb_digest_prov2legacy_newctx;
    md->freectx = ossl_lb_digest_prov2legacy_freectx;
    md->dinit = ossl_lb_digest_prov2legacy_init;
    md->dupdate = ossl_lb_digest_prov2legacy_update;
    md->dfinal = ossl_lb_digest_prov2legacy_final;
    md->get_ctx_params = ossl_lb_digest_get_ctx_params;
    md->set_ctx_params = ossl_lb_digest_set_ctx_params;
}
