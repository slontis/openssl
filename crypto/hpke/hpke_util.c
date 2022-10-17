/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/hpke.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "crypto/ecx.h"
#include "internal/hpke_util.h"
#include "internal/packet.h"

/* ASCII: "HPKE-v1", in hex for EBCDIC compatibility */
static const char LABEL_HPKEV1[] = "\x48\x50\x4B\x45\x2D\x76\x31";

/*
 * @brief table of KEMs
 * See Section 7.1 "Table 2 KEM IDs"
 */
static const OSSL_HPKE_KEM_INFO hpke_kem_tab[] = {
    { OSSL_HPKE_KEM_ID_P256, "EC", OSSL_HPKE_KEMSTR_P256,
      LN_sha256, SHA256_DIGEST_LENGTH, 65, 65, 32, 0xFF },
    { OSSL_HPKE_KEM_ID_P384, "EC", OSSL_HPKE_KEMSTR_P384,
      LN_sha384, SHA384_DIGEST_LENGTH, 97, 97, 48, 0xFF },
    { OSSL_HPKE_KEM_ID_P521, "EC", OSSL_HPKE_KEMSTR_P521,
      LN_sha512, SHA512_DIGEST_LENGTH, 133, 133, 66, 0x01 },
    { OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KEMSTR_X25519, NULL,
      LN_sha256, SHA256_DIGEST_LENGTH,
      X25519_KEYLEN, X25519_KEYLEN, X25519_KEYLEN },
    { OSSL_HPKE_KEM_ID_X448, OSSL_HPKE_KEMSTR_X448, NULL,
      LN_sha512, SHA512_DIGEST_LENGTH, X448_KEYLEN, X448_KEYLEN, X448_KEYLEN }
};

/* Return an object containing KEM constants associated with a EC curve name */
const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_curve(const char *curve)
{
    int i;

    for (i = 0; hpke_kem_tab[i].keytype != NULL; ++i) {
        const char *group = hpke_kem_tab[i].groupname;

        if (group == NULL)
            group = hpke_kem_tab[i].keytype;
        if (OPENSSL_strcasecmp(curve, group) == 0)
            return &hpke_kem_tab[i];
    }
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
    return NULL;
}

const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_id(uint16_t kemid)
{
    int i;

    for (i = 0; hpke_kem_tab[i].keytype != NULL; ++i) {
        if (hpke_kem_tab[i].kem_id == kemid)
            return &hpke_kem_tab[i];
    }
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE);
    return NULL;
}

const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_random(OSSL_LIB_CTX *libctx)
{
    unsigned char rval = 0;
    int sz = OSSL_NELEM(hpke_kem_tab);

    if (RAND_bytes_ex(libctx, &rval, sizeof(rval), 0) <= 0)
        return NULL;
    return &hpke_kem_tab[rval % sz];
}

static int kdf_derive(EVP_KDF_CTX *kctx,
                      unsigned char *out, size_t outlen, int mode,
                      const unsigned char *salt, size_t saltlen,
                      const unsigned char *ikm, size_t ikmlen,
                      const unsigned char *info, size_t infolen)
{
    int ret;
    OSSL_PARAM params[5], *p = params;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    if (salt != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (char *)salt, saltlen);
    if (ikm != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                                 (char *)ikm, ikmlen);
    if (info != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                                 (char *)info, infolen);
    *p = OSSL_PARAM_construct_end();
    ret = EVP_KDF_derive(kctx, out, outlen, params) > 0;
    if (!ret)
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION);
    return ret;
}

int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
                          unsigned char *prk, size_t prklen,
                          const unsigned char *salt, size_t saltlen,
                          const unsigned char *ikm, size_t ikmlen)
{
    return kdf_derive(kctx, prk, prklen, EVP_KDF_HKDF_MODE_EXTRACT_ONLY,
                      salt, saltlen, ikm, ikmlen, NULL, 0);
}

/* Common code to perform a HKDF expand */
int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
                         unsigned char *okm, size_t okmlen,
                         const unsigned char *prk, size_t prklen,
                         const unsigned char *info, size_t infolen)
{
    return kdf_derive(kctx, okm, okmlen, EVP_KDF_HKDF_MODE_EXPAND_ONLY,
                      NULL, 0, prk, prklen, info, infolen);
}

/*
 * See RFC 9180 Section 4 LabelExtract()
 */
int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
                              unsigned char *prk, size_t prklen,
                              const unsigned char *salt, size_t saltlen,
                              const char *protocol_label,
                              const unsigned char *suiteid, size_t suiteidlen,
                              const char *label,
                              const unsigned char *ikm, size_t ikmlen)
{
    int ret = 0;
    size_t labeled_ikmlen = 0;
    unsigned char *labeled_ikm = NULL;
    WPACKET pkt;

    labeled_ikmlen = strlen(LABEL_HPKEV1) + strlen(protocol_label)
        + suiteidlen + strlen(label) + ikmlen;
    labeled_ikm = OPENSSL_malloc(labeled_ikmlen);
    if (labeled_ikm == NULL)
        return 0;

    /* labeled_ikm = concat("HPKE-v1", suiteid, label, ikm) */
    if (!WPACKET_init_static_len(&pkt, labeled_ikm, labeled_ikmlen, 0)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, protocol_label, strlen(protocol_label))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, ikm, ikmlen)
            || !WPACKET_get_total_written(&pkt, &labeled_ikmlen)
            || !WPACKET_finish(&pkt)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }

    ret = ossl_hpke_kdf_extract(kctx, prk, prklen, salt, saltlen,
                                labeled_ikm, labeled_ikmlen);
end:
    WPACKET_cleanup(&pkt);
    OPENSSL_cleanse(labeled_ikm, labeled_ikmlen);
    OPENSSL_free(labeled_ikm);
    return ret;
}

/*
 * See RFC 9180 Section 4 LabelExpand()
 */
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
                             unsigned char *okm, size_t okmlen,
                             const unsigned char *prk, size_t prklen,
                             const char *protocol_label,
                             const unsigned char *suiteid, size_t suiteidlen,
                             const char *label,
                             const unsigned char *info, size_t infolen)
{
    int ret = 0;
    size_t labeled_infolen = 0;
    unsigned char *labeled_info = NULL;
    WPACKET pkt;

    labeled_infolen = 2 + okmlen + prklen + strlen(LABEL_HPKEV1)
        + strlen(protocol_label) + suiteidlen + strlen(label) + infolen;
    labeled_info = OPENSSL_malloc(labeled_infolen);
    if (labeled_info == NULL)
        return 0;

    /* labeled_info = concat(okmlen, "HPKE-v1", suiteid, label, info) */
    if (!WPACKET_init_static_len(&pkt, labeled_info, labeled_infolen, 0)
            || !WPACKET_put_bytes_u16(&pkt, okmlen)
            || !WPACKET_memcpy(&pkt, LABEL_HPKEV1, strlen(LABEL_HPKEV1))
            || !WPACKET_memcpy(&pkt, protocol_label, strlen(protocol_label))
            || !WPACKET_memcpy(&pkt, suiteid, suiteidlen)
            || !WPACKET_memcpy(&pkt, label, strlen(label))
            || !WPACKET_memcpy(&pkt, info, infolen)
            || !WPACKET_get_total_written(&pkt, &labeled_infolen)
            || !WPACKET_finish(&pkt)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        goto end;
    }

    ret = ossl_hpke_kdf_expand(kctx, okm, okmlen,
                               prk, prklen, labeled_info, labeled_infolen);
end:
    WPACKET_cleanup(&pkt);
    OPENSSL_free(labeled_info);
    return ret;
}

/* Common code to create a HKDF ctx */
EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
                                 OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_KDF *kdf;
    EVP_KDF_CTX *kctx = NULL;

    kdf = EVP_KDF_fetch(libctx, kdfname, propq);
    kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (kctx != NULL && mdname != NULL) {
        OSSL_PARAM params[3], *p = params;

        if (mdname != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                                    (char *)mdname, 0);
        if (propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_PROPERTIES,
                                                    (char *)propq, 0);
        *p = OSSL_PARAM_construct_end();
        if (EVP_KDF_CTX_set_params(kctx, params) <= 0) {
            EVP_KDF_CTX_free(kctx);
            return NULL;
        }
    }
    return kctx;
}
