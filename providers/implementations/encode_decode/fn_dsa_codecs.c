/* Provisional FN-DSA codecs, following draft-ietf-lamps-fn-dsa-certificates-00.
 * Uses the user-selected OID profile. No FN-DSA compatibility encodings.
 */
#include "prov/fn_dsa_codecs.h"
#include "crypto/fn_dsa.h"
#include "internal/encoder.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/proverr.h>
#include <openssl/x509.h>
#include <string.h>
#include "crypto/x509.h"

typedef struct {
    size_t public_bytes;
} FN_DSA_CODEC;
static const FN_DSA_CODEC codecs[2] = {
    {FN_DSA_512_PUB_LEN},
    {FN_DSA_1024_PUB_LEN}};
static const FN_DSA_CODEC *get_codec(unsigned logn)
{
    return logn == 9 || logn == 10 ? &codecs[logn - 9] : NULL;
}
static ASN1_OBJECT *get_oid(unsigned logn)
{
    const FN_DSA_CODEC *codec = get_codec(logn);
    if (codec == NULL)
        return NULL;
    return OBJ_dup(OBJ_nid2obj(logn == 9 ? EVP_PKEY_FN_DSA_512
                                       : EVP_PKEY_FN_DSA_1024));
}
static int check_algorithm(const X509_ALGOR *alg, const ASN1_OBJECT *expected)
{
    const ASN1_OBJECT *actual;
    int type;
    X509_ALGOR_get0(&actual, &type, NULL, alg);
    return type == V_ASN1_UNDEF && OBJ_cmp(actual, expected) == 0;
}
static int copy_payload(const unsigned char *data, size_t len, size_t expected,
                        unsigned char **out)
{
    if (data == NULL || len != expected)
        return 0;
    if (out != NULL && (*out = OPENSSL_memdup(data, len)) == NULL)
        return 0;
    return (int)len;
}
int ossl_fn_dsa_i2d_pubkey_data(const unsigned char *pub, size_t publen,
                           unsigned logn, unsigned char **out)
{
    const FN_DSA_CODEC *codec = get_codec(logn);
    return codec == NULL ? 0
                         : copy_payload(pub, publen, codec->public_bytes, out);
}
int ossl_fn_dsa_i2d_prvkey_data(const unsigned char *seed, size_t seedlen,
                           unsigned char **out)
{
    /* The PKCS#8 privateKey OCTET STRING contains the raw seed directly. */
    return copy_payload(seed, seedlen, FN_DSA_SEED_BYTES, out);
}
int ossl_fn_dsa_i2d_PUBKEY_data(const unsigned char *pub, size_t publen,
                           unsigned logn, unsigned char **out)
{
    X509_PUBKEY *spki = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *raw = NULL;
    int ret = 0;
    if (ossl_fn_dsa_i2d_pubkey_data(pub, publen, logn, NULL) == 0 ||
        (oid = get_oid(logn)) == NULL || (spki = X509_PUBKEY_new()) == NULL ||
        (raw = OPENSSL_memdup(pub, publen)) == NULL)
        goto end;
    if (!X509_PUBKEY_set0_param(spki, oid, V_ASN1_UNDEF, NULL, raw,
                                (int)publen))
        goto end;
    oid = NULL;
    raw = NULL;
    ret = i2d_X509_PUBKEY(spki, out);
end:
    ASN1_OBJECT_free(oid);
    OPENSSL_free(raw);
    X509_PUBKEY_free(spki);
    return ret > 0 ? ret : 0;
}
int ossl_fn_dsa_i2d_PKCS8_data(const unsigned char *seed, size_t seedlen,
                          unsigned logn, unsigned char **out)
{
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *raw = NULL;
    const unsigned char *owned = NULL;
    int ret = 0, ownedlen = 0;
    if (ossl_fn_dsa_i2d_prvkey_data(seed, seedlen, NULL) == 0 ||
        (oid = get_oid(logn)) == NULL ||
        (p8 = PKCS8_PRIV_KEY_INFO_new()) == NULL ||
        (raw = OPENSSL_memdup(seed, seedlen)) == NULL)
        goto end;
    if (!PKCS8_pkey_set0(p8, oid, 0, V_ASN1_UNDEF, NULL, raw, (int)seedlen))
        goto end;
    oid = NULL;
    raw = NULL;
    ret = i2d_PKCS8_PRIV_KEY_INFO(p8, out);
end:
    ASN1_OBJECT_free(oid);
    OPENSSL_clear_free(raw, seedlen);
    if (p8 != NULL && PKCS8_pkey_get0(NULL, &owned, &ownedlen, NULL, p8))
        OPENSSL_cleanse((void *)owned, (size_t)ownedlen);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return ret > 0 ? ret : 0;
}
int ossl_fn_dsa_d2i_PUBKEY_data(const unsigned char *der, long derlen, unsigned logn,
                           unsigned char *pub, size_t publen)
{
    const FN_DSA_CODEC *codec = get_codec(logn);
    const unsigned char *p = der, *raw = NULL;
    X509_PUBKEY *spki = NULL;
    X509_ALGOR *alg = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *canonical = NULL;
    int rawlen = 0, encoded, ret = 0;
    if (codec == NULL || der == NULL || derlen <= 0 || pub == NULL ||
        publen != codec->public_bytes || (oid = get_oid(logn)) == NULL ||
        /* Parsing within a provider decoder must not recursively fetch it. */
        (spki = ossl_d2i_X509_PUBKEY_INTERNAL(&p, derlen, NULL, NULL)) == NULL ||
        p != der + derlen ||
        !X509_PUBKEY_get0_param(NULL, &raw, &rawlen, &alg, spki) ||
        !check_algorithm(alg, oid) || rawlen != (int)publen)
        goto end;
    /* Rewrapping requires zero unused BIT STRING bits and canonical DER. */
    encoded = ossl_fn_dsa_i2d_PUBKEY_data(raw, publen, logn, &canonical);
    if (encoded != derlen || canonical == NULL ||
        CRYPTO_memcmp(canonical, der, (size_t)derlen) != 0)
        goto end;
    memcpy(pub, raw, publen);
    ret = 1;
end:
    ASN1_OBJECT_free(oid);
    X509_PUBKEY_free(spki);
    OPENSSL_free(canonical);
    return ret;
}

/* Match ML-DSA: PKCS#8 decoding creates a seed prekey. Provider load expands
 * the seed; the expanded internal cache is never serialized as PKCS#8.
 */
FN_DSA_KEY *ossl_fn_dsa_d2i_PKCS8(const uint8_t *der, int derlen,
    int evp_type, PROV_CTX *provctx, const char *propq)
{
    const FN_DSA_PARAMS *p = ossl_fn_dsa_params_get(evp_type);
    unsigned char seed[FN_DSA_SEED_BYTES];
    FN_DSA_KEY *key = NULL;

    if (p == NULL || !ossl_fn_dsa_d2i_PKCS8_data(der, derlen, p->logn,
                         seed, sizeof(seed)))
        goto end;
    key = ossl_fn_dsa_key_new(provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx),
        propq, evp_type);
    if (key != NULL && !ossl_fn_dsa_set_prekey(key, 0, 0, seed, sizeof(seed), NULL, 0)) {
        ossl_fn_dsa_key_free(key);
        key = NULL;
    }
end:
    OPENSSL_cleanse(seed, sizeof(seed));
    return key;
}

FN_DSA_KEY *ossl_fn_dsa_d2i_PUBKEY(const uint8_t *der, int derlen,
    int evp_type, PROV_CTX *provctx, const char *propq)
{
    const FN_DSA_PARAMS *p = ossl_fn_dsa_params_get(evp_type);
    unsigned char pub[MAX_FN_DSA_PUB_LEN];
    FN_DSA_KEY *key;

    if (p == NULL || !ossl_fn_dsa_d2i_PUBKEY_data(der, derlen, p->logn, pub, p->pk_len))
        return NULL;
    key = ossl_fn_dsa_key_new(provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx),
        propq, evp_type);
    if (key != NULL && !ossl_fn_dsa_pk_decode(key, pub, p->pk_len)) {
        ossl_fn_dsa_key_free(key);
        key = NULL;
    }
    return key;
}

int ossl_fn_dsa_i2d_pubkey(const FN_DSA_KEY *key, unsigned char **out)
{
    const FN_DSA_PARAMS *p = ossl_fn_dsa_key_params(key);

    return ossl_fn_dsa_i2d_pubkey_data(ossl_fn_dsa_key_get_pub(key), p->pk_len,
        p->logn, out);
}

int ossl_fn_dsa_i2d_prvkey(const FN_DSA_KEY *key, unsigned char **out)
{
    const unsigned char *seed = ossl_fn_dsa_key_get_seed(key);

    if (ossl_fn_dsa_key_get_priv(key) == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NOT_A_PRIVATE_KEY);
        return 0;
    }
    if (seed == NULL
        || !(ossl_fn_dsa_key_get_prov_flags(key) & FN_DSA_KEY_RETAIN_SEED)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        return 0;
    }
    return ossl_fn_dsa_i2d_prvkey_data(seed, FN_DSA_SEED_BYTES, out);
}
int ossl_fn_dsa_d2i_PKCS8_data(const unsigned char *der, long derlen, unsigned logn,
                          unsigned char *seed, size_t seedlen)
{
    const unsigned char *p = der, *raw = NULL;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    const X509_ALGOR *alg = NULL;
    ASN1_OBJECT *oid = NULL;
    unsigned char *canonical = NULL;
    int rawlen = 0, encoded = 0, ret = 0;
    if (der == NULL || derlen <= 0 || seed == NULL ||
        seedlen != FN_DSA_SEED_BYTES ||
        (oid = get_oid(logn)) == NULL ||
        (p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, derlen)) == NULL ||
        p != der + derlen || !PKCS8_pkey_get0(NULL, &raw, &rawlen, &alg, p8) ||
        !check_algorithm(alg, oid) || rawlen != (int)seedlen)
        goto end;
    encoded = i2d_PKCS8_PRIV_KEY_INFO(p8, &canonical);
    if (encoded != derlen || canonical == NULL ||
        CRYPTO_memcmp(canonical, der, (size_t)derlen) != 0)
        goto end;
    memcpy(seed, raw, seedlen);
    ret = 1;
end:
    ASN1_OBJECT_free(oid);
    if (raw != NULL && rawlen > 0)
        OPENSSL_cleanse((void *)raw, (size_t)rawlen);
    PKCS8_PRIV_KEY_INFO_free(p8);
    OPENSSL_clear_free(canonical, encoded > 0 ? (size_t)encoded : 0);
    return ret;
}

/* Match the shared ML-DSA text format; private material needs private selection. */
int ossl_fn_dsa_key_to_text(BIO *out, const FN_DSA_KEY *key, int selection)
{
    const FN_DSA_PARAMS *params;
    const unsigned char *pub, *priv, *seed;
    int private = (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    params = ossl_fn_dsa_key_params(key);
    pub = ossl_fn_dsa_key_get_pub(key);
    priv = ossl_fn_dsa_key_get_priv(key);
    seed = ossl_fn_dsa_key_get_seed(key);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0
        || pub == NULL || (private && priv == NULL)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_MISSING_KEY,
            "no %s key material available for selection", params->alg);
        return 0;
    }
    if (BIO_printf(out, "%s %s-Key:\n", params->alg,
            private ? "Private" : "Public") <= 0)
        return 0;
    if (private) {
        if (seed != NULL
            && !ossl_bio_print_labeled_buf(out, "seed:", seed, FN_DSA_SEED_BYTES))
            return 0;
        if (!ossl_bio_print_labeled_buf(out, "priv:", priv, params->sk_len))
            return 0;
    }
    return ossl_bio_print_labeled_buf(out, "pub:", pub, params->pk_len);
}
