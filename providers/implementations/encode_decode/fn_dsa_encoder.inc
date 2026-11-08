/* FN-DSA uses the shared PKCS#8, encrypted PKCS#8 and SPKI encoders. */
#ifndef OPENSSL_NO_FN_DSA
#include "prov/fn_dsa_codecs.h"

static int fn_dsa_spki_pub_to_der(const void *key, unsigned char **out, void *ctx)
{
    (void)ctx;
    return ossl_fn_dsa_i2d_pubkey(key, out);
}
static int fn_dsa_pki_priv_to_der(const void *key, unsigned char **out, void *ctx)
{
    KEY2ANY_CTX *ectx = ctx;

    if (ectx->output_formats != NULL && ectx->output_formats[0] != '\0') {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }
    return ossl_fn_dsa_i2d_prvkey(key, out);
}
#define fn_dsa_epki_priv_to_der fn_dsa_pki_priv_to_der
#define prepare_fn_dsa_params NULL
#define fn_dsa_check_key_type NULL
#define fn_dsa_512_evp_type EVP_PKEY_FN_DSA_512
#define fn_dsa_1024_evp_type EVP_PKEY_FN_DSA_1024
#define fn_dsa_512_pem_type "FN-DSA-512"
#define fn_dsa_1024_pem_type "FN-DSA-1024"
MAKE_ENCODER(fn_dsa_512, fn_dsa, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(fn_dsa_512, fn_dsa, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(fn_dsa_512, fn_dsa, PrivateKeyInfo, der);
MAKE_ENCODER(fn_dsa_512, fn_dsa, PrivateKeyInfo, pem);
MAKE_ENCODER(fn_dsa_512, fn_dsa, SubjectPublicKeyInfo, der);
MAKE_ENCODER(fn_dsa_512, fn_dsa, SubjectPublicKeyInfo, pem);
MAKE_ENCODER(fn_dsa_1024, fn_dsa, EncryptedPrivateKeyInfo, der);
MAKE_ENCODER(fn_dsa_1024, fn_dsa, EncryptedPrivateKeyInfo, pem);
MAKE_ENCODER(fn_dsa_1024, fn_dsa, PrivateKeyInfo, der);
MAKE_ENCODER(fn_dsa_1024, fn_dsa, PrivateKeyInfo, pem);
MAKE_ENCODER(fn_dsa_1024, fn_dsa, SubjectPublicKeyInfo, der);
MAKE_ENCODER(fn_dsa_1024, fn_dsa, SubjectPublicKeyInfo, pem);
#endif
