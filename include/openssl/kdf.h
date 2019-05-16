/*
 * Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef HEADER_KDF_H
# define HEADER_KDF_H

# include <stdarg.h>
# include <stddef.h>
# include <openssl/ossl_typ.h>
# include <openssl/kdferr.h>
# ifdef __cplusplus
extern "C" {
# endif

/**
 * @addtogroup CRYPTO_KDF_PBKDF2
 * @see EVP_KDF_CTX_new_id().
 */
# define EVP_KDF_PBKDF2     NID_id_pbkdf2
/**
 * @addtogroup CRYPTO_KDF_SCRYPT
 * @see EVP_KDF_CTX_new_id().
 */
# define EVP_KDF_SCRYPT     NID_id_scrypt
/**
 * @addtogroup CRYPTO_KDF_TLS1_PRF
 * @see EVP_KDF_CTX_new_id().
 */
# define EVP_KDF_TLS1_PRF   NID_tls1_prf
/**
 * @addtogroup CRYPTO_KDF_HKDF
 * @see EVP_KDF_CTX_new_id().
 */
# define EVP_KDF_HKDF       NID_hkdf
/**
 * @addtogroup CRYPTO_KDF_SSHKDF
 * @see EVP_KDF_CTX_new_id().
 */
# define EVP_KDF_SSHKDF     NID_sshkdf
/**
 * @addtogroup CRYPTO_KDF_SSKDF
 * @see EVP_KDF_CTX_new_id().
 */
# define EVP_KDF_SS         NID_sskdf
# define EVP_KDF_X963       NID_x963kdf

/**
 * @addtogroup CRYPTO_KDF_FUNCTIONS
 * @{
 */

/** @brief Creates a new @ref EVP_KDF_CTX */
EVP_KDF_CTX *EVP_KDF_CTX_new_id(int id);
/** @brief Creates a new @ref EVP_KDF_CTX */
EVP_KDF_CTX *EVP_KDF_CTX_new(const EVP_KDF *kdf);
/** @brief Creates a new @ref EVP_KDF_CTX */
void EVP_KDF_CTX_free(EVP_KDF_CTX *ctx);
/** Get the @ref EVP_KDF object associated with the @ref EVP_KDF_CTX */
const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx);
/** @brief Resets the @ref EVP_KDF_CTX to the default state. */
void EVP_KDF_reset(EVP_KDF_CTX *ctx);
/** @brief Provide inputs to the KDF algorithm */
int EVP_KDF_ctrl(EVP_KDF_CTX *ctx, int cmd, ...);
/** @brief Provide inputs to the KDF algorithm */
int EVP_KDF_vctrl(EVP_KDF_CTX *ctx, int cmd, va_list args);
/** @brief Provide inputs to the KDF algorithm using a type:value pair */
int EVP_KDF_ctrl_str(EVP_KDF_CTX *ctx, const char *type, const char *value);
/** @brief Get the output size */
size_t EVP_KDF_size(EVP_KDF_CTX *ctx);
/** @brief Derive Key Material */
int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen);

int EVP_KDF_nid(const EVP_KDF *kdf);
# define EVP_get_kdfbynid(a)    EVP_get_kdfbyname(OBJ_nid2sn(a))
# define EVP_get_kdfbyobj(a)    EVP_get_kdfbynid(OBJ_obj2nid(a))
# define EVP_KDF_name(o)        OBJ_nid2sn(EVP_KDF_nid(o))
const EVP_KDF *EVP_get_kdfbyname(const char *name);

/**
 * @}
 */ /* CRYPTO_KDF_FUNCTIONS */

/**
 * @addtogroup CRYPTO_KDF_CTRLS_ID
 * @{
 * The following controls identifiers are used as the 'cmd' parameter for the
 * EVP_KDF_ctrl() function. Any additional arguements following the cmd are
 * dependent on the cmd.
 */

/**
 * Some KDF implementations require a password.  For those KDF implementations
 * that support it, this control sets the password.
 *
 * EVP_KDF_ctrl() expects two additional arguments:
 *     - unsigned char *pass
 *     - size_t passlen
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 *     - "pass" : The value string is used as is.
 *     - "hexpass" : The value string is expected to be a hexadecimal number,
 *                   which will be decoded before being passed on as the control
 *                   value.
 */
# define EVP_KDF_CTRL_SET_PASS          0x01 /* unsigned char *, size_t */

/**
 * Some KDF implementations can take a salt.  For those KDF implementations that
 * support it, this control sets the salt.
 * The default value, if any, is implementation dependent.
 *
 * EVP_KDF_ctrl() usage:
 *
 * EVP_KDF_ctrl(ctx, EVP_KDF_CTRL_SET_PASS, (unsigned char *)salt, (size_t)saltlen)
 *
 * EVP_KDF_ctrl_str() parameters
 * | type string | value string | example |
 * | :---- |:----| :----- |
 * | "salt" | used as is. | EVP_KDF_ctrl_str(ctx, "salt", "NaCl") |
 * | "hexsalt" | hexadecimal number. | EVP_KDF_ctrl_str(ctx, "hexsalt", "DEBE01") |
 */
# define EVP_KDF_CTRL_SET_SALT          0x02 /* unsigned char *, size_t */

/**
 * Some KDF implementations require an iteration count. For those KDF
 * implementations that support it, this control sets the iteration count.
 *
 * The default value, if any, is implementation dependent.
 * This control expects one argument:
 * - int iter
 *
 * EVP_KDF_ctrl_str() type string: "iter"
 * The value string is expected to be a decimal number.
 */
# define EVP_KDF_CTRL_SET_ITER          0x03 /* int */

/**
 * For MAC implementations that use a message digest as an underlying computation
 * algorithm, this control sets what the digest algorithm should be.
 *
 * This control expects one argument:
 * - EVP_MD *md
 *
 * EVP_KDF_ctrl_str() type string: "digest"
 * The value string is expected to be the name of a digest.
 */
# define EVP_KDF_CTRL_SET_MD            0x04 /* EVP_MD * */
/**
 * The shared secret used for key derivation.  For those KDF implementations
 * that support it, this control sets the secret.
 *
 * EVP_KDF_ctrl() expects two additional arguments:
 *     - unsigned char *secret
 *     - size_t secretlen
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 *     - "secret" : The value string is used as is.
 *     - "hexsecret" : The value string is expected to be a hexadecimal number,
 *                     which will be decoded before being passed on as the
 *                     control value.
 */
# define EVP_KDF_CTRL_SET_KEY           0x05 /* unsigned char *, size_t */
/**
 * Memory-hard password-based KDF algorithms, such as scrypt, use an amount of
 * memory that depends on the load factors provided as input.  For those KDF
 * implementations that support it, this control sets an upper limit on the amount
 * of memory that may be consumed while performing a key derivation.  If this
 * memory usage limit is exceeded because the load factors are chosen too high,
 * the key derivation will fail.
 *
 * The default value is implementation dependent.
 *
 * This control expects one argument: C<uint64_t maxmem_bytes>
 *
 * EVP_KDF_ctrl_str() type string: "maxmem_bytes"
 * The value string is expected to be a decimal number.
 */
# define EVP_KDF_CTRL_SET_MAXMEM_BYTES  0x06 /* uint64_t */
/**
 * Sets the secret value of the TLS PRF to "seclen" bytes of the buffer "sec".
 * Any existing secret value is replaced.
 *
 * This control expects two arguments:
 * - unsigned char *sec
 * - size_t seclen
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 * - "secret" : The value string is used as is.
 * - "hexsecret" : The value string is expected to be a hexadecimal number,
 * which will be decoded before being passed on as the control value.
 */
# define EVP_KDF_CTRL_SET_TLS_SECRET    0x07 /* unsigned char *, size_t */
/**
 * Resets the context seed buffer to zero length.
 *
 * This control does not expect any arguments.
 */
# define EVP_KDF_CTRL_RESET_TLS_SEED    0x08

/**
 * Sets the seed to "seedlen" bytes of "seed".  If a seed is already set it is
 * appended to the existing value.
 *
 * This control expects two arguments:
 * - unsigned char *seed
 * - size_t seedlen
 *
 * The total length of the context seed buffer cannot exceed 1024 bytes;
 * this should be more than enough for any normal use of the TLS PRF.
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 * - "seed" : The value string is used as is.
 * - "hexseed": The value string is expected to be a hexadecimal number,
 * which will be decoded before being passed on as the control value.
 */
# define EVP_KDF_CTRL_ADD_TLS_SEED      0x09 /* unsigned char *, size_t */

/**
 * Resets the context info buffer to zero length.
 *
 * This control does not expect any arguments.
 */
# define EVP_KDF_CTRL_RESET_HKDF_INFO   0x0a

/**
 * This control expects two arguments: C<unsigned char *info>, C<size_t infolen>
 *
 * Sets the info value to the first B<infolen> bytes of the buffer B<info>.  If a
 * value is already set, the contents of the buffer are appended to the existing
 * value.
 *
 * The total length of the context info buffer cannot exceed 1024 bytes;
 * this should be more than enough for any normal use of HKDF.
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 * - "info" : The value string is used as is.
 * - "hexinfo" : The value string is expected to be a hexadecimal number,
 * which will be decoded before being passed on as the control value.
 *
 */
# define EVP_KDF_CTRL_ADD_HKDF_INFO     0x0b /* unsigned char *, size_t */

/**
 * Sets the mode for the EVP_KDF_HKDF operation.
 * This control expects one argument: C<int mode>
 * There are three modes that are currently defined:
 * Which is one of
 *     - @ref EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
 *     - @ref EVP_KDF_HKDF_MODE_EXTRACT_ONLY
 *     - @ref EVP_KDF_HKDF_MODE_EXPAND_ONLY
 *
 *
 * EVP_KDF_ctrl_str() type string: "mode"
 *
 * The value string is expected to be one of:
 * - "EXTRACT_AND_EXPAND"
 * - "EXTRACT_ONLY"
 * - "EXPAND_ONLY"
 */
# define EVP_KDF_CTRL_SET_HKDF_MODE     0x0c /* int */

/**
 * Sets the scrypt work factor N.
 * This control expects one argument:
 * - uint64_t N
 *
 * EVP_KDF_ctrl_str() type string: "N".
 * The corresponding value string is expected to be a decimal number.
 */
# define EVP_KDF_CTRL_SET_SCRYPT_N      0x0d /* uint64_t */
/**
 * Sets the scrypt work factor R.
 * This control expects one argument:
 * - uint32_t N
 *
 *
 * EVP_KDF_ctrl_str() type string: "R".
 * The corresponding value string is expected to be a decimal number.
 */
# define EVP_KDF_CTRL_SET_SCRYPT_R      0x0e /* uint32_t */
/**
 * Sets the scrypt work factor P.
 * This control expects one argument:
 * - uint32_t N
 *
 * EVP_KDF_ctrl_str() type string: "P".
 * The corresponding value string is expected to be a decimal number.
 */
# define EVP_KDF_CTRL_SET_SCRYPT_P      0x0f /* uint32_t */

/**
 * Sets the xcghash to the first "length" bytes of the buffer "buffer".
 * If a value is already set, the contents are replaced.
 * This control expects two arguments:
 * - unsigned char *buffer
 * - size_t length
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 * - "xcghash" : The value string is used as is.
 * - "hexxcghash" : The value string is expected to be a hexadecimal number, which will be
 * decoded before being passed on as the control value.
 */
# define EVP_KDF_CTRL_SET_SSHKDF_XCGHASH    0x10 /* unsigned char *, size_t */
/**
 * Sets the session_id to the first "length" bytes of the buffer "buffer".
 * If a value is already set, the contents are replaced.
 * This control expects two arguments:
 * - unsigned char *buffer
 * - size_t length
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 * - "session_id" : The value string is used as is.
 * - "hexsession_id" : The value string is expected to be a hexadecimal number,
 * which will be decoded before being passed on as the control value.
 */
# define EVP_KDF_CTRL_SET_SSHKDF_SESSION_ID 0x11 /* unsigned char *, size_t */

/**
 * Sets the type for the SSHHKDF operation.
 * This control expects one argument: C<int mode>
 *
 * There are six supported types: see @ref CRYPTO_KDF_SSHKDF_TYPE
 *
 * EVP_KDF_ctrl_str() type string: "type"
 * The value is a string of length one character. The only valid values
 * are the numerical values of the ASCII caracters: "A" (65) to "F" (70).
 */
# define EVP_KDF_CTRL_SET_SSHKDF_TYPE       0x12 /* int */

/**
 * Some KDF implementations use a MAC as an underlying computation
 * algorithm, this control sets what the MAC algorithm should be.
 *
 * This control expects one argument:
 * - EVP_MAC *mac
 *
 * EVP_KDF_ctrl_str() type string: "mac"
 * The value string is expected to be the name of a MAC.
 */
# define EVP_KDF_CTRL_SET_MAC           0x13 /* EVP_MAC * */
/**
 * Used by implementations that use a MAC with a variable output size (KMAC).
 * For those KDF implementations that support it, this control sets the MAC
 * output size. The default value, if any, is implementation dependent.
 *
 * EVP_KDF_ctrl() expects one additional argument:
 *     - size_t size
 *
 * EVP_KDF_ctrl_str() type string:
 *     - "outlen" : The value string is expected to be a decimal number.
 */
# define EVP_KDF_CTRL_SET_MAC_SIZE      0x14 /* size_t */

/**
 * This control sets the fixedinfo for @ref EVP_KDF_SS.
 * It is an optional value also known as otherinfo.
 *
 * EVP_KDF_ctrl() expects two additional arguments:
 *     - unsigned char *info
 *     - size_t infolen
 *
 * EVP_KDF_ctrl_str() takes two type strings for this control:
 *     - "info" : The value string is used as is.
 *     - "hexinfo" : The value string is expected to be a hexadecimal number,
 *                   which will be decoded before being passed on as the control
 *                   value.
 */
# define EVP_KDF_CTRL_SET_SSKDF_INFO    0x15 /* unsigned char *, size_t */
# define EVP_KDF_CTRL_SET_SHARED_INFO   EVP_KDF_CTRL_SET_SSKDF_INFO

/**
 * @}
 */

/**
 * @addtogroup CRYPTO_KDF_HKDF_MODE
 * @{
 */

 /**
  * This is the default mode.  Calling EVP_KDF_derive() on an @ref EVP_KDF_CTX set
  * up for @ref EVP_KDF_HKDF will perform an extract followed by an expand operation in one go.
  * The derived key returned will be the result after the expand operation. The
  * intermediate fixed-length pseudorandom key K is not returned.
  *
  * In this mode the digest, key, salt and info values must be set before a key is
  * derived otherwise an error will occur.
  */
# define EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND  0

/**
 * In this mode calling EVP_KDF_derive() will just perform the extract
 * operation. The value returned will be the intermediate fixed-length pseudorandom
 * key K.  The "keylen" parameter must match the size of K, which can be looked
 * up by calling EVP_KDF_size() after setting the mode and digest.
 *
 * The digest, key and salt values must be set before a key is derived otherwise
 * an error will occur.
 */
# define EVP_KDF_HKDF_MODE_EXTRACT_ONLY        1

/**
 * In this mode calling EVP_KDF_derive() will just perform the expand
 * operation. The input key should be set to the intermediate fixed-length
 * pseudorandom key K returned from a previous extract operation.
 *
 * The digest, key and info values must be set before a key is derived otherwise
 * an error will occur.
 */
# define EVP_KDF_HKDF_MODE_EXPAND_ONLY         2

/**
 * @}
 */ /* CRYPTO_KDF_HKDF_MODE */


/**
 * @addtogroup CRYPTO_KDF_SSHKDF_TYPE
 * @{
 */

/**
 * The Initial IV from client to server.
 * A single char of value 65 (ASCII char 'A').
 */
#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_CLI_TO_SRV 65
/**
 * The Initial IV from server to client
 * A single char of value 66 (ASCII char 'B').
 */
#define EVP_KDF_SSHKDF_TYPE_INITIAL_IV_SRV_TO_CLI 66
/**
 * The Encryption Key from client to server
 * A single char of value 67 (ASCII char 'C').
 */
#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_CLI_TO_SRV 67
/**
 * The Encryption Key from server to client
 * A single char of value 68 (ASCII char 'D').
 */
#define EVP_KDF_SSHKDF_TYPE_ENCRYPTION_KEY_SRV_TO_CLI 68
/**
 * The Integrity Key from client to server
 * A single char of value 69 (ASCII char 'E').
 */
#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_CLI_TO_SRV 69
/**
 * The Integrity Key from server to client
 * A single char of value 70 (ASCII char 'F').
 */
#define EVP_KDF_SSHKDF_TYPE_INTEGRITY_KEY_SRV_TO_CLI 70

/**
 * @}
 */ /* CRYPTO_KDF_SSHKDF_TYPE */


/* The legacy PKEY-based KDF API follows. */
/**
 * @addtogroup CRYPTO_KDF_LEGACY_CTRLS
 * @{
 */
# define EVP_PKEY_CTRL_TLS_MD                   (EVP_PKEY_ALG_CTRL)
# define EVP_PKEY_CTRL_TLS_SECRET               (EVP_PKEY_ALG_CTRL + 1)
# define EVP_PKEY_CTRL_TLS_SEED                 (EVP_PKEY_ALG_CTRL + 2)
# define EVP_PKEY_CTRL_HKDF_MD                  (EVP_PKEY_ALG_CTRL + 3)
# define EVP_PKEY_CTRL_HKDF_SALT                (EVP_PKEY_ALG_CTRL + 4)
# define EVP_PKEY_CTRL_HKDF_KEY                 (EVP_PKEY_ALG_CTRL + 5)
# define EVP_PKEY_CTRL_HKDF_INFO                (EVP_PKEY_ALG_CTRL + 6)
# define EVP_PKEY_CTRL_HKDF_MODE                (EVP_PKEY_ALG_CTRL + 7)
# define EVP_PKEY_CTRL_PASS                     (EVP_PKEY_ALG_CTRL + 8)
# define EVP_PKEY_CTRL_SCRYPT_SALT              (EVP_PKEY_ALG_CTRL + 9)
# define EVP_PKEY_CTRL_SCRYPT_N                 (EVP_PKEY_ALG_CTRL + 10)
# define EVP_PKEY_CTRL_SCRYPT_R                 (EVP_PKEY_ALG_CTRL + 11)
# define EVP_PKEY_CTRL_SCRYPT_P                 (EVP_PKEY_ALG_CTRL + 12)
# define EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES      (EVP_PKEY_ALG_CTRL + 13)

/**
 * @}
 */ /* CRYPTO_KDF_LEGACY_CTRLS */

/**
 * @addtogroup CRYPTO_KDF_LEGACY_FUNC
 * @{
 */
# define EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND \
            EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND
# define EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY       \
            EVP_KDF_HKDF_MODE_EXTRACT_ONLY
# define EVP_PKEY_HKDEF_MODE_EXPAND_ONLY        \
            EVP_KDF_HKDF_MODE_EXPAND_ONLY

# define EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, seclen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_SECRET, seclen, (void *)(sec))

# define EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed, seedlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_TLS_SEED, seedlen, (void *)(seed))

# define EVP_PKEY_CTX_set_hkdf_md(pctx, md) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MD, 0, (void *)(md))

# define EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_SALT, saltlen, (void *)(salt))

# define EVP_PKEY_CTX_set1_hkdf_key(pctx, key, keylen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_KEY, keylen, (void *)(key))

# define EVP_PKEY_CTX_add1_hkdf_info(pctx, info, infolen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_INFO, infolen, (void *)(info))

# define EVP_PKEY_CTX_hkdf_mode(pctx, mode) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                              EVP_PKEY_CTRL_HKDF_MODE, mode, NULL)

# define EVP_PKEY_CTX_set1_pbe_pass(pctx, pass, passlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_PASS, passlen, (void *)(pass))

# define EVP_PKEY_CTX_set1_scrypt_salt(pctx, salt, saltlen) \
            EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_SALT, saltlen, (void *)(salt))

# define EVP_PKEY_CTX_set_scrypt_N(pctx, n) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_N, n)

# define EVP_PKEY_CTX_set_scrypt_r(pctx, r) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_R, r)

# define EVP_PKEY_CTX_set_scrypt_p(pctx, p) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_P, p)

# define EVP_PKEY_CTX_set_scrypt_maxmem_bytes(pctx, maxmem_bytes) \
            EVP_PKEY_CTX_ctrl_uint64(pctx, -1, EVP_PKEY_OP_DERIVE, \
                            EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, maxmem_bytes)
/**
 * @}
 */ /* CRYPTO_KDF_LEGACY_FUNC */


# ifdef __cplusplus
}
# endif
#endif
