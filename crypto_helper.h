#ifndef KEYMASTER_H
#define KEYMASTER_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <stdlib.h>

#include "log.h"

#define AES_GCM_256_IV_LEN 16
#define AES_GCM_256_KEY_LEN 32
#define AES_GCM_256_TAG_LEN 16
#define SHA256_DEFAULT_SIZE 32
#define MODE_ENCRYPT 1
#define MODE_DECRYPT 2

/**
 * @brief AES256EncryptDecrypt
 *        The function does encryption/decryption of input data
 *        depending on 'mode' parameter using AES encryption algorithm
 *        with 256-bit key.
 *
 * @param[in] mode - set mode for operation. Can be MODE_ENCRYPT or MODE_DECRYPT
 * @param[in] in - input data array. No limitations on array length.
 * @param[in] in_len - length of input data array
 * @param[in] key - key data array. Length must be AES_GCM_256_KEY_LEN bytes.
 * @param[in] iv - initialization vector array. Must be AES_GCM_256_IV_LEN bytes.
 *            This array must be the same for encrypt/decrypt operation pair.
 *            Can be generated ramdomly or filled in manually.
 * @param[in]/[out] tag - authentication tag array. Must be AES_GCM_256_TAG_LEN bytes.
 *                        This array is generated as a result of encrypt operation,
 *                        and used as input parameter for decrypt operation. To correctly do
 *                        decrypt, use array generated previously in encrypt operation.
 * @param [out] out - output array which stores encrypted/decrypted data depending on chosen mode.
 *                    must not be less than in_len bytes.
 * @param [out] out_len - resulting encrypted array len. Expectin it will be equal in_len value.
 * @return
 */
int AES256EncryptDecrypt(int mode, char *in, size_t in_len, char *key,
                         char *iv, char* tag, char *out, size_t *out_len);


EVP_PKEY *GenerateRSAKey (int key_len_bits);
int RSASign(char *in, size_t in_len, EVP_PKEY *key, char**sig, size_t *sig_len);
int RSAVerify(char *in, size_t in_len, EVP_PKEY *key, char*sig, size_t sig_len);

int MakeCertificate(X509 **x509p, EVP_PKEY *pk, int serial, int days);

#endif // KEYMASTER_H
