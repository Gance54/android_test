#include "crypto_helper.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

int AES256EncryptDecrypt(int mode, char *in, size_t in_len, char *key,
                         char *iv, char* tag, char *out, size_t *out_len) {
    int len;
    int res_len;
    int ret = -1;
    int (*CryptInit)(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                     const unsigned char *, const unsigned char *);
    int (*CryptUpdate)(EVP_CIPHER_CTX *, unsigned char *,
            int *, const unsigned char *, int);
    int (*CryptFinal)(EVP_CIPHER_CTX *, unsigned char *, int *);

    CryptInit = mode == MODE_ENCRYPT ? EVP_EncryptInit_ex : EVP_DecryptInit_ex;
    CryptUpdate = mode == MODE_ENCRYPT ? EVP_EncryptUpdate : EVP_DecryptUpdate;
    CryptFinal = mode == MODE_ENCRYPT ? EVP_EncryptFinal_ex : EVP_DecryptFinal_ex;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        LOGE("Failed to create ctx");
        return -1;
    }

    if (1 != CryptInit(ctx, EVP_aes_256_gcm(), NULL, (unsigned char*)key,
                       (unsigned char*)iv)) {
        LOGE("Failed to init operation");
        goto out;
    }

    if (1 != CryptUpdate(ctx, (unsigned char*)out, (int*)&len,
                         (unsigned char*)in, (int)in_len)) {
        LOGE("Failed to update operation");
        goto out;
    }

    res_len = len;

    if (mode == MODE_DECRYPT) {
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_256_TAG_LEN,
                                    (unsigned char*)tag)) {
            LOGE("Failed to set tag to context");
            goto out;
        }
    }

    if (1 != CryptFinal(ctx, (unsigned char*)(in+len), &len)) {
        LOGE("Failed to do crypt final");
        goto out;
    }
    else
        res_len += len;

    if (mode == MODE_ENCRYPT) {
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_256_TAG_LEN,
                                    (unsigned char*)tag)) {
            LOGE("Failed to get tag from ctx");
        }
    }

    ret = 0;
    *out_len = (size_t)res_len;

out:
    EVP_CIPHER_CTX_free(ctx);;
    return ret;
}


