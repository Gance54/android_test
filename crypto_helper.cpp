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

int RSASign(char *in, size_t in_len, EVP_PKEY *key, char**out, size_t *out_len) {
     EVP_PKEY_CTX *ctx = NULL;
     unsigned char md[SHA256_DEFAULT_SIZE];
     unsigned char *sig = NULL;
     size_t siglen;
     int ret = -1;

     if(!SHA256((unsigned char*)in, in_len, md)) {
         LOGE("Failed to digest message");
         return -1;
     }

     ctx = EVP_PKEY_CTX_new(key, NULL);
     if (!ctx) {
         LOGE("Failed to init evp_pkey ctx");
         return -1;
     }

     if (EVP_PKEY_sign_init(ctx) <= 0) {
         LOGE("Failed to init signing");
         goto out;
     }

     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
         LOGE("Failed to set padding");
         goto out;
     }

     if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
         LOGE("Failed to set digest alforithm");
         goto out;
     }

     /* First we need to determine the length of signature */
     if (EVP_PKEY_sign(ctx, NULL, &siglen, md, sizeof(md)) <= 0) {
        LOGE("Failed to determine siglen");
        goto out;
     }

     sig = (unsigned char*)malloc(siglen);
     if (!sig) {
         LOGE("Failed to allocate memory");
         goto out;
     }

     if (EVP_PKEY_sign(ctx, sig, &siglen, md, sizeof(md)) <= 0) {
         LOGE("Failed to sign message");
         goto out;
     }

     ret = 0;

     *out = (char*)sig;
     *out_len = siglen;

out:
     EVP_PKEY_CTX_free(ctx);
     if(ret)
         free(sig);

     return ret;
}

int RSAVerify(char *in, size_t in_len, EVP_PKEY *key, char*sig, size_t sig_len) {
     EVP_PKEY_CTX *ctx = NULL;
     unsigned char md[SHA256_DEFAULT_SIZE];
     int ret = -1;

     if(!SHA256((unsigned char*)in, in_len, md)) {
         LOGE("Failed to digest message");
         return -1;
     }

     ctx = EVP_PKEY_CTX_new(key, NULL);
     if (!ctx) {
         LOGE("Failed to init evp_pkey ctx");
         return -1;
     }

     if (EVP_PKEY_verify_init(ctx) <= 0) {
         LOGE("Failed to init verification");
         goto out;
     }

     if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0) {
         LOGE("Failed to set padding");
         goto out;
     }

     if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) {
         LOGE("Failed to set digest algorithm");
         goto out;
     }

     if (EVP_PKEY_verify(ctx, (unsigned char*)sig, sig_len, md, sizeof(md)) != 1) {
        LOGE("Failed to verify signature");
        goto out;
     }

     ret = 0;

out:
     EVP_PKEY_CTX_free(ctx);
     if(ret)
         free(sig);

     return ret;
}

EVP_PKEY *GenerateRSAKey (int key_len_bits) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        LOGE("Failed to create key generation context");
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        LOGE("Failed to init keygen ctx");
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_len_bits) <= 0) {
        LOGE("Failed to set keygen bits");
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        LOGE("Failed to generate a key");

out:
    EVP_PKEY_CTX_free(ctx);

    return pkey;
}


