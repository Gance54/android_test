#include "crypto_helper.h"

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

static int add_ext(X509 *cert, int nid, char *value) {
    X509_EXTENSION *ex = NULL;
    ASN1_OCTET_STRING *str = ASN1_OCTET_STRING_new();
    if (!str) {
        LOGE("Failed to create asn1 string");
        return -1;
    }
    ASN1_OCTET_STRING_set(str, (const unsigned char*)value, strlen(value));
    X509_EXTENSION_create_by_NID(&ex, nid, 0, str);
    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 0;
}


int MakeCertificate(X509 **x509p, EVP_PKEY *pk, int serial, int days) {
    X509_NAME *name=NULL;
    X509 *x = X509_new();
    if (!x) {
        LOGE("Failed to allocate memory");
        goto err;
    }

    X509_set_version(x,2);
    ASN1_INTEGER_set(X509_get_serialNumber(x),serial);
    X509_gmtime_adj(X509_get_notBefore(x),0);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    name=X509_get_subject_name(x);

    X509_NAME_add_entry_by_txt(name,"C",
                MBSTRING_ASC, (const unsigned char*)"UA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                MBSTRING_ASC, (const unsigned char*)"AndroidS ProCamp", -1, -1, 0);

    /*
     * Its self signed so set the issuer name to be the same as the
     * subject.
     */
    X509_set_issuer_name(x,name);

    /* Add various extensions: standard extensions */
    add_ext(x, NID_basic_constraints, (char*)"critical,CA:TRUE");
    add_ext(x, NID_key_usage, (char*)"critical,keyCertSign,cRLSign");

    add_ext(x, NID_subject_key_identifier, (char*)"hash");

    add_ext(x, NID_netscape_cert_type, (char*)"sslCA");

    add_ext(x, NID_netscape_comment, (char*)"example comment extension");

    {
        int nid;
        nid = OBJ_create("1.2.3.4", "TestAlias", "My Extension");
        X509V3_EXT_add_alias(nid, NID_netscape_comment);
        add_ext(x, nid, (char*)"Example comment");
    }

    if (!X509_sign(x,pk,EVP_sha256()))
        goto err;

    *x509p=x;
    return 0 ;

err:

    X509_free(x);
    return(-1);
}

