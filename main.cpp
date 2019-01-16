#include "gtest/gtest.h"
#include "log.h"
#include "crypto_helper.h"

#define CERT_PATH "/data/local/tmp/cert.der"
#define SIGNATURE_PATH "/data/local/tmp/signature.dat"

class Base : public ::testing::Test {
  public:
    Base() {}
    virtual ~Base() {}
    void SetUp() {}
    void TearDown() {}
    int GenerateRandomBytes(char *buf, size_t size) {
        return RAND_bytes((unsigned char*)buf, (int)size);
    }
};

TEST_F(Base, AES256GCMEncryptDecryptSuccess) {
    char key[AES_GCM_256_KEY_LEN] = { 0, };
    char iv[AES_GCM_256_IV_LEN] = { 0, };
    char tag[AES_GCM_256_TAG_LEN] = { 0, };
    char plaintext[] = "What is the key to the life on Earth?";
    char ciphertext[256] = { 0, };
    char decrypted_text[256] = { 0, };
    size_t ciphertext_len, decryptedtext_len;

    ASSERT_EQ(1, GenerateRandomBytes(key, sizeof(key)));
    ASSERT_EQ(1, GenerateRandomBytes(iv, sizeof(iv)));

    ASSERT_EQ(0, AES256EncryptDecrypt(MODE_ENCRYPT, plaintext,
        strlen(plaintext), key, iv, tag, ciphertext, &ciphertext_len))
            << "Failed to encrypt message";

    ASSERT_TRUE(ciphertext_len == strlen(plaintext));

    ASSERT_EQ(0, AES256EncryptDecrypt(MODE_DECRYPT, ciphertext,
        ciphertext_len, key, iv, tag, decrypted_text, &decryptedtext_len))
            << "Failed to decrypt message";

    ASSERT_EQ(strlen(plaintext), decryptedtext_len)
            << "Decrypted text len != plaintext len";

    ASSERT_EQ(0, strcmp(decrypted_text, plaintext))
            << "Decrypted text != plaintext";

    LOGI("Plaintext: %s\nEncrypted Text: %s\nDecrypted text: %s\n",
         plaintext, ciphertext, decrypted_text);
}

TEST_F(Base, AES256GCMBrokenEncryptedText) {
    char key[AES_GCM_256_KEY_LEN] = { 0, };
    char iv[AES_GCM_256_IV_LEN] = { 0, };
    char tag[AES_GCM_256_TAG_LEN] = { 0, };
    char plaintext[] = "What is the key to the life on Earth?";
    char ciphertext[256] = { 0, };
    char decrypted_text[256] = { 0, };
    size_t ciphertext_len, decryptedtext_len;

    ASSERT_EQ(1, GenerateRandomBytes(key, sizeof(key)));
    ASSERT_EQ(1, GenerateRandomBytes(iv, sizeof(iv)));

    ASSERT_EQ(0, AES256EncryptDecrypt(MODE_ENCRYPT, plaintext,
        strlen(plaintext), key, iv, tag, ciphertext, &ciphertext_len))
            << "Failed to encrypt message";

    ciphertext[0] ^= 1;

    ASSERT_EQ(-1, AES256EncryptDecrypt(MODE_DECRYPT, ciphertext,
        ciphertext_len, key, iv, tag, decrypted_text, &decryptedtext_len))
            << "Message decryption should have failed";
}

TEST_F(Base, AES256GCMBrokenKey) {
    char key[AES_GCM_256_KEY_LEN] = { 0, };
    char iv[AES_GCM_256_IV_LEN] = { 0, };
    char tag[AES_GCM_256_TAG_LEN] = { 0, };
    char plaintext[] = "What is the key to the life on Earth?";
    char ciphertext[256] = { 0, };
    char decrypted_text[256] = { 0, };
    size_t ciphertext_len, decryptedtext_len;

    ASSERT_EQ(1, GenerateRandomBytes(key, sizeof(key)));
    ASSERT_EQ(1, GenerateRandomBytes(iv, sizeof(iv)));

    ASSERT_EQ(0, AES256EncryptDecrypt(MODE_ENCRYPT, plaintext,
        strlen(plaintext), key, iv, tag, ciphertext, &ciphertext_len))
            << "Failed to encrypt message";

    key[0] ^= 1;

    ASSERT_EQ(-1, AES256EncryptDecrypt(MODE_DECRYPT, ciphertext,
        ciphertext_len, key, iv, tag, decrypted_text, &decryptedtext_len))
            << "Message decryption should have failed";
}

TEST_F(Base, AES256GCMBrokenTag) {
    char key[AES_GCM_256_KEY_LEN] = { 0, };
    char iv[AES_GCM_256_IV_LEN] = { 0, };
    char tag[AES_GCM_256_TAG_LEN] = { 0, };
    char plaintext[] = "What is the key to the life on Earth?";
    char ciphertext[256] = { 0, };
    char decrypted_text[256] = { 0, };
    size_t ciphertext_len, decryptedtext_len;

    ASSERT_EQ(1, GenerateRandomBytes(key, sizeof(key)));
    ASSERT_EQ(1, GenerateRandomBytes(iv, sizeof(iv)));

    ASSERT_EQ(0, AES256EncryptDecrypt(MODE_ENCRYPT, plaintext,
        strlen(plaintext), key, iv, tag, ciphertext, &ciphertext_len))
            << "Failed to encrypt message";

    tag[0] ^= 1;

    ASSERT_EQ(-1, AES256EncryptDecrypt(MODE_DECRYPT, ciphertext,
        ciphertext_len, key, iv, tag, decrypted_text, &decryptedtext_len))
            << "Message decryption should have failed";
}

TEST_F(Base, RSASignVerifySuccess) {
    char plaintext[] = "What is the key to the life on Earth?";
    char *signature = NULL;
    size_t siglen;
    EVP_PKEY *pkey = GenerateRSAKey(2048);

    ASSERT_NE((evp_pkey_st *)NULL, pkey) << "Failed to generate rsa key";

    ASSERT_EQ(0, RSASign(plaintext, strlen(plaintext), pkey,
        &signature, &siglen)) << "Failed to sign data";

    ASSERT_EQ(0, RSAVerify(plaintext, strlen(plaintext),
        pkey, signature, siglen)) << "Failed to verify signature";

    EVP_PKEY_free(pkey);
    free(signature);
}

TEST_F(Base, RSASignVerifyFakeKeyFails) {
    char plaintext[] = "What is the key to the life on Earth?";
    char *signature = NULL;
    size_t siglen;
    EVP_PKEY *pkey = GenerateRSAKey(2048);
    EVP_PKEY *fake_pkey = GenerateRSAKey(2048);

    ASSERT_NE((evp_pkey_st *)NULL, pkey) << "Failed to generate rsa key";

    ASSERT_EQ(0, RSASign(plaintext, strlen(plaintext), pkey,
        &signature, &siglen)) << "Failed to sign data";

    ASSERT_NE(0, RSAVerify(plaintext, strlen(plaintext),
        fake_pkey, signature, siglen)) << "Should have failed to verify signature";

    EVP_PKEY_free(pkey);
    EVP_PKEY_free(fake_pkey);
    free(signature);
}

TEST_F(Base, RSASignVerifyChangedDataFails) {
    char plaintext[] = "What is the key to the life on Earth?";
    char *signature = NULL;
    size_t siglen;
    EVP_PKEY *pkey = GenerateRSAKey(2048);
    ASSERT_NE((evp_pkey_st *)NULL, pkey) << "Failed to generate rsa key";

    ASSERT_EQ(0, RSASign(plaintext, strlen(plaintext), pkey,
        &signature, &siglen)) << "Failed to sign data";

    plaintext[0] ^= 1;

    ASSERT_NE(0, RSAVerify(plaintext, strlen(plaintext),
        pkey, signature, siglen)) << "should have failed to verify signature";

    EVP_PKEY_free(pkey);
    free(signature);
}

TEST_F(Base, RSASignVerifyChangedSignatureFails) {
    char plaintext[] = "What is the key to the life on Earth?";
    char *signature = NULL;
    size_t siglen;
    EVP_PKEY *pkey = GenerateRSAKey(2048);
    ASSERT_NE((evp_pkey_st *)NULL, pkey) << "Failed to generate rsa key";

    ASSERT_EQ(0, RSASign(plaintext, strlen(plaintext), pkey,
        &signature, &siglen)) << "Failed to sign data";

    signature[0] ^= 1;

    ASSERT_NE(0, RSAVerify(plaintext, strlen(plaintext),
        pkey, signature, siglen)) << "should have failed to verify signature";

    EVP_PKEY_free(pkey);
    free(signature);
}

TEST_F(Base, SignAndMakeCert) {
    char plaintext[] = "What is the key to the life on Earth?";
    int len;
    char *signature = NULL;
    size_t siglen;
    unsigned char *cert_data = NULL;
    X509 *cert = NULL;
    FILE *pFile;
    EVP_PKEY *pkey = GenerateRSAKey(2048);
    ASSERT_NE((evp_pkey_st *)NULL, pkey) << "Failed to generate rsa key";
    ASSERT_EQ(0, MakeCertificate(&cert, pkey, 1, 365));
    len = i2d_X509(cert, NULL);

    ASSERT_FALSE(0 > len) << "Failed to get cert length";
    len = i2d_X509(cert, &cert_data);
    ASSERT_FALSE(0 > len) << "Failed to serialize certificate";
    pFile = fopen(CERT_PATH, "wb");
    ASSERT_NE((FILE*)NULL, pFile) << "Failed to open a file";
    ASSERT_EQ(fwrite(cert_data, 1, (size_t)len, pFile), (size_t)len)
            << "Dailed to write certificate to a file";
    fclose(pFile);

    free(cert_data);
    X509_free(cert);

    ASSERT_EQ(0, RSASign(plaintext, strlen(plaintext), pkey,
        &signature, &siglen)) << "Failed to sign data";

    pFile = fopen(SIGNATURE_PATH, "wb");
    ASSERT_NE((FILE*)NULL, pFile) << "Failed to open a file";
    ASSERT_EQ(fwrite(signature, 1, siglen, pFile), siglen)
            << "Failed to write signature to a file";
    fclose(pFile);

    EVP_PKEY_free(pkey);
    free(signature);
}



int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
