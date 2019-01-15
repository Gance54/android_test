#include "gtest/gtest.h"
#include "log.h"
#include "crypto_helper.h"

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

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
