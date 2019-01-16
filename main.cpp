#include "gtest/gtest.h"
#include "log.h"
#include "crypto_helper.h"

#include <android/hardware/keymaster/3.0/IKeymasterDevice.h>
#include <android/hardware/keymaster/3.0/types.h>
#include <keymaster/keymaster_configuration.h>

#include "authorization_set.h"
#include "key_param_output.h"

#define CERT_PATH "/data/local/tmp/cert.der"
#define SIGNATURE_PATH "/data/local/tmp/signature.dat"

using ::android::sp;

namespace android {
namespace hardware {
namespace keymaster {
namespace V3_0 {

class HidlBuf : public hidl_vec<uint8_t> {
    typedef hidl_vec<uint8_t> super;

  public:
    HidlBuf() {}
    HidlBuf(const super& other) : super(other) {}
    HidlBuf(super&& other) : super(std::move(other)) {}
    explicit HidlBuf(const std::string& other) : HidlBuf() { *this = other; }

    HidlBuf& operator=(const super& other) {
        super::operator=(other);
        return *this;
    }

    HidlBuf& operator=(super&& other) {
        super::operator=(std::move(other));
        return *this;
    }

    HidlBuf& operator=(const std::string& other) {
        resize(other.size());
        for (size_t i = 0; i < other.size(); ++i) {
            (*this)[i] = static_cast<uint8_t>(other[i]);
        }
        return *this;
    }

    std::string to_string() const { return std::string(reinterpret_cast<const char*>(data()), size()); }
};

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

class Derived : public Base {
public:
    sp<IKeymasterDevice> keymaster_;
    bool isSecure_, supportsEc_, supportsSymmetric_, supportsAttestation_, supportsAllDigests_;
    hidl_string name_;
    hidl_string author_;
    HidlBuf key_blob_;
    KeyCharacteristics key_characteristics_;
    Derived() {
        if(!keymaster_)
            keymaster_ =  IKeymasterDevice::getService();

        if(!keymaster_) {
            LOGE("Failed to get keymaster device");
            return;
        }

        auto err = keymaster_->getHardwareFeatures([&](bool isSecure, bool supportsEc, bool supportsSymmetric,
                                               bool supportsAttestation, bool supportsAllDigests,
                                               const hidl_string& name, const hidl_string& author) {
                isSecure_ = isSecure;
                name_ = name;
                author_ = author;
                supportsEc_ = supportsEc;
                supportsSymmetric_ = supportsSymmetric;
                supportsAttestation_ = supportsAttestation;
                supportsAllDigests_ = supportsAllDigests;
                });

        if(!err.isOk()) {
            LOGI("Security level = %d", (int)isSecure_);
            LOGI("name = %s", name_.c_str());
            LOGI("author_ = %s", name_.c_str());
        }
        else
            LOGE("Failed to get hardware features. error %s", err.description().c_str());

    }

    ~Derived() {
        if(keymaster_)
            keymaster_.clear();
    }

    ErrorCode GenerateKey(const AuthorizationSet& key_desc, HidlBuf* key_blob,
                          KeyCharacteristics* key_characteristics) {
        EXPECT_NE(key_blob, nullptr);
        EXPECT_NE(key_characteristics, nullptr);
        EXPECT_EQ(0U, key_blob->size());
        ErrorCode error;
        EXPECT_TRUE(keymaster_
                        ->generateKey(key_desc.hidl_data(),
                                      [&](ErrorCode hidl_error, const HidlBuf& hidl_key_blob,
                                          const KeyCharacteristics& hidl_key_characteristics) {
                                          error = hidl_error;
                                          *key_blob = hidl_key_blob;
                                          *key_characteristics = hidl_key_characteristics;
                                      })
                        .isOk());
        // On error, blob & characteristics should be empty.
        if (error != ErrorCode::OK) {
            EXPECT_EQ(0U, key_blob->size());
            EXPECT_EQ(0U, (key_characteristics->softwareEnforced.size() +
                           key_characteristics->teeEnforced.size()));
        }
        return error;
    }

    ErrorCode GenerateKey(const AuthorizationSet& key_desc) {
        return GenerateKey(key_desc, &key_blob_, &key_characteristics_);
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

TEST_F(Derived, KeymasterTest) {
    for (auto key_size : {1024, 2048, 3072, 4096}) {
        HidlBuf key_blob;
        KeyCharacteristics key_characteristics;
        ASSERT_EQ(ErrorCode::OK, GenerateKey(AuthorizationSetBuilder()
                                                 .RsaSigningKey(key_size, 3)
                                                 .Digest(Digest::NONE)
                                                 .Padding(PaddingMode::NONE),
                                                 &key_blob, &key_characteristics));
    }
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}


}}}}
