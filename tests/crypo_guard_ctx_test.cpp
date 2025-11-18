#include "crypto_guard_ctx.h"
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>

void Encrypt(const std::string &input, std::string &output, const std::string &password) {
    auto *ctx = EVP_CIPHER_CTX_new();
    try {
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 1;

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;  // Обрабатываем первые N символов
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }  // Обрабатываем оставшиеся символы
        std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }  // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    EVP_CIPHER_CTX_free(ctx);
    // std::cout << "String encoded successfully. Result: " << output << "\n\n";
}

void Decrypt(const std::string &input, std::string &output, const std::string &password) {
    auto *ctx = EVP_CIPHER_CTX_new();
    try {
        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = 0;

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);
        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;  // Обрабатываем первые N символов
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }  // Обрабатываем оставшиеся символы
        std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }  // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    EVP_CIPHER_CTX_free(ctx);
    // std::cout << "String encoded successfully. Result: " << output << "\n\n";
}

// Empty input stream
TEST(CryptoGuardCtxTest, EmptyStream) {
    std::stringstream emptyStream;
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    // cryptoCtx.DecryptFile(emptyStream, outStream, "secret");

    EXPECT_THROW(cryptoCtx.DecryptFile(emptyStream, outStream, "secret"), std::exception);
}

TEST(CryptoGuardCtxTest, EmptyPassword) {
    std::stringstream emptyStream;
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    // cryptoCtx.DecryptFile(emptyStream, outStream, "");

    EXPECT_THROW(cryptoCtx.DecryptFile(emptyStream, outStream, ""), std::runtime_error);
}

// decrypt sing the written function and comparison with the original
TEST(CryptoGuardCtxTest, Decryption) {
    std::string data = "fhdkwplxobvqntserjuczaymwgkilbop";
    std::string encrypted_data;
    std::string password = "9876543";

    Encrypt(data, encrypted_data, password);

    std::stringstream inStream(encrypted_data);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    cryptoCtx.DecryptFile(inStream, outStream, password);

    std::string decrypted = outStream.str();
    EXPECT_FALSE(decrypted.empty());

    decrypted.erase(std::find(decrypted.begin(), decrypted.end(), '\0'), decrypted.end());
    EXPECT_EQ(decrypted, data);
}

// encrypt using the written function and comparison with the original
TEST(CryptoGuardCtxTest, Encryption) {
    std::string data = "a8#Tp9!XqZ3@bW7^sDdL2&VmYr5*Cf0";
    std::string encrypted_data;
    std::string password = "47291538";

    std::stringstream inStream(data);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;
    cryptoCtx.EncryptFile(inStream, outStream, password);

    std::string encrypted = outStream.str();
    EXPECT_FALSE(encrypted.empty());

    // encrypted.erase(std::find(encrypted.begin(), encrypted.end(), '\0'), encrypted.end());
    std::string decrypted;
    Decrypt(encrypted, decrypted, password);

    EXPECT_EQ(decrypted, data);
}

// encrypt and decrypt using the written function
TEST(CryptoGuardCtxTest, EncryptionDecryption) {
    std::string input_file = "input_data.txt";
    std::string data = "a8#Tp9!XqZ3@bW7^sDdL2&VmYr5*Cf0";
    std::fstream input_data(input_file.c_str(), std::ios::out | std::ios::trunc);
    input_data.write(data.c_str(), data.size());
    input_data.close();

    std::string encrypted_data;
    std::string password = "47291538";
    CryptoGuard::CryptoGuardCtx cryptoCtx;

    std::fstream inStream(input_file, std::ios::in);
    std::stringstream outStream;

    cryptoCtx.EncryptFile(inStream, outStream, password);
    std::stringstream decryptStream;

    cryptoCtx.DecryptFile(outStream, decryptStream, password);
    std::string encrypted = decryptStream.str();

    EXPECT_FALSE(encrypted.empty());

    // encrypted.erase(std::find(encrypted.begin(), encrypted.end(), '\0'), encrypted.end());

    EXPECT_EQ(encrypted, data);
}

// very very long password
TEST(CryptoGuardCtxTest, VeryLongPassword) {
    std::string data = "important data";
    std::string very_long_password(1000, 'a');

    std::stringstream inStream(data);
    std::stringstream outStream;

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    cryptoCtx.EncryptFile(inStream, outStream, very_long_password);
    std::string encrypted = outStream.str();
    EXPECT_FALSE(encrypted.empty());

    std::stringstream encryptedStream(encrypted);
    std::stringstream decryptedStream;
    cryptoCtx.DecryptFile(encryptedStream, decryptedStream, very_long_password);

    std::string decrypted = decryptedStream.str();
    decrypted.erase(std::find(decrypted.begin(), decrypted.end(), '\0'), decrypted.end());

    EXPECT_EQ(decrypted, data);
}

// check whether the result is saved with multiple repetitions
TEST(CryptoGuardCtxTest, ManyCryption) {
    std::string original_data = "original data";
    std::string password = "password";

    std::string current_data = original_data;

    CryptoGuard::CryptoGuardCtx cryptoCtx;

    for (int i = 0; i < 5; ++i) {
        std::stringstream inStream(current_data);
        std::stringstream encryptedStream;

        cryptoCtx.EncryptFile(inStream, encryptedStream, password);
        std::string encrypted = encryptedStream.str();

        std::stringstream encryptedInStream(encrypted);
        std::stringstream decryptedStream;

        cryptoCtx.DecryptFile(encryptedInStream, decryptedStream, password);
        std::string decrypted = decryptedStream.str();
        decrypted.erase(std::find(decrypted.begin(), decrypted.end(), '\0'), decrypted.end());

        EXPECT_EQ(decrypted, original_data);
        current_data = decrypted;
    }
}