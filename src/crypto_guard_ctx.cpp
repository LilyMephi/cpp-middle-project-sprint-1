#include "crypto_guard_ctx.h"

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    Impl() {
        OpenSSL_add_all_algorithms();
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_)
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    EVP_CIPHER_CTX *GetCtx() { return ctx_; }
    void CreateChiperParamsFromPassword(std::string_view password) {
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return;
    }
    void setEncrypt(int encrypt) { params.encrypt = encrypt; }
    const AesCipherParams &getParams() { return params; }

    ~Impl() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
            ctx_ = nullptr;
        }
        EVP_cleanup();
    }

private:
    EVP_CIPHER_CTX *ctx_;
    AesCipherParams params;
};

std::string CryptoGuardCtx::get_openssl_error() const {
    std::stringstream ss;
    unsigned long error_code;
    char error_buf[256];

    while ((error_code = ERR_get_error()) != 0) {
        ERR_error_string_n(error_code, error_buf, sizeof(error_buf));
        ss << error_buf << "\n";
    }

    return ss.str();
}
CryptoGuardCtx::CryptoGuardCtx() {}
CryptoGuardCtx::~CryptoGuardCtx() {}

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream || !outStream || password.empty()) {
        throw std::runtime_error{"Wrong input parametrs"};
    }

    pImpl_ = std::make_unique<Impl>();
    pImpl_->CreateChiperParamsFromPassword(password);
    pImpl_->setEncrypt(1);
    if (!EVP_CipherInit_ex(pImpl_->GetCtx(), pImpl_->getParams().cipher, nullptr, pImpl_->getParams().key.data(),
                           pImpl_->getParams().iv.data(), pImpl_->getParams().encrypt)) {
        throw std::runtime_error{"Error: cipher init failed: " + get_openssl_error() + "\n"};
        return;
    }

    const size_t buffer_size = 16;
    std::vector<unsigned char> outBuf(buffer_size + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(buffer_size);
    int outLen;

    while (true) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        std::streamsize inLen = inStream.gcount();
        if (inLen <= 0)
            break;

        if (!EVP_CipherUpdate(pImpl_->GetCtx(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inLen))) {
            throw std::runtime_error{"Error: cipher update failed: " + get_openssl_error() + "\n"};
            return;
        }
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
    }

    if (!EVP_CipherFinal_ex(pImpl_->GetCtx(), outBuf.data(), &outLen)) {
        throw std::runtime_error{"Error: cipher final failed: " + get_openssl_error() + "\n"};
        return;
    }
    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    if (!inStream || !outStream || password.empty()) {
        throw std::runtime_error{"Wrong input parametrs"};
    }

    pImpl_ = std::make_unique<Impl>();
    pImpl_->CreateChiperParamsFromPassword(password);
    pImpl_->setEncrypt(0);
    if (!EVP_CipherInit_ex(pImpl_->GetCtx(), pImpl_->getParams().cipher, nullptr, pImpl_->getParams().key.data(),
                           pImpl_->getParams().iv.data(), pImpl_->getParams().encrypt)) {
        throw std::runtime_error{"Error: cipher init failed: " + get_openssl_error() + "\n"};
        return;
    }

    const size_t buffer_size = 1024;
    std::vector<unsigned char> outBuf(buffer_size + EVP_MAX_BLOCK_LENGTH);
    std::vector<unsigned char> inBuf(buffer_size);
    int outLen;

    while (true) {
        inStream.read(reinterpret_cast<char *>(inBuf.data()), inBuf.size());
        std::streamsize inLen = inStream.gcount();
        if (inLen <= 0)
            break;

        if (!EVP_CipherUpdate(pImpl_->GetCtx(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(inLen))) {
            throw std::runtime_error{"Error: cipher update failed: " + get_openssl_error() + "\n"};
            return;
        }
        outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
    }

    if (!EVP_CipherFinal_ex(pImpl_->GetCtx(), outBuf.data(), &outLen)) {
        throw std::runtime_error{"Error: cipher final failed: " + get_openssl_error() + "\n"};
        return;
    }
    outStream.write(reinterpret_cast<const char *>(outBuf.data()), outLen);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
    if (!inStream) {
        throw std::runtime_error{"Wrong input stream"};
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        throw std::runtime_error{"Error: EVP_MD_CTX_new failed"};
    }

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error{"Error: EVP_DigestInit_ex failed"};
    }

    std::vector<unsigned char> buffer(4096);
    while (true) {
        inStream.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        std::streamsize bytesRead = inStream.gcount();

        if (bytesRead <= 0)
            break;

        if (EVP_DigestUpdate(mdctx, buffer.data(), bytesRead) != 1) {
            EVP_MD_CTX_free(mdctx);
            throw std::runtime_error{"Error: EVP_DigestUpdate failed"};
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error{"Error: EVP_DigestFinal_ex failed"};
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < hashLen; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return ss.str();
}
}  // namespace CryptoGuard
