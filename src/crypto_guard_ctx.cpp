#include "crypto_guard_ctx.h"

namespace CryptoGuard {

class CryptoGuardCtx::Impl {
public:
    Impl() {
        ctx_ = EVP_CIPHER_CTX_new();
        if (!ctx_)
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    EVP_CIPHER_CTX *GetCtx() { return ctx_; }

    ~Impl() {
        if (ctx_) {
            EVP_CIPHER_CTX_free(ctx_);
            ctx_ = nullptr;
        }
    }

private:
    EVP_CIPHER_CTX *ctx_;
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

    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = 1;

    pImpl_ = std::make_unique<Impl>();
    if (!EVP_CipherInit_ex(pImpl_->GetCtx(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                           params.encrypt)) {
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

    AesCipherParams params = CreateChiperParamsFromPassword(password);
    params.encrypt = 0;

    pImpl_ = std::make_unique<Impl>();
    if (!EVP_CipherInit_ex(pImpl_->GetCtx(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                           params.encrypt)) {
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
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        throw std::runtime_error{"Error: SHA256 init failed"};
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    std::vector<unsigned char> buffer(4096);

    while (true) {
        inStream.read(reinterpret_cast<char *>(buffer.data()), buffer.size());
        std::streamsize bufferLen = inStream.gcount();

        if (bufferLen <= 0)
            break;

        if (!SHA256_Update(&sha256, buffer.data(), bufferLen)) {
            throw std::runtime_error{"Error: SHA256 update failed"};
        }

        if (!SHA256_Final(hash, &sha256)) {
            throw std::runtime_error{"Error: SHA256 final failed"};
        }
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0');

    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return ss.str();
}
}  // namespace CryptoGuard
