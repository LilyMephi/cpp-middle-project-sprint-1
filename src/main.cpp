#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <algorithm>
#include <array>
#include <iostream>
#include <openssl/evp.h>
#include <stdexcept>
#include <string>
#include <fstream>

int main(int argc, char *argv[]) {
    try { 
        CryptoGuard::ProgramOptions prg_opt;
        prg_opt.Parse(argc, argv);
        //
        // OpenSSL пример использования:
        //
        std::string input = "01234567890123456789";
        std::string output;

        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        auto *ctx = EVP_CIPHER_CTX_new();

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        // Обрабатываем первые N символов
        std::copy(input.begin(), std::next(input.begin(), 16), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Обрабатываем оставшиеся символы
        std::copy(std::next(input.begin(), 16), input.end(), inBuf.begin());
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(input.size() - 16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        EVP_CIPHER_CTX_free(ctx);
        std::cout << "String encoded successfully. Result: " << output << "\n\n";
        
        //
        // Конец примера
        //

        CryptoGuard::ProgramOptions options;

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        options.Parse(argc, argv);
        
        std::fstream input_file(options.GetInputFile().c_str(), std::ios::in);
        if (!input_file.is_open()) {
            std::cerr << "Can't open the input file 4444\n";
            return 1;
        }


        std::fstream output_file(options.GetOutputFile().c_str(), std::ios::out | std::ios::trunc);
        if (!output_file.is_open()) {
            std::cerr << "Can't open the output file\n";
            return 1;
        }
        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT:
            cryptoCtx.EncryptFile(input_file,output_file, options.GetPassword());
            std::cout << "File encoded successfully\n";
            break;

        case COMMAND_TYPE::DECRYPT:
            cryptoCtx.DecryptFile(input_file,output_file, options.GetPassword());
            std::cout << "File decoded successfully\n";
            break;

        case COMMAND_TYPE::CHECKSUM:
            std::cout << "Checksum: \n CHECKSUM_NOT_IMPLEMENTED";
            break;

        default:
            throw std::runtime_error{"Unsupported command"};
        }
    
        input_file.close();
        output_file.close();
        EVP_cleanup();
    
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}