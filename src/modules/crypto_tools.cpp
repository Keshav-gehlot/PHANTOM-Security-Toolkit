#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <iomanip>
#include <openssl/evp.h>

namespace phantom::modules {
    void printHash(const std::string& input, const EVP_MD* algo) {
        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, algo, nullptr);
        EVP_DigestUpdate(mdctx, input.c_str(), input.length());
        
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        EVP_DigestFinal_ex(mdctx, hash, &hashLen);
        EVP_MD_CTX_free(mdctx);

        for (unsigned int i = 0; i < hashLen; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        std::cout << std::dec << "\n";
    }

    void run_crypto_tools() {
        std::cout << "\n=== Crypto Tools ===\n";
        std::cout << "Enter text to hash: ";
        std::string input;
        std::getline(std::cin, input);
        
        if (input.empty()) return;

        std::cout << "MD5:    "; printHash(input, EVP_md5());
        std::cout << "SHA256: "; printHash(input, EVP_sha256());
        std::cout << "SHA512: "; printHash(input, EVP_sha512());
        
        std::cout << "====================\n";
    }
}
