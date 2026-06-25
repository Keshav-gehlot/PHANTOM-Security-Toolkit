#include "phantom/modules.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>

namespace phantom::modules {
    void run_file_integrity() {
        std::cout << "\n=== File Integrity Check (SHA-256) ===\n";
        std::cout << "Enter the path of the file to check: ";
        std::string filepath;
        std::getline(std::cin, filepath);

        if (filepath.empty()) return;

        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file: " << filepath << std::endl;
            return;
        }

        EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
        if (mdctx == nullptr) {
            std::cerr << "Error: Could not create EVP_MD_CTX." << std::endl;
            return;
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
            std::cerr << "Error: EVP_DigestInit_ex failed." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return;
        }

        const size_t bufferSize = 8192;
        std::vector<char> buffer(bufferSize);

        while (file.read(buffer.data(), bufferSize)) {
            EVP_DigestUpdate(mdctx, buffer.data(), file.gcount());
        }
        if (file.gcount() > 0) {
            EVP_DigestUpdate(mdctx, buffer.data(), file.gcount());
        }

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
            std::cerr << "Error: EVP_DigestFinal_ex failed." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return;
        }

        EVP_MD_CTX_free(mdctx);

        std::cout << "SHA-256 Hash:\n";
        for (unsigned int i = 0; i < hashLen; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        std::cout << std::dec << "\n======================================\n";
    }
}
