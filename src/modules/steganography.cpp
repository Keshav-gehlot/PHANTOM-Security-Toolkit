#include "phantom/modules.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

namespace phantom::modules {
    void run_steganography() {
        std::cout << "\n=== Steganography (LSB in BMP) ===\n";
        std::cout << "1. Hide Message\n";
        std::cout << "2. Extract Message\n";
        std::cout << "Select option: ";
        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) {
            std::cout << "Enter source BMP path: ";
            std::string srcPath;
            std::getline(std::cin, srcPath);
            
            std::cout << "Enter message to hide: ";
            std::string msg;
            std::getline(std::cin, msg);
            msg += '\0'; // Null terminator as end marker

            std::ifstream file(srcPath, std::ios::binary);
            if (!file) { std::cerr << "File not found!\n"; return; }
            std::vector<char> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            if (data.size() < 54 + msg.length() * 8) {
                std::cerr << "Image too small to hold message.\n";
                return;
            }

            int dataIdx = 54;
            for (char c : msg) {
                for (int i = 0; i < 8; ++i) {
                    char bit = (c >> i) & 1;
                    data[dataIdx] = (data[dataIdx] & ~1) | bit;
                    dataIdx++;
                }
            }

            std::cout << "Enter output BMP path: ";
            std::string outPath;
            std::getline(std::cin, outPath);

            std::ofstream outFile(outPath, std::ios::binary);
            outFile.write(data.data(), data.size());
            std::cout << "Message hidden successfully!\n";
            
        } else if (choice == 2) {
            std::cout << "Enter BMP path to extract from: ";
            std::string srcPath;
            std::getline(std::cin, srcPath);

            std::ifstream file(srcPath, std::ios::binary);
            if (!file) { std::cerr << "File not found!\n"; return; }
            std::vector<char> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            file.close();

            if (data.size() <= 54) { std::cerr << "Invalid file.\n"; return; }

            std::string msg = "";
            int dataIdx = 54;
            while (dataIdx + 8 <= data.size()) {
                char c = 0;
                for (int i = 0; i < 8; ++i) {
                    char bit = data[dataIdx] & 1;
                    c |= (bit << i);
                    dataIdx++;
                }
                if (c == '\0') break;
                msg += c;
            }

            std::cout << "Extracted Message: " << msg << "\n";
        }
        std::cout << "==================================\n";
    }
}
