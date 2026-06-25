#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <random>

namespace phantom::modules {
    void run_password_tools() {
        std::cout << "\n=== Password Tools ===\n";
        std::cout << "1. Generate Password\n";
        std::cout << "2. Password Strength Estimator\n";
        std::cout << "Select option: ";
        int choice;
        std::cin >> choice;
        std::cin.ignore();

        if (choice == 1) {
            std::cout << "Length: ";
            int length;
            std::cin >> length;
            const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
            
            std::string pwd;
            for(int i = 0; i < length; ++i) pwd += charset[dis(gen)];
            std::cout << "Generated: " << pwd << "\n";
        } else if (choice == 2) {
            std::cout << "Enter password: ";
            std::string pwd;
            std::getline(std::cin, pwd);
            int score = 0;
            if (pwd.length() >= 8) score++;
            if (pwd.length() >= 12) score++;
            if (pwd.find_first_of("0123456789") != std::string::npos) score++;
            if (pwd.find_first_of("!@#$%^&*()") != std::string::npos) score++;
            if (pwd.find_first_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ") != std::string::npos) score++;
            
            std::cout << "Strength Score: " << score << "/5\n";
        }
        std::cout << "======================\n";
    }
}
