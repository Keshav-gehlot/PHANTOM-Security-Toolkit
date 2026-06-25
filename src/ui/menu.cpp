// menu.cpp — PHANTOM Security Toolkit Main Menu
// Full interactive CLI dispatcher for all 13 modules
#include "phantom/ui.h"
#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <windows.h>

namespace phantom::ui {

    // Enable ANSI colors on Windows 10+
    static void enable_ansi() {
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD mode = 0;
        GetConsoleMode(h, &mode);
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        
        // Set Windows Console Code Page to UTF-8 (65001) to render Unicode characters correctly
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
    }

    void init_menu() {
        enable_ansi();
    }

    static void print_banner() {
        std::cout << "\033[1;31m";
        std::cout << R"(
  ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
  ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
)" << "\033[0m";
        std::cout << "\033[1;36m";
        std::cout << "       Security Toolkit v2.0 — Educational / Authorized Testing Only\n";
        std::cout << "\033[0m\n";
    }

    static void print_menu() {
        std::cout << "\033[1;33m  ╔══════════════════════════════════════════════════╗\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1mNETWORK\033[0m                                       \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[1]\033[0m Network Scanner  (Ping + Port + Banners)  \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[2]\033[0m Packet Sniffer   (Raw socket capture)     \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[3]\033[0m Vulnerability Scanner (Port risk audit)   \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[4]\033[0m Wi-Fi Scanner    (Available networks)     \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1mSYSTEM & FORENSICS\033[0m                           \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[5]\033[0m Process Inspector (Running processes)     \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[6]\033[0m File Integrity    (SHA-256 hash verify)   \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[7]\033[0m Forensics         (File metadata)         \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[8]\033[0m PE Analyzer       (Static binary analysis)\033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1mCRYPTO & STEGANOGRAPHY\033[0m                       \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[9]\033[0m Crypto Tools      (Hash: MD5/SHA256/512)   \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[10]\033[0m Password Tools   (Generate + Strength)    \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;32m[11]\033[0m Steganography    (LSB hide/extract BMP)   \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1mEDUCATIONAL PAYLOADS\033[0m  \033[1;31m[Authorized use ONLY]\033[0m  \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;31m[12]\033[0m Keylogger        (WH_KEYBOARD_LL hook)    \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;31m[13]\033[0m Reverse Shell    (TCP cmd.exe relay)      \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╠══════════════════════════════════════════════════╣\033[0m\n";
        std::cout << "\033[1;33m  ║\033[0m  \033[1;36m[0]\033[0m Exit                                       \033[1;33m║\033[0m\n";
        std::cout << "\033[1;33m  ╚══════════════════════════════════════════════════╝\033[0m\n";
        std::cout << "\n  \033[1mSelect module\033[0m [0-13]: ";
    }

    void render_menu() {
        // Not used in new flow — kept for API compat
    }

    void cleanup_menu() {
        // Nothing needed without ncurses
    }

} // namespace phantom::ui

// ── Override phantom::run() from utils.cpp ─────────────────────────────────
namespace phantom {
    void run() {
        phantom::ui::print_banner();
        while (true) {
            phantom::ui::print_menu();
            std::string line;
            std::getline(std::cin, line);
            if (line.empty()) continue;
            int choice = std::stoi(line);

            std::cout << "\n";
            switch (choice) {
                case 0:
                    std::cout << "  \033[1;36mExiting PHANTOM. Stay ethical.\033[0m\n\n";
                    return;
                // Network
                case 1:  phantom::modules::run_network_scanner();  break;
                case 2:  phantom::modules::run_packet_sniffer();   break;
                case 3:  phantom::modules::run_vuln_scanner();     break;
                case 4:  phantom::modules::run_wifi_scanner();     break;
                // System & Forensics
                case 5:  phantom::modules::run_process_inspector(); break;
                case 6:  phantom::modules::run_file_integrity();    break;
                case 7:  phantom::modules::run_forensics();         break;
                case 8:  phantom::modules::run_pe_analyzer();       break;
                // Crypto & Stego
                case 9:  phantom::modules::run_crypto_tools();     break;
                case 10: phantom::modules::run_password_tools();   break;
                case 11: phantom::modules::run_steganography();    break;
                // Educational Payloads
                case 12: phantom::modules::run_keylogger();        break;
                case 13: phantom::modules::run_reverse_shell();    break;
                default:
                    std::cout << "  \033[1;31mInvalid choice.\033[0m\n";
            }

            std::cout << "\n  \033[2mPress Enter to return to menu...\033[0m";
            std::getline(std::cin, line);
            std::cout << "\n";
        }
    }
}
