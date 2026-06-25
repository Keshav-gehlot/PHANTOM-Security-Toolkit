#pragma once

namespace phantom::modules {
    // Network
    void run_network_scanner();
    void run_packet_sniffer();
    void run_vuln_scanner();
    void run_wifi_scanner();

    // System & Forensics
    void run_process_inspector();
    void run_file_integrity();
    void run_forensics();
    void run_pe_analyzer();       // NEW — PE/ELF static analyzer

    // Crypto & Steganography
    void run_crypto_tools();
    void run_password_tools();
    void run_steganography();

    // Educational Payloads
    void run_keylogger();
    void run_reverse_shell();
}
