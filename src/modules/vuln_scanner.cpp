// vuln_scanner.cpp — PHANTOM Vulnerability Scanner
// Upgraded with backdoor port list from toolkit ids/rules.c
// Features: threaded port scan, service detection, backdoor port flagging, JSON output
#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <iomanip>
#include <fstream>
#include <cstring>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

namespace phantom::modules {

// ── Backdoor/suspicious ports (from toolkit ids/rules.c) ──────────────────────
static const uint16_t BACKDOOR_PORTS[] = {
    4444, 5555, 6666, 7777, 8888, 9999,    // common reverse shells
    1337, 31337,                            // elite/backdoor
    12345, 27374, 54321,                    // classic trojans
    1234,  2222,  3333,  4321,  5678,      // other common shells
    6000,  6001,  6006,  6660, 6661,       // IRC/botnet
    0
};

// ── Common vulnerable services to check ───────────────────────────────────────
static const uint16_t VULN_PORTS[] = {
    21,   // FTP — anonymous login risk
    22,   // SSH — brute force target
    23,   // Telnet — plaintext creds
    25,   // SMTP — open relay
    53,   // DNS — zone transfer
    80,   // HTTP — web vulns
    110,  // POP3 — plaintext
    135,  // MSRPC — many exploits
    139,  // NetBIOS — SMB
    143,  // IMAP — plaintext
    443,  // HTTPS
    445,  // SMB — EternalBlue
    1433, // MSSQL
    1521, // Oracle DB
    2082, // cPanel HTTP
    2083, // cPanel HTTPS
    3306, // MySQL
    3389, // RDP — BlueKeep
    5432, // PostgreSQL
    5900, // VNC — no auth risk
    6379, // Redis — unauthenticated by default
    8080, // HTTP-alt
    8443, // HTTPS-alt
    27017 // MongoDB — unauthenticated by default
};
static const int N_VULN_PORTS = sizeof(VULN_PORTS) / sizeof(VULN_PORTS[0]);

// ── Service/risk notes for well-known ports ────────────────────────────────────
struct VulnNote { uint16_t port; const char* service; const char* risk; };
static const VulnNote VULN_NOTES[] = {
    {21,    "FTP",        "Anonymous login, cleartext creds"},
    {22,    "SSH",        "Brute-force target, outdated versions exploitable"},
    {23,    "Telnet",     "CRITICAL: Cleartext protocol — sniffable"},
    {25,    "SMTP",       "Open relay possible, spam abuse"},
    {53,    "DNS",        "Zone transfer (AXFR) may expose records"},
    {80,    "HTTP",       "Web application vulnerabilities"},
    {135,   "MSRPC",      "Exploitable (MS03-026, MS04-011)"},
    {139,   "NetBIOS",    "Information disclosure, SMB relay"},
    {143,   "IMAP",       "Cleartext credentials"},
    {445,   "SMB",        "CRITICAL: EternalBlue (MS17-010) target"},
    {1433,  "MSSQL",      "SA brute-force, xp_cmdshell abuse"},
    {3306,  "MySQL",      "Remote root login, data exfil"},
    {3389,  "RDP",        "BlueKeep (CVE-2019-0708), brute-force"},
    {5432,  "PostgreSQL", "Default trust auth, remote access"},
    {5900,  "VNC",        "No-auth VNC exposes desktop"},
    {6379,  "Redis",      "Unauthenticated by default — full RCE risk"},
    {8080,  "HTTP-alt",   "Dev servers, proxy misconfig"},
    {27017, "MongoDB",    "Unauthenticated by default — data theft"},
    {0,     nullptr,      nullptr}
};

struct ScanResult {
    uint16_t    port;
    bool        open;
    bool        backdoor;
    const char* service;
    const char* risk_note;
    char        banner[128];
};

static bool is_backdoor_port(uint16_t p) {
    for (int i = 0; BACKDOOR_PORTS[i]; i++)
        if (BACKDOOR_PORTS[i] == p) return true;
    return false;
}

static const VulnNote* get_vuln_note(uint16_t p) {
    for (int i = 0; VULN_NOTES[i].service; i++)
        if (VULN_NOTES[i].port == p) return &VULN_NOTES[i];
    return nullptr;
}

// Grab banner from open port
static void grab_banner(const std::string& ip, ScanResult& r) {
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) return;

    DWORD tv = 2000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(r.port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(fd); return;
    }
    if (r.port == 80 || r.port == 8080 || r.port == 443) {
        const char* p = "HEAD / HTTP/1.0\r\n\r\n";
        send(fd, p, (int)strlen(p), 0);
    }
    char buf[256] = {};
    recv(fd, buf, sizeof(buf) - 1, 0);
    closesocket(fd);
    if (buf[0]) {
        strncpy_s(r.banner, sizeof(r.banner), buf, _TRUNCATE);
        for (char& c : r.banner) if (c == '\r' || c == '\n') { c = '\0'; break; }
    }
}

// Probe a port: non-blocking connect with select timeout
static bool probe_port(const std::string& ip, uint16_t port, int timeout_ms = 1000) {
    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) return false;

    u_long nb = 1; ioctlsocket(fd, FIONBIO, &nb);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    connect(fd, (sockaddr*)&addr, sizeof(addr));

    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
    timeval tv; tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    bool open = false;
    if (select(0, nullptr, &wfds, nullptr, &tv) > 0) {
        int err = 0, elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
        open = (err == 0);
    }
    closesocket(fd);
    return open;
}

// Save JSON report (from toolkit output.c json style)
static void save_json(const std::string& target,
                      const std::vector<ScanResult>& results,
                      const std::string& path) {
    std::ofstream f(path);
    if (!f) { std::cerr << "  Cannot write JSON to " << path << "\n"; return; }
    f << "{\n  \"target\": \"" << target << "\",\n  \"ports\": [\n";
    bool first = true;
    for (const auto& r : results) {
        if (!r.open) continue;
        if (!first) f << ",\n";
        f << "    {\"port\":" << r.port
          << ",\"service\":\"" << (r.service ? r.service : "unknown") << "\""
          << ",\"backdoor\":" << (r.backdoor ? "true" : "false")
          << ",\"banner\":\"" << r.banner << "\""
          << ",\"risk\":\"" << (r.risk_note ? r.risk_note : "") << "\"}";
        first = false;
    }
    f << "\n  ]\n}\n";
    std::cout << "  JSON report saved to " << path << "\n";
}

void run_vuln_scanner() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed.\n"; return;
    }

    std::cout << "\n\033[1;31m";
    std::cout << "  ╔══════════════════════════════════════╗\n";
    std::cout << "  ║     PHANTOM Vulnerability Scanner    ║\n";
    std::cout << "  ║     Port Audit + Risk Assessment     ║\n";
    std::cout << "  ╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";

    std::cout << "  Target IP: ";
    std::string ip; std::getline(std::cin, ip);
    if (ip.empty()) { WSACleanup(); return; }

    std::cout << "  Save JSON report? (Enter filename or leave blank): ";
    std::string json_file; std::getline(std::cin, json_file);

    std::cout << "\n  \033[1m[*] Scanning " << N_VULN_PORTS
              << " vulnerability-relevant ports on " << ip << "...\033[0m\n\n";

    std::cout << "  \033[1;36m" << std::left
              << std::setw(8)  << "PORT"
              << std::setw(14) << "SERVICE"
              << std::setw(10) << "STATE"
              << std::setw(8)  << "THREAT"
              << "RISK / BANNER\033[0m\n";
    std::cout << "  " << std::string(80, '-') << "\n";

    std::vector<ScanResult> results;
    int open_count = 0;
    int backdoor_count = 0;

    // Threaded scan
    std::vector<bool> port_open(N_VULN_PORTS, false);
    {
        std::vector<std::thread> threads;
        for (int i = 0; i < N_VULN_PORTS; i++) {
            threads.emplace_back([&, i]() {
                port_open[i] = probe_port(ip, VULN_PORTS[i], 1200);
            });
        }
        for (auto& t : threads) t.join();
    }

    for (int i = 0; i < N_VULN_PORTS; i++) {
        uint16_t port = VULN_PORTS[i];
        const VulnNote* note = get_vuln_note(port);
        bool backdoor = is_backdoor_port(port);

        ScanResult r{};
        r.port     = port;
        r.open     = port_open[i];
        r.backdoor = backdoor;
        r.service  = note ? note->service : "unknown";
        r.risk_note = note ? note->risk : "";

        if (r.open) {
            grab_banner(ip, r);
            open_count++;
            if (backdoor) backdoor_count++;

            const char* threat_color = backdoor ? "\033[1;31mHIGH  \033[0m"
                                                : "\033[1;33mMEDIUM\033[0m";
            std::cout << "  \033[1;32m"
                      << std::setw(7)  << port  << "\033[0m  "
                      << std::setw(13) << (note ? note->service : "unknown") << "  "
                      << "\033[1;32mOPEN  \033[0m  "
                      << threat_color  << "  "
                      << (r.banner[0] ? r.banner : (r.risk_note ? r.risk_note : "-"))
                      << "\n";
        }

        results.push_back(r);
    }

    // Check additional backdoor ports
    std::cout << "\n  \033[1m[*] Probing known backdoor ports...\033[0m\n";
    for (int i = 0; BACKDOOR_PORTS[i]; i++) {
        uint16_t port = BACKDOOR_PORTS[i];
        // Skip if already scanned
        bool already = false;
        for (auto& r : results) if (r.port == port) { already = true; break; }
        if (already) continue;

        bool open = probe_port(ip, port, 600);
        if (open) {
            ScanResult r{};
            r.port    = port;
            r.open    = true;
            r.backdoor = true;
            r.service  = "backdoor?";
            r.risk_note = "Known reverse shell / trojan port";
            grab_banner(ip, r);
            backdoor_count++;
            open_count++;
            std::cout << "  \033[1;31m[!!] Backdoor port " << port
                      << " is OPEN — " << r.risk_note << "\033[0m\n";
            results.push_back(r);
        }
    }

    // Summary
    std::cout << "\n  " << std::string(80, '=') << "\n";
    std::cout << "  \033[1mSUMMARY\033[0m\n";
    std::cout << "  Target      : " << ip << "\n";
    std::cout << "  Open ports  : " << open_count << "\n";
    std::cout << "  \033[1;31mBackdoor hits: " << backdoor_count << "\033[0m\n";

    if (open_count == 0) {
        std::cout << "  \033[1;32mNo high-risk ports found.\033[0m\n";
    } else if (backdoor_count > 0) {
        std::cout << "  \033[1;31m[!] CRITICAL — Possible compromise detected!\033[0m\n";
    } else {
        std::cout << "  \033[1;33m[!] Open services found — review above.\033[0m\n";
    }

    if (!json_file.empty()) save_json(ip, results, json_file);

    std::cout << "  " << std::string(80, '=') << "\n";
    WSACleanup();
}

} // namespace phantom::modules
