// network_scanner.cpp — PHANTOM Network Scanner
// Ported from phantom-toolkit connect_scan.c + service_detect.c
// Features: ICMP host discovery, threaded TCP port scan, banner grabbing, service detection
#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <iomanip>
#include <fstream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace phantom::modules {

// ── Port / Service table (from toolkit service_detect.c) ──────────────────────
struct port_name_t { uint16_t port; const char* name; };
static const port_name_t PORT_NAMES[] = {
    {21,  "ftp"},     {22,  "ssh"},      {23,  "telnet"},  {25,  "smtp"},
    {53,  "dns"},     {80,  "http"},     {110, "pop3"},    {143, "imap"},
    {443, "https"},   {445, "smb"},      {3306,"mysql"},   {3389,"rdp"},
    {5432,"pgsql"},   {6379,"redis"},    {8080,"http-alt"},{8443,"https-alt"},
    {27017,"mongodb"},{1433,"mssql"},    {5900,"vnc"},     {631, "ipp"},
    {0,   nullptr}
};

// ── Top-100 ports (from toolkit main.c) ───────────────────────────────────────
static const uint16_t TOP_PORTS[] = {
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,
    1723,3306,3389,5900,8080,8443,8888,
    20,69,79,88,119,123,137,138,161,179,194,389,427,465,514,
    515,543,544,548,554,587,631,636,646,873,990,993,1080,1194,
    1433,1521,2049,2082,2083,2086,2087,2095,2096,3000,3128,
    4444,5000,5432,5555,5601,6379,6443,7001,8000,8008,8081,
    8082,8083,8084,8085,8086,8087,8088,8089,8090,8181,8888,
    9000,9090,9200,9300,9418,27017,27018,27019,28017
};
static const int N_TOP_PORTS = sizeof(TOP_PORTS) / sizeof(TOP_PORTS[0]);

// ── Result structures ──────────────────────────────────────────────────────────
enum PortState { OPEN, CLOSED, FILTERED };

struct PortResult {
    uint16_t  port;
    PortState state;
    char      service[32];
    char      banner[128];
};

static std::mutex g_print_mtx;

// ── Helpers ────────────────────────────────────────────────────────────────────
static const char* port_to_service(uint16_t port) {
    for (int i = 0; PORT_NAMES[i].name; i++)
        if (PORT_NAMES[i].port == port) return PORT_NAMES[i].name;
    return "unknown";
}

// Banner grab + service detection (ported from service_detect.c)
static void detect_service(const char* ip, PortResult& r) {
    strncpy_s(r.service, sizeof(r.service), port_to_service(r.port), _TRUNCATE);
    if (r.state != OPEN) return;

    SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) return;

    DWORD tv = 2000; // 2 second timeout
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(r.port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    if (connect(fd, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(fd);
        return;
    }

    // Send HTTP probe for web ports
    if (r.port == 80 || r.port == 8080 || r.port == 8443 || r.port == 443) {
        const char* probe = "HEAD / HTTP/1.0\r\n\r\n";
        send(fd, probe, (int)strlen(probe), 0);
    }

    char buf[256] = {0};
    recv(fd, buf, sizeof(buf) - 1, 0);
    closesocket(fd);

    if (buf[0]) {
        strncpy_s(r.banner, sizeof(r.banner), buf, _TRUNCATE);
        // Strip newlines
        for (char& c : r.banner) if (c == '\r' || c == '\n') { c = '\0'; break; }

        // Signature matching (from service_detect.c:L65-71)
        if (strstr(buf, "SSH-"))   strncpy_s(r.service, sizeof(r.service), "ssh",      _TRUNCATE);
        if (strstr(buf, "220 "))   strncpy_s(r.service, sizeof(r.service), "ftp/smtp", _TRUNCATE);
        if (strstr(buf, "HTTP/"))  strncpy_s(r.service, sizeof(r.service), "http",     _TRUNCATE);
        if (strstr(buf, "MySQL"))  strncpy_s(r.service, sizeof(r.service), "mysql",    _TRUNCATE);
        if (strstr(buf, "+OK"))    strncpy_s(r.service, sizeof(r.service), "pop3",     _TRUNCATE);
        if (strstr(buf, "* OK"))   strncpy_s(r.service, sizeof(r.service), "imap",     _TRUNCATE);
        if (strstr(buf, "RFB"))    strncpy_s(r.service, sizeof(r.service), "vnc",      _TRUNCATE);
    }
}

// Non-blocking TCP connect scan for a range of ports (ported from connect_scan.c)
static void scan_port_range(const char* ip, const std::vector<uint16_t>& ports,
                             int start, int end, std::vector<PortResult>& results,
                             int timeout_ms) {
    for (int i = start; i < end; i++) {
        uint16_t port = ports[i];
        SOCKET fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == INVALID_SOCKET) continue;

        // Set non-blocking (ioctlsocket = fcntl O_NONBLOCK on Linux)
        u_long mode = 1;
        ioctlsocket(fd, FIONBIO, &mode);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        connect(fd, (sockaddr*)&addr, sizeof(addr));

        // select() with timeout (mirrors connect_scan.c:L44-58)
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        timeval tv;
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        int sel = select(0, nullptr, &wfds, nullptr, &tv);
        if (sel > 0) {
            int err = 0;
            int elen = sizeof(err);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&err, &elen);
            results[i].state = (err == 0) ? OPEN : CLOSED;
        } else if (sel == 0) {
            results[i].state = FILTERED;
        } else {
            results[i].state = CLOSED;
        }

        closesocket(fd);
        results[i].port = port;
    }
}

// ICMP ping sweep using Windows IcmpSendEcho
static std::vector<std::string> icmp_ping_sweep(const std::string& baseIp) {
    std::vector<std::string> live_hosts;
    HANDLE hIcmp = IcmpCreateFile();
    if (hIcmp == INVALID_HANDLE_VALUE) return live_hosts;

    char send_data[32] = "PHANTOM";
    DWORD reply_size = sizeof(ICMP_ECHO_REPLY) + sizeof(send_data) + 8;
    void* reply_buf = malloc(reply_size);
    if (!reply_buf) { IcmpCloseHandle(hIcmp); return live_hosts; }

    std::cout << "  Pinging " << baseIp << "1 - " << baseIp << "254...\n";
    for (int i = 1; i < 255; i++) {
        std::string target = baseIp + std::to_string(i);
        DWORD ip = inet_addr(target.c_str());
        DWORD ret = IcmpSendEcho(hIcmp, ip, send_data, sizeof(send_data),
                                 nullptr, reply_buf, reply_size, 300);
        if (ret > 0) {
            auto* rep = (PICMP_ECHO_REPLY)reply_buf;
            if (rep->Status == IP_SUCCESS) {
                live_hosts.push_back(target);
                std::cout << "  \033[1;32m[+]\033[0m Host up: " << target << "\n";
            }
        }
    }
    free(reply_buf);
    IcmpCloseHandle(hIcmp);
    return live_hosts;
}

// Print results table (ported from output.c)
static void print_results(const std::string& target,
                           const std::vector<uint16_t>& ports,
                           const std::vector<PortResult>& results) {
    int open_count = 0;
    std::cout << "\n\033[1;36m  PORT       STATE      SERVICE          BANNER\033[0m\n";
    std::cout << "  ---------- ---------- ---------------- --------------------------------\n";
    for (int i = 0; i < (int)results.size(); i++) {
        if (results[i].state == CLOSED) continue;
        const char* state_str = results[i].state == OPEN
            ? "\033[1;32mopen    \033[0m"
            : "\033[1;33mfiltered\033[0m";
        std::cout << "  " << std::left << std::setw(5) << results[i].port
                  << "/tcp  " << state_str << "  "
                  << std::setw(16) << results[i].service << "  "
                  << (results[i].banner[0] ? results[i].banner : "-") << "\n";
        if (results[i].state == OPEN) open_count++;
    }
    std::cout << "\n  \033[1m" << open_count << " open port(s) found on " << target << "\033[0m\n";
}

// ── Main entry point ───────────────────────────────────────────────────────────
void run_network_scanner() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed.\n"; return;
    }

    std::cout << "\n\033[1;31m";
    std::cout << "  ╔══════════════════════════════════════╗\n";
    std::cout << "  ║     PHANTOM-SCAN  v2.0               ║\n";
    std::cout << "  ║     Network Scanner & Port Scanner   ║\n";
    std::cout << "  ╚══════════════════════════════════════╝\n";
    std::cout << "\033[0m\n";

    std::cout << "  Modes:\n";
    std::cout << "    1. ICMP Host Discovery (ping sweep)\n";
    std::cout << "    2. TCP Port Scan (single host)\n";
    std::cout << "    3. Full Scan (ping + port scan all live hosts)\n";
    std::cout << "  Select: ";
    int mode; std::cin >> mode; std::cin.ignore();

    if (mode == 1) {
        // ── ICMP Ping Sweep ──────────────────────────────────────
        std::cout << "  Enter subnet base (e.g. 192.168.1.): ";
        std::string base; std::getline(std::cin, base);
        if (base.empty()) { WSACleanup(); return; }

        std::cout << "\n\033[1m  [*] Starting ICMP Ping Sweep...\033[0m\n";
        auto hosts = icmp_ping_sweep(base);
        std::cout << "\n  Found " << hosts.size() << " live host(s).\n";

    } else if (mode == 2 || mode == 3) {
        // ── TCP Port Scan ────────────────────────────────────────
        std::vector<std::string> targets;

        if (mode == 2) {
            std::cout << "  Target IP: ";
            std::string ip; std::getline(std::cin, ip);
            if (ip.empty()) { WSACleanup(); return; }
            targets.push_back(ip);
        } else {
            std::cout << "  Enter subnet base (e.g. 192.168.1.): ";
            std::string base; std::getline(std::cin, base);
            if (base.empty()) { WSACleanup(); return; }
            std::cout << "\n\033[1m  [*] Phase 1 — ICMP Ping Sweep...\033[0m\n";
            targets = icmp_ping_sweep(base);
            if (targets.empty()) {
                std::cout << "  No live hosts found.\n";
                WSACleanup(); return;
            }
        }

        std::cout << "  Custom ports? (Enter range like 1-1024, or press Enter for top-100): ";
        std::string port_spec; std::getline(std::cin, port_spec);

        std::cout << "  Timeout per port (ms, Enter=800): ";
        std::string tout_str; std::getline(std::cin, tout_str);
        int timeout_ms = tout_str.empty() ? 800 : std::stoi(tout_str);

        // Build port list
        std::vector<uint16_t> ports;
        if (port_spec.empty()) {
            ports.assign(TOP_PORTS, TOP_PORTS + N_TOP_PORTS);
        } else {
            // Parse "lo-hi" or "p1,p2,p3"
            char buf[512];
            strncpy_s(buf, sizeof(buf), port_spec.c_str(), _TRUNCATE);
            char* tok = strtok(buf, ",");
            while (tok) {
                char* dash = strchr(tok, '-');
                if (dash) {
                    *dash = '\0';
                    int lo = atoi(tok), hi = atoi(dash + 1);
                    for (int p = lo; p <= hi; p++) ports.push_back((uint16_t)p);
                } else {
                    ports.push_back((uint16_t)atoi(tok));
                }
                tok = strtok(nullptr, ",");
            }
        }

        bool do_banner = false;
        std::cout << "  Grab service banners? (y/n, default=y): ";
        std::string yesno; std::getline(std::cin, yesno);
        do_banner = yesno.empty() || yesno[0] == 'y' || yesno[0] == 'Y';

        // Scan each target
        for (const auto& target : targets) {
            std::cout << "\n\033[1m  [*] Scanning " << target
                      << " — " << ports.size() << " ports, timeout=" << timeout_ms << "ms\033[0m\n";

            std::vector<PortResult> results(ports.size());

            // Split into threads (ported from connect_scan.c threaded design)
            int nthreads = std::min((int)std::thread::hardware_concurrency(), 8);
            if (nthreads < 1) nthreads = 4;
            int chunk = ((int)ports.size() + nthreads - 1) / nthreads;

            std::vector<std::thread> threads;
            for (int t = 0; t < nthreads; t++) {
                int start = t * chunk;
                int end   = std::min(start + chunk, (int)ports.size());
                if (start >= end) break;
                threads.emplace_back(scan_port_range, target.c_str(),
                                     std::cref(ports), start, end,
                                     std::ref(results), timeout_ms);
            }
            for (auto& th : threads) th.join();

            // Banner grab open ports
            if (do_banner) {
                std::cout << "  [*] Grabbing banners from open ports...\n";
                for (auto& r : results)
                    if (r.state == OPEN) detect_service(target.c_str(), r);
            } else {
                for (auto& r : results)
                    strncpy_s(r.service, sizeof(r.service),
                              port_to_service(r.port), _TRUNCATE);
            }

            print_results(target, ports, results);
        }
    }

    std::cout << "\n  \033[1;31m[PHANTOM-SCAN]\033[0m Done.\n";
    WSACleanup();
}

} // namespace phantom::modules
