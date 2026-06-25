# PHANTOM Security Toolkit

A suite of 8 security tools written in C/C++, organized as a portfolio-grade project.

---

## Tools

| Tool | Binary | Language | Root? |
|------|--------|----------|-------|
| IDS | `phantom-ids` | C99 | Yes |
| Packet Sniffer | `phantom-sniffer` | C99 | Yes |
| HTTP Server | `phantom-httpd` | C11 | No |
| Port Scanner | `phantom-scan` | C99 | Yes (SYN) |
| DNS Resolver | `phantom-dns` | C99 | No |
| BOF Study | `vuln / defended / exploit_demo` | C11 | No |
| ARP Monitor | `phantom-arp` | C99 | Yes |
| PE/ELF Analyzer | `phantom-analyzer` | C++17 | No |

---

## Build

```bash
# All tools at once
make all

# Single tool
make ids
make sniffer
make httpd
make port-scanner
make dns-resolver
make bof-study
make arp-monitor
make pe-elf-analyzer

# Clean
make clean
```

### Dependencies

```bash
# Ubuntu / Debian
sudo apt install build-essential gcc g++ libpcap-dev

# Fedora / RHEL
sudo dnf install gcc gcc-c++ libpcap-devel
```

---

## Usage

### 1. IDS — Intrusion Detection System
```bash
sudo ./ids/phantom-ids -i eth0 -t 10 -l alerts.log
```
- Detects port scans, ICMP floods, suspicious ports
- Alerts to terminal (color-coded) + log file

### 2. Packet Sniffer
```bash
sudo ./sniffer/phantom-sniffer -i eth0 --proto tcp --port 80 --payload
sudo ./sniffer/phantom-sniffer -i eth0 --hex --proto udp
```

### 3. HTTP Server
```bash
./httpd/phantom-httpd --port 8080 --root ./www --log access.log
curl http://localhost:8080/health   # built-in health endpoint
```

### 4. Port Scanner
```bash
# Connect scan (no root needed)
./port-scanner/phantom-scan 192.168.1.1 -p 1-1024 -sV

# SYN stealth scan (root required)
sudo ./port-scanner/phantom-scan 192.168.1.1 -sS --top-ports 100 --oJ out.json
```

### 5. DNS Resolver
```bash
./dns-resolver/phantom-dns example.com
./dns-resolver/phantom-dns example.com MX --server 1.1.1.1
./dns-resolver/phantom-dns example.com --recursive --trace
./dns-resolver/phantom-dns --ptr 8.8.8.8
./dns-resolver/phantom-dns example.com --json
```

### 6. Buffer Overflow Study
```bash
cd bof-study && make

# See vulnerable vs defended side by side
./exploit_demo          # visualise payload anatomy
./vuln                  # deliberately vulnerable
./defended $(python3 -c "print('A'*200)")  # triggers canary abort

# Disable ASLR for full demo (root required)
make disable-aslr
```

### 7. ARP Monitor / Spoofer
```bash
# Monitor mode — detect ARP spoofing on your network
sudo ./arp-monitor/phantom-arp --mode monitor -i eth0 -v

# Spoof mode — educational MITM demo (authorized networks ONLY)
sudo ./arp-monitor/phantom-arp --mode spoof -i eth0 \
     --target 192.168.1.100 --gateway 192.168.1.1
```

### 8. PE/ELF Analyzer
```bash
# Analyze any binary
./pe-elf-analyzer/phantom-analyzer /bin/ls
./pe-elf-analyzer/phantom-analyzer malware.exe
./pe-elf-analyzer/phantom-analyzer malware.exe --json
./pe-elf-analyzer/phantom-analyzer /bin/bash --strings-only
./pe-elf-analyzer/phantom-analyzer /bin/bash --sections-only
```

---

## Architecture

Each tool follows Google C/C++ Style Guide conventions:
- Modular source: `src/` per concern
- Shared types in `include/`
- No external dependencies except `libpcap` (sniffer only) and `pthreads`
- RAII in C++ tools, no malloc/free — `std::vector`/`std::ifstream`
- Graceful SIGINT handling in all tools

---

## Disclaimer

These tools are for **educational and authorized testing only**.
- IDS, sniffer, port scanner: use only on networks you own or have permission to test
- ARP spoofer: illegal to use on networks without explicit written permission
- BOF study: `vuln` is intentionally vulnerable — do not expose it

---

*PHANTOM Security Toolkit — SRMIST NWC Department*
