# PHANTOM Security Toolkit

A modular C/C++ offensive/defensive security toolkit built from scratch on Windows using **MinGW-w64**.

## Modules
1. Network Scanner
2. Packet Sniffer
3. Password Tools
4. Vulnerability Scanner
5. Crypto Tools
6. Steganography
7. File Integrity Monitor
8. Keylogger
9. Reverse Shell
10. Forensics / Log Analyzer
11. Wi-Fi Scanner
12. Process Inspector

## Build
```cmd
cmake -B build -S . -GNinja -DCMAKE_TOOLCHAIN_FILE=[path-to-vcpkg]/scripts/buildsystems/vcpkg.cmake
cmake --build build
```
