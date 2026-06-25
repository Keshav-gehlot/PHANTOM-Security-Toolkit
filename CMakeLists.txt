cmake_minimum_required(VERSION 3.20)
project(PHANTOM VERSION 2.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Dependencies
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# All module sources
set(SOURCES
    src/main.cpp
    src/ui/menu.cpp
    src/ui/gui_dashboard.cpp
    src/core/logger.cpp
    src/core/utils.cpp
    # Network
    src/modules/network_scanner.cpp
    src/modules/packet_sniffer.cpp
    src/modules/vuln_scanner.cpp
    src/modules/wifi_scanner.cpp
    # System & Forensics
    src/modules/process_inspector.cpp
    src/modules/file_integrity.cpp
    src/modules/forensics.cpp
    src/modules/pe_analyzer.cpp
    # Crypto & Steganography
    src/modules/crypto_tools.cpp
    src/modules/password_tools.cpp
    src/modules/steganography.cpp
    # Educational Payloads
    src/modules/keylogger.cpp
    src/modules/reverse_shell.cpp
)

add_executable(phantom ${SOURCES})

# Link libraries
target_link_libraries(phantom PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ws2_32       # WinSock2  — network_scanner, vuln_scanner, packet_sniffer, reverse_shell
    iphlpapi     # IP Helper — network_scanner (ICMP)
    wlanapi      # WLAN API  — wifi_scanner
    comctl32     # Common Controls (modern Win32 styling)
    dwmapi       # DWM (for Immersive Dark Mode window frame)
)
