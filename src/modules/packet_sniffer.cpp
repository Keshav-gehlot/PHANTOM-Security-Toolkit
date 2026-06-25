#include "phantom/modules.h"
#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mstcpip.h>

namespace phantom::modules {
    void run_packet_sniffer() {
        std::cout << "\n=== Packet Sniffer (Raw Socket) ===\n";
        
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return;

        SOCKET sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
        if (sniffer == INVALID_SOCKET) {
            std::cerr << "Failed to create raw socket. You must run this as Administrator!\n";
            WSACleanup();
            return;
        }

        char hostname[128];
        gethostname(hostname, sizeof(hostname));
        struct hostent* local = gethostbyname(hostname);
        
        if (local == nullptr || local->h_addr_list[0] == nullptr) {
            std::cerr << "Cannot resolve local IP.\n";
            closesocket(sniffer);
            WSACleanup();
            return;
        }

        sockaddr_in dest;
        dest.sin_family = AF_INET;
        dest.sin_port = 0;
        dest.sin_addr.s_addr = *(u_long*)local->h_addr_list[0]; // Bind to first local IP

        if (bind(sniffer, (sockaddr*)&dest, sizeof(dest)) == SOCKET_ERROR) {
            std::cerr << "Failed to bind socket. Error: " << WSAGetLastError() << "\n";
            closesocket(sniffer);
            WSACleanup();
            return;
        }

        // Enable promiscuous mode using SIO_RCVALL
        int j = 1;
        DWORD bytesRet = 0;
        if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), nullptr, 0, &bytesRet, nullptr, nullptr) == SOCKET_ERROR) {
            std::cerr << "Failed to set promiscuous mode. (Ensure you are running as Administrator)\n";
            closesocket(sniffer);
            WSACleanup();
            return;
        }

        std::cout << "Sniffing started on " << inet_ntoa(dest.sin_addr) << " ...\n";
        
        char buffer[65536];
        int count = 0;
        while (count < 10) { // Limit to 10 packets for educational purposes
            int data_size = recvfrom(sniffer, buffer, 65536, 0, nullptr, nullptr);
            if (data_size > 0) {
                std::cout << "[Packet " << ++count << "] Size: " << data_size << " bytes\n";
            }
        }
        std::cout << "Sniffed 10 packets successfully.\n";

        closesocket(sniffer);
        WSACleanup();
        std::cout << "===================================\n";
    }
}
