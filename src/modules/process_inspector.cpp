#include "phantom/modules.h"
#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <iomanip>

namespace phantom::modules {
    void run_process_inspector() {
        std::cout << "\n=== Process Inspector ===\n";
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to take process snapshot." << std::endl;
            return;
        }

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (!Process32First(hProcessSnap, &pe32)) {
            std::cerr << "Failed to read first process." << std::endl;
            CloseHandle(hProcessSnap);
            return;
        }

        std::cout << std::left << std::setw(8) << "PID" 
                  << std::setw(8) << "PPID" 
                  << std::setw(12) << "Threads"
                  << "Executable Name" << std::endl;
        std::cout << std::string(50, '-') << std::endl;

        do {
            std::cout << std::left << std::setw(8) << pe32.th32ProcessID
                      << std::setw(8) << pe32.th32ParentProcessID
                      << std::setw(12) << pe32.cntThreads
                      << pe32.szExeFile << std::endl;
        } while (Process32Next(hProcessSnap, &pe32));

        CloseHandle(hProcessSnap);
        std::cout << "=========================\n";
    }
}
