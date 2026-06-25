#include "phantom/modules.h"
#include <iostream>
#include <windows.h>
#include <string>

namespace phantom::modules {

    void printFileTime(const char* label, FILETIME ft) {
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&ft, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
        
        printf("%s: %02d/%02d/%d  %02d:%02d:%02d\n", label,
               stLocal.wDay, stLocal.wMonth, stLocal.wYear,
               stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    }

    void run_forensics() {
        std::cout << "\n=== Forensics (File Metadata) ===\n";
        std::cout << "Enter the path of the file to inspect: ";
        std::string filepath;
        std::getline(std::cin, filepath);

        if (filepath.empty()) return;

        WIN32_FILE_ATTRIBUTE_DATA fileInfo;
        if (GetFileAttributesExA(filepath.c_str(), GetFileExInfoStandard, &fileInfo)) {
            std::cout << "\nMetadata for: " << filepath << "\n";
            std::cout << "Attributes: 0x" << std::hex << fileInfo.dwFileAttributes << std::dec << "\n";
            
            printFileTime("Creation Time   ", fileInfo.ftCreationTime);
            printFileTime("Last Access Time", fileInfo.ftLastAccessTime);
            printFileTime("Last Write Time ", fileInfo.ftLastWriteTime);

            ULARGE_INTEGER fileSize;
            fileSize.HighPart = fileInfo.nFileSizeHigh;
            fileSize.LowPart = fileInfo.nFileSizeLow;
            std::cout << "File Size: " << fileSize.QuadPart << " bytes\n";
        } else {
            std::cerr << "Error: Could not retrieve attributes for file. Code: " << GetLastError() << std::endl;
        }
        std::cout << "=================================\n";
    }
}
