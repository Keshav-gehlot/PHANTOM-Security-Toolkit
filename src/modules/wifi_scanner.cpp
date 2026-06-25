#include "phantom/modules.h"
#include <iostream>
#include <windows.h>
#include <wlanapi.h>

#pragma comment(lib, "wlanapi.lib")

namespace phantom::modules {
    void run_wifi_scanner() {
        std::cout << "\n=== Wi-Fi Scanner ===\n";
        
        HANDLE hClient = NULL;
        DWORD dwMaxClient = 2;
        DWORD dwCurVersion = 0;
        DWORD dwResult = 0;
        
        dwResult = WlanOpenHandle(dwMaxClient, NULL, &dwCurVersion, &hClient);
        if (dwResult != ERROR_SUCCESS) {
            std::cerr << "WlanOpenHandle failed with error: " << dwResult << "\n";
            return;
        }
        
        PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
        dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
        if (dwResult != ERROR_SUCCESS) {
            std::cerr << "WlanEnumInterfaces failed.\n";
            WlanCloseHandle(hClient, NULL);
            return;
        }

        for (int i = 0; i < (int) pIfList->dwNumberOfItems; i++) {
            PWLAN_INTERFACE_INFO pIfInfo = (WLAN_INTERFACE_INFO *) &pIfList->InterfaceInfo[i];
            
            PWLAN_AVAILABLE_NETWORK_LIST pBssList = NULL;
            dwResult = WlanGetAvailableNetworkList(hClient, &pIfInfo->InterfaceGuid, 0, NULL, &pBssList);
            
            if (dwResult == ERROR_SUCCESS) {
                std::cout << "Found " << pBssList->dwNumberOfItems << " networks on interface " << i << ":\n";
                for (int j = 0; j < (int) pBssList->dwNumberOfItems; j++) {
                    PWLAN_AVAILABLE_NETWORK pNetwork = (WLAN_AVAILABLE_NETWORK *) &pBssList->Network[j];
                    std::cout << "  SSID: ";
                    if (pNetwork->dot11Ssid.uSSIDLength > 0) {
                        for (int k = 0; k < pNetwork->dot11Ssid.uSSIDLength; k++) {
                            std::cout << pNetwork->dot11Ssid.ucSSID[k];
                        }
                    } else {
                        std::cout << "<Hidden>";
                    }
                    std::cout << " | Signal: " << pNetwork->wlanSignalQuality << "%\n";
                }
                WlanFreeMemory(pBssList);
            }
        }
        
        if (pIfList != NULL) {
            WlanFreeMemory(pIfList);
        }
        WlanCloseHandle(hClient, NULL);
        std::cout << "=====================\n";
    }
}
