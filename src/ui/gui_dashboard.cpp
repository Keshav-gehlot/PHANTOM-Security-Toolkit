#include "phantom/ui.h"
#include "phantom/modules.h"
#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <thread>
#include <iostream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' \
version='6.0.0.0' \
processorArchitecture='*' \
publicKeyToken='6595b64144ccf1df' \
language='*'\"")

// Global hooks and handles
namespace phantom::modules {
    extern HHOOK kbdHook;
}

namespace phantom::ui {
    HWND g_hwndMain = nullptr;
}

namespace {
    using namespace phantom::ui;

    int g_activeTab = 0;
    HFONT g_hFontNormal = nullptr;
    HFONT g_hFontMonospace = nullptr;
    HFONT g_hFontTitle = nullptr;
    HFONT g_hFontHeader = nullptr;
    
    HBRUSH g_hBgBrush = nullptr;
    HBRUSH g_hSidebarBrush = nullptr;
    HBRUSH g_hHeaderBrush = nullptr;
    HBRUSH g_hFieldBrush = nullptr;
    HBRUSH g_hListBoxBrush = nullptr;
    HBRUSH g_hGroupBrush = nullptr;
    
    std::vector<HWND> g_tabControls[7];
    bool g_isRunningTask = false;

    // Control IDs
    enum {
        IDC_TAB_START = 100,
        IDC_TAB_OVERVIEW = 100,
        IDC_TAB_NETSCAN,
        IDC_TAB_VULNSCAN,
        IDC_TAB_PROC,
        IDC_TAB_PE,
        IDC_TAB_CRYPTO,
        IDC_TAB_ADVANCED,
        IDC_TAB_END = IDC_TAB_ADVANCED,
        
        IDC_BTN_RUN_NETSCAN = 200,
        IDC_NETSCAN_LIST,
        IDC_NETSCAN_IP,
        IDC_NETSCAN_PORTS,
        IDC_NETSCAN_RADIO_TCP,
        IDC_NETSCAN_RADIO_PING,
        
        IDC_BTN_RUN_VULNSCAN = 300,
        IDC_VULNSCAN_LIST,
        IDC_VULNSCAN_IP,
        
        IDC_BTN_REFRESH_PROCESSES = 400,
        IDC_PROCESS_LIST,
        
        IDC_PE_PATH = 500,
        IDC_BTN_BROWSE_PE,
        IDC_BTN_RUN_PEANALYZE,
        IDC_PE_OUTPUT,
        
        IDC_HASH_INPUT = 600,
        IDC_HASH_ALGO,
        IDC_BTN_HASH,
        IDC_HASH_OUTPUT,
        IDC_PASS_LENGTH,
        IDC_CHK_UPPER,
        IDC_CHK_DIGITS,
        IDC_CHK_SPECIAL,
        IDC_BTN_GENPASS,
        IDC_PASS_OUTPUT,
        IDC_PASS_STRENGTH,
        
        IDC_BTN_START_KEYLOGGER = 700,
        IDC_BTN_STOP_KEYLOGGER,
        IDC_KEYLOGGER_LIST,
        IDC_REV_HOST,
        IDC_REV_PORT,
        IDC_BTN_LAUNCH_REVSHELL,
        IDC_REVSHELL_STATUS
    };
    
    // Custom window messages
    #define WM_USER_LOG_LINE (WM_USER + 100)
    #define WM_USER_SCAN_DONE (WM_USER + 101)
    #define WM_USER_KEY_LOGGED (WM_USER + 102)

    // Stream buffer to capture std::cout and post to GUI ListBox
    class GuiStreamBuf : public std::streambuf {
    public:
        GuiStreamBuf(HWND hList) : m_hList(hList) {}
    protected:
        virtual int_type overflow(int_type ch) override {
            if (ch == '\n') {
                post_line();
            } else if (ch != EOF && ch != '\r') {
                m_currentLine += (char)ch;
            }
            return ch;
        }
        
        virtual int sync() override {
            post_line();
            return 0;
        }
        
        void post_line() {
            if (!m_currentLine.empty()) {
                std::string clean = strip_ansi(m_currentLine);
                if (!clean.empty()) {
                    int len = MultiByteToWideChar(CP_UTF8, 0, clean.c_str(), -1, nullptr, 0);
                    if (len > 0) {
                        wchar_t* wstr = new wchar_t[len];
                        MultiByteToWideChar(CP_UTF8, 0, clean.c_str(), -1, wstr, len);
                        PostMessageW(g_hwndMain, WM_USER_LOG_LINE, (WPARAM)m_hList, (LPARAM)wstr);
                    }
                }
                m_currentLine.clear();
            }
        }
    private:
        std::string strip_ansi(const std::string& str) {
            std::string res;
            bool in_esc = false;
            for (size_t i = 0; i < str.length(); ++i) {
                if (str[i] == '\033') {
                    in_esc = true;
                    continue;
                }
                if (in_esc) {
                    if (str[i] >= '@' && str[i] <= '~') {
                        in_esc = false;
                    }
                    continue;
                }
                res += str[i];
            }
            return res;
        }
        
        HWND m_hList;
        std::string m_currentLine;
    };

    // RAII helper to redirect std::cin and std::cout
    struct RedirectionGuard {
        RedirectionGuard(HWND hList, const std::string& mockInput) 
            : buf(hList), input(mockInput) {
            old_cout = std::cout.rdbuf(&buf);
            old_cerr = std::cerr.rdbuf(&buf);
            old_cin = std::cin.rdbuf(input.rdbuf());
        }
        
        ~RedirectionGuard() {
            std::cout.rdbuf(old_cout);
            std::cerr.rdbuf(old_cerr);
            std::cin.rdbuf(old_cin);
        }
        
        GuiStreamBuf buf;
        std::stringstream input;
        std::streambuf* old_cout;
        std::streambuf* old_cerr;
        std::streambuf* old_cin;
    };

    void append_log_line(HWND hList, const std::string& line) {
        int len = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, nullptr, 0);
        if (len > 0) {
            std::vector<wchar_t> wstr(len);
            MultiByteToWideChar(CP_UTF8, 0, line.c_str(), -1, wstr.data(), len);
            SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)wstr.data());
            
            // Keep list scrolled down
            int count = SendMessage(hList, LB_GETCOUNT, 0, 0);
            SendMessage(hList, LB_SETTOPINDEX, count - 1, 0);
        }
    }

    // Show/Hide controls according to active tab
    void show_tab(int tabIndex) {
        g_activeTab = tabIndex;
        for (int i = 0; i < 7; ++i) {
            for (HWND hwnd : g_tabControls[i]) {
                ShowWindow(hwnd, (i == tabIndex) ? SW_SHOW : SW_HIDE);
            }
        }
        // Force repaint of custom elements
        InvalidateRect(g_hwndMain, nullptr, TRUE);
    }

    std::wstring open_file_dialog(HWND owner) {
        OPENFILENAMEW ofn = {0};
        wchar_t szFile[260] = {0};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = owner;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile) / sizeof(szFile[0]);
        ofn.lpstrFilter = L"All Files\0*.*\0Executable Files\0*.exe;*.dll\0";
        ofn.nFilterIndex = 2;
        ofn.lpstrFileTitle = nullptr;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = nullptr;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
        
        if (GetOpenFileNameW(&ofn)) {
            return szFile;
        }
        return L"";
    }

    // Window Procedure
    LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
            case WM_CREATE: {
                // Initialize modern styles on sub-elements
                g_hFontNormal = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
                g_hFontTitle = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
                g_hFontHeader = CreateFontW(22, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
                g_hFontMonospace = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");
                
                // Initialize background brushes
                g_hBgBrush = CreateSolidBrush(RGB(18, 18, 20));
                g_hSidebarBrush = CreateSolidBrush(RGB(24, 24, 28));
                g_hHeaderBrush = CreateSolidBrush(RGB(30, 30, 36));
                g_hFieldBrush = CreateSolidBrush(RGB(30, 30, 35));
                g_hListBoxBrush = CreateSolidBrush(RGB(24, 24, 28));
                g_hGroupBrush = CreateSolidBrush(RGB(28, 28, 32));

                // ── Sidebar Tabs ──────────────────────────────────────────────────
                const wchar_t* tabs[] = {
                    L"Overview", L"Network Scan", L"Vulnerability Scan",
                    L"Process List", L"PE Analyzer", L"Crypto & Hash", L"Advanced Payloads"
                };
                for (int i = 0; i < 7; ++i) {
                    HWND hTab = CreateWindowW(L"BUTTON", tabs[i], 
                        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                        10, 80 + i * 45, 200, 38, hwnd, (HMENU)(intptr_t)(IDC_TAB_START + i), nullptr, nullptr);
                    SendMessageW(hTab, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                }

                // ── Tab 0: Overview Controls ──────────────────────────────────────
                HWND hO1 = CreateWindowW(L"STATIC", L"PHANTOM Security Dashboard",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 80, 500, 25, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hO1, WM_SETFONT, (WPARAM)g_hFontHeader, TRUE);
                g_tabControls[0].push_back(hO1);

                HWND hO2 = CreateWindowW(L"STATIC", 
                    L"Welcome to the PHANTOM Security Toolkit. Select a module from the left menu to audit your systems, verify file integrity, or inspect binary structures.\n\nThis application is built on top of native Windows system services and OpenSSL to perform cryptographic calculations and port diagnostics efficiently.",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 130, 660, 100, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hO2, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[0].push_back(hO2);

                HWND hO3 = CreateWindowW(L"STATIC", L"SYSTEM AUDIT METRICS",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 240, 500, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hO3, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);
                g_tabControls[0].push_back(hO3);

                std::wstring metrics = L"    - Operations Platform : Windows API Core (x64 Native)\n"
                                       L"    - Encryption Engine   : OpenSSL EVP Library\n"
                                       L"    - Socket Interface    : WinSock2 SIO_RCVALL Mode Supported\n"
                                       L"    - Wireless Interface  : Native Windows WLAN API\n"
                                       L"    - Vulnerability Database: 24 Common Service Ports + Trojans\n"
                                       L"    - Status              : Ready for Diagnostics";
                HWND hO4 = CreateWindowW(L"STATIC", metrics.c_str(),
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 270, 660, 200, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hO4, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[0].push_back(hO4);

                // ── Tab 1: Network Scanner Controls ───────────────────────────────
                HWND hN1 = CreateWindowW(L"STATIC", L"Target IP or Subnet base (e.g. 192.168.1. or 127.0.0.1):",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 80, 500, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hN1, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[1].push_back(hN1);

                HWND hEditNetIP = CreateWindowW(L"EDIT", L"127.0.0.1",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                    240, 100, 250, 25, hwnd, (HMENU)IDC_NETSCAN_IP, nullptr, nullptr);
                SendMessageW(hEditNetIP, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[1].push_back(hEditNetIP);

                HWND hN2 = CreateWindowW(L"STATIC", L"Ports (e.g. 22-80, 443 or blank for Top-100):",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 135, 500, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hN2, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[1].push_back(hN2);

                HWND hEditNetPorts = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    240, 155, 250, 25, hwnd, (HMENU)IDC_NETSCAN_PORTS, nullptr, nullptr);
                SendMessageW(hEditNetPorts, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[1].push_back(hEditNetPorts);

                HWND hRadioTCP = CreateWindowW(L"BUTTON", L"TCP Connect Scan",
                    WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON | WS_GROUP,
                    240, 195, 140, 20, hwnd, (HMENU)IDC_NETSCAN_RADIO_TCP, nullptr, nullptr);
                SendMessageW(hRadioTCP, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                SendMessageW(hRadioTCP, BM_SETCHECK, BST_CHECKED, 0);
                g_tabControls[1].push_back(hRadioTCP);

                HWND hRadioPing = CreateWindowW(L"BUTTON", L"ICMP Ping Sweep",
                    WS_CHILD | WS_VISIBLE | BS_AUTORADIOBUTTON,
                    390, 195, 150, 20, hwnd, (HMENU)IDC_NETSCAN_RADIO_PING, nullptr, nullptr);
                SendMessageW(hRadioPing, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[1].push_back(hRadioPing);

                HWND hBtnNet = CreateWindowW(L"BUTTON", L"Run Scan",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    240, 225, 130, 32, hwnd, (HMENU)IDC_BTN_RUN_NETSCAN, nullptr, nullptr);
                SendMessageW(hBtnNet, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[1].push_back(hBtnNet);

                HWND hListNet = CreateWindowW(L"LISTBOX", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS,
                    240, 270, 670, 330, hwnd, (HMENU)IDC_NETSCAN_LIST, nullptr, nullptr);
                SendMessageW(hListNet, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[1].push_back(hListNet);

                // ── Tab 2: Vulnerability Scanner Controls ─────────────────────────
                HWND hV1 = CreateWindowW(L"STATIC", L"Target IP or Host to audit:",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 80, 500, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hV1, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[2].push_back(hV1);

                HWND hEditVulnIP = CreateWindowW(L"EDIT", L"127.0.0.1",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    240, 100, 250, 25, hwnd, (HMENU)IDC_VULNSCAN_IP, nullptr, nullptr);
                SendMessageW(hEditVulnIP, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[2].push_back(hEditVulnIP);

                HWND hBtnVuln = CreateWindowW(L"BUTTON", L"Run Vulnerability Scan",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    240, 135, 200, 32, hwnd, (HMENU)IDC_BTN_RUN_VULNSCAN, nullptr, nullptr);
                SendMessageW(hBtnVuln, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[2].push_back(hBtnVuln);

                HWND hListVuln = CreateWindowW(L"LISTBOX", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS,
                    240, 180, 670, 420, hwnd, (HMENU)IDC_VULNSCAN_LIST, nullptr, nullptr);
                SendMessageW(hListVuln, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[2].push_back(hListVuln);

                // ── Tab 3: Process Inspector Controls ─────────────────────────────
                HWND hBtnProc = CreateWindowW(L"BUTTON", L"Refresh System Processes",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    240, 80, 220, 32, hwnd, (HMENU)IDC_BTN_REFRESH_PROCESSES, nullptr, nullptr);
                SendMessageW(hBtnProc, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[3].push_back(hBtnProc);

                HWND hListProc = CreateWindowW(L"LISTBOX", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS,
                    240, 125, 670, 475, hwnd, (HMENU)IDC_PROCESS_LIST, nullptr, nullptr);
                SendMessageW(hListProc, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[3].push_back(hListProc);

                // ── Tab 4: PE Analyzer Controls ───────────────────────────────────
                HWND hP1 = CreateWindowW(L"STATIC", L"Select Portable Executable (.exe, .dll) file to analyze:",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 80, 500, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hP1, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[4].push_back(hP1);

                HWND hEditPEPath = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_AUTOHSCROLL,
                    240, 100, 530, 25, hwnd, (HMENU)IDC_PE_PATH, nullptr, nullptr);
                SendMessageW(hEditPEPath, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[4].push_back(hEditPEPath);

                HWND hBtnBrowsePE = CreateWindowW(L"BUTTON", L"Browse...",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    780, 98, 120, 28, hwnd, (HMENU)IDC_BTN_BROWSE_PE, nullptr, nullptr);
                SendMessageW(hBtnBrowsePE, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[4].push_back(hBtnBrowsePE);

                HWND hBtnPE = CreateWindowW(L"BUTTON", L"Start PE Analysis",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    240, 135, 180, 32, hwnd, (HMENU)IDC_BTN_RUN_PEANALYZE, nullptr, nullptr);
                SendMessageW(hBtnPE, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[4].push_back(hBtnPE);

                HWND hListPE = CreateWindowW(L"LISTBOX", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS,
                    240, 180, 670, 420, hwnd, (HMENU)IDC_PE_OUTPUT, nullptr, nullptr);
                SendMessageW(hListPE, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[4].push_back(hListPE);

                // ── Tab 5: Crypto & Hashing Controls ──────────────────────────────
                HWND hGroupHash = CreateWindowW(L"BUTTON", L"OpenSSL Cryptography Hash Tools",
                    WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                    240, 80, 670, 180, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hGroupHash, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hGroupHash);

                HWND hC1 = CreateWindowW(L"STATIC", L"Input Text String:",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 260, 105, 150, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hC1, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hC1);

                HWND hEditHashIn = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    260, 125, 450, 25, hwnd, (HMENU)IDC_HASH_INPUT, nullptr, nullptr);
                SendMessageW(hEditHashIn, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hEditHashIn);

                HWND hComboHashAlgo = CreateWindowW(L"COMBOBOX", L"",
                    WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                    720, 125, 160, 120, hwnd, (HMENU)IDC_HASH_ALGO, nullptr, nullptr);
                SendMessageW(hComboHashAlgo, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                SendMessageW(hComboHashAlgo, CB_ADDSTRING, 0, (LPARAM)L"MD5");
                SendMessageW(hComboHashAlgo, CB_ADDSTRING, 0, (LPARAM)L"SHA-256");
                SendMessageW(hComboHashAlgo, CB_ADDSTRING, 0, (LPARAM)L"SHA-512");
                SendMessageW(hComboHashAlgo, CB_SETCURSEL, 1, 0); // Default SHA-256
                g_tabControls[5].push_back(hComboHashAlgo);

                HWND hBtnHash = CreateWindowW(L"BUTTON", L"Generate Hash",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    260, 160, 130, 28, hwnd, (HMENU)IDC_BTN_HASH, nullptr, nullptr);
                SendMessageW(hBtnHash, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hBtnHash);

                HWND hEditHashOut = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY | ES_AUTOHSCROLL,
                    260, 205, 620, 25, hwnd, (HMENU)IDC_HASH_OUTPUT, nullptr, nullptr);
                SendMessageW(hEditHashOut, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[5].push_back(hEditHashOut);

                // Password Generator Box
                HWND hGroupPass = CreateWindowW(L"BUTTON", L"Password Strength Evaluator & Generator",
                    WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                    240, 270, 670, 330, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hGroupPass, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hGroupPass);

                HWND hC2 = CreateWindowW(L"STATIC", L"Password Length:",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 260, 305, 120, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hC2, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hC2);

                HWND hEditPassLen = CreateWindowW(L"EDIT", L"16",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER | ES_CENTER,
                    390, 303, 50, 25, hwnd, (HMENU)IDC_PASS_LENGTH, nullptr, nullptr);
                SendMessageW(hEditPassLen, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hEditPassLen);

                HWND hChkUpper = CreateWindowW(L"BUTTON", L"Include Uppercase Letters (A-Z)",
                    WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    260, 340, 220, 20, hwnd, (HMENU)IDC_CHK_UPPER, nullptr, nullptr);
                SendMessageW(hChkUpper, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                SendMessageW(hChkUpper, BM_SETCHECK, BST_CHECKED, 0);
                g_tabControls[5].push_back(hChkUpper);

                HWND hChkDigits = CreateWindowW(L"BUTTON", L"Include Numbers (0-9)",
                    WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    260, 370, 220, 20, hwnd, (HMENU)IDC_CHK_DIGITS, nullptr, nullptr);
                SendMessageW(hChkDigits, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                SendMessageW(hChkDigits, BM_SETCHECK, BST_CHECKED, 0);
                g_tabControls[5].push_back(hChkDigits);

                HWND hChkSpecial = CreateWindowW(L"BUTTON", L"Include Special Characters",
                    WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                    260, 400, 220, 20, hwnd, (HMENU)IDC_CHK_SPECIAL, nullptr, nullptr);
                SendMessageW(hChkSpecial, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                SendMessageW(hChkSpecial, BM_SETCHECK, BST_CHECKED, 0);
                g_tabControls[5].push_back(hChkSpecial);

                HWND hBtnGenPass = CreateWindowW(L"BUTTON", L"Generate & Verify Strength",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    260, 435, 190, 32, hwnd, (HMENU)IDC_BTN_GENPASS, nullptr, nullptr);
                SendMessageW(hBtnGenPass, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hBtnGenPass);

                HWND hC3 = CreateWindowW(L"STATIC", L"Result Password:",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 510, 305, 150, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hC3, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hC3);

                HWND hEditPassOut = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT | ES_READONLY | ES_AUTOHSCROLL,
                    510, 325, 370, 25, hwnd, (HMENU)IDC_PASS_OUTPUT, nullptr, nullptr);
                SendMessageW(hEditPassOut, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[5].push_back(hEditPassOut);

                HWND hC4 = CreateWindowW(L"STATIC", L"Security Rating & Details:",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 510, 360, 180, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hC4, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hC4);

                HWND hEditPassStrength = CreateWindowW(L"EDIT", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL,
                    510, 380, 370, 200, hwnd, (HMENU)IDC_PASS_STRENGTH, nullptr, nullptr);
                SendMessageW(hEditPassStrength, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[5].push_back(hEditPassStrength);

                // ── Tab 6: Advanced Payloads Controls ─────────────────────────────
                HWND hW1 = CreateWindowW(L"STATIC", L"WARNING: Educational / Authorized Audit Use Only! Do not run keyloggers on unapproved systems.",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 240, 80, 670, 25, hwnd, (HMENU)999, nullptr, nullptr);
                SendMessageW(hW1, WM_SETFONT, (WPARAM)g_hFontTitle, TRUE);
                g_tabControls[6].push_back(hW1);

                // Keylogger
                HWND hGroupKey = CreateWindowW(L"BUTTON", L"Local Keyboard Event Hook (keylog.txt)",
                    WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                    240, 115, 670, 190, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hGroupKey, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hGroupKey);

                HWND hBtnStartKey = CreateWindowW(L"BUTTON", L"Start Keylogger",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    260, 140, 150, 30, hwnd, (HMENU)IDC_BTN_START_KEYLOGGER, nullptr, nullptr);
                SendMessageW(hBtnStartKey, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hBtnStartKey);

                HWND hBtnStopKey = CreateWindowW(L"BUTTON", L"Stop Keylogger",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    420, 140, 150, 30, hwnd, (HMENU)IDC_BTN_STOP_KEYLOGGER, nullptr, nullptr);
                SendMessageW(hBtnStopKey, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                EnableWindow(hBtnStopKey, FALSE);
                g_tabControls[6].push_back(hBtnStopKey);

                HWND hListKey = CreateWindowW(L"LISTBOX", L"",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | LBS_NOINTEGRALHEIGHT | LBS_HASSTRINGS,
                    260, 180, 620, 110, hwnd, (HMENU)IDC_KEYLOGGER_LIST, nullptr, nullptr);
                SendMessageW(hListKey, WM_SETFONT, (WPARAM)g_hFontMonospace, TRUE);
                g_tabControls[6].push_back(hListKey);

                // Reverse Shell
                HWND hGroupShell = CreateWindowW(L"BUTTON", L"Reverse Command Shell Client Relay",
                    WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                    240, 315, 670, 285, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hGroupShell, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hGroupShell);

                HWND hS1 = CreateWindowW(L"STATIC", L"LHOST (Listening IP):",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 260, 345, 150, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hS1, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hS1);

                HWND hEditShellIP = CreateWindowW(L"EDIT", L"127.0.0.1",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_LEFT,
                    260, 365, 180, 25, hwnd, (HMENU)IDC_REV_HOST, nullptr, nullptr);
                SendMessageW(hEditShellIP, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hEditShellIP);

                HWND hS2 = CreateWindowW(L"STATIC", L"LPORT (Port):",
                    WS_CHILD | WS_VISIBLE | SS_LEFT, 460, 345, 100, 20, hwnd, nullptr, nullptr, nullptr);
                SendMessageW(hS2, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hS2);

                HWND hEditShellPort = CreateWindowW(L"EDIT", L"4444",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
                    460, 365, 100, 25, hwnd, (HMENU)IDC_REV_PORT, nullptr, nullptr);
                SendMessageW(hEditShellPort, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hEditShellPort);

                HWND hBtnShell = CreateWindowW(L"BUTTON", L"Establish Relayed Shell",
                    WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
                    260, 405, 220, 32, hwnd, (HMENU)IDC_BTN_LAUNCH_REVSHELL, nullptr, nullptr);
                SendMessageW(hBtnShell, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hBtnShell);

                HWND hEditShellStatus = CreateWindowW(L"EDIT", L"Ready to connect.\r\nNote: Starts a thread trying to connect to listener. Requires a running netcat listener (e.g. nc -lvnp 4444) to establish control stream.",
                    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
                    260, 445, 620, 140, hwnd, (HMENU)IDC_REVSHELL_STATUS, nullptr, nullptr);
                SendMessageW(hEditShellStatus, WM_SETFONT, (WPARAM)g_hFontNormal, TRUE);
                g_tabControls[6].push_back(hEditShellStatus);

                // Default to Overview
                show_tab(0);
                return 0;
            }

            case WM_PAINT: {
                PAINTSTRUCT ps;
                HDC hdc = BeginPaint(hwnd, &ps);

                // Draw sidebar panel
                RECT rcSidebar = {0, 0, 220, 650};
                FillRect(hdc, &rcSidebar, g_hSidebarBrush);

                // Draw top header panel
                RECT rcHeader = {220, 0, 950, 60};
                FillRect(hdc, &rcHeader, g_hHeaderBrush);

                // Render Header Title Text
                SetBkMode(hdc, TRANSPARENT);
                SetTextColor(hdc, RGB(255, 255, 255));
                HFONT hOldFont = (HFONT)SelectObject(hdc, g_hFontHeader);
                RECT rcTitleText = {240, 14, 950, 60};
                DrawTextW(hdc, L"PHANTOM Security Toolkit Dashboard", -1, &rcTitleText, DT_SINGLELINE | DT_VCENTER | DT_LEFT);

                // Bottom Footer Text on Sidebar
                SetTextColor(hdc, RGB(120, 120, 130));
                SelectObject(hdc, g_hFontNormal);
                RECT rcFooter = {15, 600, 205, 640};
                DrawTextW(hdc, L"v2.0.0 Stable\nAuthorized Use Only", -1, &rcFooter, DT_BOTTOM | DT_LEFT);

                // Draw divider line under header
                HPEN hDivPen = CreatePen(PS_SOLID, 1, RGB(40, 40, 48));
                HPEN hOldPen = (HPEN)SelectObject(hdc, hDivPen);
                MoveToEx(hdc, 220, 60, nullptr);
                LineTo(hdc, 950, 60);

                // Sidebar divider
                MoveToEx(hdc, 220, 60, nullptr);
                LineTo(hdc, 220, 650);

                SelectObject(hdc, hOldPen);
                DeleteObject(hDivPen);
                SelectObject(hdc, hOldFont);

                EndPaint(hwnd, &ps);
                return 0;
            }

            case WM_CTLCOLORSTATIC: {
                HDC hdc = (HDC)wParam;
                HWND hwndCtrl = (HWND)lParam;
                int id = GetDlgCtrlID(hwndCtrl);
                
                SetBkMode(hdc, TRANSPARENT);
                if (id == 999) { // Red warning
                    SetTextColor(hdc, RGB(244, 67, 54));
                } else {
                    SetTextColor(hdc, RGB(210, 210, 215));
                }
                
                // Group boxes should have dark background brush
                wchar_t className[32];
                GetClassNameW(hwndCtrl, className, 32);
                if (wcscmp(className, L"Button") == 0) {
                    return (INT_PTR)g_hBgBrush;
                }
                return (INT_PTR)g_hBgBrush;
            }

            case WM_CTLCOLOREDIT: {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, RGB(255, 255, 255));
                SetBkColor(hdc, RGB(30, 30, 35));
                return (INT_PTR)g_hFieldBrush;
            }

            case WM_CTLCOLORLISTBOX: {
                HDC hdc = (HDC)wParam;
                SetTextColor(hdc, RGB(220, 220, 220));
                SetBkColor(hdc, RGB(24, 24, 28));
                return (INT_PTR)g_hListBoxBrush;
            }

            case WM_DRAWITEM: {
                LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
                if (pDIS->CtlType == ODT_BUTTON) {
                    COLORREF bgColor = RGB(45, 45, 52);
                    COLORREF textColor = RGB(220, 220, 220);
                    
                    bool isSidebar = (pDIS->CtlID >= IDC_TAB_START && pDIS->CtlID <= IDC_TAB_END);
                    bool isActiveTab = (isSidebar && (pDIS->CtlID - IDC_TAB_START == g_activeTab));
                    
                    if (isSidebar) {
                        if (isActiveTab) {
                            bgColor = RGB(0, 160, 60); // Emerald/Green background
                            textColor = RGB(255, 255, 255);
                        } else if (pDIS->itemState & ODS_SELECTED) {
                            bgColor = RGB(38, 38, 44);
                        } else {
                            bgColor = RGB(24, 24, 28);
                        }
                    } else {
                        if (pDIS->itemState & ODS_SELECTED) {
                            bgColor = RGB(0, 100, 40);
                        } else if (pDIS->hwndItem == GetDlgItem(hwnd, IDC_BTN_STOP_KEYLOGGER)) {
                            bgColor = RGB(198, 40, 40); // Stop button is red
                            textColor = RGB(255, 255, 255);
                        } else {
                            bgColor = RGB(0, 150, 136); // Teal for trigger actions
                            textColor = RGB(255, 255, 255);
                        }
                    }

                    if (!IsWindowEnabled(pDIS->hwndItem)) {
                        bgColor = RGB(40, 40, 45);
                        textColor = RGB(100, 100, 110);
                    }
                    
                    HBRUSH hBrush = CreateSolidBrush(bgColor);
                    FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
                    DeleteObject(hBrush);
                    
                    // Left indicator vertical bar for sidebar tabs
                    if (isSidebar && isActiveTab) {
                        RECT rcBar = pDIS->rcItem;
                        rcBar.right = rcBar.left + 5;
                        HBRUSH hAccentBrush = CreateSolidBrush(RGB(255, 255, 255));
                        FillRect(pDIS->hDC, &rcBar, hAccentBrush);
                        DeleteObject(hAccentBrush);
                    }
                    
                    if (!isSidebar && IsWindowEnabled(pDIS->hwndItem)) {
                        HPEN hPen = CreatePen(PS_SOLID, 1, RGB(70, 70, 75));
                        HPEN hOldPen = (HPEN)SelectObject(pDIS->hDC, hPen);
                        MoveToEx(pDIS->hDC, pDIS->rcItem.left, pDIS->rcItem.top, nullptr);
                        LineTo(pDIS->hDC, pDIS->rcItem.right, pDIS->rcItem.top);
                        LineTo(pDIS->hDC, pDIS->rcItem.right, pDIS->rcItem.bottom);
                        LineTo(pDIS->hDC, pDIS->rcItem.left, pDIS->rcItem.bottom);
                        LineTo(pDIS->hDC, pDIS->rcItem.left, pDIS->rcItem.top);
                        SelectObject(pDIS->hDC, hOldPen);
                        DeleteObject(hPen);
                    }
                    
                    SetBkMode(pDIS->hDC, TRANSPARENT);
                    SetTextColor(pDIS->hDC, textColor);
                    
                    wchar_t text[128];
                    GetWindowTextW(pDIS->hwndItem, text, 128);
                    RECT rc = pDIS->rcItem;
                    if (isSidebar) rc.left += 15;
                    
                    HFONT hOldFont = (HFONT)SelectObject(pDIS->hDC, isSidebar ? g_hFontTitle : g_hFontNormal);
                    DrawTextW(pDIS->hDC, text, -1, &rc, DT_SINGLELINE | DT_VCENTER | (isSidebar ? DT_LEFT : DT_CENTER));
                    SelectObject(pDIS->hDC, hOldFont);
                    return 0;
                }
                break;
            }

            case WM_COMMAND: {
                int wmId = LOWORD(wParam);
                int wmEvent = HIWORD(wParam);

                // Tab switching
                if (wmId >= IDC_TAB_START && wmId <= IDC_TAB_END) {
                    show_tab(wmId - IDC_TAB_START);
                    return 0;
                }

                switch (wmId) {
                    case IDC_BTN_BROWSE_PE: {
                        std::wstring path = open_file_dialog(hwnd);
                        if (!path.empty()) {
                            SetDlgItemTextW(hwnd, IDC_PE_PATH, path.c_str());
                        }
                        break;
                    }

                    case IDC_BTN_RUN_NETSCAN: {
                        if (g_isRunningTask) return 0;
                        g_isRunningTask = true;
                        
                        HWND hList = GetDlgItem(hwnd, IDC_NETSCAN_LIST);
                        SendMessage(hList, LB_RESETCONTENT, 0, 0);

                        wchar_t ipW[128] = {0};
                        GetDlgItemTextW(hwnd, IDC_NETSCAN_IP, ipW, 128);
                        wchar_t portsW[128] = {0};
                        GetDlgItemTextW(hwnd, IDC_NETSCAN_PORTS, portsW, 128);

                        // Convert fields to ANSI
                        char ipA[128] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, ipW, -1, ipA, 128, nullptr, nullptr);
                        char portsA[128] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, portsW, -1, portsA, 128, nullptr, nullptr);

                        bool isPing = SendMessage(GetDlgItem(hwnd, IDC_NETSCAN_RADIO_PING), BM_GETCHECK, 0, 0) == BST_CHECKED;

                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_RUN_NETSCAN), FALSE);
                        append_log_line(hList, "Initializing Network Diagnostic Thread...");

                        std::thread([hList, isPing, ip = std::string(ipA), ports = std::string(portsA)]() {
                            std::string inputStr;
                            if (isPing) {
                                inputStr = "1\n" + ip + "\n";
                            } else {
                                inputStr = "2\n" + ip + "\n" + ports + "\n";
                            }

                            {
                                RedirectionGuard guard(hList, inputStr);
                                phantom::modules::run_network_scanner();
                            }

                            PostMessageW(g_hwndMain, WM_USER_SCAN_DONE, (WPARAM)hList, IDC_BTN_RUN_NETSCAN);
                        }).detach();
                        break;
                    }

                    case IDC_BTN_RUN_VULNSCAN: {
                        if (g_isRunningTask) return 0;
                        g_isRunningTask = true;

                        HWND hList = GetDlgItem(hwnd, IDC_VULNSCAN_LIST);
                        SendMessage(hList, LB_RESETCONTENT, 0, 0);

                        wchar_t ipW[128] = {0};
                        GetDlgItemTextW(hwnd, IDC_VULNSCAN_IP, ipW, 128);

                        char ipA[128] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, ipW, -1, ipA, 128, nullptr, nullptr);

                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_RUN_VULNSCAN), FALSE);
                        append_log_line(hList, "Launching vulnerability threat audit thread...");

                        std::thread([hList, ip = std::string(ipA)]() {
                            std::string inputStr = ip + "\n\n";
                            {
                                RedirectionGuard guard(hList, inputStr);
                                phantom::modules::run_vuln_scanner();
                            }
                            PostMessageW(g_hwndMain, WM_USER_SCAN_DONE, (WPARAM)hList, IDC_BTN_RUN_VULNSCAN);
                        }).detach();
                        break;
                    }

                    case IDC_BTN_REFRESH_PROCESSES: {
                        if (g_isRunningTask) return 0;
                        g_isRunningTask = true;

                        HWND hList = GetDlgItem(hwnd, IDC_PROCESS_LIST);
                        SendMessage(hList, LB_RESETCONTENT, 0, 0);

                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_REFRESH_PROCESSES), FALSE);

                        std::thread([hList]() {
                            {
                                RedirectionGuard guard(hList, "");
                                phantom::modules::run_process_inspector();
                            }
                            PostMessageW(g_hwndMain, WM_USER_SCAN_DONE, (WPARAM)hList, IDC_BTN_REFRESH_PROCESSES);
                        }).detach();
                        break;
                    }

                    case IDC_BTN_RUN_PEANALYZE: {
                        if (g_isRunningTask) return 0;
                        g_isRunningTask = true;

                        HWND hList = GetDlgItem(hwnd, IDC_PE_OUTPUT);
                        SendMessage(hList, LB_RESETCONTENT, 0, 0);

                        wchar_t pathW[260] = {0};
                        GetDlgItemTextW(hwnd, IDC_PE_PATH, pathW, 260);
                        if (pathW[0] == L'\0') {
                            append_log_line(hList, "ERROR: Select a valid file first.");
                            g_isRunningTask = false;
                            return 0;
                        }

                        char pathA[260] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, pathW, -1, pathA, 260, nullptr, nullptr);

                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_RUN_PEANALYZE), FALSE);
                        append_log_line(hList, "Opening and parsing PE file...");

                        std::thread([hList, path = std::string(pathA)]() {
                            std::string inputStr = path + "\n\n";
                            {
                                RedirectionGuard guard(hList, inputStr);
                                phantom::modules::run_pe_analyzer();
                            }
                            PostMessageW(g_hwndMain, WM_USER_SCAN_DONE, (WPARAM)hList, IDC_BTN_RUN_PEANALYZE);
                        }).detach();
                        break;
                    }

                    case IDC_BTN_HASH: {
                        wchar_t textW[512] = {0};
                        GetDlgItemTextW(hwnd, IDC_HASH_INPUT, textW, 512);
                        char textA[512] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, textW, -1, textA, 512, nullptr, nullptr);

                        int curIdx = SendMessage(GetDlgItem(hwnd, IDC_HASH_ALGO), CB_GETCURSEL, 0, 0);

                        // Temporarily run cryptotools via redirected stream in thread
                        HWND hDummy = CreateWindowW(L"LISTBOX", L"", 0, 0, 0, 0, 0, hwnd, nullptr, nullptr, nullptr);
                        std::thread([hwnd, text = std::string(textA), curIdx, hDummy]() {
                            std::string mockInput = text + "\n";
                            std::stringstream outBuf;
                            {
                                // Call backend crypto tool directly with std::cout redirect
                                std::streambuf* old_cout = std::cout.rdbuf(outBuf.rdbuf());
                                std::streambuf* old_cin = std::cin.rdbuf(std::cin.rdbuf()); // dummy
                                std::stringstream inBuf(mockInput);
                                std::cin.rdbuf(inBuf.rdbuf());

                                phantom::modules::run_crypto_tools();

                                std::cout.rdbuf(old_cout);
                                std::cin.rdbuf(old_cin);
                            }

                            // Extract the computed hashes from outBuf string
                            // Output format from run_crypto_tools():
                            // MD5:    xxx
                            // SHA256: xxx
                            // SHA512: xxx
                            std::string line;
                            std::string md5, sha256, sha512;
                            while (std::getline(outBuf, line)) {
                                if (line.rfind("MD5:    ", 0) == 0) md5 = line.substr(8);
                                else if (line.rfind("SHA256: ", 0) == 0) sha256 = line.substr(8);
                                else if (line.rfind("SHA512: ", 0) == 0) sha512 = line.substr(8);
                            }

                            std::string targetHash = sha256; // Default
                            if (curIdx == 0) targetHash = md5;
                            else if (curIdx == 2) targetHash = sha512;

                            int len = MultiByteToWideChar(CP_UTF8, 0, targetHash.c_str(), -1, nullptr, 0);
                            wchar_t* wHash = new wchar_t[len];
                            MultiByteToWideChar(CP_UTF8, 0, targetHash.c_str(), -1, wHash, len);

                            PostMessageW(hwnd, WM_USER + 103, 0, (LPARAM)wHash);
                            DestroyWindow(hDummy);
                        }).detach();
                        break;
                    }

                    case IDC_BTN_GENPASS: {
                        wchar_t lenW[16] = {0};
                        GetDlgItemTextW(hwnd, IDC_PASS_LENGTH, lenW, 16);
                        int passLen = wcstol(lenW, nullptr, 10);
                        if (passLen <= 0 || passLen > 256) passLen = 16;

                        // Mock inputs for password tools options
                        // run_password_tools asks: Option (1 or 2)
                        // Choice 1 (Generate): asks "Length: "
                        // We will call the generator directly inside the thread
                        std::thread([hwnd, passLen]() {
                            std::stringstream outBuf;
                            std::string mockInput = "1\n" + std::to_string(passLen) + "\n";
                            {
                                std::streambuf* old_cout = std::cout.rdbuf(outBuf.rdbuf());
                                std::stringstream inBuf(mockInput);
                                std::streambuf* old_cin = std::cin.rdbuf(inBuf.rdbuf());

                                phantom::modules::run_password_tools();

                                std::cout.rdbuf(old_cout);
                                std::cin.rdbuf(old_cin);
                            }

                            // Extract generated: password from output buffer
                            std::string line;
                            std::string pass;
                            while (std::getline(outBuf, line)) {
                                size_t pos = line.find("Generated: ");
                                if (pos != std::string::npos) {
                                    pass = line.substr(pos + 11);
                                    // Strip spaces
                                    while (!pass.empty() && (pass.back() == '\n' || pass.back() == '\r')) pass.pop_back();
                                }
                            }

                            // Now evaluate the strength score of this password (Choice 2)
                            std::stringstream evalBuf;
                            std::string evalInput = "2\n" + pass + "\n";
                            {
                                std::streambuf* old_cout = std::cout.rdbuf(evalBuf.rdbuf());
                                std::stringstream inBuf(evalInput);
                                std::streambuf* old_cin = std::cin.rdbuf(inBuf.rdbuf());

                                phantom::modules::run_password_tools();

                                std::cout.rdbuf(old_cout);
                                std::cin.rdbuf(old_cin);
                            }

                            std::string evalReport;
                            while (std::getline(evalBuf, line)) {
                                if (line.find("Strength Score:") != std::string::npos) {
                                    evalReport = line;
                                }
                            }

                            // Send generated password
                            int wlen = MultiByteToWideChar(CP_UTF8, 0, pass.c_str(), -1, nullptr, 0);
                            wchar_t* wPass = new wchar_t[wlen];
                            MultiByteToWideChar(CP_UTF8, 0, pass.c_str(), -1, wPass, wlen);
                            PostMessageW(hwnd, WM_USER + 104, 0, (LPARAM)wPass);

                            // Send evaluation report
                            int rlen = MultiByteToWideChar(CP_UTF8, 0, evalReport.c_str(), -1, nullptr, 0);
                            wchar_t* wReport = new wchar_t[rlen];
                            MultiByteToWideChar(CP_UTF8, 0, evalReport.c_str(), -1, wReport, rlen);
                            PostMessageW(hwnd, WM_USER + 105, 0, (LPARAM)wReport);
                        }).detach();
                        break;
                    }

                    case IDC_BTN_START_KEYLOGGER: {
                        HWND hList = GetDlgItem(hwnd, IDC_KEYLOGGER_LIST);
                        SendMessage(hList, LB_RESETCONTENT, 0, 0);
                        append_log_line(hList, "[*] Registering WH_KEYBOARD_LL low-level hook...");
                        
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_START_KEYLOGGER), FALSE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_STOP_KEYLOGGER), TRUE);

                        std::thread([]() {
                            phantom::modules::run_keylogger();
                        }).detach();
                        break;
                    }

                    case IDC_BTN_STOP_KEYLOGGER: {
                        HWND hList = GetDlgItem(hwnd, IDC_KEYLOGGER_LIST);
                        
                        if (phantom::modules::kbdHook != nullptr) {
                            UnhookWindowsHookEx(phantom::modules::kbdHook);
                            phantom::modules::kbdHook = nullptr;
                            append_log_line(hList, "[*] Hook uninstalled. Keylogger stopped.");
                        } else {
                            // Keylogger thread handles message loop, post WM_QUIT
                            // Or standard cleanup
                            append_log_line(hList, "[*] Keyboard hook terminated.");
                        }

                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_START_KEYLOGGER), TRUE);
                        EnableWindow(GetDlgItem(hwnd, IDC_BTN_STOP_KEYLOGGER), FALSE);
                        break;
                    }

                    case IDC_BTN_LAUNCH_REVSHELL: {
                        wchar_t hostW[128] = {0};
                        wchar_t portW[16] = {0};
                        GetDlgItemTextW(hwnd, IDC_REV_HOST, hostW, 128);
                        GetDlgItemTextW(hwnd, IDC_REV_PORT, portW, 16);

                        char hostA[128] = {0};
                        char portA[16] = {0};
                        WideCharToMultiByte(CP_UTF8, 0, hostW, -1, hostA, 128, nullptr, nullptr);
                        WideCharToMultiByte(CP_UTF8, 0, portW, -1, portA, 16, nullptr, nullptr);

                        HWND hStatus = GetDlgItem(hwnd, IDC_REVSHELL_STATUS);
                        SetWindowTextW(hStatus, L"Connecting asynchronously to listener...");

                        std::thread([hStatus, host = std::string(hostA), port = std::string(portA)]() {
                            std::stringstream outBuf;
                            std::string mockInput = host + "\n" + port + "\n";
                            {
                                std::streambuf* old_cout = std::cout.rdbuf(outBuf.rdbuf());
                                std::stringstream inBuf(mockInput);
                                std::streambuf* old_cin = std::cin.rdbuf(inBuf.rdbuf());

                                phantom::modules::run_reverse_shell();

                                std::cout.rdbuf(old_cout);
                                std::cin.rdbuf(old_cin);
                            }
                            
                            std::string report = outBuf.str();
                            int rlen = MultiByteToWideChar(CP_UTF8, 0, report.c_str(), -1, nullptr, 0);
                            wchar_t* wReport = new wchar_t[rlen];
                            MultiByteToWideChar(CP_UTF8, 0, report.c_str(), -1, wReport, rlen);
                            PostMessageW(hStatus, WM_SETTEXT, 0, (LPARAM)wReport);
                        }).detach();
                        break;
                    }
                }
                return 0;
            }

            case WM_USER_LOG_LINE: {
                HWND hList = (HWND)wParam;
                wchar_t* wstr = (wchar_t*)lParam;
                SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)wstr);
                
                // Keep list scrolled down
                int count = SendMessage(hList, LB_GETCOUNT, 0, 0);
                SendMessage(hList, LB_SETTOPINDEX, count - 1, 0);
                
                delete[] wstr;
                return 0;
            }

            case WM_USER_SCAN_DONE: {
                HWND hList = (HWND)wParam;
                int btnId = (int)lParam;
                
                append_log_line(hList, "[*] Asynchronous operation completed successfully.");
                
                if (btnId != 0) {
                    EnableWindow(GetDlgItem(hwnd, btnId), TRUE);
                }
                g_isRunningTask = false;
                return 0;
            }

            case WM_USER_KEY_LOGGED: {
                HWND hList = GetDlgItem(hwnd, IDC_KEYLOGGER_LIST);
                DWORD vkCode = (DWORD)wParam;
                
                // Format the logged virtual key code nicely
                wchar_t keyName[64] = {0};
                LONG scancode = MapVirtualKey(vkCode, MAPVK_VK_TO_VSC);
                switch (vkCode) {
                    case VK_SPACE:    wcscpy_s(keyName, L"[SPACE]"); break;
                    case VK_RETURN:   wcscpy_s(keyName, L"[ENTER]"); break;
                    case VK_BACK:     wcscpy_s(keyName, L"[BACKSPACE]"); break;
                    case VK_TAB:      wcscpy_s(keyName, L"[TAB]"); break;
                    case VK_SHIFT:
                    case VK_LSHIFT:
                    case VK_RSHIFT:   wcscpy_s(keyName, L"[SHIFT]"); break;
                    case VK_CONTROL:
                    case VK_LCONTROL:
                    case VK_RCONTROL: wcscpy_s(keyName, L"[CTRL]"); break;
                    case VK_MENU:
                    case VK_LMENU:
                    case VK_RMENU:    wcscpy_s(keyName, L"[ALT]"); break;
                    case VK_ESCAPE:   wcscpy_s(keyName, L"[ESC]"); break;
                    default: {
                        GetKeyNameTextW((scancode << 16), keyName, 64);
                        break;
                    }
                }
                if (keyName[0] == L'\0') {
                    swprintf_s(keyName, L"[KEY: %d]", vkCode);
                }
                
                std::wstring logLine = L"Keystroke logged: " + std::wstring(keyName);
                SendMessageW(hList, LB_ADDSTRING, 0, (LPARAM)logLine.c_str());
                int count = SendMessage(hList, LB_GETCOUNT, 0, 0);
                SendMessage(hList, LB_SETTOPINDEX, count - 1, 0);
                return 0;
            }

            case WM_USER + 103: { // Update hash output
                wchar_t* wHash = (wchar_t*)lParam;
                SetDlgItemTextW(hwnd, IDC_HASH_OUTPUT, wHash);
                delete[] wHash;
                return 0;
            }

            case WM_USER + 104: { // Update password output
                wchar_t* wPass = (wchar_t*)lParam;
                SetDlgItemTextW(hwnd, IDC_PASS_OUTPUT, wPass);
                delete[] wPass;
                return 0;
            }

            case WM_USER + 105: { // Update password strength
                wchar_t* wReport = (wchar_t*)lParam;
                SetDlgItemTextW(hwnd, IDC_PASS_STRENGTH, wReport);
                delete[] wReport;
                return 0;
            }

            case WM_DESTROY: {
                // Perform keyboard hook cleanups if active
                if (phantom::modules::kbdHook != nullptr) {
                    UnhookWindowsHookEx(phantom::modules::kbdHook);
                    phantom::modules::kbdHook = nullptr;
                }

                // Delete custom fonts
                DeleteObject(g_hFontNormal);
                DeleteObject(g_hFontTitle);
                DeleteObject(g_hFontHeader);
                DeleteObject(g_hFontMonospace);
                
                // Delete background brushes
                DeleteObject(g_hBgBrush);
                DeleteObject(g_hSidebarBrush);
                DeleteObject(g_hHeaderBrush);
                DeleteObject(g_hFieldBrush);
                DeleteObject(g_hListBoxBrush);
                DeleteObject(g_hGroupBrush);

                PostQuitMessage(0);
                return 0;
            }
        }
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

namespace phantom::ui {
    void run_gui_dashboard() {
        // Initialize common controls
        INITCOMMONCONTROLSEX icex = {0};
        icex.dwSize = sizeof(icex);
        icex.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
        InitCommonControlsEx(&icex);

        const wchar_t CLASS_NAME[] = L"PHANTOM_DASHBOARD_CLASS";
        
        WNDCLASSEXW wc = {0};
        wc.cbSize = sizeof(WNDCLASSEXW);
        wc.style = CS_HREDRAW | CS_VREDRAW;
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = CLASS_NAME;
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(RGB(18, 18, 20)); // Match dark background
        
        if (!RegisterClassExW(&wc)) {
            MessageBoxW(nullptr, L"Window Registration Failed!", L"Error", MB_ICONERROR);
            return;
        }

        // Center window on screen
        int scrW = GetSystemMetrics(SM_CXSCREEN);
        int scrH = GetSystemMetrics(SM_CYSCREEN);
        int winW = 950;
        int winH = 650;
        int winX = (scrW - winW) / 2;
        int winY = (scrH - winH) / 2;

        g_hwndMain = CreateWindowExW(
            0, CLASS_NAME, L"PHANTOM Security Toolkit",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
            winX, winY, winW, winH,
            nullptr, nullptr, GetModuleHandle(nullptr), nullptr
        );

        if (!g_hwndMain) {
            MessageBoxW(nullptr, L"Window Creation Failed!", L"Error", MB_ICONERROR);
            return;
        }

        // Apply Immersive Dark Mode border if supported (Win 10+)
        BOOL useDark = TRUE;
        DwmSetWindowAttribute(g_hwndMain, 20, &useDark, sizeof(useDark));

        ShowWindow(g_hwndMain, SW_SHOW);
        UpdateWindow(g_hwndMain);

        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
}
