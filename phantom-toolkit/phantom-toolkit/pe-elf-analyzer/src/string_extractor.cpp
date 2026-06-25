// string_extractor.cpp — extract and categorise printable strings
#include <cstdio>
#include <cstring>
#include <cctype>
#include "../include/analyzer.h"

static int categorise(const char *s) {
    if (strncmp(s,"http://",7)==0||strncmp(s,"https://",8)==0||strncmp(s,"ftp://",6)==0)
        return 1; // URL
    // IP pattern: digits.digits.digits.digits
    int dots=0; bool all_ok=true;
    for (const char *p=s; *p; p++) {
        if (*p=='.') dots++;
        else if (!isdigit((unsigned char)*p)) { all_ok=false; break; }
    }
    if (all_ok && dots==3) return 2; // IP

    if (strncmp(s,"HKEY_",5)==0||strncmp(s,"SOFTWARE\\",9)==0) return 3; // registry
    if (s[0]=='/'||strncmp(s,"C:\\",3)==0||strncmp(s,"%APPDATA%",9)==0||
        strncmp(s,"%TEMP%",6)==0) return 4; // path

    // Suspicious keywords
    static const char *susp[] = {
        "CreateRemoteThread","VirtualAlloc","VirtualProtect","WriteProcessMemory",
        "LoadLibrary","GetProcAddress","NtUnmapViewOfSection","SetWindowsHookEx",
        "cmd.exe","powershell","/etc/passwd","/etc/shadow","nc -e","bash -i",
        "wget ","curl ","chmod 777","WScript","base64","eval(",
        "ShellExecute","WinExec","CreateProcess","RegSetValue",
        NULL
    };
    for (int i=0; susp[i]; i++)
        if (strstr(s, susp[i])) return 5;
    return 0;
}

void extract_strings(const uint8_t *data, size_t len, bin_info_t *info) {
    char buf[512];
    int  blen = 0;

    for (size_t i = 0; i <= len; i++) {
        unsigned char c = (i < len) ? data[i] : 0;
        if (c >= 0x20 && c < 0x7F && blen < 510) {
            buf[blen++] = (char)c;
        } else {
            if (blen >= MIN_STR_LEN && info->nstrings < MAX_STRINGS) {
                buf[blen] = '\0';
                auto &e = info->strings[info->nstrings];
                strncpy(e.value, buf, sizeof(e.value)-1);
                e.category = categorise(buf);
                info->nstrings++;
            }
            blen = 0;
        }
    }
}
