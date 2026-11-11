#include "config.h"
#ifdef INCLUDE_CMD_UAC

#include "commands.h"
#include "json_out.h"

// read registry via the RtlOpenUsersKey or use advapi32

typedef LONG  (WINAPI *fn_RegOpenKeyExA_t)(void*, LPCSTR, DWORD, DWORD, void**);
typedef LONG  (WINAPI *fn_RegQueryValueExA_t)(void*, LPCSTR, DWORD*, DWORD*, BYTE*, DWORD*);
typedef LONG  (WINAPI *fn_RegCloseKey_t)(void*);

static LONG read_reg_dword(fn_RegOpenKeyExA_t open, fn_RegQueryValueExA_t query,
                           fn_RegCloseKey_t close, void* root,
                           const char* path, const char* name, DWORD* out) {
    void* key = 0;
    LONG r = open(root, path, 0, 0x20019 /*KEY_READ*/, &key);
    if (r != 0) return r;
    DWORD size = sizeof(DWORD), type = 0;
    r = query(key, name, NULL, &type, (BYTE*)out, &size);
    close(key);
    return r;
}

VOID cmd_uac(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    fn_RegOpenKeyExA_t pOpen = h_adv ?
        (fn_RegOpenKeyExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegOpenKeyExA") : NULL;
    fn_RegQueryValueExA_t pQuery = h_adv ?
        (fn_RegQueryValueExA_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegQueryValueExA") : NULL;
    fn_RegCloseKey_t pClose = h_adv ?
        (fn_RegCloseKey_t)(void*)inst->Win32.GetProcAddress(h_adv, "RegCloseKey") : NULL;
    if (!pOpen || !pQuery || !pClose) {
        package_add_string(inst, response, XSTR("advapi32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    // HKEY_LOCAL_MACHINE = 0x80000002
    void* HKLM = (void*)0x80000002;
    const char* key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
    DWORD enable_lua = 0, consent = 0, secure_ui_path = 0, type_admin = 0;
    DWORD lua_ok = read_reg_dword(pOpen, pQuery, pClose, HKLM, key_path, "EnableLUA", &enable_lua);
    DWORD consent_ok = read_reg_dword(pOpen, pQuery, pClose, HKLM, key_path, "ConsentPromptBehaviorAdmin", &consent);
    DWORD sup_ok = read_reg_dword(pOpen, pQuery, pClose, HKLM, key_path, "EnableSecureUIAPaths", &secure_ui_path);
    DWORD type_ok = read_reg_dword(pOpen, pQuery, pClose, HKLM, key_path, "PromptOnSecureDesktop", &type_admin);

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"enable_lua\":");
    j_append_uint(&jb, (lua_ok == 0) ? enable_lua : 0xFFFFFFFF);
    j_append_raw(&jb, ",\"consent_prompt\":");
    j_append_uint(&jb, (consent_ok == 0) ? consent : 0xFFFFFFFF);
    j_append_raw(&jb, ",\"secure_ui_paths\":");
    j_append_uint(&jb, (sup_ok == 0) ? secure_ui_path : 0xFFFFFFFF);
    j_append_raw(&jb, ",\"prompt_on_secure_desktop\":");
    j_append_uint(&jb, (type_ok == 0) ? type_admin : 0xFFFFFFFF);
    // UAC level interpretation
    const char* level = "unknown";
    if (lua_ok == 0 && enable_lua == 0) level = "disabled";
    else if (lua_ok == 0 && consent_ok == 0) {
        if (consent == 0) level = "never_notifies";
        else if (consent == 5) level = "default_notify_only_elevating";
        else level = "always_notify";
    }
    j_append_raw(&jb, ",\"level\":");
    j_append_str(&jb, level);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
