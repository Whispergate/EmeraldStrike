#include "config.h"
#ifdef INCLUDE_CMD_GETUID

#include "commands.h"

VOID cmd_getuid(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    HANDLE hToken = NULL;
    if (!inst->Win32.OpenProcessToken(inst->Win32.GetCurrentProcess(),
                                       0x0008 /* TOKEN_QUERY */, &hToken)) {
        response->is_error = TRUE;
        package_add_string(inst, response, "Failed to open process token");
        return;
    }

    BYTE buf[256];
    DWORD needed = 0;
    if (!inst->Win32.GetTokenInformation(hToken, TokenUser, buf, sizeof(buf), &needed)) {
        gate_CloseHandle(inst, hToken);
        response->is_error = TRUE;
        package_add_string(inst, response, "Failed to get token information");
        return;
    }

    TOKEN_USER* tu = (TOKEN_USER*)buf;
    char user[128] = {0};
    char domain[128] = {0};
    DWORD user_len = 128;
    DWORD domain_len = 128;
    SID_NAME_USE snu;

    if (!inst->Win32.LookupAccountSidA(NULL, tu->User.Sid,
                                        user, &user_len,
                                        domain, &domain_len, &snu)) {
        gate_CloseHandle(inst, hToken);
        response->is_error = TRUE;
        package_add_string(inst, response, "Failed to lookup account SID");
        return;
    }

    gate_CloseHandle(inst, hToken);

    char result[260];
    DWORD pos = 0;
    for (DWORD i = 0; domain[i] && pos < 255; i++)
        result[pos++] = domain[i];
    result[pos++] = '\\';
    for (DWORD i = 0; user[i] && pos < 259; i++)
        result[pos++] = user[i];
    result[pos] = 0;

    package_add_string(inst, response, result);
}

#endif
