#include "config.h"
#ifdef INCLUDE_CMD_WHOAMI

#include "commands.h"

VOID cmd_whoami(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    HANDLE hToken = NULL;
    if (!inst->Win32.OpenProcessToken ||
        !inst->Win32.OpenProcessToken(inst->Win32.GetCurrentProcess(), 0x0008 /*TOKEN_QUERY*/, &hToken)) {
        package_add_string(inst, response, XSTR("Failed to open process token"));
        response->is_error = TRUE;
        return;
    }

    BYTE token_user_buf[256] = {0};
    DWORD ret_len = 0;
    if (!inst->Win32.GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)1 /*TokenUser*/,
                                          token_user_buf, sizeof(token_user_buf), &ret_len)) {
        gate_CloseHandle(inst, hToken);
        package_add_string(inst, response, XSTR("Failed to get token info"));
        response->is_error = TRUE;
        return;
    }
    gate_CloseHandle(inst, hToken);

    typedef struct { PSID Sid; DWORD Attributes; } _TOKEN_USER;
    _TOKEN_USER* tu = (_TOKEN_USER*)token_user_buf;

    char name[128] = {0};
    char domain[128] = {0};
    DWORD name_len = 128, domain_len = 128;
    SID_NAME_USE snu;

    if (inst->Win32.LookupAccountSidA(NULL, tu->Sid, name, &name_len, domain, &domain_len, &snu)) {
        char result[260] = {0};
        int pos = 0;
        for (int i = 0; domain[i] && pos < 250; i++) result[pos++] = domain[i];
        result[pos++] = '\\';
        for (int i = 0; name[i] && pos < 259; i++) result[pos++] = name[i];
        package_add_string(inst, response, result);
    } else {
        package_add_string(inst, response, XSTR("Unknown user"));
    }
}

#endif
