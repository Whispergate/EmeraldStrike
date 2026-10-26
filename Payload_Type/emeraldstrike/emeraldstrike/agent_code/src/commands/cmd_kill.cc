#include "config.h"
#ifdef INCLUDE_CMD_KILL

#include "commands.h"

VOID cmd_kill(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid = parser_int32(args);
    if (pid == 0) {
        package_add_string(inst, response, XSTR("No PID specified"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hProc = gate_OpenProcess(inst, PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        package_add_string(inst, response, XSTR("Failed to open process"));
        response->is_error = TRUE;
        return;
    }

    if (inst->Win32.TerminateProcess(hProc, 0)) {
        package_add_string(inst, response, XSTR("Process terminated"));
    } else {
        package_add_string(inst, response, XSTR("Failed to terminate process"));
        response->is_error = TRUE;
    }
    gate_CloseHandle(inst, hProc);
}

#endif
