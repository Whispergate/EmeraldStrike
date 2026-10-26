#include "config.h"
#ifdef INCLUDE_CMD_PS

#include "commands.h"
#include <tlhelp32.h>

VOID cmd_ps(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    HANDLE hSnap = inst->Win32.CreateToolhelp32Snapshot(0x00000002 /*TH32CS_SNAPPROCESS*/, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Failed to create snapshot"));
        response->is_error = TRUE;
        return;
    }

    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!inst->Win32.Process32First(hSnap, &pe)) {
        gate_CloseHandle(inst, hSnap);
        return;
    }

    do {
        // Format: PID\tPPID\tName\n
        char line[512] = {0};
        int pos = 0;

        // PID
        DWORD pid = pe.th32ProcessID;
        char tmp[16]; int ti = 0;
        if (pid == 0) { line[pos++] = '0'; }
        else {
            while (pid > 0) { tmp[ti++] = '0' + (pid % 10); pid /= 10; }
            for (int j = ti - 1; j >= 0; j--) line[pos++] = tmp[j];
        }
        line[pos++] = '\t';

        // PPID
        DWORD ppid = pe.th32ParentProcessID;
        ti = 0;
        if (ppid == 0) { line[pos++] = '0'; }
        else {
            while (ppid > 0) { tmp[ti++] = '0' + (ppid % 10); ppid /= 10; }
            for (int j = ti - 1; j >= 0; j--) line[pos++] = tmp[j];
        }
        line[pos++] = '\t';

        // Name
        for (int i = 0; pe.szExeFile[i] && pos < 500; i++)
            line[pos++] = pe.szExeFile[i];
        line[pos++] = '\n';

        package_add_bytes(inst, response, (BYTE*)line, pos);
    } while (inst->Win32.Process32Next(hSnap, &pe));

    gate_CloseHandle(inst, hSnap);
}

#endif
