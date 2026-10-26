#include "config.h"
#ifdef INCLUDE_CMD_CAT

#include "commands.h"

VOID cmd_cat(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);
    if (!path || path_len == 0) {
        package_add_string(inst, response, XSTR("No file specified"));
        response->is_error = TRUE;
        return;
    }

    char pathbuf[MAX_PATH] = {0};
    es_memcpy(pathbuf, path, path_len < MAX_PATH-1 ? path_len : MAX_PATH-1);

    HANDLE hFile = inst->Win32.CreateFileA(
        pathbuf, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Failed to open file"));
        response->is_error = TRUE;
        return;
    }

    DWORD file_size = inst->Win32.GetFileSize(hFile, NULL);
    if (file_size == 0 || file_size == INVALID_FILE_SIZE) {
        gate_CloseHandle(inst, hFile);
        package_add_string(inst, response, "");
        return;
    }

    BYTE* buf = (BYTE*)es_malloc(inst, file_size);
    if (!buf) {
        gate_CloseHandle(inst, hFile);
        return;
    }

    DWORD read_bytes = 0;
    inst->Win32.ReadFile(hFile, buf, file_size, &read_bytes, NULL);
    gate_CloseHandle(inst, hFile);

    package_add_bytes(inst, response, buf, read_bytes);
    es_free(inst, buf);
}

#endif
