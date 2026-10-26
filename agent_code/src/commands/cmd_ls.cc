#include "config.h"
#ifdef INCLUDE_CMD_LS

#include "commands.h"

VOID cmd_ls(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);

    char search_path[MAX_PATH + 4] = {0};
    if (path && path_len > 0) {
        es_memcpy(search_path, path, path_len < MAX_PATH ? path_len : MAX_PATH);
        DWORD end = path_len < MAX_PATH ? path_len : MAX_PATH;
        if (search_path[end-1] != '\\' && search_path[end-1] != '/') {
            search_path[end] = '\\';
            end++;
        }
        search_path[end] = '*';
    } else {
        search_path[0] = '.'; search_path[1] = '\\'; search_path[2] = '*';
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = inst->Win32.FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Directory not found"));
        response->is_error = TRUE;
        return;
    }

    do {
        char line[512] = {0};
        int pos = 0;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            line[pos++] = 'd';
        } else {
            line[pos++] = '-';
        }
        line[pos++] = '\t';

        DWORD size = fd.nFileSizeLow;
        char sizestr[16] = {0};
        int si = 0;
        if (size == 0) { sizestr[si++] = '0'; }
        else {
            char tmp[16]; int ti = 0;
            while (size > 0) { tmp[ti++] = '0' + (size % 10); size /= 10; }
            for (int j = ti - 1; j >= 0; j--) sizestr[si++] = tmp[j];
        }
        for (int i = 0; sizestr[i]; i++) line[pos++] = sizestr[i];
        line[pos++] = '\t';

        for (int i = 0; fd.cFileName[i] && pos < 500; i++)
            line[pos++] = fd.cFileName[i];
        line[pos++] = '\n';

        package_add_bytes(inst, response, (BYTE*)line, pos);
    } while (inst->Win32.FindNextFileA(hFind, &fd));

    inst->Win32.FindClose(hFind);
}

#endif
