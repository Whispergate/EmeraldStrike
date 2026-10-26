#include "config.h"
#ifdef INCLUDE_CMD_CP

#include "commands.h"

VOID cmd_cp(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD src_len = 0, dst_len = 0;
    char* src = parser_string(args, &src_len);
    char* dst = parser_string(args, &dst_len);

    if (!src || !dst || src_len == 0 || dst_len == 0) {
        package_add_string(inst, response, XSTR("Usage: cp <src> <dst>"));
        response->is_error = TRUE;
        return;
    }

    char srcbuf[MAX_PATH] = {0}, dstbuf[MAX_PATH] = {0};
    es_memcpy(srcbuf, src, src_len < MAX_PATH-1 ? src_len : MAX_PATH-1);
    es_memcpy(dstbuf, dst, dst_len < MAX_PATH-1 ? dst_len : MAX_PATH-1);

    if (inst->Win32.CopyFileA(srcbuf, dstbuf, FALSE)) {
        package_add_string(inst, response, XSTR("File copied"));
    } else {
        package_add_string(inst, response, XSTR("Failed to copy file"));
        response->is_error = TRUE;
    }
}

#endif
