#include "config.h"
#ifdef INCLUDE_CMD_PROCINFO

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_QueryFullProcessImageNameA_t)(HANDLE, DWORD, char*, DWORD*);

VOID cmd_procinfo(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD pid_len = 0;
    char* pid_str = parser_string(args, &pid_len);
    if (!pid_str || pid_len == 0) {
        package_add_string(inst, response, XSTR("Usage: procinfo <pid>"));
        response->is_error = TRUE;
        return;
    }
    DWORD pid = 0;
    for (DWORD i = 0; i < pid_len; i++) {
        if (pid_str[i] >= '0' && pid_str[i] <= '9') pid = pid * 10 + (pid_str[i] - '0');
    }

    xstr(_k32, "kernel32.dll");
    HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
    typedef DWORD (WINAPI *fn_QueryFullProcessImageNameA_t)(HANDLE, DWORD, char*, DWORD*);

    HANDLE h_proc = inst->Win32.OpenProcess(
        0x1000 /*QUERY_LIMITED*/ | 0x0400 /*DUP_HANDLE*/, FALSE, pid);
    if (!h_proc) {
        package_add_string(inst, response, XSTR("OpenProcess failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"pid\":");
    j_append_uint(&jb, pid);

    // image path
    fn_QueryFullProcessImageNameA_t pQFPIN = (fn_QueryFullProcessImageNameA_t)(void*)inst->Win32.GetProcAddress(
        h_k32, "QueryFullProcessImageNameA");
    j_append_raw(&jb, ",\"path\":");
    if (pQFPIN) {
        char path[512] = {0};
        DWORD psz = 511;
        if (pQFPIN(h_proc, 0, path, &psz) && psz > 0)
            j_append_str(&jb, path);
        else
            j_append_str(&jb, "-");
    } else {
        j_append_str(&jb, "-");
    }

    // user from token
    j_append_raw(&jb, ",\"user\":");
    HANDLE h_tok = NULL;
    BOOL got_user = FALSE;
    char user_buf[128] = "-";
    typedef BOOL (WINAPI *fn_OpenProcTok_t)(HANDLE, DWORD, PHANDLE);
    typedef BOOL (WINAPI *fn_GetTokInfo_t)(HANDLE, DWORD, void*, DWORD, DWORD*);
    typedef BOOL (WINAPI *fn_LookupAcctSidW_t)(LPCWSTR, void*, LPWSTR, LPDWORD, LPWSTR, LPDWORD, void*);
    typedef int (WINAPI *fn_wc2mb_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
    xstr(_adv, "advapi32.dll");
    HMODULE h_adv = inst->Win32.LoadLibraryA(_adv);
    fn_OpenProcTok_t pOpenTok = h_adv ? (fn_OpenProcTok_t)(void*)inst->Win32.GetProcAddress(h_adv, "OpenProcessToken") : NULL;
    fn_GetTokInfo_t pTokInfo = h_adv ? (fn_GetTokInfo_t)(void*)inst->Win32.GetProcAddress(h_adv, "GetTokenInformation") : NULL;
    fn_LookupAcctSidW_t pLookup = h_adv ? (fn_LookupAcctSidW_t)(void*)inst->Win32.GetProcAddress(h_adv, "LookupAccountSidW") : NULL;
    fn_wc2mb_t pWC2MB = (fn_wc2mb_t)(void*)inst->Win32.GetProcAddress(h_k32, "WideCharToMultiByte");
    if (pOpenTok && pTokInfo && pOpenTok(h_proc, 0x0008, &h_tok)) {
        BYTE tok_buf[128];
        DWORD needed = 0;
        if (pTokInfo(h_tok, 1 /*TokenUser*/, tok_buf, 128, &needed) && needed >= 8) {
            void* sid = *(void**)tok_buf;
            if (sid && pLookup && pWC2MB) {
                wchar_t wname[64] = {0}, wdom[64] = {0};
                DWORD wnl = 64, wdl = 64, use = 0;
                if (pLookup(NULL, sid, wname, &wnl, wdom, &wdl, &use)) {
                    char nb[64] = {0}, db[64] = {0};
                    pWC2MB(0, 0, wname, -1, nb, 64, NULL, NULL);
                    pWC2MB(0, 0, wdom, -1, db, 64, NULL, NULL);
                    int up = 0;
                    BOOL have_dom = FALSE;
                    for (int d = 0; db[d]; d++) if (db[d] != ' ') { have_dom = TRUE; break; }
                    if (have_dom) { for (int d = 0; db[d]; d++) user_buf[up++] = db[d]; user_buf[up++] = '\\'; }
                    for (int n = 0; nb[n]; n++) user_buf[up++] = nb[n];
                    user_buf[up] = 0;
                    got_user = TRUE;
                }
            }
        }
        gate_CloseHandle(inst, h_tok);
    }
    j_append_str(&jb, user_buf);
    gate_CloseHandle(inst, h_proc);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
