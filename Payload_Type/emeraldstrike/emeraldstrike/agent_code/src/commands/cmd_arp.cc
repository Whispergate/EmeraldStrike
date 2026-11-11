#include "config.h"
#ifdef INCLUDE_CMD_ARP

#include "commands.h"
#include "json_out.h"

// iphlpapi: GetIpNetTable
typedef void* PILH;
typedef DWORD (WINAPI *fn_GetIpNetTable_t)(void*, DWORD*, BOOL);
typedef DWORD (WINAPI *fn_GetIfEntry_t)(void*);

#pragma pack(push, 1)
struct MIB_IPNETROW_A {
    DWORD dwIndex;
    DWORD dwPhysAddrLen;
    BYTE  bPhysAddr[8];
    DWORD dwAddr;
    DWORD dwType;
};
struct MIB_IPNETTABLE_A {
    DWORD dwNumEntries;
    MIB_IPNETROW_A table[1];
};
#pragma pack(pop)

static void ip_to_str(DWORD ip, char* out) {
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

VOID cmd_arp(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_iph, "iphlpapi.dll");
    HMODULE h_iph = inst->Win32.LoadLibraryA(_iph);
    fn_GetIpNetTable_t pGet = h_iph ?
        (fn_GetIpNetTable_t)resolve_function(h_iph, hash_string_djb2(XSTR("GetIpNetTable"))) : NULL;
    if (!pGet) {
        package_add_string(inst, response, XSTR("iphlpapi resolve failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD size = 0;
    if (pGet(NULL, &size, FALSE) != 122 /*ERROR_INSUFFICIENT_BUFFER*/ || size == 0) {
        package_add_string(inst, response, XSTR("no ARP entries"));
        return;
    }
    // align to avoid unaligned access on the packed struct array
    static BYTE* buf = NULL;
    // heap-resident: static arrays embed zero-filled in the PIC blob
    if (!buf) buf = (BYTE*)es_malloc(inst, 65536);
    if (!buf) return;
    if (size > sizeof(buf)) size = sizeof(buf);
    if (pGet(buf, &size, FALSE) != 0) {
        package_add_string(inst, response, XSTR("GetIpNetTable failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD count = *(DWORD*)buf;
    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"arp\":[");
    DWORD printed = 0;
    for (DWORD i = 0; i < count; i++) {
        MIB_IPNETROW_A* row = (MIB_IPNETROW_A*)(buf + 4 + i * sizeof(MIB_IPNETROW_A));
        if (row->dwPhysAddrLen == 0) continue;
        if (printed) j_append_raw(&jb, ",");
        j_append_raw(&jb, "{\"ip\":");
        char ip[16];
        ip_to_str(row->dwAddr, ip);
        j_append_str(&jb, ip);
        j_append_raw(&jb, ",\"mac\":\"");
        for (DWORD m = 0; m < row->dwPhysAddrLen && m < 8; m++) {
            if (m) j_append_raw(&jb, ":");
            char mb[4];
            mb[0] = "0123456789abcdef"[(row->bPhysAddr[m] >> 4) & 0xF];
            mb[1] = "0123456789abcdef"[row->bPhysAddr[m] & 0xF];
            mb[2] = 0;
            j_append_raw(&jb, mb);
        }
        j_append_raw(&jb, "\",\"type\":");
        j_append_uint(&jb, row->dwType);
        j_append_raw(&jb, "}");
        printed++;
    }
    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, printed);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
