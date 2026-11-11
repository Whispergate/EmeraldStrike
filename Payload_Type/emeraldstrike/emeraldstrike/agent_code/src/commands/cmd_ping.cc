#include "config.h"
#ifdef INCLUDE_CMD_PING

#include "commands.h"
#include "json_out.h"

typedef HANDLE (WINAPI *fn_IcmpCreateFile_t)(void);
typedef DWORD (WINAPI *fn_IcmpSendEcho_t)(HANDLE, DWORD, void*, WORD, void*, void*, DWORD, DWORD);
typedef BOOL (WINAPI *fn_IcmpCloseHandle_t)(HANDLE);

#pragma pack(push, 1)
struct ICMP_ECHO_REPLY_A {
    DWORD addr;
    DWORD status;
    DWORD round_trip;
    WORD  data_size;
    WORD  reserved;
    void* data_ptr;
    // ... more fields we don't need
};
#pragma pack(pop)

static DWORD resolve_ip(PINSTANCE inst, const char* hostname) {
    // use getaddrinfo from ws2_32
    xstr(_ws2, "ws2_32.dll");
    HMODULE h_ws2 = inst->Win32.LoadLibraryA(_ws2);
    if (!h_ws2) return 0;
    typedef int (WINAPI *fn_getaddrinfo_t)(const char*, const char*, void*, void**);
    typedef void (WINAPI *fn_freeaddrinfo_t)(void*);
    fn_getaddrinfo_t pGet = (fn_getaddrinfo_t)(void*)inst->Win32.GetProcAddress(h_ws2, "getaddrinfo");
    fn_freeaddrinfo_t pFree = (fn_freeaddrinfo_t)(void*)inst->Win32.GetProcAddress(h_ws2, "freeaddrinfo");
    if (!pGet || !pFree) return 0;
    // addrinfo minimal: flags,family,socktype,proto,addrlen,canonname,addr,next
    BYTE hints[64] = {0};
    *(DWORD*)(hints + 4) = 2; // AF_INET
    void* result = NULL;
    if (pGet(hostname, NULL, &hints, &result) != 0 || !result) return 0;
    // get the first IPv4 address: addrinfo at [16] = sockaddr pointer
    void* ai = result;
    void* sa = *(void**)((BYTE*)ai + 32);
    DWORD ip = sa ? *(DWORD*)((BYTE*)sa + 4) : 0; // sin_addr at offset 4
    pFree(result);
    return ip;
}

VOID cmd_ping(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0, count = 0;
    char* host = parser_string(args, &host_len);
    char* count_str = parser_string(args, &count);
    if (!host || host_len == 0) {
        package_add_string(inst, response, XSTR("Usage: ping <host> [count]"));
        response->is_error = TRUE;
        return;
    }
    DWORD num_pings = 4;
    if (count_str && count > 0) {
        DWORD v = 0;
        for (DWORD i = 0; i < count && count_str[i] >= '0' && count_str[i] <= '9'; i++)
            v = v * 10 + (count_str[i] - '0');
        if (v > 0 && v <= 20) num_pings = v;
    }

    xstr(_iph, "iphlpapi.dll");
    HMODULE h_iph = inst->Win32.LoadLibraryA(_iph);
    fn_IcmpCreateFile_t pCreate = h_iph ? (fn_IcmpCreateFile_t)(void*)inst->Win32.GetProcAddress(h_iph, "IcmpCreateFile") : NULL;
    fn_IcmpSendEcho_t pSend = h_iph ? (fn_IcmpSendEcho_t)(void*)inst->Win32.GetProcAddress(h_iph, "IcmpSendEcho") : NULL;
    fn_IcmpCloseHandle_t pCloseIcmp = h_iph ? (fn_IcmpCloseHandle_t)(void*)inst->Win32.GetProcAddress(h_iph, "IcmpCloseHandle") : NULL;
    if (!pCreate || !pSend || !pCloseIcmp) {
        package_add_string(inst, response, XSTR("ICMP resolve failed"));
        response->is_error = TRUE;
        return;
    }

    DWORD ip = resolve_ip(inst, host);
    if (ip == 0) {
        package_add_string(inst, response, XSTR("DNS resolution failed"));
        response->is_error = TRUE;
        return;
    }

    HANDLE hIcmp = pCreate();
    if (hIcmp == INVALID_HANDLE_VALUE) {
        package_add_string(inst, response, XSTR("IcmpCreateFile failed"));
        response->is_error = TRUE;
        return;
    }

    char send_buf[32];
    es_memset(send_buf, 0xAB, 32);
    BYTE reply_buf[512];

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"host\":");
    j_append_str(&jb, host);
    j_append_raw(&jb, ",\"pings\":[");

    DWORD ok_count = 0;
    for (DWORD i = 0; i < num_pings; i++) {
        if (i) j_append_raw(&jb, ",");
        // IcmpSendEcho reply buffer: at minimum 8 bytes (addr + status) + 32 data
        DWORD ret = pSend(hIcmp, ip, send_buf, 32, NULL, reply_buf, sizeof(reply_buf), 2000);
        BOOL got_reply = (ret > 0);
        // reply_buf: DWORD addr; DWORD status; DWORD round_trip_time
        DWORD rt_time = 0, r_status = 0;
        if (got_reply) {
            DWORD rep_addr = *(DWORD*)reply_buf;
            r_status = *(DWORD*)(reply_buf + 4);
            rt_time = *(DWORD*)(reply_buf + 8);
            got_reply = (r_status == 0);
        }
        j_append_raw(&jb, "{\"ok\":");
        j_append_bool(&jb, got_reply);
        j_append_raw(&jb, ",\"rtt\":");
        j_append_uint(&jb, got_reply ? rt_time : 0);
        j_append_raw(&jb, "}");
        if (got_reply) ok_count++;
        inst->Win32.Sleep(500);
    }
    pCloseIcmp(hIcmp);

    j_append_raw(&jb, "],\"sent\":");
    j_append_uint(&jb, num_pings);
    j_append_raw(&jb, ",\"received\":");
    j_append_uint(&jb, ok_count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
