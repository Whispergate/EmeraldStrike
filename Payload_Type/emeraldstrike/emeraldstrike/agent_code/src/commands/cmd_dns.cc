#include "config.h"
#ifdef INCLUDE_CMD_DNS

#include "commands.h"
#include "json_out.h"

VOID cmd_dns(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0;
    char* host = parser_string(args, &host_len);
    if (!host || host_len == 0) {
        package_add_string(inst, response, XSTR("Usage: dns <hostname>"));
        response->is_error = TRUE;
        return;
    }

    xstr(_ws2, "ws2_32.dll");
    HMODULE h_ws2 = inst->Win32.LoadLibraryA(_ws2);
    typedef int (WINAPI *fn_getaddrinfo_t)(const char*, const char*, void*, void**);
    typedef void (WINAPI *fn_freeaddrinfo_t)(void*);
    fn_getaddrinfo_t pGet = h_ws2 ? (fn_getaddrinfo_t)(void*)inst->Win32.GetProcAddress(h_ws2, "getaddrinfo") : NULL;
    fn_freeaddrinfo_t pFree = h_ws2 ? (fn_freeaddrinfo_t)(void*)inst->Win32.GetProcAddress(h_ws2, "freeaddrinfo") : NULL;
    if (!pGet || !pFree) {
        package_add_string(inst, response, XSTR("ws2_32 resolve failed"));
        response->is_error = TRUE;
        return;
    }

    BYTE hints[64] = {0};
    *(DWORD*)(hints + 4) = 2; // AF_INET
    void* result = NULL;
    int r = pGet(host, NULL, &hints, &result);
    if (r != 0 || !result) {
        package_add_string(inst, response, XSTR("Resolution failed"));
        response->is_error = TRUE;
        return;
    }

    JSON_BUF jb;
    j_init(&jb);
    j_append_raw(&jb, "{\"host\":");
    j_append_str(&jb, host);
    j_append_raw(&jb, ",\"addresses\":[");

    // walk the addrinfo linked list
    void* ai = result;
    DWORD count = 0;
    while (ai && count < 16) {
        // addrinfo: ai_flags(4) ai_family(4) ai_socktype(4) ai_protocol(4)
        //           ai_addrlen(8) ai_canonname(8) ai_addr(8) ai_next(8)
        DWORD family = *(DWORD*)((BYTE*)ai + 4);
        void* addr_ptr = *(void**)((BYTE*)ai + 40);
        void* next = *(void**)((BYTE*)ai + 48);
        if (family == 2 && addr_ptr) { // AF_INET
            DWORD ip = *(DWORD*)((BYTE*)addr_ptr + 4);
            if (count) j_append_raw(&jb, ",");
            unsigned char* b = (unsigned char*)&ip;
            char ip_str[16];
            int p = 0;
            for (int i = 0; i < 4; i++) {
                DWORD v = b[i];
                char tmp[4]; int ti = 0;
                if (v == 0) tmp[ti++] = '0';
                else while (v > 0) { tmp[ti++] = '0' + (char)(v % 10); v /= 10; }
                for (int jj = ti - 1; jj >= 0; jj--) ip_str[p++] = tmp[jj];
                if (i < 3) ip_str[p++] = '.';
            }
            ip_str[p] = 0;
            j_append_str(&jb, ip_str);
            count++;
        }
        ai = next;
    }
    pFree(result);

    j_append_raw(&jb, "],\"count\":");
    j_append_uint(&jb, count);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
