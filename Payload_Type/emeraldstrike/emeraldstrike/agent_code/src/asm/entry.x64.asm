[BITS 64]
DEFAULT REL

GLOBAL _start
GLOBAL __Instance_offset
GLOBAL __Instance
GLOBAL _get_instance

EXTERN main_entry

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

section .text$C

__Instance_offset:  dd 0
__Instance:         dq 0
__InstanceStorage:  times 16384 db 0
