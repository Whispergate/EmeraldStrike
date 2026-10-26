[BITS 32]

; PIC entry point for EmeraldStrike x86

DEFAULT REL

GLOBAL _start
GLOBAL ___Instance_offset
GLOBAL ___Instance
GLOBAL __get_instance

EXTERN _main_entry

section .text$A

_start:
    push    ebx
    push    esi
    push    edi
    push    ebp

    call    _rip_ref
_rip_ref:
    pop     ebx
    sub     ebx, _rip_ref

    lea     eax, [ebx + ___Instance]
    mov     [eax], ebx

    lea     eax, [ebx + ___Instance_offset]
    lea     ecx, [ebx + ___Instance]
    sub     ecx, ebx
    mov     [eax], ecx

    push    ebx
    call    _main_entry
    add     esp, 4

    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

section .text$B

__get_instance:
    call    _gi_ref
_gi_ref:
    pop     eax
    sub     eax, _gi_ref
    lea     eax, [eax + ___Instance]
    mov     eax, [eax]
    ret

section .data

___Instance_offset: dd 0
___Instance:        dd 0
