; PIC entry point for EmeraldStrike x86.
;
; Every symbol reference below is written as (label - _start) so NASM assembles
; it into a plain constant instead of a relocation record. That is deliberate:
; the loader runs a runtime relocation pass over the shellcode which biases the
; C code's absolute addresses by the load base (x86 has no RIP-relative
; addressing). If this stub also carried relocations, its base-relative
; [ebx + off] displacements would get the base added a second time and the
; agent would fault on the first INSTANCE access.
;
; The relocation list is produced at build time by diffing two links of the
; same objects at different VMAs (see Makefile x86 target and linker_probe.ld).

[BITS 32]

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
    sub     ebx, _rip_ref - _start          ; ebx = load base

    ; __Instance must point at the dedicated storage buffer, never at the image
    ; base: main_entry() memsets sizeof(INSTANCE) bytes through it and would
    ; erase this stub and the code that follows if it aliased the base.
    lea     eax, [ebx + ___Instance - _start]
    lea     ecx, [ebx + ___InstanceStorage - _start]
    mov     [eax], ecx

    ; __Instance_offset = ___Instance - base
    lea     eax, [ebx + ___Instance_offset - _start]
    mov     ecx, ___Instance - _start
    mov     [eax], ecx

    push    ebx
    call    _main_entry
    add     esp, 4

    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

__get_instance:
    call    _gi_ref
_gi_ref:
    pop     eax
    sub     eax, _gi_ref - _start
    lea     eax, [eax + ___Instance - _start]
    mov     eax, [eax]
    ret

___Instance_offset: dd 0
___Instance:        dd 0
___InstanceStorage: times 16384 db 0
