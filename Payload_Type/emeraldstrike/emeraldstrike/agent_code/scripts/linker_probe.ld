/* Probe link script: identical layout to linker.ld but with .text placed at a
   non-zero VMA. Linking the same objects twice and diffing the two .text blobs
   yields the exact set of dwords that hold absolute addresses, which the x86
   loader turns into runtime relocations (x86 has no RIP-relative addressing). */

SECTIONS
{
    .text 0x10000 :
    {
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .text$* );
        *( .text );
        *( .rdata* );
        *( .rodata* );
        *( .data );
        *( .bss );
    }
}
