SECTIONS
{
    .text :
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
