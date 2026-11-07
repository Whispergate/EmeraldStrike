SECTIONS
{
    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .text$* );
        *( .text );
        *( .rdata* );
        *( .rodata* );
        *( .data );
        *( .bss );
        *( .instdata );
    }
}
