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
        *( .xdata* );
        . = ALIGN(4);
        __pdata_start = .;
        *( .pdata* );
        __pdata_end = .;
        *( .instdata );
    }
}
