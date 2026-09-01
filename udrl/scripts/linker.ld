SECTIONS
{
    . = 0x0000;

    .text :
    {
        *( .text$A );
        *( .text$B );
        *( .text$C );
        *( .text$D );
        *( .text$E );
        *( .text$F );
        *( .text );
        *( .text.* );
        *( .rdata* );
        *( .rodata* );
        *( .data* );
        *( .idata* );
        *( .CRT* );
        *( .tls* );
        *( .ctors* );
        *( .edata* );
        /* Zero-initialized statics MUST be folded in: objcopy only dumps this
           one output section, so any .bss/COMMON left as an orphan lands at an
           address that is not part of the emitted shellcode at all. */
        *( .bss* );
        *( COMMON );
        KEEP( *(.text$ZZ) );
    }

    /* Discard exception handling and debug sections */
    /DISCARD/ :
    {
        *(.pdata);
        *(.xdata);
        *(.debug*);
        *(.eh_frame);
        *(.note*);
        *(.comment*);
    }
}
