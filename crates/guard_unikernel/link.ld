ENTRY(_start)

SECTIONS
{
    . = 0x40080000;

    .text : {
        KEEP(*(.text._start)) /* CRITICAL: Prevents the linker from deleting our entry point */
        *(.text*)
    }

    .rodata : ALIGN(8) {
        *(.rodata*)
        *(.srodata*)
    }

    .data : ALIGN(8) {
        *(.data*)
        *(.sdata*)
    }

    .bss : ALIGN(8) {
        __bss_start = .;
        *(.bss*)
        *(COMMON)
        __bss_end = .;
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.note*)
    }
}
