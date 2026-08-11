/* SPDX-License-Identifier: BSD-2-Clause-Patent */
ENTRY(cdk2_graphics_output_entry)
SECTIONS {
	. = 0x1000;
	.text ALIGN(0x1000) : { *(.text .text.*) *(.rodata .rodata.*) }
	.data ALIGN(0x1000) : { *(.data .data.*) *(.bss .bss.*) *(COMMON) }
	.reloc ALIGN(0x1000) : { *(.reloc) }
	/DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) }
}
