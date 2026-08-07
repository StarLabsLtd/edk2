/* SPDX-License-Identifier: BSD-2-Clause-Patent */
ENTRY(cdk2_status_code_router_entry)
SECTIONS
{
	.text 0x1000 : { *(.text*) }
	.data ALIGN(0x1000) : { *(.rodata*) *(.data*) *(.bss*) *(COMMON) }
	.reloc ALIGN(0x1000) : { *(.reloc) }
}
