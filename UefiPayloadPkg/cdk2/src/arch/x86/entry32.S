/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * coreboot enters x86 payloads in 32-bit protected mode.  The native cdk2
 * body is x86-64, so this entry builds a temporary identity map and performs
 * the same long-mode transition as the EDK II IA32 payload entry.
 */

.section .text.entry, "ax", @progbits
.set CDK2_ENTRY32_IDENTITY_MAP_GIB, 128
.set CDK2_ENTRY32_PAGE_SIZE, 4096
.set CDK2_ENTRY32_PAGE_DIRECTORY_ENTRIES, 512
.set CDK2_ENTRY32_PAGE_DIRECTORY_COUNT, CDK2_ENTRY32_IDENTITY_MAP_GIB
.set CDK2_ENTRY32_PAGE_ENTRY_COUNT, CDK2_ENTRY32_PAGE_DIRECTORY_COUNT * CDK2_ENTRY32_PAGE_DIRECTORY_ENTRIES
.set CDK2_ENTRY32_PAGE_DIRECTORY_BYTES, CDK2_ENTRY32_PAGE_DIRECTORY_COUNT * CDK2_ENTRY32_PAGE_SIZE
.set CDK2_ENTRY32_PAGE_TABLE_BYTES, (2 * CDK2_ENTRY32_PAGE_SIZE) + CDK2_ENTRY32_PAGE_DIRECTORY_BYTES
.set CDK2_ENTRY32_PAGE_TABLE_DWORDS, CDK2_ENTRY32_PAGE_TABLE_BYTES / 4
.set CDK2_ENTRY32_IDENTITY_MAP_TOP, CDK2_ENTRY32_IDENTITY_MAP_GIB << 30
.set CDK2_ENTRY32_BOOT_STACK_SIZE, 0x8000

.globl cdk2_entry32_identity_map_top
.set cdk2_entry32_identity_map_top, CDK2_ENTRY32_IDENTITY_MAP_TOP
.globl cdk2_entry32_page_directory_count
.set cdk2_entry32_page_directory_count, CDK2_ENTRY32_PAGE_DIRECTORY_COUNT
.globl cdk2_entry32_boot_stack_size
.set cdk2_entry32_boot_stack_size, CDK2_ENTRY32_BOOT_STACK_SIZE

.code32
.globl Cdk2CorebootEntry32
.type Cdk2CorebootEntry32, @function
Cdk2CorebootEntry32:
        cli
        cld

        /* protected_mode_call_1arg leaves the argument at 4(%esp). */
        movl    4(%esp), %eax
        movl    %eax, cdk2_bootloader_parameter

        /* Clear the PML4, PDPT, and temporary page directories. */
        movl    $cdk2_pml4, %edi
        xorl    %eax, %eax
        movl    $CDK2_ENTRY32_PAGE_TABLE_DWORDS, %ecx
        rep stosl

        /* PML4[0] -> PDPT. */
        movl    $cdk2_pdpt, %eax
        orl     $0x3, %eax
        movl    %eax, cdk2_pml4

        /* PDPT[0..127] -> page directories covering the first 128 GiB. */
        movl    $cdk2_pd, %edi
        movl    $cdk2_pdpt, %esi
        movl    $CDK2_ENTRY32_PAGE_DIRECTORY_COUNT, %ecx
1:
        movl    %edi, %eax
        orl     $0x3, %eax
        movl    %eax, (%esi)
        addl    $8, %esi
        addl    $0x1000, %edi
        loop    1b

        /*
         * Map 0..128 GiB with writable 2 MiB pages.  StarBook reports its
         * coreboot HOB RAM as 0x100000000..0x1080000000, so this bounded
         * map covers the high arena used before DXE owns paging.
         */
        movl    $cdk2_pd, %edi
        xorl    %edx, %edx
        movl    $CDK2_ENTRY32_PAGE_ENTRY_COUNT, %ecx
2:
        movl    %edx, %eax
        shll    $21, %eax
        orl     $0x83, %eax       /* present, writable, large page */
        movl    %eax, (%edi)
        movl    %edx, %eax
        shrl    $11, %eax         /* high 32 bits of edx << 21 */
        movl    %eax, 4(%edi)
        addl    $8, %edi
        incl    %edx
        loop    2b

        /* Enable PAE, long mode, and paging. */
        movl    %cr4, %eax
        orl     $0x20, %eax       /* CR4.PAE */
        movl    %eax, %cr4

        movl    $cdk2_pml4, %eax
        movl    %eax, %cr3

        movl    $0xc0000080, %ecx /* IA32_EFER */
        rdmsr
        orl     $0x100, %eax      /* EFER.LME */
        wrmsr

        movl    %cr0, %eax
        orl     $0x80000000, %eax /* CR0.PG */
        movl    %eax, %cr0

        /* coreboot's ramstage GDT has a flat 64-bit code selector at 0x18. */
        ljmp    $0x18, $cdk2_long_mode_entry

.code64
cdk2_long_mode_entry:
        movw    $0x10, %ax        /* coreboot's flat data selector */
        movw    %ax, %ds
        movw    %ax, %es
        movw    %ax, %ss
        xorw    %ax, %ax
        movw    %ax, %fs
        movw    %ax, %gs

        movabs  $cdk2_boot_stack_top, %rsp
        andq    $-16, %rsp         /* SysV x64 pre-call alignment */
        movl    cdk2_bootloader_parameter, %edi
        call    Cdk2NativeStageEntry

3:
        cli
        hlt
        jmp     3b

.size Cdk2CorebootEntry32, .-Cdk2CorebootEntry32

.section .text.cdk2.fault, "ax", @progbits
.code64
.globl Cdk2NativeExceptionDeadLoop
.type Cdk2NativeExceptionDeadLoop, @function
Cdk2NativeExceptionDeadLoop:
        cli
4:
        hlt
        jmp     4b
.size Cdk2NativeExceptionDeadLoop, .-Cdk2NativeExceptionDeadLoop

.section .bss, "aw", @nobits
.align 4096
.type cdk2_pml4, @object
cdk2_pml4:
        .skip   CDK2_ENTRY32_PAGE_SIZE
.size cdk2_pml4, .-cdk2_pml4
.type cdk2_pdpt, @object
cdk2_pdpt:
        .skip   CDK2_ENTRY32_PAGE_SIZE
.size cdk2_pdpt, .-cdk2_pdpt
.type cdk2_pd, @object
cdk2_pd:
        .skip   CDK2_ENTRY32_PAGE_DIRECTORY_BYTES
.size cdk2_pd, .-cdk2_pd

.align 16
.type cdk2_boot_stack, @object
cdk2_boot_stack:
        .skip   CDK2_ENTRY32_BOOT_STACK_SIZE
.size cdk2_boot_stack, .-cdk2_boot_stack
cdk2_boot_stack_top:

.align 4
.type cdk2_bootloader_parameter, @object
cdk2_bootloader_parameter:
        .long   0
.size cdk2_bootloader_parameter, .-cdk2_bootloader_parameter
