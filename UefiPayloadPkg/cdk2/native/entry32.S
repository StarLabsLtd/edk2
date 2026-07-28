/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * coreboot enters x86 payloads in 32-bit protected mode.  The native cdk2
 * body is x86-64, so this entry builds a temporary identity map and performs
 * the same long-mode transition as the EDK II IA32 payload entry.
 */

.section .text.entry, "ax", @progbits
.code32
.globl Cdk2CorebootEntry32
.type Cdk2CorebootEntry32, @function
Cdk2CorebootEntry32:
        cli
        cld

        /* protected_mode_call_1arg leaves the argument at 4(%esp). */
        movl    4(%esp), %eax
        movl    %eax, cdk2_bootloader_parameter

        /* Clear the PML4, PDPT, and four page directories. */
        movl    $cdk2_pml4, %edi
        xorl    %eax, %eax
        movl    $6144, %ecx
        rep stosl

        /* PML4[0] -> PDPT. */
        movl    $cdk2_pdpt, %eax
        orl     $0x3, %eax
        movl    %eax, cdk2_pml4

        /* PDPT[0..3] -> four page directories. */
        movl    $cdk2_pd, %edi
        movl    $cdk2_pdpt, %esi
        movl    $4, %ecx
1:
        movl    %edi, %eax
        orl     $0x3, %eax
        movl    %eax, (%esi)
        addl    $8, %esi
        addl    $0x1000, %edi
        loop    1b

        /* Map 0..4 GiB with writable 2 MiB pages. */
        movl    $cdk2_pd, %edi
        xorl    %edx, %edx
        movl    $2048, %ecx
2:
        movl    %edx, %eax
        shll    $21, %eax
        orl     $0x83, %eax       /* present, writable, large page */
        movl    %eax, (%edi)
        movl    $0, 4(%edi)
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
        andq    $-16, %rsp
        subq    $8, %rsp           /* SysV x64 call-entry alignment */
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
cdk2_pml4:
        .skip   4096
cdk2_pdpt:
        .skip   4096
cdk2_pd:
        .skip   16384

.align 16
cdk2_boot_stack:
        .skip   0x8000
cdk2_boot_stack_top:

.align 4
cdk2_bootloader_parameter:
        .long   0
