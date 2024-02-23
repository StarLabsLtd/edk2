;-------------------------------------------------------------------------------
; Copyright (c) 2025, 9elements GmbH. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   TransferExec.nasm
;
; Abstract:
;
;   Code to transfer execution between bootloader SMM and payload MM
;
;-------------------------------------------------------------------------------

%include "Nasm.inc"

;
; Types referenced by ASM code
;

struc Edk2PrivateData
  PrivateDataStackPointers: resq 1
  PrivateDataPageTable: resd 1
  Intel5LevelPagingNeeded: resb 1
  XdSupported: resb 1
  MsrIa32MiscEnableSupported: resb 1
endstruc

struc PayloadMmCallContext
  MmEntryPointArg1: resq 1
  MmEntryPointArg2: resq 1
  MmEntryPointArg3: resq 1
  ImplementationPrivateData: resq 1
endstruc

;
; Variables referenced by ASM code
;

%define MSR_IA32_MISC_ENABLE  0x1A0
%define MSR_EFER  0xc0000080

; Refer to coreboot's SMM entry code. Preserving DS.
%define PROTECTED_MODE_CS 0x08
%define LONG_MODE_CS 0x18

extern ASM_PFX(CEntryPoint)

    DEFAULT REL
    SECTION .text

;UINT8
;sysv_abi
;_ModuleEntryPoint (
;  PAYLOAD_MM_CORE_CALL_CONTEXT  *PayloadMmCallContext
;  )

global ASM_PFX(_ModuleEntryPoint)
ASM_PFX(_ModuleEntryPoint):
BITS 32
    ; x86 assembly vs machine code trickery.
    xor     eax, eax
    db      0x40, 0x90                  ; 32-bit decodes: inc eax, nop
                                        ; 64-bit decodes: rex xchg eax, eax
    jz      NativeModeCallCEntry

global ASM_PFX(ModeSwitchCallCEntry)
ASM_PFX(ModeSwitchCallCEntry):
    ; Switch stack
    mov     ecx, esp
    mov     edx, ebp

    ; Acquire internal private data
    mov     ebx, [esp + 4]
    mov     ebx, [ebx + ImplementationPrivateData]

    ; Really, need per-CPU stack.
    mov     eax, [ebx + PrivateDataStackPointers]
    mov     esp, dword [eax]

    push    ecx
    push    edx

    ; System V ABI: Preserve registers (not truly required by X64 ABI)
    ;push    ebx
    push    esi
    push    edi

    ; System V ABI: Stash argument
    mov     edi, [ecx + 4]

    ; Enable features
    mov     eax, cr3
    push    eax

    mov     eax, dword [ebx + PrivateDataPageTable]
    mov     cr3, eax

    mov     eax, cr4
    push    eax
    or      eax, 0x660                  ; as cr4.PGE is not set here, refresh cr3

    cmp     byte [ebx + Intel5LevelPagingNeeded], 0
    je      .SkipEnable5LevelPaging
    or      eax, BIT12                  ; set LA57 bit
.SkipEnable5LevelPaging:

    mov     cr4, eax                    ; in PreModifyMtrrs() to flush TLB

    sub     esp, 6
    sidt    [esp]

; enable NXE if supported
    cmp     byte [ebx + XdSupported], 0
    jz      .SkipXd

; If MSR_IA32_MISC_ENABLE is supported, clear XD Disable bit
    cmp     byte [ebx + MsrIa32MiscEnableSupported], 1
    jz      .MsrIa32MiscEnableSupported

; MSR_IA32_MISC_ENABLE not supported
    xor     edx, edx
    push    edx                         ; don't try to restore the XD Disable bit just before RSM
    jmp     .EnableNxe

; Check XD disable bit
.MsrIa32MiscEnableSupported:
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    push    edx                         ; save MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2                   ; MSR_IA32_MISC_ENABLE[34]
    jz      .EnableNxe
    and     dx, ~BIT2                   ; clear XD Disable bit if it is set
    wrmsr
.EnableNxe:
    mov     ecx, MSR_EFER
    rdmsr
    or      ax, BIT11                   ; enable NXE
    wrmsr
.SkipXd:

    mov     ecx, MSR_EFER
    rdmsr
    or      ax, BIT8                    ; enable LME
    wrmsr

    mov     eax, cr0
    push    eax
    or      eax, 0x80010022             ; enable paging + WP + NE + MP

    mov     cr0, eax

; Switch into @LongMode
    push    LONG_MODE_CS
    call    .Base
.Base:
    add     dword [esp], .@LongMode - .Base
    retf

BITS 64
.@LongMode:
; coreboot controls silicon-specific features, such as CET.

    ; FXSAVE data requires 16-bit alignment. Save the stack (FXSAVE workaround).
    mov     r12, rsp
    and     rsp, ~0xF

    ;
    ; Save FP registers
    ;
    sub     rsp, 0x200
    fxsave64 [rsp]

    ; Reserve a shadow store and do ABI conversion
    sub     rsp, 0x20
    mov     rcx, rdi
    call    ASM_PFX(CEntryPoint)
    add     rsp, 0x20

    ;
    ; Restore FP registers
    ;
    fxrstor64 [rsp]
    add     rsp, 0x200

    ; FXSAVE data requires 16-bit alignment. Restore the stack (FXSAVE workaround).
    mov     rsp, r12

; Switch into @CompatMode
    mov     rcx, dword PROTECTED_MODE_CS
    shl     rcx, 32
    lea     rdx, [.@CompatMode]
    or      rcx, rdx
    push    rcx
    retf

BITS 32
.@CompatMode:
    pop     eax
    mov     cr0, eax

    mov     ecx, MSR_EFER
    rdmsr
    and     ax, ~BIT8                   ; disable LME
    wrmsr

    cmp     byte [ebx + XdSupported], 0
    jz      .1

    mov     ecx, MSR_EFER
    rdmsr
    and     ax, ~BIT11                  ; disable NXE
    wrmsr

    pop     edx                         ; get saved MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2
    jz      .1
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    or      dx, BIT2                    ; set XD Disable bit if it was set before
    wrmsr

.1:
    lidt    [esp]
    add     esp, 6

    ; Disable features
    pop     eax
    mov     cr4, eax

    pop     eax
    mov     cr3, eax

    ; System V ABI: Restore registers
    pop     edi
    pop     esi
    ;pop     ebx

    ; Switch stack
    pop     edx
    pop     ecx

    mov     ebp, edx
    mov     esp, ecx

    ; Set PAYLOAD_MM_RET_SUCCESS; TODO: Real return value.
    xor     eax, eax

    ret

global ASM_PFX(NativeModeCallCEntry)
ASM_PFX(NativeModeCallCEntry):
BITS 64
    ; Switch stack
    mov     rcx, rsp
    mov     rdx, rbp

    ; Acquire internal private data
    mov     rbx, [rdi + ImplementationPrivateData]

    ; Really, need per-CPU stack.
    mov     rax, [rbx + PrivateDataStackPointers]
    mov     esp, dword [rax]

    push    rcx
    push    rdx

    ; System V ABI: Preserve registers (not truly required by X64 ABI)
    ;push    rbx
    push    r12
    push    r13
    push    r14
    push    r15

    ; Enable features
    mov     rax, cr3
    push    rax

    mov     eax, dword [rbx + PrivateDataPageTable]
    mov     cr3, rax

    mov     rax, cr4
    push    rax
    or      rax, 0x660                  ; as cr4.PGE is not set here, refresh cr3

    cmp     byte [rbx + Intel5LevelPagingNeeded], 0
    je      .SkipEnable5LevelPaging
    or      rax, BIT12                  ; set LA57 bit
.SkipEnable5LevelPaging:

    mov     cr4, rax                    ; in PreModifyMtrrs() to flush TLB

    sub     rsp, 10
    sidt    [rsp]

; enable NXE if supported
    cmp     byte [rbx + XdSupported], 0
    jz      .SkipXd

; If MSR_IA32_MISC_ENABLE is supported, clear XD Disable bit
    cmp     byte [rbx + MsrIa32MiscEnableSupported], 1
    jz      .MsrIa32MiscEnableSupported

; MSR_IA32_MISC_ENABLE not supported
    xor     edx, edx
    push    rdx                         ; don't try to restore the XD Disable bit just before RSM
    jmp     .EnableNxe

; Check XD disable bit
.MsrIa32MiscEnableSupported:
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    push    rdx                         ; save MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2                   ; MSR_IA32_MISC_ENABLE[34]
    jz      .EnableNxe
    and     dx, ~BIT2                   ; clear XD Disable bit if it is set
    wrmsr
.EnableNxe:
    mov     ecx, MSR_EFER
    rdmsr
    or      ax, BIT11                   ; enable NXE
    wrmsr
.SkipXd:

    mov     rax, cr0
    push    rax
    or      eax, 0x80010022             ; enable paging + WP + NE + MP

    mov     cr0, rax

; coreboot controls silicon-specific features, such as CET.

    ; FXSAVE data requires 16-bit alignment. Save the stack (FXSAVE workaround).
    mov     r12, rsp
    and     rsp, ~0xF

    ;
    ; Save FP registers
    ;
    sub     rsp, 0x200
    fxsave64 [rsp]

    ; Reserve a shadow store and do ABI conversion
    sub     rsp, 0x20
    mov     rcx, rdi
    call    ASM_PFX(CEntryPoint)
    add     rsp, 0x20

    ;
    ; Restore FP registers
    ;
    fxrstor64 [rsp]
    add     rsp, 0x200

    ; FXSAVE data requires 16-bit alignment. Restore the stack (FXSAVE workaround).
    mov     rsp, r12

    pop     rax
    mov     cr0, rax

    cmp     byte [rbx + XdSupported], 0
    jz      .1

    mov     ecx, MSR_EFER
    rdmsr
    and     ax, ~BIT11                  ; disable NXE
    wrmsr

    pop     rdx                         ; get saved MSR_IA32_MISC_ENABLE[63-32]
    test    edx, BIT2
    jz      .1
    mov     ecx, MSR_IA32_MISC_ENABLE
    rdmsr
    or      dx, BIT2                    ; set XD Disable bit if it was set before
    wrmsr

.1:
    lidt    [rsp]
    add     rsp, 10

    ; Disable features
    pop     rax
    mov     cr4, rax

    pop     rax
    mov     cr3, rax

    ; System V ABI: Restore registers
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    ;pop     rbx

    ; Switch stack
    pop     rdx
    pop     rcx

    mov     rbp, rdx
    mov     rsp, rcx

    ; Set PAYLOAD_MM_RET_SUCCESS; TODO: Real return value.
    xor     rax, rax

    ret
