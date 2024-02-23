;------------------------------------------------------------------------------ ;
; Copyright (c) 2016 - 2018, Intel Corporation. All rights reserved.<BR>
; SPDX-License-Identifier: BSD-2-Clause-Patent
;
; Module Name:
;
;   SmiException.nasm
;
; Abstract:
;
;   Exception handlers used in SM mode
;
;-------------------------------------------------------------------------------

extern  ASM_PFX(SmiPFHandler)

    SECTION .data

global ASM_PFX(gSmiHandlerIdtr)
ASM_PFX(gSmiHandlerIdtr):
    DW      0
    DQ      0

    DEFAULT REL
    SECTION .text

;------------------------------------------------------------------------------
; _SmiExceptionEntryPoints is the collection of exception entrypoints followed
; by a common exception handler.
;
; Stack frame would be as follows as specified in IA32 manuals:
;
; +---------------------+ <-- 16-byte aligned ensured by processor
; +    Old SS           +
; +---------------------+
; +    Old RSP          +
; +---------------------+
; +    RFlags           +
; +---------------------+
; +    CS               +
; +---------------------+
; +    RIP              +
; +---------------------+
; +    Error Code       +
; +---------------------+
; +   Vector Number     +
; +---------------------+
; +    RBP              +
; +---------------------+ <-- RBP, 16-byte aligned
;
; RSP set to odd multiple of 8 at @CommonEntryPoint means ErrCode PRESENT
;------------------------------------------------------------------------------
global ASM_PFX(PageFaultIdtHandlerSmmProfile)
ASM_PFX(PageFaultIdtHandlerSmmProfile):
    push    0xe                         ; Page Fault
    test    spl, 8                      ; odd multiple of 8 => ErrCode present
    jnz     .0
    push    qword [rsp]                       ; duplicate INT# if no ErrCode
    mov     qword [rsp + 8], 0
.0:
    push    rbp
    mov     rbp, rsp

    ;
    ; Since here the stack pointer is 16-byte aligned, so
    ; EFI_FX_SAVE_STATE_X64 of EFI_SYSTEM_CONTEXT_x64
    ; is 16-byte aligned
    ;

;; UINT64  Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
;; UINT64  R8, R9, R10, R11, R12, R13, R14, R15;
    push    r15
    push    r14
    push    r13
    push    r12
    push    r11
    push    r10
    push    r9
    push    r8
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    qword [rbp + 48]  ; RSP
    push    qword [rbp]       ; RBP
    push    rsi
    push    rdi

;; UINT64  Gs, Fs, Es, Ds, Cs, Ss;  insure high 16 bits of each is zero
    movzx   rax, word [rbp + 56]
    push    rax                      ; for ss
    movzx   rax, word [rbp + 32]
    push    rax                      ; for cs
    mov     rax, ds
    push    rax
    mov     rax, es
    push    rax
    mov     rax, fs
    push    rax
    mov     rax, gs
    push    rax

;; UINT64  Rip;
    push    qword [rbp + 24]

;; UINT64  Gdtr[2], Idtr[2];
    sub     rsp, 16
    sidt    [rsp]
    sub     rsp, 16
    sgdt    [rsp]

;; UINT64  Ldtr, Tr;
    xor     rax, rax
    str     ax
    push    rax
    sldt    ax
    push    rax

;; UINT64  RFlags;
    push    qword [rbp + 40]

;; UINT64  Cr0, Cr1, Cr2, Cr3, Cr4, Cr8;
    mov     rax, cr8
    push    rax
    mov     rax, cr4
    or      rax, 0x208
    mov     cr4, rax
    push    rax
    mov     rax, cr3
    push    rax
    mov     rax, cr2
    push    rax
    xor     rax, rax
    push    rax
    mov     rax, cr0
    push    rax

;; UINT64  Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
    mov     rax, dr7
    push    rax
    mov     rax, dr6
    push    rax
    mov     rax, dr3
    push    rax
    mov     rax, dr2
    push    rax
    mov     rax, dr1
    push    rax
    mov     rax, dr0
    push    rax

;; FX_SAVE_STATE_X64 FxSaveState;

    sub rsp, 512
    mov rdi, rsp
    fxsave [rdi]

; UEFI calling convention for x64 requires that Direction flag in EFLAGs is clear
    cld

;; UINT32  ExceptionData;
    push    qword [rbp + 16]

;; call into exception handler
    mov     rcx, [rbp + 8]
    lea     rax, [ASM_PFX(SmiPFHandler)]

;; Prepare parameter and call
    mov     rdx, rsp
    ;
    ; Per X64 calling convention, allocate maximum parameter stack space
    ; and make sure RSP is 16-byte aligned
    ;
    sub     rsp, 4 * 8 + 8
    call    rax
    add     rsp, 4 * 8 + 8
    jmp     .1

.1:
;; UINT64  ExceptionData;
    add     rsp, 8

;; FX_SAVE_STATE_X64 FxSaveState;

    mov rsi, rsp
    fxrstor [rsi]
    add rsp, 512

;; UINT64  Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
;; Skip restoration of DRx registers to support debuggers
;; that set breakpoints in interrupt/exception context
  add     rsp, 8 * 6

;; UINT64  Cr0, Cr1, Cr2, Cr3, Cr4, Cr8;
    pop     rax
    mov     cr0, rax
    add     rsp, 8   ; not for Cr1
    pop     rax
    mov     cr2, rax
    pop     rax
    mov     cr3, rax
    pop     rax
    mov     cr4, rax
    pop     rax
    mov     cr8, rax

;; UINT64  RFlags;
    pop     qword [rbp + 40]

;; UINT64  Ldtr, Tr;
;; UINT64  Gdtr[2], Idtr[2];
;; Best not let anyone mess with these particular registers...
    add     rsp, 48

;; UINT64  Rip;
    pop     qword [rbp + 24]

;; UINT64  Gs, Fs, Es, Ds, Cs, Ss;
    pop     rax
    ; mov     gs, rax ; not for gs
    pop     rax
    ; mov     fs, rax ; not for fs
    ; (X64 will not use fs and gs, so we do not restore it)
    pop     rax
    mov     es, rax
    pop     rax
    mov     ds, rax
    pop     qword [rbp + 32]  ; for cs
    pop     qword [rbp + 56]  ; for ss

;; UINT64  Rdi, Rsi, Rbp, Rsp, Rbx, Rdx, Rcx, Rax;
;; UINT64  R8, R9, R10, R11, R12, R13, R14, R15;
    pop     rdi
    pop     rsi
    add     rsp, 8               ; not for rbp
    pop     qword [rbp + 48] ; for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
    pop     r8
    pop     r9
    pop     r10
    pop     r11
    pop     r12
    pop     r13
    pop     r14
    pop     r15

    mov     rsp, rbp

; Enable TF bit after page fault handler runs
    bts     dword [rsp + 40], 8  ;RFLAGS

    pop     rbp
    add     rsp, 16           ; skip INT# & ErrCode
    iretq

