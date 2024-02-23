/** @file
  SMM CPU misc functions for x64 arch specific.

Copyright (c) 2015 - 2024, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/BaseLib.h>

#include "BlSmmCpuPayloadMm.h"

/**
  Initialize IDT IST Field.

  @param[in]  ExceptionType       Exception type.
  @param[in]  Ist                 IST value.

**/
VOID
EFIAPI
InitializeIdtIst (
  IN EFI_EXCEPTION_TYPE  ExceptionType,
  IN UINT8               Ist
  )
{
  IA32_IDT_GATE_DESCRIPTOR  *IdtGate;

  IdtGate                  = (IA32_IDT_GATE_DESCRIPTOR *)gSmiHandlerIdtr.Base;
  IdtGate                 += ExceptionType;
  IdtGate->Bits.Reserved_0 = Ist;
}

/**
  Initialize Gdt for all processors.

**/
VOID
InitGdt (
  IN  UINTN  Cr3
  )
{
  //
  // Bootloader handlers follow payload MM in memory. Map them.
  //
  SmmClearMemoryAttributesEx (
    Cr3,
    mPagingMode,
    mSmrrBase + mSmrrSize,
    mSmrrSize,
    EFI_MEMORY_RP
    );

  // And immediately protect them.
  SmmSetMemoryAttributesEx (
    Cr3,
    mPagingMode,
    mSmrrBase + mSmrrSize,
    mSmrrSize,
    EFI_MEMORY_RO | EFI_MEMORY_XP
    );
}
