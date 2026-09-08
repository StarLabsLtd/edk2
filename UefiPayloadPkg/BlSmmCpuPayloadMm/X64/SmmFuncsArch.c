/** @file
  SMM CPU misc functions for x64 arch specific.

Copyright (c) 2015 - 2024, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/BaseLib.h>
#include <Library/HobLib.h>

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
EFI_STATUS
InitGdt (
  IN  UINTN  Cr3
  )
{
  EFI_HOB_GUID_TYPE          *Hob;
  PAYLOAD_MM_INTERFACE_INFO  *Info;
  EFI_STATUS                 Status;

  Hob = GetFirstGuidHob (&gPayloadMmInterfaceInfoGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*Info))) {
    return EFI_NOT_FOUND;
  }

  Info = GET_GUID_HOB_DATA (Hob);
  if ((Info->HandlerBase == 0) || (Info->HandlerBase >= mSmrrBase) ||
      (Info->HandlerSize != mSmrrBase - Info->HandlerBase) ||
      (((Info->HandlerBase | Info->HandlerSize) & EFI_PAGE_MASK) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  // Runtime mode switching reads coreboot's GDT in the actual handler region.
  Status = SmmClearMemoryAttributesEx (Cr3, mPagingMode, Info->HandlerBase, Info->HandlerSize, EFI_MEMORY_RP);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return SmmSetMemoryAttributesEx (Cr3, mPagingMode, Info->HandlerBase, Info->HandlerSize, EFI_MEMORY_RO | EFI_MEMORY_XP);
}
