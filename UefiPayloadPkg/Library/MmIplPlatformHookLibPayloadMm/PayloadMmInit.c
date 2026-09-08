/** @file
  Load the resident MM core through the coreboot boot-only interface.

  Copyright (c) 2025, 9elements GmbH.<BR>
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmIplPlatformHookLib.h>
#include <Library/PayloadMmHelperLib.h>
#include <Library/PcdLib.h>
#include <Library/PeCoffLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include "PayloadMmCmdInterface.h"

typedef struct {
  EFI_PHYSICAL_ADDRESS    Base;
  UINT64                  Size;
  UINT64                  Attributes;
  BOOLEAN                 Changed;
} MM_BOOT_MAPPING;

STATIC MM_BOOT_MAPPING  mMappings[2];
STATIC VOID             *mImageBuffer;
STATIC UINTN            mImagePages;

STATIC
VOID *
AllocatePagesBelow4G (
  IN UINTN  Pages
  )
{
  EFI_PHYSICAL_ADDRESS  Address;
  EFI_STATUS            Status;

  Address = MAX_UINT32;
  Status  = gBS->AllocatePages (AllocateMaxAddress, EfiReservedMemoryType, Pages, &Address);
  if (EFI_ERROR (Status)) {
    return NULL;
  }

  ZeroMem ((VOID *)(UINTN)Address, EFI_PAGES_TO_SIZE (Pages));
  return (VOID *)(UINTN)Address;
}

EFI_STATUS
EFIAPI
PlatformHookBeforeMmLoad (
  IN PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext
  )
{
  if ((ImageContext == NULL) || (mImageBuffer != NULL) ||
      (ImageContext->ImageSize == 0) ||
      (ImageContext->ImageSize > MAX_UINT32 - EFI_PAGE_MASK) ||
      (ImageContext->SectionAlignment > EFI_PAGE_SIZE))
  {
    return EFI_INVALID_PARAMETER;
  }

  mImagePages  = EFI_SIZE_TO_PAGES (ImageContext->ImageSize);
  mImageBuffer = AllocatePagesBelow4G (mImagePages);
  if (mImageBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ImageContext->DestinationAddress = ImageContext->ImageAddress;
  ImageContext->ImageAddress       = (UINTN)mImageBuffer;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
RestoreMmMappings (
  IN EFI_MEMORY_ATTRIBUTE_PROTOCOL  *MemoryAttributes
  )
{
  EFI_STATUS  Status;
  EFI_STATUS  Result;
  UINTN       Index;

  Result = EFI_SUCCESS;
  for (Index = 0; Index < ARRAY_SIZE (mMappings); Index++) {
    if (!mMappings[Index].Changed) {
      continue;
    }

    Status = MemoryAttributes->ClearMemoryAttributes (
                                 MemoryAttributes,
                                 mMappings[Index].Base,
                                 mMappings[Index].Size,
                                 EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_XP
                                 );
    if (!EFI_ERROR (Status) && (mMappings[Index].Attributes != 0)) {
      Status = MemoryAttributes->SetMemoryAttributes (
                                   MemoryAttributes,
                                   mMappings[Index].Base,
                                   mMappings[Index].Size,
                                   mMappings[Index].Attributes
                                   );
    }

    if (EFI_ERROR (Status)) {
      Result = Status;
    } else {
      mMappings[Index].Changed = FALSE;
    }
  }

  return Result;
}

STATIC
EFI_STATUS
MapMmEnvironment (
  IN EFI_MEMORY_ATTRIBUTE_PROTOCOL  *MemoryAttributes
  )
{
  EFI_HOB_GUID_TYPE          *Hob;
  PAYLOAD_MM_INTERFACE_INFO  *Info;
  EFI_STATUS                 Status;
  UINTN                      Index;

  Hob = GetFirstGuidHob (&gPayloadMmInterfaceInfoGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*Info))) {
    return EFI_NOT_FOUND;
  }

  Info = GET_GUID_HOB_DATA (Hob);
  if ((Info->HandlerBase == 0) || (Info->HandlerSize == 0) ||
      (Info->PayloadSize == 0) || (Info->HandlerBase >= Info->PayloadBase) ||
      (Info->HandlerSize != Info->PayloadBase - Info->HandlerBase) ||
      (Info->PayloadBase > MAX_UINT32) ||
      (Info->PayloadSize > MAX_UINT32 - Info->PayloadBase) ||
      (((Info->HandlerBase | Info->HandlerSize | Info->PayloadBase | Info->PayloadSize) & EFI_PAGE_MASK) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  mMappings[0].Base = Info->PayloadBase;
  mMappings[0].Size = Info->PayloadSize;
  mMappings[1].Base = Info->HandlerBase;
  mMappings[1].Size = Info->HandlerSize;
  for (Index = 0; Index < ARRAY_SIZE (mMappings); Index++) {
    Status = MemoryAttributes->GetMemoryAttributes (
                                 MemoryAttributes,
                                 mMappings[Index].Base,
                                 mMappings[Index].Size,
                                 &mMappings[Index].Attributes
                                 );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  // The bootstrap executes the payload and reads coreboot's GDT under the DXE CR3.
  for (Index = 0; Index < ARRAY_SIZE (mMappings); Index++) {
    mMappings[Index].Changed = TRUE;
    Status                   = MemoryAttributes->ClearMemoryAttributes (
                                                   MemoryAttributes,
                                                   mMappings[Index].Base,
                                                   mMappings[Index].Size,
                                                   EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_XP
                                                   );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return MemoryAttributes->SetMemoryAttributes (
                             MemoryAttributes,
                             mMappings[1].Base,
                             mMappings[1].Size,
                             EFI_MEMORY_RO | EFI_MEMORY_XP
                             );
}

EFI_STATUS
EFIAPI
PlatformHookCallMmCore (
  IN     PE_COFF_LOADER_IMAGE_CONTEXT  *ImageContext,
  IN     VOID                          *Context,
  IN OUT EFI_STATUS                    *PiSmmCoreStatus
  )
{
  PAYLOAD_MM_LOAD_CONTEXT        *Load;
  PAYLOAD_MM_EDK2_PRIVATE_DATA   *Private;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL  *MemoryAttributes;
  VOID                           *Control;
  VOID                           *Stack;
  UINTN                          StackPages;
  EFI_STATUS                     Status;
  EFI_STATUS                     RestoreStatus;

  if ((ImageContext == NULL) || (Context == NULL) || (PiSmmCoreStatus == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *PiSmmCoreStatus = EFI_DEVICE_ERROR;
  Control          = NULL;
  Stack            = NULL;
  if ((mImageBuffer == NULL) || (ImageContext->ImageAddress != (UINTN)mImageBuffer) ||
      (ImageContext->DestinationAddress > MAX_UINT32) ||
      (EFI_PAGES_TO_SIZE (mImagePages) > MAX_UINT32 - ImageContext->DestinationAddress) ||
      (ImageContext->EntryPoint < ImageContext->DestinationAddress) ||
      (ImageContext->EntryPoint - ImageContext->DestinationAddress >= ImageContext->ImageSize) ||
      (AsmReadCr3 () > MAX_UINT32) || (PcdGet32 (PcdCpuSmmStackSize) == 0))
  {
    Status = EFI_INVALID_PARAMETER;
    goto Done;
  }

  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&MemoryAttributes);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  // The coreboot command argument and bootstrap stack are 32-bit addresses.
  Control    = AllocatePagesBelow4G (1);
  StackPages = EFI_SIZE_TO_PAGES (PcdGet32 (PcdCpuSmmStackSize));
  Stack      = AllocatePagesBelow4G (StackPages);
  if ((Control == NULL) || (Stack == NULL)) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Done;
  }

  Load                      = Control;
  Private                   = (VOID *)((UINT8 *)Control + ALIGN_VALUE (sizeof (*Load), sizeof (UINT64)));
  Private->StackPointers    = (VOID *)((UINT8 *)Private + ALIGN_VALUE (sizeof (*Private), sizeof (UINT64)));
  Private->StackPointers[0] = (UINT32)((UINTN)Stack + EFI_PAGES_TO_SIZE (StackPages) - sizeof (UINT64));
  Private->PageTable        = (UINT32)AsmReadCr3 ();
  CheckFeatureSupported (Private);

  Load->HeaderSize                = sizeof (*Load);
  Load->HeaderRevision            = PLD_MM_CORE_LOAD_CONTEXT_REVISION;
  Load->MmCoreSourceAddress       = ImageContext->ImageAddress;
  Load->MmCoreDestinationAddress  = (UINT32)ImageContext->DestinationAddress;
  Load->MmCoreSize                = (UINT32)EFI_PAGES_TO_SIZE (mImagePages);
  Load->MmEntryPointOffset        = (UINT32)(ImageContext->EntryPoint - ImageContext->DestinationAddress);
  Load->MmEntryPointArg1          = (UINTN)Context;
  Load->ImplementationPrivateData = (UINTN)Private;

  Status = MapMmEnvironment (MemoryAttributes);
  if (!EFI_ERROR (Status)) {
    Status = PayloadMmCmdLoadAndCallCore (Load);
  }

  RestoreStatus = RestoreMmMappings (MemoryAttributes);
  if (EFI_ERROR (RestoreStatus)) {
    Status = RestoreStatus;
  }

Done:
  if (Stack != NULL) {
    FreePages (Stack, StackPages);
  }

  if (Control != NULL) {
    FreePages (Control, 1);
  }

  if (mImageBuffer != NULL) {
    FreePages (mImageBuffer, mImagePages);
    mImageBuffer = NULL;
  }

  // EFI_UNSUPPORTED asks the generic IPL to call the entrypoint outside SMM.
  if (Status == EFI_UNSUPPORTED) {
    Status = EFI_DEVICE_ERROR;
  }

  *PiSmmCoreStatus = Status;
  return Status;
}
