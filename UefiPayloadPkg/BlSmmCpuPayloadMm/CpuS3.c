/** @file
  This file saves some payload MM state to communicated region,
  to register payload MM with bootloader SMM.

  Copyright (c) 2024, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiSmm.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <Guid/SmmS3CommunicationInfoGuid.h>
#include <Guid/SmramMemoryReserve.h>

#include "BlSmmCpuPayloadMm.h"

/**
  Initialise payload MM restore struct used by bootloader.

**/
EFI_STATUS
SaveMmInfoForS3 (
  IN EFI_PHYSICAL_ADDRESS  PayloadMmEntryPoint
  )
{
  EFI_HOB_GUID_TYPE               *GuidHob;
  PLD_S3_COMMUNICATION            *PldS3Communication;
  EFI_SMRAM_HOB_DESCRIPTOR_BLOCK  *SmramHob;
  PAYLOAD_MM_SHARED_INFO          Info;
  EFI_SMRAM_DESCRIPTOR            *Region;
  UINT64                          Offset;
  UINTN                           HobSize;
  BOOLEAN                         EntryPointInSmram;
  UINTN                           Index;

  GuidHob = GetFirstGuidHob (&gS3CommunicationGuid);
  if ((GuidHob == NULL) || (GET_GUID_HOB_DATA_SIZE (GuidHob) < sizeof (*PldS3Communication))) {
    return EFI_NOT_FOUND;
  }

  PldS3Communication = GET_GUID_HOB_DATA (GuidHob);

  GuidHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
  if (GuidHob == NULL) {
    return EFI_NOT_FOUND;
  }

  SmramHob = GET_GUID_HOB_DATA (GuidHob);
  HobSize  = GET_GUID_HOB_DATA_SIZE (GuidHob);
  if ((HobSize < OFFSET_OF (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, Descriptor)) ||
      (SmramHob->NumberOfSmmReservedRegions >
       (HobSize - OFFSET_OF (EFI_SMRAM_HOB_DESCRIPTOR_BLOCK, Descriptor)) / sizeof (*Region)) ||
      (PldS3Communication->CommBuffer.PhysicalStart == 0) ||
      (PldS3Communication->CommBuffer.PhysicalStart > MAX_UINT32) ||
      (PldS3Communication->CommBuffer.PhysicalSize < sizeof (Info)) ||
      (PayloadMmEntryPoint == 0) || (PayloadMmEntryPoint > MAX_UINT32))
  {
    return EFI_INVALID_PARAMETER;
  }

  EntryPointInSmram = FALSE;
  for (Index = 0; Index < SmramHob->NumberOfSmmReservedRegions; Index++) {
    Region = &SmramHob->Descriptor[Index];
    if (((Region->RegionState & EFI_ALLOCATED) == 0) &&
        (PayloadMmEntryPoint >= Region->PhysicalStart) &&
        (PayloadMmEntryPoint - Region->PhysicalStart < Region->PhysicalSize))
    {
      EntryPointInSmram = TRUE;
    }
  }

  if (!EntryPointInSmram) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < SmramHob->NumberOfSmmReservedRegions; Index++) {
    Region = &SmramHob->Descriptor[Index];
    if (((Region->RegionState & EFI_ALLOCATED) == 0) ||
        (Region->CpuStart != Region->PhysicalStart) ||
        (PldS3Communication->CommBuffer.PhysicalStart < Region->PhysicalStart))
    {
      continue;
    }

    Offset = PldS3Communication->CommBuffer.PhysicalStart - Region->PhysicalStart;
    if ((Offset <= Region->PhysicalSize) && (sizeof (Info) <= Region->PhysicalSize - Offset)) {
      break;
    }
  }

  if (Index == SmramHob->NumberOfSmmReservedRegions) {
    return EFI_BUFFER_TOO_SMALL;
  }

  // Publish only a complete, validated registration record, including reserved bytes.
  ZeroMem (&Info, sizeof (Info));
  Info.HeaderMagic         = PLD_MM_STRUCT_MAGIC;
  Info.SharedInfoSize      = sizeof (Info);
  Info.HeaderRevision      = PLD_MM_SHARED_STRUCT_REVISION;
  Info.MmEntryPointAddress = (UINT32)PayloadMmEntryPoint;
  CopyMem ((VOID *)(UINTN)PldS3Communication->CommBuffer.PhysicalStart, &Info, sizeof (Info));

  return EFI_SUCCESS;
}
