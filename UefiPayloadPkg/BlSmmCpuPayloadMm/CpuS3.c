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
  PAYLOAD_MM_SHARED_INFO          *PldSmmInfo;
  UINTN                           Index;

  GuidHob = GetFirstGuidHob (&gS3CommunicationGuid);
  ASSERT (GuidHob != NULL);

  PldS3Communication = GET_GUID_HOB_DATA (GuidHob);

  GuidHob = GetFirstGuidHob (&gEfiSmmSmramMemoryGuid);
  ASSERT (GuidHob != NULL);

  SmramHob = GET_GUID_HOB_DATA (GuidHob);

  PldSmmInfo                  = (PAYLOAD_MM_SHARED_INFO *)PldS3Communication->CommBuffer.PhysicalStart;
  PldSmmInfo->SharedInfoSize  = sizeof (PAYLOAD_MM_SHARED_INFO);
  for (Index = 0; Index < SmramHob->NumberOfSmmReservedRegions; Index++) {
    if ((PldS3Communication->CommBuffer.PhysicalStart >= SmramHob->Descriptor[Index].PhysicalStart) &&
        (PldS3Communication->CommBuffer.PhysicalStart <  SmramHob->Descriptor[Index].PhysicalStart + SmramHob->Descriptor[Index].PhysicalSize))
    {
      break;
    }
  }

  if (Index == SmramHob->NumberOfSmmReservedRegions) {
    return EFI_NOT_FOUND;
  }

  //
  // Make sure the dedicated region for SMM info communication whose attribute is "allocated" (i.e., excluded from SMM memory service)
  //
  if ((SmramHob->Descriptor[Index].RegionState & EFI_ALLOCATED) == 0) {
    DEBUG ((DEBUG_ERROR, "SMM communication region not set to EFI_ALLOCATED\n"));
    return EFI_INVALID_PARAMETER;
  }

  if (((UINTN)PldSmmInfo + PldSmmInfo->SharedInfoSize) > (SmramHob->Descriptor[Index].PhysicalStart + SmramHob->Descriptor[Index].PhysicalSize)) {
    DEBUG ((DEBUG_ERROR, "SMM communication buffer (0x%x) is too small (0x%x).\n", SmramHob->Descriptor[Index].PhysicalSize, PldSmmInfo->SharedInfoSize));
    return EFI_BUFFER_TOO_SMALL;
  }

  PldSmmInfo->HeaderMagic          = PLD_MM_STRUCT_MAGIC;
  PldSmmInfo->HeaderRevision       = PLD_MM_SHARED_STRUCT_REVISION;
  PldSmmInfo->MmEntryPointAddress  = (UINT32)(UINTN)PayloadMmEntryPoint;

  return EFI_SUCCESS;
}
