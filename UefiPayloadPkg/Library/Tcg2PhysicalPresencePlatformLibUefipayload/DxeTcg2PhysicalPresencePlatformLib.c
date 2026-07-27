/** @file
  Returns the platform specific configuration for the QEMU PPI.

  Caution: This module requires additional review when modified.
  This driver will have external input - variable.
  This external input must be validated carefully to avoid security issue.

Copyright (C) 2018, Red Hat, Inc.
Copyright (c) 2018, IBM Corporation. All rights reserved.<BR>
Copyright (c) 2013 - 2016, Intel Corporation. All rights reserved.<BR>
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <Library/Tcg2PhysicalPresencePlatformLib.h>
#include <Library/HobLib.h>
#include <Library/DebugLib.h>
#include <Library/DxeServicesTableLib.h>

#include <Guid/TcgPhysicalPresenceGuid.h>

/**
  Reads QEMU PPI config from TcgPhysicalPresenceInfoHobGuid.

  @param[out]  Config  The config structure to fill in.

  @retval EFI_SUCCESS           Operation completed successfully.
  @retval EFI_INVALID_PARAMETER Config is NULL.
  @retval EFI_PROTOCOL_ERROR    Invalid HOB entry.
**/
EFI_STATUS
EFIAPI
TpmPpiPlatformReadConfig (
  OUT TCG2_PHYSICAL_PRESENCE_PLATFORM_CONFIG  *Config
  )
{
  EFI_HOB_GUID_TYPE                       *GuidHob;
  TCG_PHYSICAL_PRESENCE_INFO              *pPPInfo;

  if (Config == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Find the TPM Physical Presence HOB
  //
  GuidHob = GetFirstGuidHob (&gEfiTcgPhysicalPresenceInfoHobGuid);

  if (GuidHob == NULL) {
    return EFI_NOT_FOUND;
  }

  pPPInfo = (TCG_PHYSICAL_PRESENCE_INFO *)GET_GUID_HOB_DATA (GuidHob);

  if (pPPInfo->PpiAddress == 0 || pPPInfo->PpiAddress == ~0) {
    return EFI_NOT_FOUND;
  } else {
    Config->PpiAddress = pPPInfo->PpiAddress;
  }

  if (pPPInfo->TpmVersion == UEFIPAYLOAD_TPM_VERSION_1_2) {
    Config->TpmVersion = Tcg2PhysicalPresenceTpmVersion12;
  } else if (pPPInfo->TpmVersion == UEFIPAYLOAD_TPM_VERSION_2) {
    Config->TpmVersion = Tcg2PhysicalPresenceTpmVersion20;
  } else {
    return EFI_UNSUPPORTED;
  }

  if ((pPPInfo->PpiVersion != UEFIPAYLOAD_TPM_PPI_VERSION_NONE) &&
      (pPPInfo->PpiVersion != UEFIPAYLOAD_TPM_PPI_VERSION_1_30))
  {
    return EFI_UNSUPPORTED;
  }

  Config->PpiInMmio = FALSE;

  return EFI_SUCCESS;
}
