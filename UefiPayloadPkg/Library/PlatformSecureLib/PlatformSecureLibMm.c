/** @file
  Secure Boot configuration policy for the resident payload MM variable service.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Guid/EventGroup.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PlatformSecureLib.h>

/**
  Allow Secure Boot configuration during trusted firmware Setup only.

  This policy trusts preboot firmware, not an independent presence sensor.
  Setup remains available until the boot manager hands off to an OS. MM also
  closes the window before any external preboot image runs. These markers
  persist across S3, so returning from an image cannot reopen the window.

  @retval TRUE   Neither boot handoff event has reached MM.
  @retval FALSE  A handoff occurred, or the MM lookup failed unexpectedly.
**/
BOOLEAN
EFIAPI
UserPhysicalPresent (
  VOID
  )
{
  VOID  *Interface;

  if (gMmst->MmLocateProtocol (&gEfiEventReadyToBootGuid, NULL, &Interface) != EFI_NOT_FOUND) {
    return FALSE;
  }

  if (gMmst->MmLocateProtocol (&gEfiEventExitBootServicesGuid, NULL, &Interface) != EFI_NOT_FOUND) {
    return FALSE;
  }

  return gMmst->MmLocateProtocol (&gEfiEventExternalImageStartGuid, NULL, &Interface) == EFI_NOT_FOUND;
}
