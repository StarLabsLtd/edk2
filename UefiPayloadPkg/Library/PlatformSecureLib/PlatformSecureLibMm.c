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
  The boot manager signals ReadyToBoot before executing a boot option, but
  exempts its built-in Setup menu. MM retains the event markers across S3;
  returning from a boot option must not reopen the configuration window.

  @retval TRUE   Neither boot handoff event has reached MM.
  @retval FALSE  A handoff event occurred, or the MM lookup failed unexpectedly.
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

  return gMmst->MmLocateProtocol (&gEfiEventExitBootServicesGuid, NULL, &Interface) == EFI_NOT_FOUND;
}
