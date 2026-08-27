/** @file
  Fail-closed boot-key power-safety instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyPowerSafetyLib.h>

EFI_STATUS
EFIAPI
BootKeyPowerSafetyArm (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
BootKeyPowerSafetyDisarm (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}
