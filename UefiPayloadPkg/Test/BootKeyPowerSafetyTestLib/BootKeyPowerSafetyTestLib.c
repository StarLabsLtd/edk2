/** @file
  DEBUG-only synthetic boot-key power-safety instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyPowerSafetyLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

STATIC_ASSERT (
  FixedPcdGetBool (PcdBootKeyPowerSafetyTestEnabled),
  "BootKeyPowerSafetyTestLib requires a boot-key test build"
  );

EFI_STATUS
EFIAPI
BootKeyPowerSafetyArm (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_POWER_SAFETY_ARMED\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyPowerSafetyDisarm (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_POWER_SAFETY_DISARMED\n"));
  return EFI_SUCCESS;
}
