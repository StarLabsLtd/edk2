/** @file
  DEBUG-only boot-key platform security boundary test instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyPlatformSecurityLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>

STATIC_ASSERT (
  FixedPcdGetBool (PcdBootKeyPlatformBoundaryTestEnabled),
  "BootKeyPlatformSecurityTestLib requires a boot-key test build"
  );

EFI_STATUS
EFIAPI
BootKeyVerifyPlatformSecurityBoundary (
  VOID
  )
{
  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_PLATFORM_BOUNDARY_VERIFIED\n"));
  return EFI_SUCCESS;
}
