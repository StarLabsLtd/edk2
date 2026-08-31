/** @file
  Fail-closed boot-key platform security boundary instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyPlatformSecurityLib.h>

EFI_STATUS
EFIAPI
BootKeyVerifyPlatformSecurityBoundary (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}
