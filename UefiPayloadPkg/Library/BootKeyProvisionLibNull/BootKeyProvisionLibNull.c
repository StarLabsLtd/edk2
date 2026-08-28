/** @file
  Null factory boot-key provisioning library.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyProvisionLib.h>

BOOLEAN
EFIAPI
BootKeyFactoryProvisioningRequired (
  VOID
  )
{
  return FALSE;
}

EFI_STATUS
EFIAPI
BootKeyProvisionFactorySet (
  IN BOOT_KEY_PROVISION_WAIT_CALLBACK  WaitCallback OPTIONAL
  )
{
  (VOID)WaitCallback;
  return EFI_UNSUPPORTED;
}
