/** @file
  Null boot-key TPM NV authorization provider.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyNvAuthLib.h>

EFI_STATUS
EFIAPI
BootKeyNvAuthAcquire (
  IN  BOOLEAN  FactoryInitialization,
  OUT UINT8    Auth[BOOT_KEY_NV_AUTH_SIZE],
  OUT BOOLEAN  *ProvisionRequired
  )
{
  if ((Auth == NULL) || (ProvisionRequired == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Auth, BOOT_KEY_NV_AUTH_SIZE);
  *ProvisionRequired = FALSE;
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
BootKeyNvAuthCommit (
  IN CONST UINT8  Auth[BOOT_KEY_NV_AUTH_SIZE]
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
BootKeyNvAuthClose (
  VOID
  )
{
  return EFI_SUCCESS;
}
