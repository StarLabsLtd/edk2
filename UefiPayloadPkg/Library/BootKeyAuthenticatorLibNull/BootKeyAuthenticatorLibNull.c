/** @file
  Null boot-key authenticator instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyAuthenticatorLib.h>

EFI_STATUS
EFIAPI
BootKeyAuthenticatorPrepare (
  VOID
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyGetAssertion (
  IN  CONST CHAR8                *RpId,
  IN  CONST UINT8                ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN  CONST UINT8        *CONST  *CredentialIds,
  IN  CONST UINTN                *CredentialIdSizes,
  IN  UINTN                      CredentialCount,
  OUT BOOT_KEY_ASSERTION         *Assertion
  )
{
  return EFI_NOT_FOUND;
}
