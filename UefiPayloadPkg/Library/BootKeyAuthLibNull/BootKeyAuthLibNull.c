/** @file
  No-op boot-key authentication policy library.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyAuthLib.h>

BOOLEAN
EFIAPI
BootKeyAuthenticationRequired (
  VOID
  )
{
  return FALSE;
}

EFI_STATUS
EFIAPI
BootKeyVerifyAssertion (
  IN CONST CHAR8                *RpId,
  IN CONST UINT8                ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN CONST BOOT_KEY_CREDENTIAL  *Credential,
  IN CONST BOOT_KEY_ASSERTION   *Assertion,
  OUT UINT32                    *SignCount
  )
{
  (VOID)RpId;
  (VOID)ClientDataHash;
  (VOID)Credential;
  (VOID)Assertion;
  (VOID)SignCount;
  return EFI_UNSUPPORTED;
}

VOID
EFIAPI
BootKeyRequireAuthentication (
  IN BOOT_KEY_AUTH_WAIT_CALLBACK  WaitCallback OPTIONAL
  )
{
  (VOID)WaitCallback;
}
