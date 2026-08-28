/** @file
  Null boot-key credential-store instance.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyCredentialStoreLib.h>

EFI_STATUS
EFIAPI
BootKeyPrepareCredentialStore (
  IN BOOLEAN  FactoryInitialization
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyCloseCredentialStore (
  VOID
  )
{
  return EFI_NOT_FOUND;
}

VOID
EFIAPI
BootKeyAbortCredentialStore (
  VOID
  )
{
}

EFI_STATUS
EFIAPI
BootKeyGetCredentialSet (
  OUT    BOOT_KEY_CREDENTIAL  *Credentials,
  IN OUT UINTN                *CredentialCount
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyCommitSignCount (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN UINT32       SignCount
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyProvisionCredential (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN CONST UINT8  PublicKey[65],
  IN CONST UINT8  DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE]
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyProvisionCredentialSet (
  IN CONST BOOT_KEY_PROVISIONING_CREDENTIAL  *Credentials,
  IN UINTN                                   CredentialCount
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyRemoveCredential (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize
  )
{
  return EFI_NOT_FOUND;
}
