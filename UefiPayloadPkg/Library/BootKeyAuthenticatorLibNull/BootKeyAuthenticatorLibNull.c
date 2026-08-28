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

EFI_STATUS
EFIAPI
BootKeyMakeCredential (
  IN  CONST CHAR8  *RpId,
  IN  CONST UINT8  Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  OUT UINT8        *CredentialId,
  IN OUT UINTN     *CredentialIdSize,
  OUT UINT8        PublicKey[65],
  OUT UINT8        *AttestationCertificate,
  IN OUT UINTN     *AttestationCertificateSize,
  OUT UINT8        Signature[BOOT_KEY_ES256_SIGNATURE_SIZE]
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyGetAuthenticatorIdentity (
  OUT UINT8  Identity[BOOT_KEY_DEVICE_IDENTITY_SIZE]
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyAuthenticatorRequireRemoval (
  VOID
  )
{
  return EFI_NOT_FOUND;
}
