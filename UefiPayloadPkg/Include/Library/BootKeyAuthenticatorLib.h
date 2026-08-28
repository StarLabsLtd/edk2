/** @file
  Statically linked FIDO boot-key authenticator interface.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

#define BOOT_KEY_CLIENT_DATA_HASH_SIZE   32
#define BOOT_KEY_RP_ID_HASH_SIZE         32
#define BOOT_KEY_CREDENTIAL_ID_MAX_SIZE  128
#define BOOT_KEY_AUTH_DATA_SIZE          37
#define BOOT_KEY_ES256_SIGNATURE_SIZE    64
#define BOOT_KEY_DEVICE_IDENTITY_SIZE    32

#define BOOT_KEY_AUTH_DATA_USER_PRESENT     BIT0
#define BOOT_KEY_AUTH_DATA_USER_VERIFIED    BIT2
#define BOOT_KEY_AUTH_DATA_BACKUP_ELIGIBLE  BIT3
#define BOOT_KEY_AUTH_DATA_BACKUP_STATE     BIT4
#define BOOT_KEY_AUTH_DATA_ATTESTED_DATA    BIT6
#define BOOT_KEY_AUTH_DATA_EXTENSIONS       BIT7

typedef struct {
  UINTN    CredentialIdSize;
  UINT8    CredentialId[BOOT_KEY_CREDENTIAL_ID_MAX_SIZE];
  UINT8    AuthenticatorData[BOOT_KEY_AUTH_DATA_SIZE];
  UINT8    Signature[BOOT_KEY_ES256_SIGNATURE_SIZE];
} BOOT_KEY_ASSERTION;

/**
  Prepare only the trusted device path needed to reach a FIDO authenticator.

  Production implementations must not connect general storage, network,
  option-ROM, or Driver#### paths from this function.

  Transport operations must use finite hardware timeouts. The caller arms an
  asynchronous reset deadline before invoking this function so synchronous
  UEFI driver binding cannot suppress the bounded boot attempt. While waiting
  on device discovery, return EFI_NOT_READY so platform callbacks can run.
**/
EFI_STATUS
EFIAPI
BootKeyAuthenticatorPrepare (
  VOID
  );

/**
  Request an assertion for one of the supplied credential IDs.

  The implementation is responsible for FIDO transport and strict decoding.
  A minimal provider may use the U2F compatibility protocol and omit the
  assertion credential ID when exactly one credential was attempted. In that
  case, return CredentialIdSize as zero; the policy library will bind the
  assertion to that sole credential.
  The returned ES256 signature is the fixed-width R || S representation.
  The function must return control within one second, including while waiting
  for insertion or user presence; return EFI_NOT_READY and resume the bounded
  transaction on the next call.
**/
EFI_STATUS
EFIAPI
BootKeyGetAssertion (
  IN  CONST CHAR8                *RpId,
  IN  CONST UINT8                ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN  CONST UINT8        *CONST  *CredentialIds,
  IN  CONST UINTN                *CredentialIdSizes,
  IN  UINTN                      CredentialCount,
  OUT BOOT_KEY_ASSERTION         *Assertion
  );

/**
  Create a non-discoverable ES256 credential for factory provisioning.

  The authenticator must require user presence. The returned public key is the
  uncompressed P-256 point, including its 0x04 prefix. The registration
  signature and attestation certificate are returned so the provisioning
  caller can validate proof of possession before committing the credential.

  This function follows the same bounded-call rule as BootKeyGetAssertion().
**/
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
  );

/**
  Return a stable identity for the connected physical authenticator.

  Production USB implementations derive this value from the device's immutable
  manufacturer-assigned serial number and USB vendor. Product IDs are transport
  configuration, not physical identity. Authenticators without a serial number
  cannot be factory provisioned.
**/
EFI_STATUS
EFIAPI
BootKeyGetAuthenticatorIdentity (
  OUT UINT8  Identity[BOOT_KEY_DEVICE_IDENTITY_SIZE]
  );

/**
  Require removal of the currently selected physical authenticator.

  Return EFI_NOT_READY while that device is still connected. After removal,
  discard all cached transport state and return EFI_SUCCESS.
**/
EFI_STATUS
EFIAPI
BootKeyAuthenticatorRequireRemoval (
  VOID
  );
