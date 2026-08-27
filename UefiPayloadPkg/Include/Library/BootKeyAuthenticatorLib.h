/** @file
  Statically linked FIDO2 boot-key authenticator interface.

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
  Prepare only the trusted device path needed to reach a FIDO2 authenticator.

  Production implementations must not connect general storage, network,
  option-ROM, or Driver#### paths from this function.

  The function must return control within one second. While waiting on device
  discovery, return EFI_NOT_READY so platform safety callbacks can run.
**/
EFI_STATUS
EFIAPI
BootKeyAuthenticatorPrepare (
  VOID
  );

/**
  Request an assertion for one of the supplied credential IDs.

  The implementation is responsible for CTAP transport and strict decoding.
  CTAP2 permits the assertion credential descriptor to be omitted when exactly
  one credential ID was supplied. In that case, return CredentialIdSize as
  zero; the policy library will bind the assertion to that sole credential.
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
