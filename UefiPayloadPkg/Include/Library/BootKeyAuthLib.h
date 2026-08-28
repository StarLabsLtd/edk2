/** @file
  Boot-key authentication policy and pre-BDS gate.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>
#include <Library/BootKeyAuthenticatorLib.h>
#include <Library/BootKeyCredentialStoreLib.h>

typedef enum {
  BootKeyAuthWaitUnavailable,
  BootKeyAuthWaitLockout,
  BootKeyAuthWaitPrompt
} BOOT_KEY_AUTH_WAIT_STATE;

typedef
VOID
(EFIAPI *BOOT_KEY_AUTH_WAIT_CALLBACK)(
  IN BOOT_KEY_AUTH_WAIT_STATE  State,
  IN UINT32                    SecondsRemaining
  );

/**
  Return whether this firmware image requires boot-key authentication.

  @retval TRUE   The real gate library is linked into the image.
  @retval FALSE  The no-op library is linked into the image.
**/
BOOLEAN
EFIAPI
BootKeyAuthenticationRequired (
  VOID
  );

/**
  Verify a decoded FIDO2 assertion against an enrolled credential.

  @retval EFI_SUCCESS             The assertion is valid.
  @retval EFI_SECURITY_VIOLATION  The assertion violates boot-key policy.
  @retval EFI_INVALID_PARAMETER   An input structure is malformed.
**/
EFI_STATUS
EFIAPI
BootKeyVerifyAssertion (
  IN CONST CHAR8                *RpId,
  IN CONST UINT8                ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN CONST BOOT_KEY_CREDENTIAL  *Credential,
  IN CONST BOOT_KEY_ASSERTION   *Assertion,
  OUT UINT32                    *SignCount
  );

/**
  Require a valid assertion before returning to the boot manager.

  This function does not return until authentication succeeds.

  @param[in] WaitCallback  Optional trusted platform status and safety callback
                           invoked while the gate is unavailable, locked out,
                           or waiting for the authenticator.
**/
VOID
EFIAPI
BootKeyRequireAuthentication (
  IN BOOT_KEY_AUTH_WAIT_CALLBACK  WaitCallback OPTIONAL
  );
