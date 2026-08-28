/** @file
  Statically linked protected boot-key credential-store interface.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>
#include <Library/BootKeyAuthenticatorLib.h>

#define BOOT_KEY_MAX_ENROLLED_CREDENTIALS         3
#define BOOT_KEY_PUBLIC_KEY_CERTIFICATE_MAX_SIZE  1024

typedef struct {
  UINTN     CredentialIdSize;
  UINT8     CredentialId[BOOT_KEY_CREDENTIAL_ID_MAX_SIZE];
  //
  // DER X.509 wrapper containing the enrolled credential public key. This is
  // not the authenticator attestation certificate. Provisioning must verify
  // that the wrapped key is the ES256/P-256 COSE credential key.
  //
  UINTN     PublicKeyCertificateSize;
  UINT8     PublicKeyCertificate[BOOT_KEY_PUBLIC_KEY_CERTIFICATE_MAX_SIZE];
  UINT32    SignCount;
} BOOT_KEY_CREDENTIAL;

typedef struct {
  UINTN    CredentialIdSize;
  UINT8    CredentialId[BOOT_KEY_CREDENTIAL_ID_MAX_SIZE];
  UINT8    PublicKey[65];
  UINT8    DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
} BOOT_KEY_PROVISIONING_CREDENTIAL;

/**
  Validate or factory-create the credential store, then disable the TPM
  platform hierarchy before any external input is accepted.

  FactoryInitialization may permit creation or recovery of a validated but
  unwritten index. Production callers must pass FALSE and fail closed unless a
  complete record already exists.
**/
EFI_STATUS
EFIAPI
BootKeyPrepareCredentialStore (
  IN BOOLEAN  FactoryInitialization
  );

/**
  Irreversibly close the current boot's TPM credential-store write window and
  log the transition before any external code can execute.
**/
EFI_STATUS
EFIAPI
BootKeyCloseCredentialStore (
  VOID
  );

/**
  Best-effort, idempotent cleanup for every boot-key failure path.
**/
VOID
EFIAPI
BootKeyAbortCredentialStore (
  VOID
  );

/**
  Read the complete enrolled credential set as one coherent snapshot.

  On input, CredentialCount is the capacity of Credentials. On output, it is
  the number of returned credentials. EFI_SUCCESS means the complete set,
  including membership, credential IDs, public keys, and signature counters,
  came from authenticated, rollback-resistant storage. Enrollment and removal
  must become durable atomically before a subsequent snapshot can expose them.
**/
EFI_STATUS
EFIAPI
BootKeyGetCredentialSet (
  OUT    BOOT_KEY_CREDENTIAL  *Credentials,
  IN OUT UINTN                *CredentialCount
  );

/**
  Atomically advance an enrolled credential's signature counter.

  EFI_SUCCESS means the new counter is durably committed to authenticated,
  rollback-resistant storage before this function returns. Implementations
  must never report success for a volatile, cached, replayable, or partial
  update.
**/
EFI_STATUS
EFIAPI
BootKeyCommitSignCount (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN UINT32       SignCount
  );

/**
  Atomically add a factory-provisioned P-256 credential.

  PublicKey is the uncompressed 65-byte SEC1 point (0x04 || X || Y). The
  operation must reject duplicates and must not expose a partially updated
  credential set.
**/
EFI_STATUS
EFIAPI
BootKeyProvisionCredential (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN CONST UINT8  PublicKey[65],
  IN CONST UINT8  DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE]
  );

/**
  Atomically create the complete factory enrollment set with one NV write.
**/
EFI_STATUS
EFIAPI
BootKeyProvisionCredentialSet (
  IN CONST BOOT_KEY_PROVISIONING_CREDENTIAL  *Credentials,
  IN UINTN                                   CredentialCount
  );

/**
  Atomically remove an enrolled credential while preserving at least one.
**/
EFI_STATUS
EFIAPI
BootKeyRemoveCredential (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize
  );
