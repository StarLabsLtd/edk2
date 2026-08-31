/** @file
  QEMU-only boot-key credential-store library.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyCredentialStoreLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define BOOT_KEY_TEST_STATE_MAGIC    SIGNATURE_32 ('B', 'K', 'T', 'S')
#define BOOT_KEY_TEST_STATE_VERSION  1

#pragma pack (1)
typedef struct {
  UINT32    Magic;
  UINT8     Version;
  UINT8     FailureStage;
  UINT8     AttemptActive;
  UINT8     Reserved;
} BOOT_KEY_TEST_STATE;
#pragma pack ()

STATIC_ASSERT (
  FixedPcdGetBool (PcdBootKeyAuthTestEnabled),
  "BootKeyCredentialStoreTestLib requires BOOT_KEY_AUTH_TEST"
  );

extern CONST UINT8  gBootKeyTestCredentialId[];
extern CONST UINTN  gBootKeyTestCredentialIdSize;
extern CONST UINT8  gBootKeyTestCertificate[];
extern CONST UINTN  gBootKeyTestCertificateSize;

STATIC CONST UINT8  mShortCredentialId[] = { 0x10, 0x20, 0x30 };
STATIC CONST CHAR16 mBootKeyTestStateName[] = L"BootKeyQemuAttemptState";
STATIC EFI_GUID     mBootKeyTestStateGuid = {
  0x5d0f130b, 0xad55, 0x4ac5, { 0xac, 0xba, 0x41, 0x23, 0x8a, 0x1e, 0x20, 0x26 }
};
STATIC BOOT_KEY_TEST_STATE  mBootKeyTestState;

STATIC
EFI_STATUS
BootKeySaveTestState (
  VOID
  )
{
  return gRT->SetVariable (
                (CHAR16 *)mBootKeyTestStateName,
                &mBootKeyTestStateGuid,
                EFI_VARIABLE_NON_VOLATILE |
                EFI_VARIABLE_BOOTSERVICE_ACCESS |
                EFI_VARIABLE_RUNTIME_ACCESS,
                sizeof (mBootKeyTestState),
                &mBootKeyTestState
                );
}

EFI_STATUS
EFIAPI
BootKeyPrepareCredentialStore (
  IN BOOLEAN  FactoryInitialization
  )
{
  UINTN       Size;
  EFI_STATUS  Status;

  if (FactoryInitialization) {
    return EFI_UNSUPPORTED;
  }

  ZeroMem (&mBootKeyTestState, sizeof (mBootKeyTestState));
  Size   = sizeof (mBootKeyTestState);
  Status = gRT->GetVariable (
                  (CHAR16 *)mBootKeyTestStateName,
                  &mBootKeyTestStateGuid,
                  NULL,
                  &Size,
                  &mBootKeyTestState
                  );
  if (Status == EFI_NOT_FOUND) {
    mBootKeyTestState.Magic   = BOOT_KEY_TEST_STATE_MAGIC;
    mBootKeyTestState.Version = BOOT_KEY_TEST_STATE_VERSION;
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status) || (Size != sizeof (mBootKeyTestState)) ||
      (mBootKeyTestState.Magic != BOOT_KEY_TEST_STATE_MAGIC) ||
      (mBootKeyTestState.Version != BOOT_KEY_TEST_STATE_VERSION) ||
      (mBootKeyTestState.FailureStage > BOOT_KEY_FAILURE_STAGE_MAX) ||
      (mBootKeyTestState.AttemptActive > 1) ||
      (mBootKeyTestState.Reserved != 0))
  {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyCloseCredentialStore (
  VOID
  )
{
  return EFI_SUCCESS;
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
  UINTN  CredentialIndex;
  UINTN  RequiredCount;

  if ((Credentials == NULL) || (CredentialCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  RequiredCount =
    (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 11) ? 1 : 2;
  if (*CredentialCount < RequiredCount) {
    *CredentialCount = RequiredCount;
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Keep a different-length credential first to exercise multi-key matching.
  //
  *CredentialCount = RequiredCount;
  ZeroMem (Credentials, sizeof (*Credentials) * *CredentialCount);
  for (CredentialIndex = 0; CredentialIndex < *CredentialCount; CredentialIndex++) {
    if ((CredentialIndex == 0) &&
        (FixedPcdGet32 (PcdBootKeyAuthTestScenario) != 7) &&
        (FixedPcdGet32 (PcdBootKeyAuthTestScenario) != 11))
    {
      Credentials[CredentialIndex].CredentialIdSize = sizeof (mShortCredentialId);
      CopyMem (
        Credentials[CredentialIndex].CredentialId,
        mShortCredentialId,
        sizeof (mShortCredentialId)
        );
    } else {
      Credentials[CredentialIndex].CredentialIdSize = gBootKeyTestCredentialIdSize;
      CopyMem (
        Credentials[CredentialIndex].CredentialId,
        gBootKeyTestCredentialId,
        gBootKeyTestCredentialIdSize
        );
    }

    Credentials[CredentialIndex].PublicKeyCertificateSize = gBootKeyTestCertificateSize;
    CopyMem (
      Credentials[CredentialIndex].PublicKeyCertificate,
      gBootKeyTestCertificate,
      gBootKeyTestCertificateSize
      );
    Credentials[CredentialIndex].SignCount =
      (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 4) ? 1 : 0;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyPrepareAuthenticationAttempt (
  OUT UINT32  *DelaySeconds
  )
{
  EFI_STATUS  Status;

  if (DelaySeconds == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (mBootKeyTestState.AttemptActive != 0) {
    if (mBootKeyTestState.FailureStage < BOOT_KEY_FAILURE_STAGE_MAX) {
      mBootKeyTestState.FailureStage++;
    }

    mBootKeyTestState.AttemptActive = 0;
    Status                          = BootKeySaveTestState ();
    if (EFI_ERROR (Status)) {
      return Status;
    }

    DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_INTERRUPTED_ATTEMPT_RECOVERED\n"));
  }

  *DelaySeconds = ((mBootKeyTestState.FailureStage != 0) ||
                   (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 14)) ? 1 : 0;
  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_LOCKOUT_SECONDS=%u\n", *DelaySeconds));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyBeginAuthenticationAttempt (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mBootKeyTestState.AttemptActive != 0) {
    return EFI_ALREADY_STARTED;
  }

  mBootKeyTestState.AttemptActive = 1;
  Status                          = BootKeySaveTestState ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_ATTEMPT_ACTIVE\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyCommitAuthenticationFailure (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mBootKeyTestState.AttemptActive == 0) {
    return EFI_ACCESS_DENIED;
  }

  if (mBootKeyTestState.FailureStage < BOOT_KEY_FAILURE_STAGE_MAX) {
    mBootKeyTestState.FailureStage++;
  }

  mBootKeyTestState.AttemptActive = 0;
  Status                          = BootKeySaveTestState ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_FAILURE_COMMITTED\n"));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyCommitSignCount (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN UINT32       SignCount
  )
{
  EFI_STATUS  Status;

  if ((CredentialId == NULL) ||
      (CredentialIdSize != gBootKeyTestCredentialIdSize) ||
      (CompareMem (
         CredentialId,
         gBootKeyTestCredentialId,
         gBootKeyTestCredentialIdSize
         ) != 0) ||
      (SignCount != 1))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 5) {
    DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_COMMIT_WARNING\n"));
    return EFI_WARN_WRITE_FAILURE;
  }

  if (mBootKeyTestState.AttemptActive == 0) {
    return EFI_ACCESS_DENIED;
  }

  mBootKeyTestState.FailureStage  = 0;
  mBootKeyTestState.AttemptActive = 0;
  Status                          = BootKeySaveTestState ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_COUNTER_COMMITTED\n"));
  return EFI_SUCCESS;
}
