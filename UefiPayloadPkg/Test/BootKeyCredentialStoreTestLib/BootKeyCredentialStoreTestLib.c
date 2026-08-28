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

STATIC_ASSERT (
  FixedPcdGetBool (PcdBootKeyAuthTestEnabled),
  "BootKeyCredentialStoreTestLib requires BOOT_KEY_AUTH_TEST"
  );

extern CONST UINT8  gBootKeyTestCredentialId[];
extern CONST UINTN  gBootKeyTestCredentialIdSize;
extern CONST UINT8  gBootKeyTestCertificate[];
extern CONST UINTN  gBootKeyTestCertificateSize;

STATIC CONST UINT8  mShortCredentialId[] = { 0x10, 0x20, 0x30 };

EFI_STATUS
EFIAPI
BootKeyPrepareCredentialStore (
  IN BOOLEAN  FactoryInitialization
  )
{
  return FactoryInitialization ? EFI_UNSUPPORTED : EFI_SUCCESS;
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
BootKeyCommitSignCount (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN UINT32       SignCount
  )
{
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

  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_COUNTER_COMMITTED\n"));
  return EFI_SUCCESS;
}
