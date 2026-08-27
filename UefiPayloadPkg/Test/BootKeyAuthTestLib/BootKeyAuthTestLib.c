/** @file
  QEMU-only boot-key authenticator library.

  This library contains a private test key and must never be included in a
  production firmware image. UefiPayloadPkg only links it when the explicit
  BOOT_KEY_AUTH_TEST build flag is set.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/BootKeyAuthenticatorLib.h>
#include <Library/BootKeyCredentialStoreLib.h>
#include <Library/PcdLib.h>

STATIC_ASSERT (
  FixedPcdGetBool (PcdBootKeyAuthTestEnabled),
  "BootKeyAuthTestLib requires BOOT_KEY_AUTH_TEST"
  );

CONST UINT8  gBootKeyTestCredentialId[] = {
  0x1e, 0x4b, 0x33, 0x2c, 0x06, 0x00, 0x6e, 0xd0,
  0x37, 0x45, 0xd5, 0xe3, 0x62, 0xb7, 0xbc, 0x3a,
  0xcb, 0xef, 0x05, 0xe9, 0x45, 0xe0, 0x7c, 0x63,
  0x04, 0xee, 0x16, 0x6c, 0x01, 0xcd, 0xd4, 0x6a
};

CONST UINT8  gBootKeyTestCertificate[] = {
  0x30, 0x82, 0x01, 0x99, 0x30, 0x82, 0x01, 0x3f, 0xa0, 0x03, 0x02, 0x01,
  0x02, 0x02, 0x14, 0x46, 0xf3, 0xfa, 0xb8, 0xc0, 0xda, 0x13, 0x1d, 0xdb,
  0x0d, 0x6f, 0x0f, 0x57, 0xe5, 0xfa, 0x21, 0x2e, 0xb1, 0x0d, 0xee, 0x30,
  0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
  0x21, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16,
  0x42, 0x6f, 0x6f, 0x74, 0x4b, 0x65, 0x79, 0x41, 0x75, 0x74, 0x68, 0x51,
  0x65, 0x6d, 0x75, 0x46, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x30, 0x20,
  0x17, 0x0d, 0x32, 0x36, 0x30, 0x38, 0x32, 0x37, 0x30, 0x39, 0x32, 0x37,
  0x33, 0x35, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x36, 0x30, 0x38, 0x30,
  0x33, 0x30, 0x39, 0x32, 0x37, 0x33, 0x35, 0x5a, 0x30, 0x21, 0x31, 0x1f,
  0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16, 0x42, 0x6f, 0x6f,
  0x74, 0x4b, 0x65, 0x79, 0x41, 0x75, 0x74, 0x68, 0x51, 0x65, 0x6d, 0x75,
  0x46, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06,
  0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
  0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf8, 0xa2,
  0xd5, 0xe1, 0x8f, 0xda, 0x53, 0xe8, 0x04, 0x51, 0x3c, 0x89, 0x25, 0x35,
  0x0e, 0x16, 0xa7, 0x5d, 0x83, 0xa5, 0xfe, 0x00, 0x25, 0x5d, 0xc0, 0xe3,
  0xf0, 0x0d, 0x07, 0x7d, 0x63, 0x15, 0xe0, 0x78, 0x6d, 0x40, 0x0b, 0x8e,
  0x8b, 0x90, 0xf5, 0x1f, 0xe3, 0xab, 0x92, 0x4d, 0x40, 0x41, 0x0f, 0xb4,
  0xeb, 0x7d, 0x03, 0x20, 0x7f, 0x20, 0x9c, 0x86, 0xfb, 0x8c, 0xdf, 0x8e,
  0xd7, 0xf3, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
  0x0e, 0x04, 0x16, 0x04, 0x14, 0xac, 0x0c, 0xfb, 0x0b, 0xe6, 0x43, 0x8c,
  0x25, 0x04, 0x17, 0x34, 0xb4, 0xa1, 0x55, 0x14, 0xb4, 0x8f, 0x85, 0xfa,
  0xf9, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16,
  0x80, 0x14, 0xac, 0x0c, 0xfb, 0x0b, 0xe6, 0x43, 0x8c, 0x25, 0x04, 0x17,
  0x34, 0xb4, 0xa1, 0x55, 0x14, 0xb4, 0x8f, 0x85, 0xfa, 0xf9, 0x30, 0x0f,
  0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03,
  0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
  0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x2a, 0x95,
  0xef, 0xc8, 0x54, 0x8c, 0x9c, 0x0d, 0x43, 0x20, 0xc7, 0x68, 0x1c, 0x6b,
  0x17, 0x7a, 0x53, 0x50, 0xf3, 0xb6, 0xb2, 0x82, 0xb5, 0x83, 0xe2, 0xdb,
  0xa7, 0xe5, 0xad, 0xc4, 0x50, 0x9d, 0x02, 0x21, 0x00, 0xe7, 0xf9, 0x09,
  0x30, 0x74, 0xfd, 0xd7, 0x49, 0x38, 0x4f, 0x77, 0x3e, 0x34, 0x91, 0xec,
  0x46, 0x4f, 0xb8, 0x6d, 0x14, 0x33, 0xa0, 0xa9, 0x79, 0x3d, 0xf7, 0x62,
  0x2e, 0x42, 0x5f, 0xc8, 0x85
};

STATIC CONST CHAR8  mPrivateKey[] =
  "-----BEGIN EC PRIVATE KEY-----\n"
  "MHcCAQEEIK8H2cVs0KCpZe2NSFvvRJo5LpQN71QBG7CjtxPOyG9MoAoGCCqGSM49\n"
  "AwEHoUQDQgAE+KLV4Y/aU+gEUTyJJTUOFqddg6X+ACVdwOPwDQd9YxXgeG1AC46L\n"
  "kPUf46uSTUBBD7TrfQMgfyCchvuM347X8w==\n"
  "-----END EC PRIVATE KEY-----\n";

STATIC BOOLEAN  mAssertionPending;
STATIC UINT8    mPendingClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE];

CONST UINTN  gBootKeyTestCredentialIdSize = sizeof (gBootKeyTestCredentialId);
CONST UINTN  gBootKeyTestCertificateSize  = sizeof (gBootKeyTestCertificate);

STATIC
BOOLEAN
TestCredentialAllowed (
  IN CONST UINT8  *CONST  *CredentialIds,
  IN CONST UINTN          *CredentialIdSizes,
  IN UINTN                CredentialCount
  )
{
  UINTN  Index;

  for (Index = 0; Index < CredentialCount; Index++) {
    if ((CredentialIdSizes[Index] == sizeof (gBootKeyTestCredentialId)) &&
        (CompareMem (
           CredentialIds[Index],
           gBootKeyTestCredentialId,
           sizeof (gBootKeyTestCredentialId)
           ) == 0))
    {
      return TRUE;
    }
  }

  return FALSE;
}

EFI_STATUS
EFIAPI
BootKeyGetAssertion (
  IN  CONST CHAR8                              *RpId,
  IN  CONST UINT8                              ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN  CONST UINT8                      *CONST  *CredentialIds,
  IN  CONST UINTN                              *CredentialIdSizes,
  IN  UINTN                                    CredentialCount,
  OUT BOOT_KEY_ASSERTION                       *Assertion
  )
{
  UINT8    SignedData[BOOT_KEY_AUTH_DATA_SIZE + BOOT_KEY_CLIENT_DATA_HASH_SIZE];
  UINT8    SignedDataHash[SHA256_DIGEST_SIZE];
  VOID     *PrivateKey;
  UINTN    SignatureSize;
  BOOLEAN  Result;

  if ((RpId == NULL) || (ClientDataHash == NULL) || (CredentialIds == NULL) ||
      (CredentialIdSizes == NULL) || (Assertion == NULL) ||
      !TestCredentialAllowed (CredentialIds, CredentialIdSizes, CredentialCount))
  {
    return EFI_NOT_FOUND;
  }

  if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 10) {
    if (!mAssertionPending) {
      CopyMem (
        mPendingClientDataHash,
        ClientDataHash,
        sizeof (mPendingClientDataHash)
        );
      mAssertionPending = TRUE;
      DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_ASSERTION_PENDING\n"));
      return EFI_NOT_READY;
    }

    mAssertionPending = FALSE;
    if (CompareMem (
          mPendingClientDataHash,
          ClientDataHash,
          sizeof (mPendingClientDataHash)
          ) != 0)
    {
      DEBUG ((DEBUG_ERROR, "BOOT_KEY_QEMU_CHALLENGE_CHANGED\n"));
      return EFI_SECURITY_VIOLATION;
    }

    DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_ASSERTION_RESUMED\n"));
  }

  ZeroMem (Assertion, sizeof (*Assertion));
  if ((FixedPcdGet32 (PcdBootKeyAuthTestScenario) != 11) &&
      (FixedPcdGet32 (PcdBootKeyAuthTestScenario) != 12))
  {
    Assertion->CredentialIdSize = sizeof (gBootKeyTestCredentialId);
    CopyMem (
      Assertion->CredentialId,
      gBootKeyTestCredentialId,
      sizeof (gBootKeyTestCredentialId)
      );
  }

  if (!Sha256HashAll (
         (CONST UINT8 *)RpId,
         AsciiStrLen (RpId),
         Assertion->AuthenticatorData
         ))
  {
    DEBUG ((DEBUG_ERROR, "BOOT_KEY_QEMU_RP_HASH_ERROR\n"));
    return EFI_DEVICE_ERROR;
  }

  Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE] =
    BOOT_KEY_AUTH_DATA_USER_PRESENT;
  Assertion->AuthenticatorData[36] = 1;

  if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 2) {
    Assertion->AuthenticatorData[0] ^= BIT0;
  } else if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 3) {
    Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE] = 0;
  } else if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 6) {
    Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE] |=
      BOOT_KEY_AUTH_DATA_USER_VERIFIED;
  }

  CopyMem (
    SignedData,
    Assertion->AuthenticatorData,
    sizeof (Assertion->AuthenticatorData)
    );
  CopyMem (
    SignedData + sizeof (Assertion->AuthenticatorData),
    ClientDataHash,
    BOOT_KEY_CLIENT_DATA_HASH_SIZE
    );
  if (!Sha256HashAll (SignedData, sizeof (SignedData), SignedDataHash)) {
    DEBUG ((DEBUG_ERROR, "BOOT_KEY_QEMU_ASSERTION_HASH_ERROR\n"));
    return EFI_DEVICE_ERROR;
  }

  PrivateKey = NULL;
  if (!EcGetPrivateKeyFromPem (
         (CONST UINT8 *)mPrivateKey,
         sizeof (mPrivateKey),
         NULL,
         &PrivateKey
         ))
  {
    DEBUG ((DEBUG_ERROR, "BOOT_KEY_QEMU_PRIVATE_KEY_ERROR\n"));
    return EFI_DEVICE_ERROR;
  }

  SignatureSize = sizeof (Assertion->Signature);
  Result        = EcDsaSign (
                    PrivateKey,
                    CRYPTO_NID_SHA256,
                    SignedDataHash,
                    sizeof (SignedDataHash),
                    Assertion->Signature,
                    &SignatureSize
                    );
  EcFree (PrivateKey);

  if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 1) {
    Assertion->Signature[0] ^= BIT0;
  } else if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 8) {
    Assertion->CredentialIdSize = BOOT_KEY_CREDENTIAL_ID_MAX_SIZE + 1;
  }

  if (Result && (SignatureSize == sizeof (Assertion->Signature))) {
    DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_ASSERTION_READY\n"));
  } else {
    DEBUG ((DEBUG_ERROR, "BOOT_KEY_QEMU_SIGNATURE_ERROR\n"));
  }

  return (Result && (SignatureSize == sizeof (Assertion->Signature))) ?
         EFI_SUCCESS : EFI_DEVICE_ERROR;
}

EFI_STATUS
EFIAPI
BootKeyAuthenticatorPrepare (
  VOID
  )
{
  if (FixedPcdGet32 (PcdBootKeyAuthTestScenario) == 9) {
    DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_PREPARE_WARNING\n"));
    return EFI_WARN_WRITE_FAILURE;
  }

  DEBUG ((DEBUG_INFO, "BOOT_KEY_QEMU_AUTHENTICATOR_READY\n"));
  return EFI_SUCCESS;
}
