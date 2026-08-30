/** @file
  Real USB FIDO transport test for DEBUG QEMU builds.

  This driver creates one non-resident U2F credential, verifies its Yubico
  attestation, and verifies two fresh assertions and their monotonic counters.
  It does not persist a credential or change authenticator configuration.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <BootKey/BootKeyPublicKeyCertificate.h>
#include <BootKey/YubicoFidoAttestationIssuers.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyAuthenticatorLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/RngLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#define BOOT_KEY_TEST_RP_ID                  "starlabs.systems"
#define BOOT_KEY_TEST_TIMEOUT_SECONDS        86400
#define BOOT_KEY_TEST_RETRY_US               250000
#define BOOT_KEY_TEST_STACK_SIZE             SIZE_1MB
#define BOOT_KEY_TEST_ATTESTATION_CERT_SIZE  1024
#define BOOT_KEY_TEST_SIGN_COUNT_OFFSET      33

typedef enum {
  BootKeyTestPrepare,
  BootKeyTestRegister,
  BootKeyTestAssertion1,
  BootKeyTestAssertion2,
  BootKeyTestComplete
} BOOT_KEY_TEST_STATE;

typedef struct {
  BOOT_KEY_TEST_STATE    State;
  EFI_STATUS             Result;
  UINT8                  AttestationCertificate[BOOT_KEY_TEST_ATTESTATION_CERT_SIZE];
  BOOT_KEY_ASSERTION     Assertion;
  UINT8                  Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE];
  UINT8                  CredentialId[BOOT_KEY_CREDENTIAL_ID_MAX_SIZE];
  UINT8                  PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE];
  UINT8                  Signature[BOOT_KEY_ES256_SIGNATURE_SIZE];
  UINTN                  AttestationCertificateSize;
  UINTN                  CredentialIdSize;
  UINT32                 PreviousSignCount;
} BOOT_KEY_TEST_CONTEXT;

STATIC BOOT_KEY_TEST_CONTEXT  mBootKeyTest;

STATIC
VOID
BootKeyTestMessage (
  IN CONST CHAR16  *Message
  )
{
  DEBUG ((DEBUG_INFO, "%s\n", Message));
  Print (L"%s\n", Message);
}

STATIC
BOOLEAN
BootKeyTestTrustedAttestation (
  IN CONST UINT8  *Certificate,
  IN UINTN        CertificateSize
  )
{
  UINTN  Index;

  for (Index = 0; Index < ARRAY_SIZE (mYubicoFidoAttestationIssuers); Index++) {
    if (X509VerifyCert (
          Certificate,
          CertificateSize,
          mYubicoFidoAttestationIssuers[Index].Certificate,
          mYubicoFidoAttestationIssuers[Index].CertificateSize
          ))
    {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
EFI_STATUS
BootKeyTestVerifyRegistration (
  IN CONST UINT8  Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN CONST UINT8  PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE],
  IN CONST UINT8  *AttestationCertificate,
  IN UINTN        AttestationCertificateSize,
  IN CONST UINT8  Signature[BOOT_KEY_ES256_SIGNATURE_SIZE]
  )
{
  UINT8  RegistrationData[1 + BOOT_KEY_RP_ID_HASH_SIZE +
                          BOOT_KEY_CLIENT_DATA_HASH_SIZE +
                          BOOT_KEY_CREDENTIAL_ID_MAX_SIZE +
                          BOOT_KEY_PUBLIC_POINT_SIZE];
  UINT8    RegistrationHash[SHA256_DIGEST_SIZE];
  UINT8    RpIdHash[BOOT_KEY_RP_ID_HASH_SIZE];
  UINTN    RegistrationDataSize;
  VOID     *AttestationKey;
  BOOLEAN  Verified;

  if ((CredentialIdSize == 0) ||
      (CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
      (PublicKey[0] != 0x04) ||
      !BootKeyTestTrustedAttestation (
         AttestationCertificate,
         AttestationCertificateSize
         ) ||
      !Sha256HashAll (
         (CONST UINT8 *)BOOT_KEY_TEST_RP_ID,
         AsciiStrLen (BOOT_KEY_TEST_RP_ID),
         RpIdHash
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  RegistrationData[0] = 0;
  CopyMem (&RegistrationData[1], RpIdHash, sizeof (RpIdHash));
  CopyMem (
    &RegistrationData[1 + sizeof (RpIdHash)],
    Challenge,
    BOOT_KEY_CLIENT_DATA_HASH_SIZE
    );
  RegistrationDataSize = 1 + sizeof (RpIdHash) + BOOT_KEY_CLIENT_DATA_HASH_SIZE;
  CopyMem (&RegistrationData[RegistrationDataSize], CredentialId, CredentialIdSize);
  RegistrationDataSize += CredentialIdSize;
  CopyMem (
    &RegistrationData[RegistrationDataSize],
    PublicKey,
    BOOT_KEY_PUBLIC_POINT_SIZE
    );
  RegistrationDataSize += BOOT_KEY_PUBLIC_POINT_SIZE;
  if (!Sha256HashAll (
         RegistrationData,
         RegistrationDataSize,
         RegistrationHash
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  AttestationKey = NULL;
  if (!EcGetPublicKeyFromX509 (
         AttestationCertificate,
         AttestationCertificateSize,
         &AttestationKey
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Verified = EcDsaVerify (
               AttestationKey,
               CRYPTO_NID_SHA256,
               RegistrationHash,
               sizeof (RegistrationHash),
               Signature,
               BOOT_KEY_ES256_SIGNATURE_SIZE
               );
  EcFree (AttestationKey);
  return Verified ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

STATIC
UINT32
BootKeyTestReadUint32BigEndian (
  IN CONST UINT8  *Buffer
  )
{
  return ((UINT32)Buffer[0] << 24) |
         ((UINT32)Buffer[1] << 16) |
         ((UINT32)Buffer[2] << 8) |
         Buffer[3];
}

STATIC
EFI_STATUS
BootKeyTestVerifyAssertion (
  IN CONST UINT8               Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN CONST UINT8               *CredentialId,
  IN UINTN                     CredentialIdSize,
  IN CONST UINT8               PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE],
  IN CONST BOOT_KEY_ASSERTION  *Assertion,
  IN UINT32                    PreviousSignCount,
  OUT UINT32                   *SignCount
  )
{
  UINT8    Certificate[sizeof (mBootKeyPublicKeyCertificateTemplate)];
  UINT8    ExpectedRpIdHash[BOOT_KEY_RP_ID_HASH_SIZE];
  UINT8    SignedData[BOOT_KEY_AUTH_DATA_SIZE + BOOT_KEY_CLIENT_DATA_HASH_SIZE];
  UINT8    SignedDataHash[SHA256_DIGEST_SIZE];
  VOID     *CredentialKey;
  BOOLEAN  Verified;

  if ((Assertion->CredentialIdSize != CredentialIdSize) ||
      (CompareMem (
         Assertion->CredentialId,
         CredentialId,
         CredentialIdSize
         ) != 0) ||
      !Sha256HashAll (
         (CONST UINT8 *)BOOT_KEY_TEST_RP_ID,
         AsciiStrLen (BOOT_KEY_TEST_RP_ID),
         ExpectedRpIdHash
         ) ||
      (CompareMem (
         ExpectedRpIdHash,
         Assertion->AuthenticatorData,
         sizeof (ExpectedRpIdHash)
         ) != 0) ||
      (Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE] !=
       BOOT_KEY_AUTH_DATA_USER_PRESENT))
  {
    return EFI_SECURITY_VIOLATION;
  }

  *SignCount = BootKeyTestReadUint32BigEndian (
                 &Assertion->AuthenticatorData[BOOT_KEY_TEST_SIGN_COUNT_OFFSET]
                 );
  if ((*SignCount == 0) || (*SignCount <= PreviousSignCount)) {
    return EFI_SECURITY_VIOLATION;
  }

  CopyMem (
    SignedData,
    Assertion->AuthenticatorData,
    sizeof (Assertion->AuthenticatorData)
    );
  CopyMem (
    SignedData + sizeof (Assertion->AuthenticatorData),
    Challenge,
    BOOT_KEY_CLIENT_DATA_HASH_SIZE
    );
  if (!Sha256HashAll (SignedData, sizeof (SignedData), SignedDataHash)) {
    return EFI_SECURITY_VIOLATION;
  }

  CopyMem (
    Certificate,
    mBootKeyPublicKeyCertificateTemplate,
    sizeof (Certificate)
    );
  CopyMem (
    &Certificate[BOOT_KEY_X509_PUBLIC_OFFSET],
    PublicKey,
    BOOT_KEY_PUBLIC_POINT_SIZE
    );
  CredentialKey = NULL;
  if (!EcGetPublicKeyFromX509 (
         Certificate,
         sizeof (Certificate),
         &CredentialKey
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Verified = EcDsaVerify (
               CredentialKey,
               CRYPTO_NID_SHA256,
               SignedDataHash,
               sizeof (SignedDataHash),
               Assertion->Signature,
               sizeof (Assertion->Signature)
               );
  EcFree (CredentialKey);
  return Verified ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

STATIC
EFI_STATUS
BootKeyTestRandomChallenge (
  OUT UINT8  Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE]
  )
{
  UINT64  Random[4];

  if (!GetRandomNumber128 (&Random[0]) || !GetRandomNumber128 (&Random[2])) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem (Challenge, Random, sizeof (Random));
  return EFI_SUCCESS;
}

STATIC
VOID
BootKeyTestFinish (
  IN EFI_STATUS  Status
  )
{
  if (mBootKeyTest.State == BootKeyTestComplete) {
    return;
  }

  mBootKeyTest.State  = BootKeyTestComplete;
  mBootKeyTest.Result = Status;

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "BOOT_KEY_USB_TEST_FAIL: %r\n", Status));
    Print (L"BOOT_KEY_USB_TEST_FAIL: %r\n", Status);
  } else {
    BootKeyTestMessage (L"BOOT_KEY_USB_TEST_PASS");
  }
}

STATIC
VOID
EFIAPI
BootKeyTestPollCallback (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  CONST UINT8  *CredentialIds[1];
  UINT8        DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
  UINTN        CredentialIdSizes[1];
  UINT32       SignCount;
  EFI_STATUS   Status;

  (VOID)Event;
  (VOID)Context;

  switch (mBootKeyTest.State) {
    case BootKeyTestPrepare:
      Status = BootKeyAuthenticatorPrepare ();
      if (Status == EFI_NOT_READY) {
        return;
      }

      if (EFI_ERROR (Status)) {
        DEBUG ((DEBUG_INFO, "BootKeyUsbFidoTest: prepare retry after %r\n", Status));
        return;
      }

      Status = BootKeyGetAuthenticatorIdentity (DeviceIdentity);
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      Status = BootKeyTestRandomChallenge (mBootKeyTest.Challenge);
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      BootKeyTestMessage (L"BOOT_KEY_USB_TEST_IDENTITY_OK");
      BootKeyTestMessage (L"BOOT_KEY_USB_TEST_WAIT_REGISTER_TOUCH");
      mBootKeyTest.State = BootKeyTestRegister;
      return;

    case BootKeyTestRegister:
      mBootKeyTest.CredentialIdSize           = sizeof (mBootKeyTest.CredentialId);
      mBootKeyTest.AttestationCertificateSize =
        sizeof (mBootKeyTest.AttestationCertificate);
      Status = BootKeyMakeCredential (
                 BOOT_KEY_TEST_RP_ID,
                 mBootKeyTest.Challenge,
                 mBootKeyTest.CredentialId,
                 &mBootKeyTest.CredentialIdSize,
                 mBootKeyTest.PublicKey,
                 mBootKeyTest.AttestationCertificate,
                 &mBootKeyTest.AttestationCertificateSize,
                 mBootKeyTest.Signature
                 );
      if (Status == EFI_NOT_READY) {
        return;
      }

      DEBUG ((
        DEBUG_INFO,
        "BootKeyUsbFidoTest: make credential %r credential/certificate size %u/%u\n",
        Status,
        mBootKeyTest.CredentialIdSize,
        mBootKeyTest.AttestationCertificateSize
        ));
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      Status = BootKeyTestVerifyRegistration (
                 mBootKeyTest.Challenge,
                 mBootKeyTest.CredentialId,
                 mBootKeyTest.CredentialIdSize,
                 mBootKeyTest.PublicKey,
                 mBootKeyTest.AttestationCertificate,
                 mBootKeyTest.AttestationCertificateSize,
                 mBootKeyTest.Signature
                 );
      DEBUG ((DEBUG_INFO, "BootKeyUsbFidoTest: verify registration %r\n", Status));
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      Status = BootKeyTestRandomChallenge (mBootKeyTest.Challenge);
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      ZeroMem (&mBootKeyTest.Assertion, sizeof (mBootKeyTest.Assertion));
      mBootKeyTest.PreviousSignCount = 0;
      mBootKeyTest.State             = BootKeyTestAssertion1;
      BootKeyTestMessage (L"BOOT_KEY_USB_TEST_REGISTRATION_OK");
      BootKeyTestMessage (L"BOOT_KEY_USB_TEST_WAIT_ASSERTION_1_TOUCH");
      return;

    case BootKeyTestAssertion1:
    case BootKeyTestAssertion2:
      CredentialIds[0]     = mBootKeyTest.CredentialId;
      CredentialIdSizes[0] = mBootKeyTest.CredentialIdSize;
      Status               = BootKeyGetAssertion (
                               BOOT_KEY_TEST_RP_ID,
                               mBootKeyTest.Challenge,
                               CredentialIds,
                               CredentialIdSizes,
                               ARRAY_SIZE (CredentialIds),
                               &mBootKeyTest.Assertion
                               );
      if (Status == EFI_NOT_READY) {
        return;
      }

      DEBUG ((
        DEBUG_INFO,
        "BootKeyUsbFidoTest: get assertion state/status %u/%r\n",
        mBootKeyTest.State,
        Status
        ));
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      Status = BootKeyTestVerifyAssertion (
                 mBootKeyTest.Challenge,
                 mBootKeyTest.CredentialId,
                 mBootKeyTest.CredentialIdSize,
                 mBootKeyTest.PublicKey,
                 &mBootKeyTest.Assertion,
                 mBootKeyTest.PreviousSignCount,
                 &SignCount
                 );
      if (EFI_ERROR (Status)) {
        BootKeyTestFinish (Status);
        return;
      }

      mBootKeyTest.PreviousSignCount = SignCount;
      if (mBootKeyTest.State == BootKeyTestAssertion1) {
        Status = BootKeyTestRandomChallenge (mBootKeyTest.Challenge);
        if (EFI_ERROR (Status)) {
          BootKeyTestFinish (Status);
          return;
        }

        ZeroMem (&mBootKeyTest.Assertion, sizeof (mBootKeyTest.Assertion));
        mBootKeyTest.State = BootKeyTestAssertion2;
        BootKeyTestMessage (L"BOOT_KEY_USB_TEST_ASSERTION_1_OK");
        BootKeyTestMessage (L"BOOT_KEY_USB_TEST_WAIT_ASSERTION_2_TOUCH");
        return;
      }

      BootKeyTestMessage (L"BOOT_KEY_USB_TEST_ASSERTION_2_OK");
      BootKeyTestFinish (EFI_SUCCESS);
      return;

    case BootKeyTestComplete:
    default:
      return;
  }
}

STATIC
EFI_STATUS
BootKeyTestRun (
  VOID
  )
{
  EFI_STATUS  Result;
  UINTN       PollsRemaining;

  PollsRemaining =
    (BOOT_KEY_TEST_TIMEOUT_SECONDS * 1000000ULL) / BOOT_KEY_TEST_RETRY_US;
  BootKeyTestMessage (L"BOOT_KEY_USB_TEST_WAIT_INSERT");
  while ((mBootKeyTest.State != BootKeyTestComplete) &&
         (PollsRemaining-- > 0))
  {
    BootKeyTestPollCallback (NULL, NULL);
    if (mBootKeyTest.State != BootKeyTestComplete) {
      gBS->Stall (BOOT_KEY_TEST_RETRY_US);
    }
  }

  if (mBootKeyTest.State != BootKeyTestComplete) {
    BootKeyTestFinish (EFI_TIMEOUT);
  }

  Result = mBootKeyTest.Result;
  ZeroMem (&mBootKeyTest, sizeof (mBootKeyTest));
  return Result;
}

VOID
EFIAPI
BootKeyTestDedicatedStackEntry (
  IN VOID  *Context1,
  IN VOID  *Context2
  )
{
  (VOID)Context1;
  (VOID)Context2;

  ZeroMem (&mBootKeyTest, sizeof (mBootKeyTest));
  BootKeyTestRun ();
  CpuDeadLoop ();
}

EFI_STATUS
EFIAPI
BootKeyUsbFidoTestEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  VOID  *Stack;

  (VOID)ImageHandle;
  (VOID)SystemTable;

  Stack = AllocatePages (EFI_SIZE_TO_PAGES (BOOT_KEY_TEST_STACK_SIZE));
  if (Stack == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  SwitchStack (
    BootKeyTestDedicatedStackEntry,
    NULL,
    NULL,
    (VOID *)((UINTN)Stack + BOOT_KEY_TEST_STACK_SIZE - CPU_STACK_ALIGNMENT)
    );
  return EFI_DEVICE_ERROR;
}
