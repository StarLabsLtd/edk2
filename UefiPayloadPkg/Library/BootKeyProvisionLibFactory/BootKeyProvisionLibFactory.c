/** @file
  Factory provisioning for the Star Labs boot-key credential set.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/GlobalVariable.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyAuthenticatorLib.h>
#include <Library/BootKeyCredentialStoreLib.h>
#include <Library/BootKeyPlatformSecurityLib.h>
#include <Library/BootKeyPowerSafetyLib.h>
#include <Library/BootKeyProvisionLib.h>
#include <Library/DebugLib.h>
#include <Library/RngLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include "YubicoFidoAttestationIssuers.h"

#define BOOT_KEY_RP_ID                  "starlabs.systems"
#define BOOT_KEY_PROVISION_WAIT_US      250000
#define BOOT_KEY_PUBLIC_POINT_SIZE      65
#define BOOT_KEY_ATTESTATION_CERT_SIZE  1024

STATIC
BOOLEAN
BootKeyByteVariableEquals (
  IN CHAR16    *Name,
  IN EFI_GUID  *Guid,
  IN UINT32    ExpectedAttributes,
  IN UINT8     ExpectedValue
  )
{
  EFI_STATUS  Status;
  UINT32      Attributes;
  UINT8       Value;
  UINTN       Size;

  Attributes = 0;
  Value      = 0;
  Size       = sizeof (Value);
  Status     = gRT->GetVariable (Name, Guid, &Attributes, &Size, &Value);
  return (Status == EFI_SUCCESS) &&
         (Size == sizeof (Value)) &&
         (Attributes == ExpectedAttributes) &&
         (Value == ExpectedValue);
}

STATIC
BOOLEAN
BootKeySecureBootEnabled (
  VOID
  )
{
  return BootKeyByteVariableEquals (
           EFI_SETUP_MODE_NAME,
           &gEfiGlobalVariableGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
           0
           ) &&
         BootKeyByteVariableEquals (
           EFI_SECURE_BOOT_MODE_NAME,
           &gEfiGlobalVariableGuid,
           EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
           1
           ) &&
         BootKeyByteVariableEquals (
           EFI_SECURE_BOOT_ENABLE_NAME,
           &gEfiSecureBootEnableDisableGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
           1
           ) &&
         BootKeyByteVariableEquals (
           EFI_CUSTOM_MODE_NAME,
           &gEfiCustomModeEnableGuid,
           EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
           0
           );
}

STATIC
BOOLEAN
BootKeyAttestationCertificateTrusted (
  IN CONST UINT8  *Certificate,
  IN UINTN        CertificateSize
  )
{
  UINTN  Index;

  if ((Certificate == NULL) || (CertificateSize == 0)) {
    return FALSE;
  }

  //
  // Pin the published Yubico issuers that are specifically scoped to FIDO.
  // This is intentionally narrower than trusting Yubico's unified root: a
  // certificate from another Yubico product hierarchy must not enroll here.
  //
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
BootKeyVerifyRegistration (
  IN CONST UINT8  Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN CONST UINT8  PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE],
  IN CONST UINT8  *AttestationCertificate,
  IN UINTN        AttestationCertificateSize,
  IN CONST UINT8  Signature[BOOT_KEY_ES256_SIGNATURE_SIZE]
  )
{
  UINT8  RpIdHash[BOOT_KEY_RP_ID_HASH_SIZE];
  UINT8  RegistrationHash[SHA256_DIGEST_SIZE];
  UINT8  RegistrationData[1 + BOOT_KEY_RP_ID_HASH_SIZE +
                          BOOT_KEY_CLIENT_DATA_HASH_SIZE +
                          BOOT_KEY_CREDENTIAL_ID_MAX_SIZE +
                          BOOT_KEY_PUBLIC_POINT_SIZE];
  UINTN    RegistrationDataSize;
  VOID     *AttestationKey;
  BOOLEAN  Verified;

  if ((CredentialId == NULL) || (CredentialIdSize == 0) ||
      (CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
      (PublicKey == NULL) || (PublicKey[0] != 0x04) ||
      (AttestationCertificate == NULL) || (AttestationCertificateSize == 0) ||
      (Signature == NULL) ||
      !BootKeyAttestationCertificateTrusted (
         AttestationCertificate,
         AttestationCertificateSize
         ) ||
      !Sha256HashAll (
         (CONST UINT8 *)BOOT_KEY_RP_ID,
         AsciiStrLen (BOOT_KEY_RP_ID),
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
EFI_STATUS
BootKeyWaitForAuthenticator (
  VOID
  )
{
  EFI_STATUS  Status;

  do {
    Status = BootKeyAuthenticatorPrepare ();
    if (Status == EFI_NOT_READY) {
      DEBUG ((DEBUG_INFO, "BOOT_KEY_PROVISION_INSERT_KEY\n"));
      gBS->Stall (BOOT_KEY_PROVISION_WAIT_US);
    }
  } while (Status == EFI_NOT_READY);

  return Status;
}

STATIC
EFI_STATUS
BootKeyWaitForRemoval (
  VOID
  )
{
  EFI_STATUS  Status;

  do {
    Status = BootKeyAuthenticatorRequireRemoval ();
    if (Status == EFI_NOT_READY) {
      DEBUG ((DEBUG_INFO, "BOOT_KEY_PROVISION_REMOVE_KEY\n"));
      gBS->Stall (BOOT_KEY_PROVISION_WAIT_US);
    }
  } while (Status == EFI_NOT_READY);

  return Status;
}

BOOLEAN
EFIAPI
BootKeyFactoryProvisioningRequired (
  VOID
  )
{
  return TRUE;
}

EFI_STATUS
EFIAPI
BootKeyProvisionFactorySet (
  VOID
  )
{
  BOOT_KEY_PROVISIONING_CREDENTIAL  Pending[BOOT_KEY_MAX_ENROLLED_CREDENTIALS];
  BOOT_KEY_CREDENTIAL               Existing[BOOT_KEY_MAX_ENROLLED_CREDENTIALS];
  UINT8                AttestationCertificate[BOOT_KEY_ATTESTATION_CERT_SIZE];
  UINT8                Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE];
  UINT8                CredentialId[BOOT_KEY_CREDENTIAL_ID_MAX_SIZE];
  UINT8                DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
  UINT8                VerifiedDeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
  UINT8                PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE];
  UINT8                Signature[BOOT_KEY_ES256_SIGNATURE_SIZE];
  UINT64               Random[4];
  UINTN                AttestationCertificateSize;
  UINTN                CredentialCount;
  UINTN                CredentialIdSize;
  UINTN                Index;
  EFI_STATUS           Status;

  Status = BootKeyPowerSafetyArm ();
  if (Status != EFI_SUCCESS) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = BootKeyVerifyPlatformSecurityBoundary ();
  if (Status != EFI_SUCCESS) {
    return EFI_SECURITY_VIOLATION;
  }

  if (!BootKeySecureBootEnabled ()) {
    return EFI_SECURITY_VIOLATION;
  }

  ZeroMem (Pending, sizeof (Pending));
  CredentialCount = ARRAY_SIZE (Existing);
  Status          = BootKeyGetCredentialSet (Existing, &CredentialCount);
  if (Status != EFI_NOT_FOUND) {
    return EFI_SECURITY_VIOLATION;
  }

  CredentialCount = 0;

  while (CredentialCount < BOOT_KEY_MAX_ENROLLED_CREDENTIALS) {
    Status = BootKeyWaitForAuthenticator ();
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = BootKeyGetAuthenticatorIdentity (DeviceIdentity);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (!GetRandomNumber128 (&Random[0]) || !GetRandomNumber128 (&Random[2])) {
      return EFI_DEVICE_ERROR;
    }

    CopyMem (Challenge, Random, sizeof (Challenge));
    do {
      CredentialIdSize           = sizeof (CredentialId);
      AttestationCertificateSize = sizeof (AttestationCertificate);
      Status                     = BootKeyMakeCredential (
                                     BOOT_KEY_RP_ID,
                                     Challenge,
                                     CredentialId,
                                     &CredentialIdSize,
                                     PublicKey,
                                     AttestationCertificate,
                                     &AttestationCertificateSize,
                                     Signature
                                     );
      if (Status == EFI_NOT_READY) {
        DEBUG ((DEBUG_INFO, "BOOT_KEY_PROVISION_TOUCH_KEY\n"));
        gBS->Stall (BOOT_KEY_PROVISION_WAIT_US);
      }
    } while (Status == EFI_NOT_READY);

    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = BootKeyVerifyRegistration (
               Challenge,
               CredentialId,
               CredentialIdSize,
               PublicKey,
               AttestationCertificate,
               AttestationCertificateSize,
               Signature
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = BootKeyGetAuthenticatorIdentity (VerifiedDeviceIdentity);
    if (EFI_ERROR (Status) ||
        (CompareMem (
           DeviceIdentity,
           VerifiedDeviceIdentity,
           sizeof (DeviceIdentity)
           ) != 0))
    {
      return EFI_SECURITY_VIOLATION;
    }

    for (Index = 0; Index < CredentialCount; Index++) {
      if (((Pending[Index].CredentialIdSize == CredentialIdSize) &&
           (CompareMem (
              Pending[Index].CredentialId,
              CredentialId,
              CredentialIdSize
              ) == 0)) ||
          (CompareMem (
             Pending[Index].DeviceIdentity,
             DeviceIdentity,
             sizeof (DeviceIdentity)
             ) == 0))
      {
        return EFI_ALREADY_STARTED;
      }
    }

    Pending[CredentialCount].CredentialIdSize = CredentialIdSize;
    CopyMem (
      Pending[CredentialCount].CredentialId,
      CredentialId,
      CredentialIdSize
      );
    CopyMem (Pending[CredentialCount].PublicKey, PublicKey, sizeof (PublicKey));
    CopyMem (
      Pending[CredentialCount].DeviceIdentity,
      DeviceIdentity,
      sizeof (DeviceIdentity)
      );
    CredentialCount++;
    DEBUG ((
      DEBUG_INFO,
      "BOOT_KEY_PROVISION_ENROLLED_%u_OF_%u\n",
      CredentialCount,
      BOOT_KEY_MAX_ENROLLED_CREDENTIALS
      ));

    Status = BootKeyWaitForRemoval ();
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  Status = BootKeyProvisionCredentialSet (Pending, CredentialCount);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // The caller powers the machine off immediately. Keep the autonomous EC
  // guard armed until power-off, including if ResetSystem() unexpectedly
  // returns.
  //
  return EFI_SUCCESS;
}
