/** @file
  TPM 2.0 NV-backed boot-key credential store.

  Writes are authorized by a policy session bound to an OEM PCR 6 write-window
  state and to TPM2_NV_Write. Firmware irreversibly extends PCR 6 to close the
  window before any general device discovery or external code executes. The
  indices are platform-created and firmware disables the platform hierarchy
  before accepting authenticator input. Credential, attempt, and escalating
  lockout state are held in two alternating records so interrupted writes
  preserve the last valid generation. TPMA_NV_WRITEALL makes each individual
  slot update a single TPM command; it does not itself provide crash atomicity.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <IndustryStandard/UefiTcgPlatform.h>
#include <IndustryStandard/Tpm20.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyCredentialStoreLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/RngLib.h>
#include <Library/Tpm2CommandLib.h>
#include <Library/Tpm2DeviceLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/Tcg2Protocol.h>

#define BOOT_KEY_NV_INDEX_A          0x0180f1d0U
#define BOOT_KEY_NV_INDEX_B          0x0180f1d1U
#define BOOT_KEY_NV_SLOT_COUNT       2
#define BOOT_KEY_NV_RECORD_MAGIC     SIGNATURE_32 ('B', 'K', 'N', 'V')
//
// Version 3 replaces the unreleased EC-secret-backed version 2 policy. The
// policies are intentionally incompatible: production fails closed on old
// indices, while the dedicated factory image undefines and reprovisions them.
// Do not deploy this format as an in-place upgrade over a provisioned v2 unit.
//
#define BOOT_KEY_NV_RECORD_VERSION   3
#define BOOT_KEY_NV_POLICY_PCR       6
#define BOOT_KEY_PUBLIC_POINT_SIZE   65
#define BOOT_KEY_X509_PUBLIC_OFFSET  177
#define BOOT_KEY_X509_PUBLIC_SIZE    65

#pragma pack (1)
typedef struct {
  UINT8     CredentialIdSize;
  UINT8     CredentialId[BOOT_KEY_CREDENTIAL_ID_MAX_SIZE];
  UINT8     PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE];
  UINT8     DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
  UINT32    SignCount;
} BOOT_KEY_NV_CREDENTIAL;

typedef struct {
  UINT32                    Magic;
  UINT16                    Version;
  UINT16                    Size;
  UINT64                    Generation;
  UINT8                     CredentialCount;
  UINT8                     FailureStage;
  UINT8                     AttemptActive;
  UINT8                     Reserved;
  UINT8                     Digest[SHA256_DIGEST_SIZE];
  BOOT_KEY_NV_CREDENTIAL    Credentials[BOOT_KEY_MAX_ENROLLED_CREDENTIALS];
} BOOT_KEY_NV_RECORD;
#pragma pack ()

STATIC BOOLEAN                 mBootKeyStorePrepared;
STATIC BOOLEAN                 mBootKeyFactoryInitialization;
STATIC BOOLEAN                 mBootKeyWriteWindowClosed;
STATIC BOOLEAN                 mBootKeyCachedRecordValid[BOOT_KEY_NV_SLOT_COUNT];
STATIC BOOT_KEY_NV_RECORD      mBootKeyCachedRecord[BOOT_KEY_NV_SLOT_COUNT];
STATIC UINTN                   mBootKeyCurrentSlot;
STATIC CONST TPMI_RH_NV_INDEX  mBootKeyNvIndex[BOOT_KEY_NV_SLOT_COUNT] = {
  BOOT_KEY_NV_INDEX_A,
  BOOT_KEY_NV_INDEX_B
};
STATIC CONST CHAR8             mBootKeyWriteWindowClosedEvent[] =
  "StarLabs BootKey NV write window closed";

STATIC
BOOLEAN
BootKeyRecordValid (
  IN CONST BOOT_KEY_NV_RECORD  *Record
  );

STATIC_ASSERT (
  sizeof (BOOT_KEY_NV_RECORD) <= MAX_DIGEST_BUFFER,
  "Boot-key TPM NV record exceeds one atomic TPM transfer"
  );

//
// A syntactically valid P-256 certificate used only as an EDK2 BaseCryptLib
// public-key container. Its certificate signature is intentionally not a trust
// input. Provisioning independently verifies the authenticator registration,
// and TPM NV protects the substituted credential point.
//
STATIC CONST UINT8  mPublicKeyCertificateTemplate[] = {
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

STATIC
BOOLEAN
BootKeyPublicPointValid (
  IN CONST UINT8  PublicKey[BOOT_KEY_PUBLIC_POINT_SIZE]
  )
{
  UINT8  Certificate[sizeof (mPublicKeyCertificateTemplate)];
  UINT8  ParsedPublicKey[BOOT_KEY_PUBLIC_POINT_SIZE - 1];
  UINTN  ParsedPublicKeySize;
  VOID   *EcContext;

  if ((PublicKey == NULL) || (PublicKey[0] != 0x04)) {
    return FALSE;
  }

  CopyMem (Certificate, mPublicKeyCertificateTemplate, sizeof (Certificate));
  CopyMem (
    &Certificate[BOOT_KEY_X509_PUBLIC_OFFSET],
    PublicKey,
    BOOT_KEY_PUBLIC_POINT_SIZE
    );

  EcContext = NULL;
  if (!EcGetPublicKeyFromX509 (Certificate, sizeof (Certificate), &EcContext)) {
    return FALSE;
  }

  ParsedPublicKeySize = sizeof (ParsedPublicKey);
  if (!EcGetPubKey (EcContext, ParsedPublicKey, &ParsedPublicKeySize)) {
    EcFree (EcContext);
    return FALSE;
  }

  EcFree (EcContext);
  return (ParsedPublicKeySize == sizeof (ParsedPublicKey)) &&
         (CompareMem (ParsedPublicKey, PublicKey + 1, sizeof (ParsedPublicKey)) == 0);
}

STATIC
EFI_STATUS
BootKeyPolicyWriteWindow (
  IN TPMI_SH_POLICY  Session
  )
{
  UINT8   Command[64];
  UINT8   InitialPcr[SHA256_DIGEST_SIZE];
  UINT8   PcrDigest[SHA256_DIGEST_SIZE];
  UINT8   Response[sizeof (TPM2_RESPONSE_HEADER)];
  UINT8   *Buffer;
  UINT32  CommandSize;
  UINT32  ResponseSize;

  Buffer = Command;
  ZeroMem (InitialPcr, sizeof (InitialPcr));
  if (!Sha256HashAll (
         InitialPcr,
         sizeof (InitialPcr),
         PcrDigest
         ))
  {
    return EFI_DEVICE_ERROR;
  }

  WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (TPM_ST_NO_SESSIONS));
  Buffer += sizeof (UINT16);
  Buffer += sizeof (UINT32);
  WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32 (TPM_CC_PolicyPCR));
  Buffer += sizeof (UINT32);
  WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32 (Session));
  Buffer += sizeof (UINT32);
  WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (sizeof (PcrDigest)));
  Buffer += sizeof (UINT16);
  CopyMem (Buffer, PcrDigest, sizeof (PcrDigest));
  Buffer += sizeof (PcrDigest);
  WriteUnaligned32 ((UINT32 *)Buffer, SwapBytes32 (1));
  Buffer += sizeof (UINT32);
  WriteUnaligned16 ((UINT16 *)Buffer, SwapBytes16 (TPM_ALG_SHA256));
  Buffer   += sizeof (UINT16);
  *Buffer++ = 3;
  *Buffer++ = (UINT8)(1U << BOOT_KEY_NV_POLICY_PCR);
  *Buffer++ = 0;
  *Buffer++ = 0;

  CommandSize = (UINT32)(Buffer - Command);
  WriteUnaligned32 ((UINT32 *)&Command[2], SwapBytes32 (CommandSize));
  ResponseSize = sizeof (Response);
  if (EFI_ERROR (
        Tpm2SubmitCommand (
          CommandSize,
          Command,
          &ResponseSize,
          Response
          )
        ))
  {
    return EFI_DEVICE_ERROR;
  }

  if ((ResponseSize < sizeof (TPM2_RESPONSE_HEADER)) ||
      (SwapBytes32 (ReadUnaligned32 ((UINT32 *)&Response[6])) != TPM_RC_SUCCESS))
  {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

STATIC
VOID
BootKeyWipe (
  OUT VOID   *Buffer,
  IN  UINTN  Size
  )
{
  volatile UINT8  *Byte;

  Byte = Buffer;
  while (Size-- != 0) {
    *Byte++ = 0;
  }
}

STATIC
VOID
BootKeyPasswordAuthorization (
  OUT TPMS_AUTH_COMMAND  *Authorization,
  IN  CONST UINT8        *Auth,
  IN  UINT16             AuthSize
  )
{
  ZeroMem (Authorization, sizeof (*Authorization));
  Authorization->sessionHandle = TPM_RS_PW;
  Authorization->hmac.size     = AuthSize;
  CopyMem (Authorization->hmac.buffer, Auth, AuthSize);
}

STATIC
VOID
BootKeyEmptyAuthorization (
  OUT TPMS_AUTH_COMMAND  *Authorization
  )
{
  ZeroMem (Authorization, sizeof (*Authorization));
  Authorization->sessionHandle = TPM_RS_PW;
}

STATIC
EFI_STATUS
BootKeyStartPolicySession (
  OUT TPMI_SH_AUTH_SESSION  *Session,
  OUT TPM2B_NONCE           *NonceTpm
  )
{
  TPM2B_ENCRYPTED_SECRET  Salt;
  TPM2B_NONCE             NonceCaller;
  TPMT_SYM_DEF            Symmetric;
  UINT64                  Random[2];
  EFI_STATUS              Status;

  ZeroMem (&NonceCaller, sizeof (NonceCaller));
  ZeroMem (NonceTpm, sizeof (*NonceTpm));
  ZeroMem (&Salt, sizeof (Salt));
  ZeroMem (&Symmetric, sizeof (Symmetric));
  ZeroMem (Random, sizeof (Random));
  if (!GetRandomNumber128 (Random)) {
    return EFI_DEVICE_ERROR;
  }

  NonceCaller.size = sizeof (Random);
  CopyMem (NonceCaller.buffer, Random, sizeof (Random));
  Symmetric.algorithm = TPM_ALG_NULL;

  Status = Tpm2StartAuthSession (
             TPM_RH_NULL,
             TPM_RH_NULL,
             &NonceCaller,
             &Salt,
             TPM_SE_POLICY,
             &Symmetric,
             TPM_ALG_SHA256,
             Session,
             NonceTpm
             );
  BootKeyWipe (Random, sizeof (Random));
  BootKeyWipe (&NonceCaller, sizeof (NonceCaller));
  return Status;
}

STATIC
EFI_STATUS
BootKeyStartWritePolicySession (
  OUT TPMI_SH_AUTH_SESSION    *Session,
  OUT TPMS_AUTH_COMMAND       *Authorization OPTIONAL,
  OUT TPM2B_DIGEST            *PolicyDigest OPTIONAL
  )
{
  TPM2B_NONCE        NonceTpm;
  EFI_STATUS         Status;

  Status = BootKeyStartPolicySession (Session, &NonceTpm);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = BootKeyPolicyWriteWindow (*Session);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  Status = Tpm2PolicyCommandCode (*Session, TPM_CC_NV_Write);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if (PolicyDigest != NULL) {
    Status = Tpm2PolicyGetDigest (*Session, PolicyDigest);
    if (EFI_ERROR (Status)) {
      goto Error;
    }
  }

  if (Authorization != NULL) {
    ZeroMem (Authorization, sizeof (*Authorization));
    Authorization->sessionHandle = *Session;
  }

  return EFI_SUCCESS;

Error:
  Tpm2FlushContext (*Session);
  *Session = TPM_RH_NULL;
  return Status;
}

STATIC
EFI_STATUS
BootKeyValidateNvPublic (
  IN  TPMI_RH_NV_INDEX  NvIndex,
  IN  TPM2B_DIGEST      *ExpectedPolicy,
  OUT BOOLEAN           *Written OPTIONAL
  )
{
  TPM2B_NAME       Name;
  TPM2B_NV_PUBLIC  Public;
  TPMA_NV          ActualAttributes;
  TPMA_NV          ExpectedAttributes;
  EFI_STATUS       Status;

  ZeroMem (&Public, sizeof (Public));
  ZeroMem (&Name, sizeof (Name));
  Status = Tpm2NvReadPublic (NvIndex, &Public, &Name);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ZeroMem (&ExpectedAttributes, sizeof (ExpectedAttributes));
  ExpectedAttributes.TPMA_NV_POLICYWRITE    = 1;
  ExpectedAttributes.TPMA_NV_WRITEALL       = 1;
  ExpectedAttributes.TPMA_NV_AUTHREAD       = 1;
  ExpectedAttributes.TPMA_NV_NO_DA          = 1;
  ExpectedAttributes.TPMA_NV_PLATFORMCREATE = 1;
  CopyMem (&ActualAttributes, &Public.nvPublic.attributes, sizeof (ActualAttributes));
  ActualAttributes.TPMA_NV_WRITTEN = 0;

  if ((Public.nvPublic.nvIndex != NvIndex) ||
      (Public.nvPublic.nameAlg != TPM_ALG_SHA256) ||
      (CompareMem (
         &ActualAttributes,
         &ExpectedAttributes,
         sizeof (ActualAttributes)
         ) != 0) ||
      (Public.nvPublic.dataSize != sizeof (BOOT_KEY_NV_RECORD)) ||
      (Public.nvPublic.authPolicy.size != ExpectedPolicy->size) ||
      (CompareMem (
         Public.nvPublic.authPolicy.buffer,
         ExpectedPolicy->buffer,
         ExpectedPolicy->size
         ) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if (Written != NULL) {
    *Written = Public.nvPublic.attributes.TPMA_NV_WRITTEN;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyDefineNvIndex (
  IN TPMI_RH_NV_INDEX  NvIndex,
  IN TPM2B_DIGEST      *PolicyDigest
  )
{
  TPM2B_AUTH       Auth;
  TPM2B_NV_PUBLIC  Public;
  EFI_STATUS       Status;

  ZeroMem (&Auth, sizeof (Auth));
  ZeroMem (&Public, sizeof (Public));
  Public.size = sizeof (Public.nvPublic.nvIndex) +
                sizeof (Public.nvPublic.nameAlg) +
                sizeof (Public.nvPublic.attributes) +
                sizeof (Public.nvPublic.authPolicy.size) +
                PolicyDigest->size +
                sizeof (Public.nvPublic.dataSize);
  Public.nvPublic.nvIndex                           = NvIndex;
  Public.nvPublic.nameAlg                           = TPM_ALG_SHA256;
  Public.nvPublic.attributes.TPMA_NV_POLICYWRITE    = 1;
  Public.nvPublic.attributes.TPMA_NV_WRITEALL       = 1;
  Public.nvPublic.attributes.TPMA_NV_AUTHREAD       = 1;
  Public.nvPublic.attributes.TPMA_NV_NO_DA          = 1;
  Public.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
  Public.nvPublic.authPolicy                        = *PolicyDigest;
  Public.nvPublic.dataSize                          = sizeof (BOOT_KEY_NV_RECORD);
  Status                                            = Tpm2NvDefineSpace (TPM_RH_PLATFORM, NULL, &Auth, &Public);
  return Status;
}

STATIC
EFI_STATUS
BootKeyLoadRecord (
  IN  TPMI_RH_NV_INDEX    NvIndex,
  OUT BOOT_KEY_NV_RECORD  *Record
  )
{
  TPM2B_MAX_BUFFER  Data;
  TPMS_AUTH_COMMAND Authorization;
  EFI_STATUS        Status;

  BootKeyEmptyAuthorization (&Authorization);
  ZeroMem (&Data, sizeof (Data));
  Status = Tpm2NvRead (
             NvIndex,
             NvIndex,
             &Authorization,
             sizeof (*Record),
             0,
             &Data
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Data.size != sizeof (*Record)) {
    return EFI_COMPROMISED_DATA;
  }

  CopyMem (Record, Data.buffer, sizeof (*Record));
  return BootKeyRecordValid (Record) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
}

STATIC
EFI_STATUS
BootKeyDisablePlatformHierarchy (
  VOID
  )
{
  TPMS_AUTH_COMMAND  Authorization;
  TPM2B_AUTH         PlatformAuth;
  UINT64             Random[4];
  EFI_STATUS         Status;

  ZeroMem (&PlatformAuth, sizeof (PlatformAuth));
  ZeroMem (Random, sizeof (Random));
  if (!GetRandomNumber128 (&Random[0]) || !GetRandomNumber128 (&Random[2])) {
    Status = EFI_DEVICE_ERROR;
    goto Done;
  }

  PlatformAuth.size = sizeof (Random);
  CopyMem (PlatformAuth.buffer, Random, sizeof (Random));
  Status = Tpm2HierarchyChangeAuth (TPM_RH_PLATFORM, NULL, &PlatformAuth);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  BootKeyPasswordAuthorization (
    &Authorization,
    PlatformAuth.buffer,
    PlatformAuth.size
    );
  Status = Tpm2HierarchyControl (
             TPM_RH_PLATFORM,
             &Authorization,
             TPM_RH_PLATFORM,
             NO
             );
  BootKeyWipe (&Authorization, sizeof (Authorization));

Done:
  BootKeyWipe (Random, sizeof (Random));
  BootKeyWipe (&PlatformAuth, sizeof (PlatformAuth));
  return Status;
}

EFI_STATUS
EFIAPI
BootKeyPrepareCredentialStore (
  IN BOOLEAN  FactoryInitialization
  )
{
  BOOLEAN                Defined[BOOT_KEY_NV_SLOT_COUNT];
  BOOLEAN                Repairable[BOOT_KEY_NV_SLOT_COUNT];
  BOOLEAN                Written[BOOT_KEY_NV_SLOT_COUNT];
  TPM2B_DIGEST           PolicyDigest;
  TPMI_SH_AUTH_SESSION   PolicySession;
  UINTN                  Index;
  UINTN                  ValidCount;
  EFI_STATUS             Status;

  if (mBootKeyStorePrepared) {
    return (mBootKeyFactoryInitialization == FactoryInitialization) ?
           EFI_SUCCESS : EFI_ACCESS_DENIED;
  }

  ZeroMem (Defined, sizeof (Defined));
  ZeroMem (Repairable, sizeof (Repairable));
  ZeroMem (Written, sizeof (Written));
  ZeroMem (&PolicyDigest, sizeof (PolicyDigest));
  ZeroMem (mBootKeyCachedRecord, sizeof (mBootKeyCachedRecord));
  ZeroMem (mBootKeyCachedRecordValid, sizeof (mBootKeyCachedRecordValid));
  PolicySession = TPM_RH_NULL;

  //
  // Build the policy from a live session. This both computes the exact public
  // policy and proves that PCR 6 is still in the initial write-window state.
  //
  Status = BootKeyStartWritePolicySession (
             &PolicySession,
             NULL,
             &PolicyDigest
             );
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Tpm2FlushContext (PolicySession);
  PolicySession = TPM_RH_NULL;

  ValidCount = 0;
  for (Index = 0; Index < BOOT_KEY_NV_SLOT_COUNT; Index++) {
    Status = BootKeyValidateNvPublic (
               mBootKeyNvIndex[Index],
               &PolicyDigest,
               &Written[Index]
               );
    if (Status == EFI_NOT_FOUND) {
      Repairable[Index] = TRUE;
      continue;
    }

    if (Status == EFI_SECURITY_VIOLATION) {
      Defined[Index]    = TRUE;
      Repairable[Index] = TRUE;
      continue;
    }

    if (EFI_ERROR (Status)) {
      goto Done;
    }

    Defined[Index] = TRUE;
    if (!Written[Index]) {
      Repairable[Index] = TRUE;
      continue;
    }

    Status = BootKeyLoadRecord (
               mBootKeyNvIndex[Index],
               &mBootKeyCachedRecord[Index]
               );
    if ((Status == EFI_COMPROMISED_DATA) || (Status == EFI_NOT_FOUND)) {
      Repairable[Index] = TRUE;
      continue;
    }

    if (EFI_ERROR (Status)) {
      goto Done;
    }

    mBootKeyCachedRecordValid[Index] = TRUE;
    ValidCount++;
  }

  if ((ValidCount == 0) && !FactoryInitialization) {
    Status = EFI_COMPROMISED_DATA;
    goto Done;
  }

  for (Index = 0; Index < BOOT_KEY_NV_SLOT_COUNT; Index++) {
    if (!Repairable[Index]) {
      continue;
    }

    if (Defined[Index]) {
      Status = Tpm2NvUndefineSpace (
                 TPM_RH_PLATFORM,
                 mBootKeyNvIndex[Index],
                 NULL
                 );
      if (EFI_ERROR (Status)) {
        goto Done;
      }
    }

    Status = BootKeyDefineNvIndex (
               mBootKeyNvIndex[Index],
               &PolicyDigest
               );
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    Written[Index] = FALSE;
    Status         = BootKeyValidateNvPublic (
                       mBootKeyNvIndex[Index],
                       &PolicyDigest,
                       &Written[Index]
                       );
    if (EFI_ERROR (Status) || Written[Index]) {
      Status = EFI_SECURITY_VIOLATION;
      goto Done;
    }
  }

  if (ValidCount == 0) {
    mBootKeyCurrentSlot = 1;
  } else if (ValidCount == 1) {
    mBootKeyCurrentSlot = mBootKeyCachedRecordValid[0] ? 0 : 1;
  } else if (mBootKeyCachedRecord[0].Generation >
             mBootKeyCachedRecord[1].Generation)
  {
    mBootKeyCurrentSlot = 0;
  } else if (mBootKeyCachedRecord[1].Generation >
             mBootKeyCachedRecord[0].Generation)
  {
    mBootKeyCurrentSlot = 1;
  } else if (CompareMem (
               &mBootKeyCachedRecord[0],
               &mBootKeyCachedRecord[1],
               sizeof (mBootKeyCachedRecord[0])
               ) == 0)
  {
    mBootKeyCurrentSlot = 0;
  } else {
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  //
  // Production must remove empty-authorized platform authority before any
  // external USB device is parsed.  Factory keeps the authority until a
  // complete record is committed so interrupted enrollment remains
  // recoverable.
  //
  if (!FactoryInitialization) {
    Status = BootKeyDisablePlatformHierarchy ();
    if (EFI_ERROR (Status)) {
      goto Done;
    }
  }

  mBootKeyFactoryInitialization = FactoryInitialization;
  mBootKeyStorePrepared         = TRUE;

Done:
  if (PolicySession != TPM_RH_NULL) {
    Tpm2FlushContext (PolicySession);
  }

  return Status;
}

EFI_STATUS
EFIAPI
BootKeyCloseCredentialStore (
  VOID
  )
{
  EFI_TCG2_EVENT     *Event;
  EFI_TCG2_PROTOCOL  *Tcg2;
  UINTN              EventDataSize;
  EFI_STATUS         Status;

  if (!mBootKeyStorePrepared || mBootKeyWriteWindowClosed) {
    return EFI_ACCESS_DENIED;
  }

  //
  // Production removed platform authority before external USB parsing.
  // Factory removes it only after a complete credential record is committed,
  // preserving recovery across interrupted enrollment.
  //
  if (mBootKeyFactoryInitialization &&
      mBootKeyCachedRecordValid[mBootKeyCurrentSlot])
  {
    Status = BootKeyDisablePlatformHierarchy ();
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **)&Tcg2);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  EventDataSize = sizeof (mBootKeyWriteWindowClosedEvent) - 1;
  Event         = AllocateZeroPool (
                    sizeof (*Event) - sizeof (Event->Event) + EventDataSize
                    );
  if (Event == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    return Status;
  }

  Event->Size                 = (UINT32)(sizeof (*Event) - sizeof (Event->Event) + EventDataSize);
  Event->Header.HeaderSize    = sizeof (EFI_TCG2_EVENT_HEADER);
  Event->Header.HeaderVersion = EFI_TCG2_EVENT_HEADER_VERSION;
  Event->Header.PCRIndex      = BOOT_KEY_NV_POLICY_PCR;
  Event->Header.EventType     = EV_COMPACT_HASH;
  CopyMem (Event->Event, mBootKeyWriteWindowClosedEvent, EventDataSize);

  Status = Tcg2->HashLogExtendEvent (
                   Tcg2,
                   0,
                   (EFI_PHYSICAL_ADDRESS)(UINTN)mBootKeyWriteWindowClosedEvent,
                   EventDataSize,
                   Event
                   );
  FreePool (Event);
  if ((Status == EFI_SUCCESS) || (Status == EFI_VOLUME_FULL)) {
    mBootKeyWriteWindowClosed = TRUE;
  }

  if (Status == EFI_VOLUME_FULL) {
    Status = EFI_SUCCESS;
  }

  return Status;
}

VOID
EFIAPI
BootKeyAbortCredentialStore (
  VOID
  )
{
  if (mBootKeyStorePrepared && !mBootKeyWriteWindowClosed) {
    BootKeyCloseCredentialStore ();
  }
}

STATIC
VOID
BootKeyRecordDigest (
  IN OUT BOOT_KEY_NV_RECORD  *Record
  )
{
  ZeroMem (Record->Digest, sizeof (Record->Digest));
  Sha256HashAll ((CONST UINT8 *)Record, sizeof (*Record), Record->Digest);
}

STATIC
BOOLEAN
BootKeyRecordValid (
  IN CONST BOOT_KEY_NV_RECORD  *Record
  )
{
  BOOT_KEY_NV_RECORD  Copy;
  UINTN               Index;

  if ((Record->Magic != BOOT_KEY_NV_RECORD_MAGIC) ||
      (Record->Version != BOOT_KEY_NV_RECORD_VERSION) ||
      (Record->Size != sizeof (*Record)) ||
      (Record->CredentialCount != BOOT_KEY_MAX_ENROLLED_CREDENTIALS) ||
      (Record->FailureStage > BOOT_KEY_FAILURE_STAGE_MAX) ||
      (Record->AttemptActive > 1) || (Record->Reserved != 0))
  {
    return FALSE;
  }

  CopyMem (&Copy, Record, sizeof (Copy));
  BootKeyRecordDigest (&Copy);
  if (CompareMem (Copy.Digest, Record->Digest, sizeof (Copy.Digest)) != 0) {
    return FALSE;
  }

  for (Index = 0; Index < Record->CredentialCount; Index++) {
    if ((Record->Credentials[Index].CredentialIdSize == 0) ||
        (Record->Credentials[Index].CredentialIdSize >
         BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
        (Record->Credentials[Index].PublicKey[0] != 0x04))
    {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
EFI_STATUS
BootKeyReadRecord (
  OUT BOOT_KEY_NV_RECORD  *Record
  )
{
  if (!mBootKeyStorePrepared) {
    return EFI_ACCESS_DENIED;
  }

  if (!mBootKeyCachedRecordValid[mBootKeyCurrentSlot]) {
    return mBootKeyFactoryInitialization ? EFI_NOT_FOUND : EFI_COMPROMISED_DATA;
  }

  CopyMem (Record, &mBootKeyCachedRecord[mBootKeyCurrentSlot], sizeof (*Record));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyWriteRecord (
  IN OUT BOOT_KEY_NV_RECORD  *Record
  )
{
  TPMS_AUTH_COMMAND     Authorization;
  TPM2B_MAX_BUFFER      Data;
  TPMI_SH_AUTH_SESSION  Session;
  UINTN                 TargetSlot;
  EFI_STATUS            Status;

  if (!mBootKeyStorePrepared || mBootKeyWriteWindowClosed) {
    return EFI_ACCESS_DENIED;
  }

  if (Record->Generation == MAX_UINT64) {
    return EFI_VOLUME_FULL;
  }

  TargetSlot      = mBootKeyCurrentSlot ^ 1;
  Record->Magic   = BOOT_KEY_NV_RECORD_MAGIC;
  Record->Version = BOOT_KEY_NV_RECORD_VERSION;
  Record->Size    = sizeof (*Record);
  Record->Generation++;
  BootKeyRecordDigest (Record);

  ZeroMem (&Data, sizeof (Data));
  Data.size = sizeof (*Record);
  CopyMem (Data.buffer, Record, sizeof (*Record));

  Session = TPM_RH_NULL;
  Status  = BootKeyStartWritePolicySession (
              &Session,
              &Authorization,
              NULL
              );
  if (EFI_ERROR (Status)) {
    BootKeyWipe (&Authorization, sizeof (Authorization));
    return Status;
  }

  Status = Tpm2NvWrite (
             mBootKeyNvIndex[TargetSlot],
             mBootKeyNvIndex[TargetSlot],
             &Authorization,
             &Data,
             0
             );
  if (EFI_ERROR (Status)) {
    Tpm2FlushContext (Session);
  }

  BootKeyWipe (&Authorization, sizeof (Authorization));
  if (!EFI_ERROR (Status)) {
    CopyMem (&mBootKeyCachedRecord[TargetSlot], Record, sizeof (*Record));
    mBootKeyCachedRecordValid[TargetSlot] = TRUE;
    mBootKeyCurrentSlot                   = TargetSlot;
  }

  return Status;
}

STATIC
BOOLEAN
BootKeyCredentialMatches (
  IN CONST BOOT_KEY_NV_CREDENTIAL  *Credential,
  IN CONST UINT8                   *CredentialId,
  IN UINTN                         CredentialIdSize
  )
{
  return (Credential->CredentialIdSize == CredentialIdSize) &&
         (CompareMem (
            Credential->CredentialId,
            CredentialId,
            CredentialIdSize
            ) == 0);
}

EFI_STATUS
EFIAPI
BootKeyGetCredentialSet (
  OUT    BOOT_KEY_CREDENTIAL  *Credentials,
  IN OUT UINTN                *CredentialCount
  )
{
  BOOT_KEY_NV_RECORD  Record;
  UINTN               Index;
  EFI_STATUS          Status;

  if ((Credentials == NULL) || (CredentialCount == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = BootKeyReadRecord (&Record);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (*CredentialCount < Record.CredentialCount) {
    *CredentialCount = Record.CredentialCount;
    return EFI_BUFFER_TOO_SMALL;
  }

  ZeroMem (
    Credentials,
    Record.CredentialCount * sizeof (*Credentials)
    );
  for (Index = 0; Index < Record.CredentialCount; Index++) {
    Credentials[Index].CredentialIdSize =
      Record.Credentials[Index].CredentialIdSize;
    CopyMem (
      Credentials[Index].CredentialId,
      Record.Credentials[Index].CredentialId,
      Record.Credentials[Index].CredentialIdSize
      );
    Credentials[Index].PublicKeyCertificateSize =
      sizeof (mPublicKeyCertificateTemplate);
    CopyMem (
      Credentials[Index].PublicKeyCertificate,
      mPublicKeyCertificateTemplate,
      sizeof (mPublicKeyCertificateTemplate)
      );
    CopyMem (
      &Credentials[Index].PublicKeyCertificate[BOOT_KEY_X509_PUBLIC_OFFSET],
      Record.Credentials[Index].PublicKey,
      BOOT_KEY_X509_PUBLIC_SIZE
      );
    Credentials[Index].SignCount = Record.Credentials[Index].SignCount;
  }

  *CredentialCount = Record.CredentialCount;
  return EFI_SUCCESS;
}

STATIC
UINT32
BootKeyDelayForFailureStage (
  IN UINT8  FailureStage
  )
{
  switch (FailureStage) {
    case 0:
      return 0;
    case 1:
      return 60;
    case 2:
      return 120;
    case 3:
      return 600;
    default:
      return 3600;
  }
}

EFI_STATUS
EFIAPI
BootKeyPrepareAuthenticationAttempt (
  OUT UINT32  *DelaySeconds
  )
{
  BOOT_KEY_NV_RECORD  Record;
  EFI_STATUS          Status;

  if (DelaySeconds == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = BootKeyReadRecord (&Record);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Record.AttemptActive != 0) {
    if (Record.FailureStage < BOOT_KEY_FAILURE_STAGE_MAX) {
      Record.FailureStage++;
    }

    Record.AttemptActive = 0;
    Status               = BootKeyWriteRecord (&Record);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  *DelaySeconds = BootKeyDelayForFailureStage (Record.FailureStage);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyBeginAuthenticationAttempt (
  VOID
  )
{
  BOOT_KEY_NV_RECORD  Record;
  EFI_STATUS          Status;

  Status = BootKeyReadRecord (&Record);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Record.AttemptActive != 0) {
    return EFI_ALREADY_STARTED;
  }

  Record.AttemptActive = 1;
  return BootKeyWriteRecord (&Record);
}

EFI_STATUS
EFIAPI
BootKeyCommitAuthenticationFailure (
  VOID
  )
{
  BOOT_KEY_NV_RECORD  Record;
  EFI_STATUS          Status;

  Status = BootKeyReadRecord (&Record);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Record.AttemptActive == 0) {
    return EFI_ACCESS_DENIED;
  }

  if (Record.FailureStage < BOOT_KEY_FAILURE_STAGE_MAX) {
    Record.FailureStage++;
  }

  Record.AttemptActive = 0;
  return BootKeyWriteRecord (&Record);
}

EFI_STATUS
EFIAPI
BootKeyCommitSignCount (
  IN CONST UINT8  *CredentialId,
  IN UINTN        CredentialIdSize,
  IN UINT32       SignCount
  )
{
  BOOT_KEY_NV_RECORD  Record;
  UINTN               Index;
  EFI_STATUS          Status;

  if ((CredentialId == NULL) || (CredentialIdSize == 0) ||
      (CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
      (SignCount == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = BootKeyReadRecord (&Record);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Record.AttemptActive == 0) {
    return EFI_ACCESS_DENIED;
  }

  for (Index = 0; Index < Record.CredentialCount; Index++) {
    if (!BootKeyCredentialMatches (
           &Record.Credentials[Index],
           CredentialId,
           CredentialIdSize
           ))
    {
      continue;
    }

    if (SignCount <= Record.Credentials[Index].SignCount) {
      return EFI_SECURITY_VIOLATION;
    }

    Record.Credentials[Index].SignCount = SignCount;
    Record.FailureStage                 = 0;
    Record.AttemptActive                = 0;
    Status                              = BootKeyWriteRecord (&Record);
    if (EFI_ERROR (Status)) {
      BootKeyAbortCredentialStore ();
    }

    return Status;
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
BootKeyProvisionCredentialSet (
  IN CONST BOOT_KEY_PROVISIONING_CREDENTIAL  *Credentials,
  IN UINTN                                   CredentialCount
  )
{
  BOOT_KEY_NV_RECORD  Record;
  UINTN               Index;
  UINTN               PeerIndex;

  if ((Credentials == NULL) || !mBootKeyFactoryInitialization ||
      (CredentialCount != BOOT_KEY_MAX_ENROLLED_CREDENTIALS) ||
      mBootKeyCachedRecordValid[mBootKeyCurrentSlot])
  {
    return EFI_ACCESS_DENIED;
  }

  ZeroMem (&Record, sizeof (Record));
  Record.CredentialCount = (UINT8)CredentialCount;
  for (Index = 0; Index < CredentialCount; Index++) {
    if ((Credentials[Index].CredentialIdSize == 0) ||
        (Credentials[Index].CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
        !BootKeyPublicPointValid (Credentials[Index].PublicKey))
    {
      return EFI_INVALID_PARAMETER;
    }

    for (PeerIndex = 0; PeerIndex < Index; PeerIndex++) {
      if (((Credentials[PeerIndex].CredentialIdSize ==
            Credentials[Index].CredentialIdSize) &&
           (CompareMem (
              Credentials[PeerIndex].CredentialId,
              Credentials[Index].CredentialId,
              Credentials[Index].CredentialIdSize
              ) == 0)) ||
          (CompareMem (
             Credentials[PeerIndex].DeviceIdentity,
             Credentials[Index].DeviceIdentity,
             BOOT_KEY_DEVICE_IDENTITY_SIZE
             ) == 0))
      {
        return EFI_ALREADY_STARTED;
      }
    }

    Record.Credentials[Index].CredentialIdSize =
      (UINT8)Credentials[Index].CredentialIdSize;
    CopyMem (
      Record.Credentials[Index].CredentialId,
      Credentials[Index].CredentialId,
      Credentials[Index].CredentialIdSize
      );
    CopyMem (
      Record.Credentials[Index].PublicKey,
      Credentials[Index].PublicKey,
      BOOT_KEY_PUBLIC_POINT_SIZE
      );
    CopyMem (
      Record.Credentials[Index].DeviceIdentity,
      Credentials[Index].DeviceIdentity,
      BOOT_KEY_DEVICE_IDENTITY_SIZE
      );
  }

  return BootKeyWriteRecord (&Record);
}
