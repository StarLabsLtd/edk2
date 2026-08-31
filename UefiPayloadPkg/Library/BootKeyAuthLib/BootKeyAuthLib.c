/** @file
  FIDO2 boot-key policy and pre-BDS gate.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Guid/AuthenticatedVariableFormat.h>
#include <Guid/GlobalVariable.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyAuthLib.h>
#include <Library/BootKeyPlatformSecurityLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/RngLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#define BOOT_KEY_SIGN_COUNT_OFFSET        33
#define BOOT_KEY_RETRY_DELAY_US           250000
#define BOOT_KEY_AUTH_DATA_ALLOWED_FLAGS  BOOT_KEY_AUTH_DATA_USER_PRESENT
#define BOOT_KEY_100NS_PER_SECOND         10000000ULL

STATIC CONST CHAR8  mBootKeyRpId[] = "starlabs.systems";

typedef struct {
  BOOLEAN                Active;
  BOOT_KEY_CREDENTIAL    Credentials[BOOT_KEY_MAX_ENROLLED_CREDENTIALS];
  CONST UINT8            *CredentialIds[BOOT_KEY_MAX_ENROLLED_CREDENTIALS];
  UINTN                  CredentialIdSizes[BOOT_KEY_MAX_ENROLLED_CREDENTIALS];
  UINT64                 ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE / sizeof (UINT64)];
  UINTN                  CredentialCount;
} BOOT_KEY_AUTH_TRANSACTION;

STATIC BOOT_KEY_AUTH_TRANSACTION  mBootKeyAuthTransaction;

BOOLEAN
EFIAPI
BootKeyAuthenticationRequired (
  VOID
  )
{
  return TRUE;
}

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
  Status     = gRT->GetVariable (
                      Name,
                      Guid,
                      &Attributes,
                      &Size,
                      &Value
                      );
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
BootKeyEqual (
  IN CONST UINT8  *Left,
  IN CONST UINT8  *Right,
  IN UINTN        Size
  )
{
  UINT8  Difference;
  UINTN  Index;

  Difference = 0;
  for (Index = 0; Index < Size; Index++) {
    Difference |= Left[Index] ^ Right[Index];
  }

  return Difference == 0;
}

STATIC
UINT32
BootKeyReadUint32BigEndian (
  IN CONST UINT8  *Buffer
  )
{
  return ((UINT32)Buffer[0] << 24) |
         ((UINT32)Buffer[1] << 16) |
         ((UINT32)Buffer[2] << 8) |
         Buffer[3];
}

EFI_STATUS
EFIAPI
BootKeyVerifyAssertion (
  IN CONST CHAR8                *RpId,
  IN CONST UINT8                ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN CONST BOOT_KEY_CREDENTIAL  *Credential,
  IN CONST BOOT_KEY_ASSERTION   *Assertion,
  OUT UINT32                    *SignCount
  )
{
  UINT8    ExpectedRpIdHash[BOOT_KEY_RP_ID_HASH_SIZE];
  UINT8    SignedData[BOOT_KEY_AUTH_DATA_SIZE + BOOT_KEY_CLIENT_DATA_HASH_SIZE];
  UINT8    SignedDataHash[SHA256_DIGEST_SIZE];
  VOID     *PublicKey;
  BOOLEAN  Verified;

  if ((RpId == NULL) || (ClientDataHash == NULL) || (Credential == NULL) ||
      (Assertion == NULL) || (SignCount == NULL) ||
      (Credential->CredentialIdSize == 0) ||
      (Credential->PublicKeyCertificateSize == 0) ||
      (Credential->CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
      (Credential->PublicKeyCertificateSize >
       BOOT_KEY_PUBLIC_KEY_CERTIFICATE_MAX_SIZE) ||
      (Assertion->CredentialIdSize == 0) ||
      (Assertion->CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
      ((Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE] &
        ~BOOT_KEY_AUTH_DATA_ALLOWED_FLAGS) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  if ((Assertion->CredentialIdSize != Credential->CredentialIdSize) ||
      !BootKeyEqual (
         Credential->CredentialId,
         Assertion->CredentialId,
         Credential->CredentialIdSize
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if (!Sha256HashAll (
         (CONST UINT8 *)RpId,
         AsciiStrLen (RpId),
         ExpectedRpIdHash
         ) ||
      !BootKeyEqual (
         ExpectedRpIdHash,
         Assertion->AuthenticatorData,
         sizeof (ExpectedRpIdHash)
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if ((Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE] &
       BOOT_KEY_AUTH_DATA_USER_PRESENT) == 0)
  {
    return EFI_SECURITY_VIOLATION;
  }

  *SignCount = BootKeyReadUint32BigEndian (
                 &Assertion->AuthenticatorData[BOOT_KEY_SIGN_COUNT_OFFSET]
                 );
  //
  // This gate deliberately requires a monotonic counter.  YubiKey FIDO2
  // credentials provide one, and accepting zero would discard clone/replay
  // detection in a pre-boot policy intended specifically for those keys.
  //
  if ((*SignCount == 0) || (*SignCount <= Credential->SignCount)) {
    return EFI_SECURITY_VIOLATION;
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
  if (!Sha256HashAll (
         SignedData,
         sizeof (Assertion->AuthenticatorData) + BOOT_KEY_CLIENT_DATA_HASH_SIZE,
         SignedDataHash
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  PublicKey = NULL;
  if (!EcGetPublicKeyFromX509 (
         Credential->PublicKeyCertificate,
         Credential->PublicKeyCertificateSize,
         &PublicKey
         ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Verified = EcDsaVerify (
               PublicKey,
               CRYPTO_NID_SHA256,
               SignedDataHash,
               sizeof (SignedDataHash),
               Assertion->Signature,
               sizeof (Assertion->Signature)
               );
  EcFree (PublicKey);

  return Verified ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

STATIC
EFI_STATUS
BootKeyStartAuthentication (
  VOID
  )
{
  UINTN       Index;
  UINTN       PreviousIndex;
  EFI_STATUS  Status;

  ZeroMem (&mBootKeyAuthTransaction, sizeof (mBootKeyAuthTransaction));
  mBootKeyAuthTransaction.CredentialCount = BOOT_KEY_MAX_ENROLLED_CREDENTIALS;
  Status                                  = BootKeyGetCredentialSet (
                                              mBootKeyAuthTransaction.Credentials,
                                              &mBootKeyAuthTransaction.CredentialCount
                                              );
  if (Status != EFI_SUCCESS) {
    return EFI_SECURITY_VIOLATION;
  }

  if ((mBootKeyAuthTransaction.CredentialCount == 0) ||
      (mBootKeyAuthTransaction.CredentialCount > BOOT_KEY_MAX_ENROLLED_CREDENTIALS) ||
      (!FixedPcdGetBool (PcdBootKeyAuthTestEnabled) &&
       (mBootKeyAuthTransaction.CredentialCount !=
        BOOT_KEY_MAX_ENROLLED_CREDENTIALS)))
  {
    return EFI_SECURITY_VIOLATION;
  }

  for (Index = 0; Index < mBootKeyAuthTransaction.CredentialCount; Index++) {
    if ((mBootKeyAuthTransaction.Credentials[Index].CredentialIdSize == 0) ||
        (mBootKeyAuthTransaction.Credentials[Index].CredentialIdSize >
         BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
        (mBootKeyAuthTransaction.Credentials[Index].PublicKeyCertificateSize == 0) ||
        (mBootKeyAuthTransaction.Credentials[Index].PublicKeyCertificateSize >
         BOOT_KEY_PUBLIC_KEY_CERTIFICATE_MAX_SIZE))
    {
      return EFI_SECURITY_VIOLATION;
    }

    mBootKeyAuthTransaction.CredentialIds[Index] =
      mBootKeyAuthTransaction.Credentials[Index].CredentialId;
    mBootKeyAuthTransaction.CredentialIdSizes[Index] =
      mBootKeyAuthTransaction.Credentials[Index].CredentialIdSize;

    for (PreviousIndex = 0; PreviousIndex < Index; PreviousIndex++) {
      if ((mBootKeyAuthTransaction.Credentials[PreviousIndex].CredentialIdSize ==
           mBootKeyAuthTransaction.Credentials[Index].CredentialIdSize) &&
          BootKeyEqual (
            mBootKeyAuthTransaction.Credentials[PreviousIndex].CredentialId,
            mBootKeyAuthTransaction.Credentials[Index].CredentialId,
            mBootKeyAuthTransaction.Credentials[Index].CredentialIdSize
            ))
      {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }

  if (!GetRandomNumber128 (&mBootKeyAuthTransaction.ClientDataHash[0]) ||
      !GetRandomNumber128 (&mBootKeyAuthTransaction.ClientDataHash[2]))
  {
    return EFI_DEVICE_ERROR;
  }

  mBootKeyAuthTransaction.Active = TRUE;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyAuthenticateOnce (
  VOID
  )
{
  BOOT_KEY_ASSERTION  Assertion;
  EFI_STATUS          Result;
  UINT32              SignCount;
  UINTN               Index;
  EFI_STATUS          Status;

  if (!mBootKeyAuthTransaction.Active) {
    Status = BootKeyStartAuthentication ();
    if (Status != EFI_SUCCESS) {
      ZeroMem (&mBootKeyAuthTransaction, sizeof (mBootKeyAuthTransaction));
      return Status;
    }
  }

  ZeroMem (&Assertion, sizeof (Assertion));
  Status = BootKeyGetAssertion (
             mBootKeyRpId,
             (CONST UINT8 *)mBootKeyAuthTransaction.ClientDataHash,
             mBootKeyAuthTransaction.CredentialIds,
             mBootKeyAuthTransaction.CredentialIdSizes,
             mBootKeyAuthTransaction.CredentialCount,
             &Assertion
             );
  if (Status == EFI_NOT_READY) {
    return EFI_NOT_READY;
  }

  Result = EFI_SECURITY_VIOLATION;
  if (Status != EFI_SUCCESS) {
    goto Complete;
  }

  if (Assertion.CredentialIdSize == 0) {
    if (mBootKeyAuthTransaction.CredentialCount != 1) {
      goto Complete;
    }

    Assertion.CredentialIdSize =
      mBootKeyAuthTransaction.Credentials[0].CredentialIdSize;
    CopyMem (
      Assertion.CredentialId,
      mBootKeyAuthTransaction.Credentials[0].CredentialId,
      Assertion.CredentialIdSize
      );
  } else if (Assertion.CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) {
    goto Complete;
  }

  for (Index = 0; Index < mBootKeyAuthTransaction.CredentialCount; Index++) {
    if ((Assertion.CredentialIdSize !=
         mBootKeyAuthTransaction.Credentials[Index].CredentialIdSize) ||
        !BootKeyEqual (
           Assertion.CredentialId,
           mBootKeyAuthTransaction.Credentials[Index].CredentialId,
           Assertion.CredentialIdSize
           ))
    {
      continue;
    }

    Status = BootKeyVerifyAssertion (
               mBootKeyRpId,
               (CONST UINT8 *)mBootKeyAuthTransaction.ClientDataHash,
               &mBootKeyAuthTransaction.Credentials[Index],
               &Assertion,
               &SignCount
               );
    if (Status == EFI_SUCCESS) {
      Status = BootKeyCommitSignCount (
                 Assertion.CredentialId,
                 Assertion.CredentialIdSize,
                 SignCount
                 );

      if (Status == EFI_SUCCESS) {
        Result = EFI_SUCCESS;
      } else {
        Result = Status;
      }
    }

    goto Complete;
  }

Complete:
  ZeroMem (&mBootKeyAuthTransaction, sizeof (mBootKeyAuthTransaction));
  return Result;
}

STATIC
EFI_STATUS
BootKeyCreateTimer (
  IN  EFI_TIMER_DELAY  Type,
  IN  UINT32           Seconds,
  OUT EFI_EVENT        *Event
  )
{
  EFI_STATUS  Status;

  *Event = NULL;
  Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, Event);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->SetTimer (
                  *Event,
                  Type,
                  Seconds * BOOT_KEY_100NS_PER_SECOND
                  );
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (*Event);
    *Event = NULL;
  }

  return Status;
}

STATIC
VOID
EFIAPI
BootKeyPromptDeadlineExpired (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  (VOID)Event;
  (VOID)Context;

  //
  // Do not attempt TPM or protocol work from the timer notification. The
  // already-durable AttemptActive bit makes the next boot charge the failed
  // attempt. This callback exists specifically so a synchronous transport or
  // driver-binding call cannot suppress the prompt deadline.
  //
  gRT->ResetSystem (EfiResetCold, EFI_SECURITY_VIOLATION, 0, NULL);
  CpuDeadLoop ();
}

STATIC
EFI_STATUS
BootKeyCreatePromptDeadline (
  IN  UINT32     Seconds,
  OUT EFI_EVENT  *Event
  )
{
  EFI_STATUS  Status;

  *Event = NULL;
  Status = gBS->CreateEvent (
                  EVT_TIMER | EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  BootKeyPromptDeadlineExpired,
                  NULL,
                  Event
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->SetTimer (
                  *Event,
                  TimerRelative,
                  Seconds * BOOT_KEY_100NS_PER_SECOND
                  );
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (*Event);
    *Event = NULL;
  }

  return Status;
}

STATIC
BOOLEAN
BootKeyTimerExpired (
  IN EFI_EVENT  Event
  )
{
  return gBS->CheckEvent (Event) != EFI_NOT_READY;
}

STATIC
EFI_STATUS
BootKeyWaitSeconds (
  IN UINT32                       DelaySeconds,
  IN BOOT_KEY_AUTH_WAIT_CALLBACK  WaitCallback OPTIONAL
  )
{
  EFI_EVENT   Deadline;
  EFI_EVENT   SecondTick;
  UINT32      PreviousRemaining;
  UINT32      Remaining;
  EFI_STATUS  Status;

  if (DelaySeconds == 0) {
    return EFI_SUCCESS;
  }

  Status = BootKeyCreateTimer (TimerRelative, DelaySeconds, &Deadline);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = BootKeyCreateTimer (TimerPeriodic, 1, &SecondTick);
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (Deadline);
    return Status;
  }

  Remaining         = DelaySeconds;
  PreviousRemaining = MAX_UINT32;
  do {
    if (BootKeyTimerExpired (Deadline)) {
      Remaining = 0;
    }

    if (Remaining != PreviousRemaining) {
      if ((gST != NULL) && (gST->ConOut != NULL)) {
        Print (L"\rSecurity-key lockout: %u seconds remaining.   ", Remaining);
      }

      DEBUG ((DEBUG_INFO, "Boot-key lockout remaining: %u seconds\n", Remaining));
      PreviousRemaining = Remaining;
    }

    if (Remaining == 0) {
      break;
    }

    if (WaitCallback != NULL) {
      WaitCallback (BootKeyAuthWaitLockout, Remaining);
    }

    if (BootKeyTimerExpired (Deadline)) {
      Remaining = 0;
      continue;
    }

    if (BootKeyTimerExpired (SecondTick) && (Remaining > 0)) {
      Remaining--;
    }

    gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
  } while (TRUE);

  gBS->SetTimer (SecondTick, TimerCancel, 0);
  gBS->SetTimer (Deadline, TimerCancel, 0);
  gBS->CloseEvent (SecondTick);
  gBS->CloseEvent (Deadline);

  if ((gST != NULL) && (gST->ConOut != NULL)) {
    Print (L"\n");
  }

  return EFI_SUCCESS;
}

STATIC
VOID
BootKeyColdResetAfterFailure (
  IN BOOLEAN  CommitFailure
  )
{
  EFI_STATUS  Status;

  if (CommitFailure) {
    Status = BootKeyCommitAuthenticationFailure ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Boot-key failure state did not commit: %r\n", Status));
    }
  }

  Status = BootKeyCloseCredentialStore ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Boot-key write window did not close: %r\n", Status));
  }

  do {
    gRT->ResetSystem (EfiResetCold, EFI_SECURITY_VIOLATION, 0, NULL);
    gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
  } while (TRUE);
}

VOID
EFIAPI
BootKeyRequireAuthentication (
  IN BOOT_KEY_AUTH_WAIT_CALLBACK  WaitCallback OPTIONAL
  )
{
  EFI_EVENT   PromptDeadline;
  UINT32      DelaySeconds;
  UINT32      PromptTimeout;
  EFI_STATUS  Status;

  if (!BootKeySecureBootEnabled ()) {
    DEBUG ((DEBUG_ERROR, "Boot-key gate requires active Secure Boot.\n"));
    do {
      if (WaitCallback != NULL) {
        WaitCallback (BootKeyAuthWaitUnavailable, 0);
      }

      gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
    } while (TRUE);
  }

  Status = BootKeyVerifyPlatformSecurityBoundary ();
  if (Status != EFI_SUCCESS) {
    DEBUG ((
      DEBUG_ERROR,
      "Boot-key platform hardware boundary is not verified: %r\n",
      Status
      ));
    do {
      if (WaitCallback != NULL) {
        WaitCallback (BootKeyAuthWaitUnavailable, 0);
      }

      gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
    } while (TRUE);
  }

  Status = BootKeyPrepareAuthenticationAttempt (&DelaySeconds);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Boot-key attempt state is unavailable: %r\n", Status));
    do {
      if (WaitCallback != NULL) {
        WaitCallback (BootKeyAuthWaitUnavailable, 0);
      }

      gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
    } while (TRUE);
  }

  Status = BootKeyWaitSeconds (DelaySeconds, WaitCallback);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Boot-key lockout timer is unavailable: %r\n", Status));
    do {
      if (WaitCallback != NULL) {
        WaitCallback (BootKeyAuthWaitUnavailable, 0);
      }

      gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
    } while (TRUE);
  }

  Status = BootKeyBeginAuthenticationAttempt ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Boot-key attempt could not be recorded: %r\n", Status));
    do {
      if (WaitCallback != NULL) {
        WaitCallback (BootKeyAuthWaitUnavailable, 0);
      }

      gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
    } while (TRUE);
  }

  PromptTimeout = FixedPcdGet32 (PcdBootKeyAttemptTimeoutSeconds);
  if (PromptTimeout == 0) {
    DEBUG ((DEBUG_ERROR, "Boot-key attempt timeout is invalid\n"));
    BootKeyColdResetAfterFailure (TRUE);
  }

  Status = BootKeyCreatePromptDeadline (PromptTimeout, &PromptDeadline);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Boot-key prompt timer is unavailable: %r\n", Status));
    BootKeyColdResetAfterFailure (TRUE);
  }

  if ((gST != NULL) && (gST->ConOut != NULL)) {
    Print (
      L"\nInsert an enrolled security key and touch it within %u seconds.\n",
      PromptTimeout
      );
  }

  DEBUG ((
    DEBUG_INFO,
    "Insert an enrolled security key and touch it within %u seconds.\n",
    PromptTimeout
  ));

  do {
    if (WaitCallback != NULL) {
      WaitCallback (BootKeyAuthWaitPrompt, PromptTimeout);
    }

    Status = BootKeyAuthenticatorPrepare ();

    if (WaitCallback != NULL) {
      WaitCallback (BootKeyAuthWaitPrompt, PromptTimeout);
    }

    if (Status == EFI_SUCCESS) {
      break;
    }

    DEBUG ((DEBUG_ERROR, "Boot-key authenticator preparation failed: %r\n", Status));
    gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
  } while (TRUE);

  do {
    if (WaitCallback != NULL) {
      WaitCallback (BootKeyAuthWaitPrompt, PromptTimeout);
    }

    Status = BootKeyAuthenticateOnce ();

    if (WaitCallback != NULL) {
      WaitCallback (BootKeyAuthWaitPrompt, PromptTimeout);
    }

    if (Status == EFI_SUCCESS) {
      gBS->SetTimer (PromptDeadline, TimerCancel, 0);
      gBS->CloseEvent (PromptDeadline);
      if ((gST != NULL) && (gST->ConOut != NULL)) {
        Print (L"\nBoot key accepted.\n");
      }

      DEBUG ((DEBUG_INFO, "Boot-key authentication succeeded\n"));
      return;
    }

    if (Status == EFI_SECURITY_VIOLATION) {
      DEBUG ((DEBUG_ERROR, "Boot-key authentication rejected\n"));
      BootKeyColdResetAfterFailure (TRUE);
    }

    if (Status != EFI_NOT_READY) {
      DEBUG ((DEBUG_ERROR, "Boot-key authentication failed: %r\n", Status));
      BootKeyColdResetAfterFailure (FALSE);
    }

    DEBUG ((DEBUG_VERBOSE, "Boot-key authentication pending: %r\n", Status));
    gBS->Stall (BOOT_KEY_RETRY_DELAY_US);
  } while (TRUE);
}
