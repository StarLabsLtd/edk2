/** @file
  Merlin EC reset-bounded TPM NV authorization provider.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyNvAuthLib.h>
#include <Library/IoLib.h>
#include <Library/RngLib.h>
#include <Library/TimerLib.h>

#define MERLIN_EC_STATUS_PORT                0x66
#define MERLIN_EC_STATUS_OUTPUT_BUFFER_FULL  BIT0
#define MERLIN_EC_STATUS_INPUT_BUFFER_FULL   BIT1
#define MERLIN_EC_DATA_PORT                  0x62
#define MERLIN_EC_BOOT_KEY_STATUS            0xd0
#define MERLIN_EC_BOOT_KEY_READ              0xd1
#define MERLIN_EC_BOOT_KEY_CLOSE             0xd2
#define MERLIN_EC_BOOT_KEY_PROVISION_BEGIN   0xd3
#define MERLIN_EC_BOOT_KEY_PROVISION_DATA    0xd4
#define MERLIN_EC_BOOT_KEY_READY             0xa5
#define MERLIN_EC_BOOT_KEY_BLANK             0x5a
#define MERLIN_EC_BOOT_KEY_OK                0xa5
#define MERLIN_EC_WAIT_US                    10000

STATIC BOOLEAN  mProvisionRequired;

STATIC
BOOLEAN
BootKeyAllOnes (
  IN CONST UINT8  *Buffer,
  IN UINTN        Size
  )
{
  while (Size-- != 0) {
    if (*Buffer++ != MAX_UINT8) {
      return FALSE;
    }
  }

  return TRUE;
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
EFI_STATUS
MerlinEcWait (
  IN UINT8  Mask,
  IN UINT8  Value
  )
{
  UINTN  Remaining;

  for (Remaining = MERLIN_EC_WAIT_US; Remaining != 0; Remaining--) {
    if ((IoRead8 (MERLIN_EC_STATUS_PORT) & Mask) == Value) {
      return EFI_SUCCESS;
    }

    MicroSecondDelay (1);
  }

  return EFI_TIMEOUT;
}

STATIC
EFI_STATUS
MerlinEcWriteCommand (
  IN UINT8  Command
  )
{
  EFI_STATUS  Status;

  Status = MerlinEcWait (MERLIN_EC_STATUS_INPUT_BUFFER_FULL, 0);
  if (!EFI_ERROR (Status)) {
    IoWrite8 (MERLIN_EC_STATUS_PORT, Command);
  }

  return Status;
}

STATIC
EFI_STATUS
MerlinEcReadResponse (
  OUT UINT8  *Response
  )
{
  EFI_STATUS  Status;

  Status = MerlinEcWait (
             MERLIN_EC_STATUS_OUTPUT_BUFFER_FULL,
             MERLIN_EC_STATUS_OUTPUT_BUFFER_FULL
             );
  if (!EFI_ERROR (Status)) {
    *Response = IoRead8 (MERLIN_EC_DATA_PORT);
  }

  return Status;
}

STATIC
EFI_STATUS
MerlinEcCommand (
  IN  UINT8  Command,
  OUT UINT8  *Response
  )
{
  EFI_STATUS  Status;

  Status = MerlinEcWriteCommand (Command);
  return EFI_ERROR (Status) ? Status : MerlinEcReadResponse (Response);
}

STATIC
EFI_STATUS
MerlinEcReadSecret (
  OUT UINT8  Auth[BOOT_KEY_NV_AUTH_SIZE]
  )
{
  UINTN       Index;
  EFI_STATUS  Status;

  for (Index = 0; Index < BOOT_KEY_NV_AUTH_SIZE; Index++) {
    Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_READ, &Auth[Index]);
    if (EFI_ERROR (Status)) {
      BootKeyWipe (Auth, BOOT_KEY_NV_AUTH_SIZE);
      return Status;
    }
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyNvAuthClose (
  VOID
  )
{
  UINT8       Response;
  EFI_STATUS  Status;

  Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_CLOSE, &Response);
  mProvisionRequired = FALSE;
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return (Response == MERLIN_EC_BOOT_KEY_OK) ?
         EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

EFI_STATUS
EFIAPI
BootKeyNvAuthAcquire (
  IN  BOOLEAN  FactoryInitialization,
  OUT UINT8    Auth[BOOT_KEY_NV_AUTH_SIZE],
  OUT BOOLEAN  *ProvisionRequired
  )
{
  UINT8       StatusByte;
  UINT64      Random[4];
  EFI_STATUS  CloseStatus;
  EFI_STATUS  Status;

  if ((Auth == NULL) || (ProvisionRequired == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  BootKeyWipe (Auth, BOOT_KEY_NV_AUTH_SIZE);
  ZeroMem (Random, sizeof (Random));
  *ProvisionRequired = FALSE;
  mProvisionRequired = FALSE;
  Status             = MerlinEcCommand (MERLIN_EC_BOOT_KEY_STATUS, &StatusByte);
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  if (StatusByte == MERLIN_EC_BOOT_KEY_READY) {
    Status = MerlinEcReadSecret (Auth);
    goto Done;
  }

  if ((StatusByte != MERLIN_EC_BOOT_KEY_BLANK) || !FactoryInitialization) {
    Status = EFI_SECURITY_VIOLATION;
    goto Error;
  }

  if (!GetRandomNumber128 (&Random[0]) || !GetRandomNumber128 (&Random[2])) {
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  CopyMem (Auth, Random, sizeof (Random));
  BootKeyWipe (Random, sizeof (Random));
  if (IsZeroBuffer (Auth, BOOT_KEY_NV_AUTH_SIZE) ||
      BootKeyAllOnes (Auth, BOOT_KEY_NV_AUTH_SIZE))
  {
    Status = EFI_DEVICE_ERROR;
    goto Error;
  }

  mProvisionRequired  = TRUE;
  *ProvisionRequired = TRUE;
  return EFI_SUCCESS;

Done:
  if (EFI_ERROR (Status)) {
    goto Error;
  }

  CloseStatus = BootKeyNvAuthClose ();
  return EFI_ERROR (CloseStatus) ? CloseStatus : EFI_SUCCESS;

Error:
  BootKeyWipe (Random, sizeof (Random));
  BootKeyWipe (Auth, BOOT_KEY_NV_AUTH_SIZE);
  (VOID)BootKeyNvAuthClose ();
  return Status;
}

EFI_STATUS
EFIAPI
BootKeyNvAuthCommit (
  IN CONST UINT8  Auth[BOOT_KEY_NV_AUTH_SIZE]
  )
{
  UINT8       Response;
  UINT8       Readback[BOOT_KEY_NV_AUTH_SIZE];
  UINTN       Index;
  EFI_STATUS  CloseStatus;
  EFI_STATUS  Status;

  if ((Auth == NULL) || !mProvisionRequired) {
    return EFI_INVALID_PARAMETER;
  }

  Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_PROVISION_BEGIN, &Response);
  if (EFI_ERROR (Status) || (Response != MERLIN_EC_BOOT_KEY_OK)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  for (Index = 0; Index < BOOT_KEY_NV_AUTH_SIZE; Index++) {
    Status = MerlinEcWriteCommand (MERLIN_EC_BOOT_KEY_PROVISION_DATA);
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    Status = MerlinEcWait (MERLIN_EC_STATUS_INPUT_BUFFER_FULL, 0);
    if (EFI_ERROR (Status)) {
      goto Done;
    }

    IoWrite8 (MERLIN_EC_DATA_PORT, Auth[Index]);
    Status = MerlinEcReadResponse (&Response);
    if (EFI_ERROR (Status) || (Response != MERLIN_EC_BOOT_KEY_OK)) {
      Status = EFI_SECURITY_VIOLATION;
      goto Done;
    }
  }

  Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_STATUS, &Response);
  if (EFI_ERROR (Status) || (Response != MERLIN_EC_BOOT_KEY_READY)) {
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = MerlinEcReadSecret (Readback);
  if (!EFI_ERROR (Status) &&
      (CompareMem (Readback, Auth, BOOT_KEY_NV_AUTH_SIZE) != 0))
  {
    Status = EFI_SECURITY_VIOLATION;
  }

Done:
  BootKeyWipe (Readback, sizeof (Readback));
  CloseStatus = BootKeyNvAuthClose ();
  if (!EFI_ERROR (Status) && EFI_ERROR (CloseStatus)) {
    Status = CloseStatus;
  }

  return Status;
}
