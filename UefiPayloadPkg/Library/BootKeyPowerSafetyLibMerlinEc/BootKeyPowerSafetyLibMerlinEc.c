/** @file
  Merlin EC independent boot-key power-safety provider.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BootKeyPowerSafetyLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>

#define MERLIN_EC_STATUS_PORT                0x66
#define MERLIN_EC_STATUS_OUTPUT_BUFFER_FULL  BIT0
#define MERLIN_EC_STATUS_INPUT_BUFFER_FULL   BIT1
#define MERLIN_EC_DATA_PORT                  0x62
#define MERLIN_EC_BOOT_KEY_GUARD_ARM         0xd7
#define MERLIN_EC_BOOT_KEY_GUARD_DISARM      0xd8
#define MERLIN_EC_BOOT_KEY_GUARD_STATUS      0xd9
#define MERLIN_EC_BOOT_KEY_GUARD_ARMED       0xa5
#define MERLIN_EC_BOOT_KEY_GUARD_DISARMED    0x00
#define MERLIN_EC_WAIT_US                    10000

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
MerlinEcCommand (
  IN  UINT8  Command,
  OUT UINT8  *Response
  )
{
  EFI_STATUS  Status;

  if (Response == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = MerlinEcWait (MERLIN_EC_STATUS_INPUT_BUFFER_FULL, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (MERLIN_EC_STATUS_PORT, Command);
  Status = MerlinEcWait (
             MERLIN_EC_STATUS_OUTPUT_BUFFER_FULL,
             MERLIN_EC_STATUS_OUTPUT_BUFFER_FULL
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Response = IoRead8 (MERLIN_EC_DATA_PORT);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyPowerSafetyArm (
  VOID
  )
{
  UINT8       Guard;
  EFI_STATUS  Status;

  //
  // Arm through a dedicated command. An older EC does not answer this command,
  // so it cannot be mistaken for a compatible autonomous power policy.
  //
  Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_GUARD_ARM, &Guard);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Guard != MERLIN_EC_BOOT_KEY_GUARD_ARMED) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_GUARD_STATUS, &Guard);
  if (EFI_ERROR (Status) || (Guard != MERLIN_EC_BOOT_KEY_GUARD_ARMED)) {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyPowerSafetyDisarm (
  VOID
  )
{
  UINT8       Guard;
  EFI_STATUS  Status;

  Status = MerlinEcCommand (MERLIN_EC_BOOT_KEY_GUARD_DISARM, &Guard);
  if (EFI_ERROR (Status) || (Guard != MERLIN_EC_BOOT_KEY_GUARD_DISARMED)) {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}
