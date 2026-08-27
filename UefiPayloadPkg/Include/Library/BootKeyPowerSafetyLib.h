/** @file
  Independent power-safety boundary for the boot-key gate.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

/**
  Establish power safety before accepting external authenticator input.

  A production implementation must make arming the EC/PMIC cutoff its first
  hardware operation, must not perform unbounded protocol or bus operations,
  and must return within one second. Repeated calls while armed must be safe.

  The function may return EFI_SUCCESS without an autonomous cutoff only when
  the trusted platform power source verifies that no battery is present.
  Whenever a battery exists, an EC/PMIC mechanism independent of DXE execution
  must remain armed even while external power is connected. It must monitor
  loss of external power and power the system off within ten seconds after the
  battery becomes critical or its state cannot be verified. This must remain
  effective even if another firmware provider never returns.

  A UEFI event or reset-only watchdog does not satisfy this contract.

  @retval EFI_SUCCESS  Independent power safety is active.
  @retval Others       Power safety could not be established.
**/
EFI_STATUS
EFIAPI
BootKeyPowerSafetyArm (
  VOID
  );

/**
  Remove the independent boot-key power-safety policy after authentication.

  @retval EFI_SUCCESS  The policy was removed or no hardware deadline was
                       required.
  @retval Others       The policy could not be safely removed.
**/
EFI_STATUS
EFIAPI
BootKeyPowerSafetyDisarm (
  VOID
  );
