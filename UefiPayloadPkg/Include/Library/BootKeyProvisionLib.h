/** @file
  Factory boot-key provisioning interface.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

BOOLEAN
EFIAPI
BootKeyFactoryProvisioningRequired (
  VOID
  );

/**
  Provision the complete factory credential set.

  This function is called after EndOfDxe and ReadyToLock, and before deferred
  images or general console/device discovery. It returns only after exactly
  three distinct physical authenticators have been enrolled or a fatal error
  occurs.
**/
EFI_STATUS
EFIAPI
BootKeyProvisionFactorySet (
  VOID
  );
