/** @file
  Reset-bounded boot-key TPM NV authorization provider.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

#define BOOT_KEY_NV_AUTH_SIZE  32

EFI_STATUS
EFIAPI
BootKeyNvAuthAcquire (
  IN  BOOLEAN  FactoryInitialization,
  OUT UINT8    Auth[BOOT_KEY_NV_AUTH_SIZE],
  OUT BOOLEAN  *ProvisionRequired
  );

EFI_STATUS
EFIAPI
BootKeyNvAuthCommit (
  IN CONST UINT8  Auth[BOOT_KEY_NV_AUTH_SIZE]
  );

EFI_STATUS
EFIAPI
BootKeyNvAuthClose (
  VOID
  );
