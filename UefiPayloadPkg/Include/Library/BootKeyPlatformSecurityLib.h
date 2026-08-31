/** @file
  Platform security boundary required before boot-key authenticator input.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef BOOT_KEY_PLATFORM_SECURITY_LIB_H_
#define BOOT_KEY_PLATFORM_SECURITY_LIB_H_

#include <Uefi.h>

/**
  Verify that platform hardware prevents access to protected firmware state.

  This check runs after EndOfDxe and ReadyToLock processing, but before any
  authenticator input.  Implementations must read back the platform's hardware
  protection state; EFI_SMM_ACCESS2_PROTOCOL software state alone is not
  sufficient.

  @retval EFI_SUCCESS             The hardware boundary is closed and locked.
  @retval EFI_SECURITY_VIOLATION  The hardware boundary is not secure.
  @retval EFI_UNSUPPORTED         No hardware verifier is integrated.
**/
EFI_STATUS
EFIAPI
BootKeyVerifyPlatformSecurityBoundary (
  VOID
  );

#endif
