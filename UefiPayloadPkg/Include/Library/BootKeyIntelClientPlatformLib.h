/** @file
  Supported Intel client platform data for the boot-key boundary.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef BOOT_KEY_INTEL_CLIENT_PLATFORM_LIB_H_
#define BOOT_KEY_INTEL_CLIENT_PLATFORM_LIB_H_

#include <Uefi.h>

typedef struct {
  UINTN     IncludeAllVtdBaseAddress;
  UINT32    LowPmrLimitGranularity;
  UINT64    HighPmrLimitGranularity;
} BOOT_KEY_INTEL_CLIENT_PLATFORM;

/**
  Identify a supported Intel client platform.

  @param[out] Platform  Optional pointer to the selected platform data.

  @retval EFI_SUCCESS             A supported platform was identified.
  @retval EFI_SECURITY_VIOLATION  The processor is not in the allow-list.
**/
EFI_STATUS
EFIAPI
BootKeyGetIntelClientPlatform (
  OUT CONST BOOT_KEY_INTEL_CLIENT_PLATFORM  **Platform OPTIONAL
  );

#endif
