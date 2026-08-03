/** @file
  Linux EFI-application boot option helpers.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef PLATFORM_LINUX_EFI_BOOT_H_
#define PLATFORM_LINUX_EFI_BOOT_H_

#include <Uefi.h>

EFI_STATUS
PlatformLinuxEfiBootValidatePath (
  IN CONST CHAR16  *Path
  );

EFI_STATUS
PlatformLinuxEfiBootValidateDescription (
  IN CONST CHAR16  *Description
  );

#endif
