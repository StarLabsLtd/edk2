/** @file

  Native cdk2 stage entry contract.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_ENTRY_H_
#define CDK2_ENTRY_H_

#include <cdk2/context.h>

/**
  Dispatch the registered native modules using an initialized context.

  Service ownership stays with the caller so the native backend can provide
  platform-specific callbacks before module dispatch.

  @param[in,out] Context  Initialized native service context.

  @retval EFI_SUCCESS            All registered modules completed.
  @retval EFI_INVALID_PARAMETER  Context is NULL.
  @retval EFI_COMPROMISED_DATA   The linker-collected module table is invalid.
  @retval Other                  A module returned an error.
**/
EFI_STATUS
Cdk2NativeRunModules (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

/**
  Native cdk2 stage entry point.

  @param[in] BootloaderParameter Coreboot bootloader parameter address.

  @retval EFI_SUCCESS            All registered modules completed.
  @retval Other                  Stage initialization or module failure.
**/
EFI_STATUS
Cdk2NativeStageEntry (
  IN UINTN  BootloaderParameter
  );

#endif
