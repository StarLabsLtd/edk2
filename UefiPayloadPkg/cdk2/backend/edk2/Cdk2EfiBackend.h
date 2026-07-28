/** @file

  EDK II backend adapter for the native cdk2 entry path.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_EFI_BACKEND_H_
#define CDK2_EFI_BACKEND_H_

#include <Library/Cdk2NativeServices.h>

EFI_STATUS
EFIAPI
Cdk2EfiPopulateHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiBuildSerialHob (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiApplyBootMode (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiInitializeLibraries (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiSetBootloaderParameter (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiFindHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT    UINTN                 *HobMemBase
  );

EFI_STATUS
EFIAPI
Cdk2EfiInitializeFloatingPoint (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiMaskLegacyInterrupts (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2EfiBackendInitializeContext (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  );

EFI_STATUS
EFIAPI
Cdk2EfiTransferToDxeCore (
  IN CDK2_NATIVE_CONTEXT  *Context
  );

#endif
