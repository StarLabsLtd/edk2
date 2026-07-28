/** @file

  cdk2 platform extension points.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_PLATFORM_LIB_H_
#define CDK2_PLATFORM_LIB_H_

#include <Uefi.h>

typedef struct _CDK2_NATIVE_CONTEXT  CDK2_NATIVE_CONTEXT;

/**
  Register the backend used by an initialized freestanding native stage.

  Implementations must not clear or reinitialize the common native service
  table owned by Cdk2NativeStageEntry().
**/
EFI_STATUS
EFIAPI
Cdk2PlatformInitializeNativeContext (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  );

/** Run immediately before the payload hands control to DXE. */
VOID
EFIAPI
Cdk2PlatformLateInit (
  VOID
  );

#endif
