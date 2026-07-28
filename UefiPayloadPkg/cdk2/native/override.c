/** @file

  Native cdk2 strong-hook test override.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2PlatformLib.h>

EFI_STATUS
EFIAPI
Cdk2PlatformInitializeNativeContext (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  )
{
  (VOID)Context;
  (VOID)BootloaderParameter;
  return EFI_UNSUPPORTED;
}

VOID
EFIAPI
Cdk2PlatformLateInit (
  VOID
  )
{
  // A board-specific native stage can provide the strong definition here.
}
