/** @file

  Default cdk2 platform extension points.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2PlatformLib.h>

#if defined (__GNUC__)
#define CDK2_WEAK  __attribute__ ((weak))
#else
#define CDK2_WEAK
#endif

CDK2_WEAK
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

CDK2_WEAK
VOID
EFIAPI
Cdk2PlatformLateInit (
  VOID
  )
{
  // Board-specific payloads may override this hook.
}
