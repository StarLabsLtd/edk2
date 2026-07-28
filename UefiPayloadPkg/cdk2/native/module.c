/** @file

  Native cdk2 platform module.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "module.h"
STATIC
EFI_STATUS
EFIAPI
Cdk2NativePlatformModuleInit (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Late platform policy runs once at the image-load service boundary. Keep
  // this module as a registration and context-validation point only.
  return EFI_SUCCESS;
}

CDK2_NATIVE_REGISTER ("platform", Cdk2NativePlatformModuleInit);
