/** @file

  Native cdk2 payload entry flow.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>

EFI_STATUS
EFIAPI
Cdk2NativeRunEntry (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_STATUS            Status;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2NativeValidateBackend (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativePrepareEntry (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Cdk2NativeTransfer (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativePayloadEntry (
  IN UINTN                          BootloaderParameter,
  IN CDK2_NATIVE_INITIALIZE_CONTEXT InitializeContext
  )
{
  CDK2_NATIVE_CONTEXT  Context = { 0 };
  EFI_STATUS            Status;

  if (InitializeContext == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = InitializeContext (&Context, BootloaderParameter);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Cdk2NativeRunEntry (&Context);
}
