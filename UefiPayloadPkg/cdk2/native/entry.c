/** @file

  Native cdk2 stage entry point.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2PlatformLib.h>
#include <cdk2/config.h>
#include "entry.h"
#include "module.h"
#include "services.h"

#if defined (__GNUC__)
#define CDK2_ENTRY  __attribute__ ((section (".text.entry"), used))
#else
#define CDK2_ENTRY
#endif

/**
  Entry point for the native cdk2 stage.

  This is intentionally a small boundary. Platform policy is provided by the
  registered native modules; service and UEFI image loading are added behind
  this entry point as the BaseTools backend is retired. Keep the bootloader
  parameter at this boundary so a native backend receives the same handoff
  data as the current EDK II adapter.
**/
extern const CDK2_NATIVE_MODULE  __cdk2_modules_start[];
extern const CDK2_NATIVE_MODULE  __cdk2_modules_end[];

EFI_STATUS
Cdk2NativeRunModules (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  const CDK2_NATIVE_MODULE  *Module;
  EFI_STATUS                Status;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (Module = __cdk2_modules_start; Module < __cdk2_modules_end; Module++) {
    if (Module->Init != NULL) {
      Status = Module->Init (Context);
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }
  }

  return EFI_SUCCESS;
}

CDK2_ENTRY
EFI_STATUS
Cdk2NativeStageEntry (
  IN UINTN  BootloaderParameter
  )
{
  CDK2_NATIVE_CONTEXT  Context = { 0 };
  EFI_STATUS            Status;

  Status = Cdk2NativeInitializeStageContext (&Context, BootloaderParameter);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2PlatformInitializeNativeContext (&Context, BootloaderParameter);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeRunModules (&Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Cdk2NativeRunEntry (&Context);
}
