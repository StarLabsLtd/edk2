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
  UINTN  ModuleTableStart;
  UINTN  ModuleTableEnd;
  UINTN  ModuleTableSize;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ModuleTableStart = (UINTN)__cdk2_modules_start;
  ModuleTableEnd   = (UINTN)__cdk2_modules_end;
  if (ModuleTableEnd < ModuleTableStart) {
    return EFI_COMPROMISED_DATA;
  }

  ModuleTableSize = ModuleTableEnd - ModuleTableStart;
  if (ModuleTableSize == 0 ||
      (ModuleTableStart % sizeof (*__cdk2_modules_start)) != 0 ||
      (ModuleTableSize % sizeof (*__cdk2_modules_start)) != 0)
  {
    return EFI_COMPROMISED_DATA;
  }

  return Cdk2NativeRunModuleTable (
           Context,
           __cdk2_modules_start,
           ModuleTableSize / sizeof (*__cdk2_modules_start)
           );
}

EFI_STATUS
Cdk2NativeRunModuleTable (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN CONST CDK2_NATIVE_MODULE  *Modules,
  IN UINTN                    ModuleCount
  )
{
  const CDK2_NATIVE_MODULE  *Module;
  EFI_STATUS                Status;
  UINTN                     Index;

  if (Context == NULL || (Modules == NULL && ModuleCount != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < ModuleCount; Index++) {
    Module = &Modules[Index];
    if (Module->Init == NULL) {
      return EFI_COMPROMISED_DATA;
    }

    Status = Module->Init (Context);
    if (EFI_ERROR (Status)) {
      return Status;
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
