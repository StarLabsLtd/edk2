/** @file

  Native cdk2 module registration contract.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_MODULE_H_
#define CDK2_MODULE_H_

#include <cdk2/context.h>
#include <Library/Cdk2PlatformLib.h>

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_MODULE_INIT)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef struct {
  CONST CHAR8                 *Name;
  CDK2_NATIVE_MODULE_INIT     Init;
} CDK2_NATIVE_MODULE;

EFI_STATUS
Cdk2NativeRunModuleTable (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN CONST CDK2_NATIVE_MODULE  *Modules,
  IN UINTN                    ModuleCount
  );

#if defined (__GNUC__)
#define CDK2_NATIVE_REGISTER(Name, Function) \
  static const CDK2_NATIVE_MODULE  mCdk2Module_##Function \
    __attribute__ ((used, section (".cdk2.modules"))) = { Name, Function }
#else
#define CDK2_NATIVE_REGISTER(Name, Function) \
  static const CDK2_NATIVE_MODULE  mCdk2Module_##Function = { Name, Function }
#endif

#endif
