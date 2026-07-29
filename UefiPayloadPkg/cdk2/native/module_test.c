/** @file

  Host checks for native module dispatch.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "entry.h"
#include "module.h"

#include <stdio.h>

static UINTN  mFirstCalls;
static UINTN  mSecondCalls;
static UINTN  mFailCalls;

const CDK2_NATIVE_MODULE  __cdk2_modules_start[1] = {
  { "unused-start", NULL }
};
const CDK2_NATIVE_MODULE  __cdk2_modules_end[1] = {
  { "unused-end", NULL }
};

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 module test: %s\n", Message);
    return 1;
  }

  return 0;
}

static EFI_STATUS
EFIAPI
TestFirstModule (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->BootloaderParameter != 0) {
    return EFI_INVALID_PARAMETER;
  }

  mFirstCalls++;
  Context->BootloaderParameter = 1;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestSecondModule (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->BootloaderParameter != 1) {
    return EFI_INVALID_PARAMETER;
  }

  mSecondCalls++;
  Context->BootloaderParameter = 2;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestFailModule (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mFailCalls++;
  return EFI_DEVICE_ERROR;
}

EFI_STATUS
EFIAPI
Cdk2NativeInitializeStageContext (
  OUT CDK2_NATIVE_CONTEXT  *Context,
  IN  UINTN                 BootloaderParameter
  )
{
  (VOID)Context;
  (VOID)BootloaderParameter;
  return EFI_UNSUPPORTED;
}

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

EFI_STATUS
EFIAPI
Cdk2NativeRunEntry (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  (VOID)Context;
  return EFI_UNSUPPORTED;
}

int
main (
  void
  )
{
  CDK2_NATIVE_CONTEXT        Context;
  EFI_STATUS                 Status;
  int                        Failures;
  const CDK2_NATIVE_MODULE   OrderedModules[] = {
    { "first", TestFirstModule },
    { "second", TestSecondModule }
  };
  const CDK2_NATIVE_MODULE   NullInitModule[] = {
    { "null-init", NULL }
  };
  const CDK2_NATIVE_MODULE   FailingModules[] = {
    { "fail", TestFailModule },
    { "second", TestSecondModule }
  };

  Failures = 0;

  Context = (CDK2_NATIVE_CONTEXT){ 0 };
  Status = Cdk2NativeRunModuleTable (
             &Context,
             OrderedModules,
             sizeof (OrderedModules) / sizeof (OrderedModules[0])
             );
  Failures += Expect (Status == EFI_SUCCESS, "ordered modules rejected");
  Failures += Expect (mFirstCalls == 1, "first module did not run once");
  Failures += Expect (mSecondCalls == 1, "second module did not run once");
  Failures += Expect (Context.BootloaderParameter == 2, "modules ran out of order");

  Status = Cdk2NativeRunModuleTable (
             NULL,
             OrderedModules,
             sizeof (OrderedModules) / sizeof (OrderedModules[0])
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "NULL context accepted");

  Status = Cdk2NativeRunModuleTable (&Context, NULL, 1);
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "NULL module table accepted");

  Status = Cdk2NativeRunModuleTable (
             &Context,
             NullInitModule,
             sizeof (NullInitModule) / sizeof (NullInitModule[0])
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "NULL module init accepted");

  Context = (CDK2_NATIVE_CONTEXT){ 0 };
  mSecondCalls = 0;
  Status = Cdk2NativeRunModuleTable (
             &Context,
             FailingModules,
             sizeof (FailingModules) / sizeof (FailingModules[0])
             );
  Failures += Expect (Status == EFI_DEVICE_ERROR, "module failure was not returned");
  Failures += Expect (mFailCalls == 1, "failing module did not run once");
  Failures += Expect (mSecondCalls == 0, "dispatch continued after module failure");

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 module test: PASS");
  return 0;
}
