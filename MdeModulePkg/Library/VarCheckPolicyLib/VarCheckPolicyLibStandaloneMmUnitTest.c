/** @file
  Host checks for standalone MM variable-policy initialization.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <setjmp.h>

#include <PiMm.h>
#include <Library/UnitTestLib.h>

#include "VarCheckPolicyLib.c"
#include "VarCheckPolicyLibStandaloneMm.c"

typedef enum {
  EventPolicyInit,
  EventEnforcementHook,
  EventMmiHandler
} TEST_EVENT;

STATIC EFI_MM_SYSTEM_TABLE  mMmst;
EFI_MM_SYSTEM_TABLE         *gMmst = &mMmst;
STATIC EFI_STATUS           mPolicyStatus;
STATIC EFI_STATUS           mHookStatus;
STATIC EFI_STATUS           mMmiStatus;
STATIC TEST_EVENT           mEvents[3];
STATIC UINTN                mEventCount;
STATIC UINTN                mFatalCalls;
STATIC jmp_buf              mFatalJump;

EFI_STATUS
EFIAPI
VariableServiceGetVariable (
  IN      CHAR16    *VariableName,
  IN      EFI_GUID  *VendorGuid,
  OUT     UINT32    *Attributes OPTIONAL,
  IN OUT  UINTN     *DataSize,
  OUT     VOID      *Data
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
InitVariablePolicyLib (
  IN EFI_GET_VARIABLE  GetVariableHelper
  )
{
  mEvents[mEventCount++] = EventPolicyInit;
  return mPolicyStatus;
}

EFI_STATUS
EFIAPI
ValidateSetVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINT32    Attributes,
  IN UINTN     DataSize,
  IN VOID      *Data
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VarCheckLibRegisterSetVariableCheckHandler (
  IN VAR_CHECK_SET_VARIABLE_CHECK_HANDLER  Handler
  )
{
  mEvents[mEventCount++] = EventEnforcementHook;
  return mHookStatus;
}

STATIC
EFI_STATUS
EFIAPI
MmiHandlerRegister (
  IN EFI_MM_HANDLER_ENTRY_POINT  Handler,
  IN CONST EFI_GUID              *HandlerType OPTIONAL,
  OUT EFI_HANDLE                 *DispatchHandle
  )
{
  mEvents[mEventCount++] = EventMmiHandler;
  if (!EFI_ERROR (mMmiStatus)) {
    *DispatchHandle = &mMmst;
  }

  return mMmiStatus;
}

EFI_STATUS
EFIAPI
DisableVariablePolicy (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

BOOLEAN
EFIAPI
IsVariablePolicyEnabled (
  VOID
  )
{
  return FALSE;
}

EFI_STATUS
EFIAPI
RegisterVariablePolicy (
  IN CONST VARIABLE_POLICY_ENTRY  *NewPolicy
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
DumpVariablePolicy (
  OUT UINT8   *Policy,
  IN OUT UINT32  *Size
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
LockVariablePolicy (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
GetVariablePolicyInfo (
  IN CONST CHAR16            *VariableName,
  IN CONST EFI_GUID          *VendorGuid,
  IN OUT UINTN               *VariablePolicyVariableNameBufferSize OPTIONAL,
  OUT VARIABLE_POLICY_ENTRY  *VariablePolicy,
  OUT CHAR16                 *VariablePolicyVariableName OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
GetLockOnVariableStateVariablePolicyInfo (
  IN CONST CHAR16                        *VariableName,
  IN CONST EFI_GUID                      *VendorGuid,
  IN OUT UINTN                           *VariableLockPolicyVariableNameBufferSize OPTIONAL,
  OUT VARIABLE_LOCK_ON_VAR_STATE_POLICY  *VariablePolicy,
  OUT CHAR16                             *VariableLockPolicyVariableName OPTIONAL
  )
{
  return EFI_UNSUPPORTED;
}

VOID
EFIAPI
__wrap_CpuDeadLoop (
  VOID
  )
{
  mFatalCalls++;
  longjmp (mFatalJump, 1);
}

STATIC
VOID
ResetMocks (
  VOID
  )
{
  ZeroMem (&mMmst, sizeof (mMmst));
  mMmst.MmiHandlerRegister = MmiHandlerRegister;
  mPolicyStatus            = EFI_SUCCESS;
  mHookStatus              = EFI_SUCCESS;
  mMmiStatus               = EFI_SUCCESS;
  mEventCount              = 0;
  mFatalCalls              = 0;
  mPolicyMmiHandle         = NULL;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
CommonConstructorOrdering (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  UT_ASSERT_NOT_EFI_ERROR (VarCheckPolicyLibCommonConstructor ());
  UT_ASSERT_EQUAL (mEventCount, 3);
  UT_ASSERT_EQUAL (mEvents[0], EventPolicyInit);
  UT_ASSERT_EQUAL (mEvents[1], EventEnforcementHook);
  UT_ASSERT_EQUAL (mEvents[2], EventMmiHandler);

  ResetMocks ();
  mPolicyStatus = EFI_OUT_OF_RESOURCES;
  UT_ASSERT_STATUS_EQUAL (VarCheckPolicyLibCommonConstructor (), EFI_OUT_OF_RESOURCES);
  UT_ASSERT_EQUAL (mEventCount, 1);

  ResetMocks ();
  mHookStatus = EFI_ACCESS_DENIED;
  UT_ASSERT_STATUS_EQUAL (VarCheckPolicyLibCommonConstructor (), EFI_ACCESS_DENIED);
  UT_ASSERT_EQUAL (mEventCount, 2);

  ResetMocks ();
  mMmiStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (VarCheckPolicyLibCommonConstructor (), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mEventCount, 3);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
RunFatalConstructorCase (
  IN EFI_STATUS  PolicyStatus,
  IN EFI_STATUS  HookStatus,
  IN EFI_STATUS  MmiStatus,
  IN UINTN       ExpectedEvents
  )
{
  ResetMocks ();
  mPolicyStatus = PolicyStatus;
  mHookStatus   = HookStatus;
  mMmiStatus    = MmiStatus;

  if (setjmp (mFatalJump) == 0) {
    VarCheckPolicyLibStandaloneConstructor (NULL, NULL);
    return UNIT_TEST_ERROR_TEST_FAILED;
  }

  UT_ASSERT_EQUAL (mFatalCalls, 1);
  UT_ASSERT_EQUAL (mEventCount, ExpectedEvents);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
StandaloneConstructorFailsClosed (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UT_ASSERT_EQUAL (
    RunFatalConstructorCase (EFI_OUT_OF_RESOURCES, EFI_SUCCESS, EFI_SUCCESS, 1),
    UNIT_TEST_PASSED
    );
  UT_ASSERT_EQUAL (
    RunFatalConstructorCase (EFI_SUCCESS, EFI_ACCESS_DENIED, EFI_SUCCESS, 2),
    UNIT_TEST_PASSED
    );
  UT_ASSERT_EQUAL (
    RunFatalConstructorCase (EFI_SUCCESS, EFI_SUCCESS, EFI_DEVICE_ERROR, 3),
    UNIT_TEST_PASSED
    );

  ResetMocks ();
  UT_ASSERT_NOT_EFI_ERROR (VarCheckPolicyLibStandaloneConstructor (NULL, NULL));
  UT_ASSERT_EQUAL (mFatalCalls, 0);
  UT_ASSERT_EQUAL (mEventCount, 3);
  return UNIT_TEST_PASSED;
}

INT32
main (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;
  EFI_STATUS                  Status;

  Status = InitUnitTestFramework (&Framework, "Standalone MM variable policy", "VarCheckPolicyMm", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Initialization", "VarCheckPolicyMm.Init", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Common constructor preserves failures", "Common", CommonConstructorOrdering, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Standalone constructor fails closed", "Standalone", StandaloneConstructorFailsClosed, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
