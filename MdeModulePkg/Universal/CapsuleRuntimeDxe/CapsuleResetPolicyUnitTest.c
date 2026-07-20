/** @file
  Unit tests for capsule staging reset policy.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>

#include "CapsuleResetPolicy.h"

#define UNIT_TEST_APP_NAME     "Capsule Reset Policy Unit Tests"
#define UNIT_TEST_APP_VERSION  "1.0"

STATIC
UNIT_TEST_STATUS
EFIAPI
PersistedCapsulesUseWarmReset (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UT_ASSERT_EQUAL (GetCapsuleResetType (TRUE), EfiResetWarm);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ImmediateCapsulesKeepColdReset (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UT_ASSERT_EQUAL (GetCapsuleResetType (FALSE), EfiResetCold);
  return UNIT_TEST_PASSED;
}

STATIC
EFI_STATUS
EFIAPI
UnitTestingEntry (
  VOID
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      PolicyTests;

  Framework = NULL;
  DEBUG ((DEBUG_INFO, "%a v%a\n", UNIT_TEST_APP_NAME, UNIT_TEST_APP_VERSION));

  Status = InitUnitTestFramework (
             &Framework,
             UNIT_TEST_APP_NAME,
             gEfiCallerBaseName,
             UNIT_TEST_APP_VERSION
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = CreateUnitTestSuite (
             &PolicyTests,
             Framework,
             "Capsule reset policy",
             "CapsuleRuntimeDxe.ResetPolicy",
             NULL,
             NULL
             );
  if (EFI_ERROR (Status)) {
    FreeUnitTestFramework (Framework);
    return Status;
  }

  AddTestCase (PolicyTests, "Persisted capsules use warm reset", "PersistedWarm", PersistedCapsulesUseWarmReset, NULL, NULL, NULL);
  AddTestCase (PolicyTests, "Immediate capsules keep cold reset", "ImmediateCold", ImmediateCapsulesKeepColdReset, NULL, NULL, NULL);

  Status = RunAllTestSuites (Framework);
  FreeUnitTestFramework (Framework);
  return Status;
}

#define CapsuleResetPolicyUnitTestMain  main

INT32
CapsuleResetPolicyUnitTestMain (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  return EFI_ERROR (UnitTestingEntry ()) ? 1 : 0;
}
