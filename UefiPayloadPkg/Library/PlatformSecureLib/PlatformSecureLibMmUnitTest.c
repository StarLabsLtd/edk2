/** @file
  Check the real MM presence policy against a mock MM protocol database.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Guid/EventGroup.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PlatformSecureLib.h>
#include <Library/UnitTestLib.h>

STATIC EFI_MM_SYSTEM_TABLE  mMmst;
EFI_MM_SYSTEM_TABLE         *gMmst = &mMmst;
STATIC EFI_STATUS          mReadyStatus;
STATIC EFI_STATUS          mExitStatus;

STATIC
EFI_STATUS
EFIAPI
LocateProtocol (
  IN EFI_GUID        *Protocol,
  IN VOID            *Registration OPTIONAL,
  OUT VOID           **Interface
  )
{
  *Interface = NULL;
  if (CompareGuid (Protocol, &gEfiEventReadyToBootGuid)) {
    return mReadyStatus;
  }

  if (CompareGuid (Protocol, &gEfiEventExitBootServicesGuid)) {
    return mExitStatus;
  }

  return EFI_INVALID_PARAMETER;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ConfigurationWindow (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  mMmst.MmLocateProtocol = LocateProtocol;
  mReadyStatus          = EFI_NOT_FOUND;
  mExitStatus           = EFI_NOT_FOUND;
  UT_ASSERT_TRUE (UserPhysicalPresent ());

  mReadyStatus = EFI_SUCCESS;
  UT_ASSERT_FALSE (UserPhysicalPresent ());
  // Repeated calls cannot reopen the window after a boot attempt.
  UT_ASSERT_FALSE (UserPhysicalPresent ());
  mExitStatus = EFI_SUCCESS;
  UT_ASSERT_FALSE (UserPhysicalPresent ());

  // ExitBootServices must also close it without ReadyToBoot.
  mReadyStatus = EFI_NOT_FOUND;
  UT_ASSERT_FALSE (UserPhysicalPresent ());
  mExitStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_FALSE (UserPhysicalPresent ());
  mExitStatus  = EFI_NOT_FOUND;
  mReadyStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_FALSE (UserPhysicalPresent ());
  return UNIT_TEST_PASSED;
}

INT32
main (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;

  Status = InitUnitTestFramework (&Framework, "MM Secure Boot policy", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "MM phase markers", "PayloadMm.SecureBoot", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "Allow Setup and deny after handoff or lookup errors", "Window", ConfigurationWindow, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
