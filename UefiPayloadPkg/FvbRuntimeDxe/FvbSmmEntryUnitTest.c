/** @file
  Host checks for traditional SMM FVB backend initialisation ordering.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiSmm.h>
#include <Library/UnitTestLib.h>

#include "FvbServiceSmm.c"

typedef enum {
  EventBackendInit,
  EventCommonInit
} TEST_EVENT;

STATIC EFI_STATUS  mBackendStatus;
STATIC EFI_STATUS  mCommonStatus;
STATIC TEST_EVENT  mEvents[2];
STATIC UINTN       mEventCount;

EFI_SMM_SYSTEM_TABLE2       *gSmst;
EFI_BOOT_SERVICES           *gBS;
EFI_FW_VOL_BLOCK_DEVICE     mFvbDeviceTemplate;
FV_MEMMAP_DEVICE_PATH       mFvMemmapDevicePathTemplate;
FV_PIWG_DEVICE_PATH         mFvPIWGDevicePathTemplate;

EFI_STATUS
EFIAPI
GetSectionFromAnyFv (
  IN  CONST EFI_GUID   *NameGuid,
  IN  EFI_SECTION_TYPE SectionType,
  IN  UINTN            SectionInstance,
  OUT VOID             **Buffer,
  OUT UINTN            *Size
  )
{
  return EFI_NOT_FOUND;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceInit (
  VOID
  )
{
  mEvents[mEventCount++] = EventBackendInit;
  return mBackendStatus;
}

EFI_STATUS
FvbInitialize (
  IN EFI_FIRMWARE_VOLUME_HEADER  *ValidatedHeader OPTIONAL,
  IN CONST VARIABLE_FLASH_INFO   *FormatInfo OPTIONAL
  )
{
  mEvents[mEventCount++] = EventCommonInit;
  return mCommonStatus;
}

STATIC
VOID
ResetMocks (
  VOID
  )
{
  mBackendStatus = EFI_SUCCESS;
  mCommonStatus  = EFI_SUCCESS;
  mEventCount    = 0;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
BackendPrecedesCommonInitialization (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mCommonStatus = EFI_WARN_RESET_REQUIRED;

  UT_ASSERT_STATUS_EQUAL (FvbSmmInitialize (NULL, NULL), EFI_WARN_RESET_REQUIRED);
  UT_ASSERT_EQUAL (mEventCount, 2);
  UT_ASSERT_EQUAL (mEvents[0], EventBackendInit);
  UT_ASSERT_EQUAL (mEvents[1], EventCommonInit);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
BackendFailureStopsInitialization (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mBackendStatus = EFI_DEVICE_ERROR;

  UT_ASSERT_STATUS_EQUAL (FvbSmmInitialize (NULL, NULL), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mEventCount, 1);
  UT_ASSERT_EQUAL (mEvents[0], EventBackendInit);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
CommonFailureIsPropagated (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mCommonStatus = EFI_VOLUME_CORRUPTED;

  UT_ASSERT_STATUS_EQUAL (FvbSmmInitialize (NULL, NULL), EFI_VOLUME_CORRUPTED);
  UT_ASSERT_EQUAL (mEventCount, 2);
  UT_ASSERT_EQUAL (mEvents[0], EventBackendInit);
  UT_ASSERT_EQUAL (mEvents[1], EventCommonInit);
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

  Status = InitUnitTestFramework (&Framework, "Traditional SMM FVB entry", "FvbSmmEntry", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Backend ordering", "FvbSmmEntry.Init", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Backend setup precedes common setup",
               "Success",
               BackendPrecedesCommonInitialization,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Backend failure stops common setup",
               "BackendFailure",
               BackendFailureStopsInitialization,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Common setup failure is propagated",
               "CommonFailure",
               CommonFailureIsPropagated,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
