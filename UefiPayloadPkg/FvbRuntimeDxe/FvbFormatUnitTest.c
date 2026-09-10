/** @file
  Host checks for formatting an FVB variable store.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/UnitTestLib.h>

STATIC EFI_STATUS  mInitialDataStatus;
STATIC UINTN       mInitialDataSize;
STATIC UINTN       mWriteSize;
STATIC UINTN       mWriteCount;
STATIC UINT8       mInitialData[4];

#include "FvbService.c"

EFI_STATUS
GetInitialVariableData (
  OUT VOID   **VarData,
  OUT UINTN  *VarSize
  )
{
  *VarData = mInitialData;
  *VarSize = mInitialDataSize;
  return mInitialDataStatus;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceWrite (
  IN     UINTN  Address,
  IN OUT UINTN  *NumBytes,
  IN     UINT8  *Buffer
  )
{
  mWriteSize = *NumBytes;
  mWriteCount++;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceRead (
  IN     UINTN  Address,
  IN OUT UINTN  *NumBytes,
  OUT    UINT8  *Buffer
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceBlockErase (
  IN UINTN  Address,
  IN UINTN  Length
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceBlockLock (
  IN UINTN    Address,
  IN UINTN    Length,
  IN BOOLEAN  Lock
  )
{
  return EFI_SUCCESS;
}

VOID *
EFIAPI
WriteBackInvalidateDataCacheRange (
  IN VOID   *Address,
  IN UINTN  Length
  )
{
  return Address;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
InitialVariableData (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  mInitialDataStatus = EFI_SUCCESS;
  mInitialDataSize   = 0;
  mWriteCount        = 0;
  UT_ASSERT_NOT_EFI_ERROR (WriteInitialVariableData (0x1000));
  UT_ASSERT_EQUAL (mWriteCount, 0);

  mInitialDataSize = sizeof (mInitialData);
  UT_ASSERT_NOT_EFI_ERROR (WriteInitialVariableData (0x1000));
  UT_ASSERT_EQUAL (mWriteCount, 1);
  UT_ASSERT_EQUAL (mWriteSize, sizeof (mInitialData));

  mInitialDataStatus = EFI_NOT_FOUND;
  UT_ASSERT_NOT_EFI_ERROR (WriteInitialVariableData (0x1000));
  UT_ASSERT_EQUAL (mWriteCount, 1);
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

  Status = InitUnitTestFramework (&Framework, "FVB formatting", "FvbFormat", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Variable initialization", "Fvb.Format", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Skip absent and empty initial variable data",
               "InitialData",
               InitialVariableData,
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
