/** @file
  Host tests for the persistent SMMSTORE layout.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include <Library/UnitTestLib.h>

STATIC
UNIT_TEST_STATUS
EFIAPI
ExistingLayout (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_FLASH_INFO  Info;

  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF630000, SIZE_64KB, 8, &Info));
  UT_ASSERT_EQUAL (Info.Version, VARIABLE_FLASH_INFO_HOB_VERSION);
  UT_ASSERT_EQUAL (Info.Reserved, 0);
  UT_ASSERT_EQUAL (Info.NvVariableBaseAddress, 0xFF630000);
  UT_ASSERT_EQUAL (Info.NvVariableLength, 0x30000);
  UT_ASSERT_EQUAL (Info.FtwWorkingBaseAddress, 0xFF660000);
  UT_ASSERT_EQUAL (Info.FtwWorkingLength, SIZE_64KB);
  UT_ASSERT_EQUAL (Info.FtwSpareBaseAddress, 0xFF670000);
  UT_ASSERT_EQUAL (Info.FtwSpareLength, 0x40000);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
BlockGeometries (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_FLASH_INFO  Info;
  UINTN                Count;
  UINTN                Size;

  for (Size = SIZE_4KB; Size <= SIZE_64KB; Size *= 2) {
    for (Count = 3; Count <= 16; Count++) {
      UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF000000, Size, Count, &Info));
      UT_ASSERT_EQUAL (Info.FtwWorkingLength, Size);
      UT_ASSERT_EQUAL (Info.FtwSpareLength, (Count / 2) * Size);
      UT_ASSERT_EQUAL (Info.NvVariableLength, (Count - Count / 2 - 1) * Size);
      UT_ASSERT_TRUE (Info.FtwSpareLength >= Info.NvVariableLength);
      UT_ASSERT_EQUAL (Info.FtwWorkingBaseAddress, Info.NvVariableBaseAddress + Info.NvVariableLength);
      UT_ASSERT_EQUAL (Info.FtwSpareBaseAddress, Info.FtwWorkingBaseAddress + Info.FtwWorkingLength);
      UT_ASSERT_EQUAL (Info.FtwSpareBaseAddress + Info.FtwSpareLength, 0xFF000000ULL + Count * Size);
    }
  }

  // The shared format is not limited by the legacy driver's 32-bit PCDs.
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFFF80000, SIZE_64KB, 8, &Info));
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (BASE_4GB, SIZE_64KB, 8, &Info));
  UT_ASSERT_EQUAL (Info.NvVariableBaseAddress, BASE_4GB);

  // A read-cache mapping need not share the flash erase-block alignment.
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0x12345008, SIZE_64KB, 8, &Info));
  UT_ASSERT_EQUAL (Info.FtwWorkingBaseAddress, 0x12375008);
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0x12345008, SIZE_1KB, 8, &Info));
  UT_ASSERT_EQUAL (Info.FtwWorkingLength, SIZE_1KB);
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0x12345008, 0x18000, 8, &Info));
  UT_ASSERT_EQUAL (Info.NvVariableLength, 0x48000);
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (MAX_UINT64 - 2, 1, 3, &Info));
  UT_ASSERT_EQUAL (Info.FtwSpareBaseAddress, MAX_UINT64);
  UT_ASSERT_EQUAL (Info.FtwSpareLength, 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
InvalidGeometry (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_FLASH_INFO  Info;
  VARIABLE_FLASH_INFO  Original;

  SetMem (&Info, sizeof (Info), 0xA5);
  CopyMem (&Original, &Info, sizeof (Info));
  UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (0, SIZE_64KB, 8, &Info), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (0xFF000000, 0, 8, &Info), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (0xFF000000, SIZE_64KB, 0, &Info), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (0xFF000000, SIZE_64KB, 2, &Info), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (0xFF000000, SIZE_64KB, 8, NULL), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (MAX_UINT64 - 1, 1, 3, &Info), EFI_UNSUPPORTED);
  if (sizeof (UINTN) == sizeof (UINT64)) {
    UT_ASSERT_STATUS_EQUAL (SmmStoreGetFlashInfo (1, SIZE_64KB, MAX_UINTN, &Info), EFI_UNSUPPORTED);
  }
  UT_ASSERT_MEM_EQUAL (&Info, &Original, sizeof (Info));
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

  Status = InitUnitTestFramework (&Framework, "SMMSTORE geometry", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Persistent layout", "SmmStore.Geometry", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "Preserve the Lite variable and FTW boundaries", "Existing", ExistingLayout, NULL, NULL, NULL);
    AddTestCase (Suite, "Preserve even and odd block counts", "Blocks", BlockGeometries, NULL, NULL, NULL);
    AddTestCase (Suite, "Reject invalid or overflowing mappings", "Invalid", InvalidGeometry, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
