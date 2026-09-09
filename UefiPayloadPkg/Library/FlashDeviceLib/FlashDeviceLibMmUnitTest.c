/** @file
  Verify MM store containment against mock HOB and SPI providers.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FlashDeviceLib.h>
#include <Library/HobLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include <Library/SpiFlashLib.h>
#include <Library/UnitTestLib.h>
#include <Guid/PayloadMmSpiStoreInfoGuid.h>

STATIC struct {
  EFI_HOB_GUID_TYPE      Hob;
  VARIABLE_FLASH_INFO    Info;
} mHob;
STATIC struct {
  EFI_HOB_GUID_TYPE          Hob;
  PAYLOAD_MM_SPI_STORE_INFO  Info;
} mStoreHob;
STATIC BOOLEAN     mVariablePresent;
STATIC BOOLEAN     mStorePresent;
STATIC EFI_STATUS  mSpiStatus;
STATIC UINT32      mBiosBase;
STATIC UINT32      mBiosSize;
STATIC UINTN       mTransfers;
STATIC UINT32      mAddress;

VOID *
EFIAPI
GetFirstGuidHob (
  IN CONST EFI_GUID  *Guid
  )
{
  if (CompareGuid (Guid, &gVariableFlashInfoHobGuid)) {
    return mVariablePresent ? &mHob : NULL;
  }

  if (CompareGuid (Guid, &gPayloadMmSpiStoreInfoGuid)) {
    return mStorePresent ? &mStoreHob : NULL;
  }

  return NULL;
}

EFI_STATUS
EFIAPI
SpiConstructor (
  VOID
  )
{
  return mSpiStatus;
}

EFI_STATUS
EFIAPI
SpiGetRegionAddress (
  IN FLASH_REGION_TYPE  Type,
  OUT UINT32            *Base OPTIONAL,
  OUT UINT32            *Size OPTIONAL
  )
{
  if (Base != NULL) {
    *Base = mBiosBase;
  }

  if (Size != NULL) {
    *Size = mBiosSize;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SpiFlashRead (
  IN FLASH_REGION_TYPE  Type,
  IN UINT32             Address,
  IN UINT32             Size,
  OUT UINT8             *Buffer
  )
{
  mTransfers++;
  mAddress = Address;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
SpiFlashWrite (
  IN FLASH_REGION_TYPE  Type,
  IN UINT32             Address,
  IN UINT32             Size,
  IN UINT8              *Buffer
  )
{
  return SpiFlashRead (Type, Address, Size, Buffer);
}

EFI_STATUS
EFIAPI
SpiFlashErase (
  IN FLASH_REGION_TYPE  Type,
  IN UINT32             Address,
  IN UINT32             Size
  )
{
  return SpiFlashRead (Type, Address, Size, NULL);
}

STATIC
VOID
InitializeMockStore (
  VOID
  )
{
  ZeroMem (&mHob, sizeof (mHob));
  ZeroMem (&mStoreHob, sizeof (mStoreHob));
  mHob.Hob.Header.HobLength      = sizeof (mHob);
  mStoreHob.Hob.Header.HobLength = sizeof (mStoreHob);
  mVariablePresent               = TRUE;
  mStorePresent                  = TRUE;
  mSpiStatus                     = EFI_SUCCESS;
  mBiosBase                      = 0x600000;
  mBiosSize                      = 10 * SIZE_1MB;
  mTransfers                     = 0;
  ASSERT_EFI_ERROR (SmmStoreGetFlashInfo (0xEFC30000, SIZE_64KB, 8, &mHob.Info));
  mStoreHob.Info.Revision    = PAYLOAD_MM_SPI_STORE_INFO_REVISION;
  mStoreHob.Info.StoreOffset = 0x630000;
  mStoreHob.Info.StoreBase   = mHob.Info.NvVariableBaseAddress;
  mStoreHob.Info.StoreSize   = SIZE_512KB;
  mStoreHob.Info.BlockSize   = SIZE_64KB;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
StoreBounds (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8  Buffer;
  UINTN  Size;

  InitializeMockStore ();
  UT_ASSERT_NOT_EFI_ERROR (LibFvbFlashDeviceInit ());
  Size = 1;
  UT_ASSERT_NOT_EFI_ERROR (LibFvbFlashDeviceRead (0xEFC30000, &Size, &Buffer));
  UT_ASSERT_EQUAL (mAddress, 0x30000);
  UT_ASSERT_NOT_EFI_ERROR (LibFvbFlashDeviceWrite (0xEFCAFFFF, &Size, &Buffer));
  UT_ASSERT_NOT_EFI_ERROR (LibFvbFlashDeviceBlockErase (0xEFCA0000, SIZE_64KB));
  UT_ASSERT_EQUAL (mTransfers, 3);

  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceRead (0xEFC2FFFF, &Size, &Buffer), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceWrite (0xEFCB0000, &Size, &Buffer), EFI_INVALID_PARAMETER);
  Size = 2;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceWrite (0xEFCAFFFF, &Size, &Buffer), EFI_INVALID_PARAMETER);
  Size = MAX_UINTN;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceRead (0xEFC30000, &Size, &Buffer), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceBlockErase (0xEFC30001, SIZE_64KB), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceRead (0xEFC30000, NULL, &Buffer), EFI_INVALID_PARAMETER);
  Size = 1;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceRead (0xEFC30000, &Size, NULL), EFI_INVALID_PARAMETER);
  UT_ASSERT_EQUAL (mTransfers, 3);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
InitializationFailures (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8  Buffer;
  UINTN  Size;

  InitializeMockStore ();
  mVariablePresent = FALSE;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_NOT_FOUND);
  Size = 1;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceRead (0xEFC30000, &Size, &Buffer), EFI_INVALID_PARAMETER);
  mVariablePresent          = TRUE;
  mHob.Hob.Header.HobLength = sizeof (mHob) - 1;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_NOT_FOUND);
  mHob.Hob.Header.HobLength = sizeof (mHob);
  mStorePresent = FALSE;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_NOT_FOUND);
  mStorePresent = TRUE;
  mStoreHob.Hob.Header.HobLength = sizeof (mStoreHob) - 1;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_NOT_FOUND);
  mStoreHob.Hob.Header.HobLength = sizeof (mStoreHob);
  mHob.Info.FtwWorkingBaseAddress++;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mHob.Info.FtwWorkingBaseAddress--;
  mSpiStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_DEVICE_ERROR);
  mSpiStatus = EFI_SUCCESS;
  mStoreHob.Info.Revision++;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.Revision--;
  mStoreHob.Info.StoreBase++;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreBase--;
  mStoreHob.Info.StoreSize -= SIZE_64KB;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreSize += SIZE_64KB;
  mStoreHob.Info.BlockSize += SIZE_64KB;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.BlockSize -= SIZE_64KB;
  mStoreHob.Info.StoreOffset++;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreOffset--;
  mStoreHob.Info.StoreOffset = MAX_UINT32 - SIZE_256KB + 1;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreOffset = mBiosBase - 1;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreOffset = mBiosBase + mBiosSize + SIZE_64KB;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreOffset = mBiosBase + mBiosSize - SIZE_64KB;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  mStoreHob.Info.StoreOffset = 0x630000;
  mBiosSize  = SIZE_256KB;
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceInit (), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (LibFvbFlashDeviceWrite (0xEFC30000, &Size, &Buffer), EFI_INVALID_PARAMETER);
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

  Status = InitUnitTestFramework (&Framework, "MM flash containment", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Mock flash", "PayloadMm.Flash", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "Confine reads, writes and erases to the store", "Bounds", StoreBounds, NULL, NULL, NULL);
    AddTestCase (Suite, "Reject failed initialization without flash transfers", "Init", InitializationFailures, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
