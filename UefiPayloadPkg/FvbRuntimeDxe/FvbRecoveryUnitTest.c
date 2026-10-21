/** @file
  Host checks for the MM FVB recovery bootstrap.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UnitTestLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include "FvbInfo.c"
#include "FvbMmStore.c"

STATIC UINT8       mImage[SIZE_512KB];
STATIC EFI_STATUS  mReadStatus;
STATIC VARIABLE_FLASH_INFO  mFlashInfo;

EFI_STATUS
EFIAPI
GetVariableFlashFtwSpareInfo (
  OUT EFI_PHYSICAL_ADDRESS  *BaseAddress,
  OUT UINT64                *Length
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceRead (
  IN UINTN      Address,
  IN OUT UINTN  *Size,
  OUT UINT8     *Buffer
  )
{
  UINTN  Offset;

  if (EFI_ERROR (mReadStatus)) {
    return mReadStatus;
  }

  if (Address < mFlashInfo.NvVariableBaseAddress) {
    return EFI_INVALID_PARAMETER;
  }

  Offset = Address - (UINTN)mFlashInfo.NvVariableBaseAddress;
  if ((Offset > sizeof (mImage)) || (*Size > sizeof (mImage) - Offset)) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Buffer, mImage + Offset, *Size);
  return EFI_SUCCESS;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
FormatHeader (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *Header;

  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF630000, SIZE_64KB, 8, &mFlashInfo));
  Header = GetFvHeaderTemplate (&mFlashInfo);
  UT_ASSERT_NOT_NULL (Header);
  UT_ASSERT_EQUAL (Header->FvLength, SIZE_512KB);
  UT_ASSERT_EQUAL (Header->BlockMap[0].Length, SIZE_64KB);
  UT_ASSERT_EQUAL (Header->BlockMap[0].NumBlocks, 8);
  UT_ASSERT_EQUAL (CalculateSum16 ((UINT16 *)Header, Header->HeaderLength), 0);

  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF900000, SIZE_64KB, 7, &mFlashInfo));
  Header = GetFvHeaderTemplate (&mFlashInfo);
  UT_ASSERT_NOT_NULL (Header);
  UT_ASSERT_EQUAL (Header->FvLength, 7 * SIZE_64KB);
  UT_ASSERT_EQUAL (Header->BlockMap[0].Length, SIZE_64KB);
  UT_ASSERT_EQUAL (Header->BlockMap[0].NumBlocks, 7);
  UT_ASSERT_EQUAL (CalculateSum16 ((UINT16 *)Header, Header->HeaderLength), 0);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
StorageDisposition (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MM_FVB_STORE_HEADER  Snapshot;
  BOOLEAN              Format;

  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF630000, SIZE_64KB, 8, &mFlashInfo));
  mReadStatus = EFI_SUCCESS;

  SetMem (mImage, sizeof (mImage), MAX_UINT8);
  UT_ASSERT_NOT_EFI_ERROR (MmFvbInspectStorage (&mFlashInfo, &Snapshot, &Format));
  UT_ASSERT_TRUE (Format);

  mImage[SIZE_4KB] = 0;
  UT_ASSERT_STATUS_EQUAL (MmFvbInspectStorage (&mFlashInfo, &Snapshot, &Format), EFI_COMPROMISED_DATA);
  UT_ASSERT_FALSE (Format);

  mReadStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (MmFvbInspectStorage (&mFlashInfo, &Snapshot, &Format), EFI_DEVICE_ERROR);
  UT_ASSERT_FALSE (Format);
  mReadStatus = EFI_SUCCESS;
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RecoverySnapshot (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  MM_FVB_STORE_HEADER                      Snapshot;
  EFI_FIRMWARE_VOLUME_HEADER               *Fv;
  VARIABLE_STORE_HEADER                    *Variable;
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  *Workspace;
  UINTN                                    NvStoreSize;
  UINTN                                    SpareOffset;

  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF630000, SIZE_64KB, 8, &mFlashInfo));
  NvStoreSize = (UINTN)mFlashInfo.NvVariableLength;
  SpareOffset = (UINTN)(mFlashInfo.FtwSpareBaseAddress - mFlashInfo.NvVariableBaseAddress);
  mReadStatus = EFI_SUCCESS;
  SetMem (mImage, sizeof (mImage), MAX_UINT8);
  Fv = (VOID *)mImage;
  ZeroMem (Fv, sizeof (*Fv) + sizeof (EFI_FV_BLOCK_MAP_ENTRY));
  CopyGuid (&Fv->FileSystemGuid, &gEfiSystemNvDataFvGuid);
  Fv->FvLength              = sizeof (mImage);
  Fv->Signature             = EFI_FVH_SIGNATURE;
  Fv->Revision              = EFI_FVH_REVISION;
  Fv->HeaderLength          = sizeof (*Fv) + sizeof (EFI_FV_BLOCK_MAP_ENTRY);
  Fv->BlockMap[0].Length    = SIZE_64KB;
  Fv->BlockMap[0].NumBlocks = 8;
  Fv->Checksum              = CalculateCheckSum16 ((UINT16 *)Fv, Fv->HeaderLength);
  Variable                  = (VOID *)(mImage + Fv->HeaderLength);
  CopyGuid (&Variable->Signature, &gEfiAuthenticatedVariableGuid);
  Variable->Size   = (UINT32)mFlashInfo.NvVariableLength - Fv->HeaderLength;
  Variable->Format = VARIABLE_STORE_FORMATTED;
  Variable->State  = VARIABLE_STORE_HEALTHY;
  Workspace        = (VOID *)(mImage + mFlashInfo.NvVariableLength);
  CopyGuid (&Workspace->Signature, &gEdkiiWorkingBlockSignatureGuid);
  Workspace->WriteQueueSize    = SIZE_64KB - sizeof (*Workspace);
  Workspace->Crc               = CalculateCrc32 (Workspace, sizeof (*Workspace));
  Workspace->WorkingBlockValid = FTW_VALID_STATE;

  // A valid FV using another layout is not corrupt media and must not be erased.
  Fv->BlockMap[0].Length = SIZE_4KB;
  Fv->Checksum           = 0;
  Fv->Checksum           = CalculateCheckSum16 ((UINT16 *)Fv, Fv->HeaderLength);
  UT_ASSERT_STATUS_EQUAL (MmFvbReadStoreHeader (&mFlashInfo, mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_UNSUPPORTED);
  Fv->BlockMap[0].Length = SIZE_64KB;
  Fv->Checksum           = 0;
  Fv->Checksum           = CalculateCheckSum16 ((UINT16 *)Fv, Fv->HeaderLength);

  // A torn terminator is corrupt expected media, so FTW recovery may inspect it.
  Fv->BlockMap[1].NumBlocks = 1;
  UT_ASSERT_STATUS_EQUAL (MmFvbReadStoreHeader (&mFlashInfo, mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_VOLUME_CORRUPTED);
  Fv->BlockMap[1].NumBlocks = 0;
  Fv->Checksum              = 0;
  Fv->Checksum              = CalculateCheckSum16 ((UINT16 *)Fv, Fv->HeaderLength);

  UT_ASSERT_STATUS_EQUAL (MmFvbReadStoreHeader (&mFlashInfo, mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_SUCCESS);
  CopyMem (
    mImage + SpareOffset,
    mImage,
    NvStoreSize
    );

  // A valid spare lets FTW inspect and replay a pending primary journal.
  Fv->Signature = 0;
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_SUCCESS);

  // Never format over a valid primary journal without a valid spare image.
  ((EFI_FIRMWARE_VOLUME_HEADER *)(mImage + SpareOffset))->Signature = 0;
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_COMPROMISED_DATA);
  ((EFI_FIRMWARE_VOLUME_HEADER *)(mImage + SpareOffset))->Signature = EFI_FVH_SIGNATURE;

  // A workspace update keeps its replacement at the start of spare.
  CopyMem (
    mImage + SpareOffset,
    Workspace,
    (UINTN)mFlashInfo.FtwWorkingLength
    );
  Workspace->WorkingBlockInvalid = FTW_VALID_STATE;
  SetMem (
    mImage + mFlashInfo.FtwWorkingBaseAddress - mFlashInfo.NvVariableBaseAddress,
    (UINTN)mFlashInfo.FtwWorkingLength,
    MAX_UINT8
    );
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_COMPROMISED_DATA);

  // Power loss after erasing the primary leaves the committed spare available.
  Fv = GetFvHeaderTemplate (&mFlashInfo);
  UT_ASSERT_NOT_NULL (Fv);
  CopyMem (mImage, Fv, Fv->HeaderLength);
  Variable = (VOID *)(mImage + Fv->HeaderLength);
  CopyGuid (&Variable->Signature, &gEfiAuthenticatedVariableGuid);
  Variable->Size   = (UINT32)mFlashInfo.NvVariableLength - Fv->HeaderLength;
  Variable->Format = VARIABLE_STORE_FORMATTED;
  Variable->State  = VARIABLE_STORE_HEALTHY;
  SetMem (Workspace, sizeof (*Workspace), MAX_UINT8);
  CopyGuid (&Workspace->Signature, &gEdkiiWorkingBlockSignatureGuid);
  Workspace->WriteQueueSize    = SIZE_64KB - sizeof (*Workspace);
  Workspace->Crc               = CalculateCrc32 (Workspace, sizeof (*Workspace));
  Workspace->WorkingBlockValid = FTW_VALID_STATE;
  CopyMem (
    mImage + SpareOffset,
    mImage,
    NvStoreSize
    );
  SetMem (mImage, NvStoreSize, MAX_UINT8);
  UT_ASSERT_STATUS_EQUAL (MmFvbReadStoreHeader (&mFlashInfo, mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_VOLUME_CORRUPTED);
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_SUCCESS);
  UT_ASSERT_MEM_EQUAL (
    Snapshot.Bytes,
    mImage + SpareOffset,
    sizeof (Snapshot.Bytes)
    );

  // This checks the post-copy validator, not the FTW replay implementation.
  CopyMem (
    mImage,
    mImage + SpareOffset,
    NvStoreSize
    );
  UT_ASSERT_STATUS_EQUAL (MmFvbReadStoreHeader (&mFlashInfo, mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_SUCCESS);
  mReadStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_DEVICE_ERROR);
  mReadStatus = EFI_SUCCESS;

  // An odd block count still permits a committed variable-store journal.
  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF900000, SIZE_64KB, 7, &mFlashInfo));
  SpareOffset = (UINTN)(mFlashInfo.FtwSpareBaseAddress - mFlashInfo.NvVariableBaseAddress);
  SetMem (mImage, sizeof (mImage), MAX_UINT8);
  Fv = GetFvHeaderTemplate (&mFlashInfo);
  UT_ASSERT_NOT_NULL (Fv);
  CopyMem (mImage, Fv, Fv->HeaderLength);
  Variable = (VOID *)(mImage + Fv->HeaderLength);
  CopyGuid (&Variable->Signature, &gEfiAuthenticatedVariableGuid);
  Variable->Size   = (UINT32)mFlashInfo.NvVariableLength - Fv->HeaderLength;
  Variable->Format = VARIABLE_STORE_FORMATTED;
  Variable->State  = VARIABLE_STORE_HEALTHY;
  Workspace = (VOID *)(mImage + mFlashInfo.NvVariableLength);
  SetMem (Workspace, sizeof (*Workspace), MAX_UINT8);
  CopyGuid (&Workspace->Signature, &gEdkiiWorkingBlockSignatureGuid);
  Workspace->WriteQueueSize    = SIZE_64KB - sizeof (*Workspace);
  Workspace->Crc               = CalculateCrc32 (Workspace, sizeof (*Workspace));
  Workspace->WorkingBlockValid = FTW_VALID_STATE;
  CopyMem (
    mImage + SpareOffset,
    mImage,
    (UINTN)mFlashInfo.NvVariableLength
    );
  ((EFI_FIRMWARE_VOLUME_HEADER *)mImage)->Signature = 0;
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_SUCCESS);

  mFlashInfo.FtwSpareLength = mFlashInfo.NvVariableLength - 1;
  UT_ASSERT_STATUS_EQUAL (MmFvbReadRecoveryHeader (&mFlashInfo, &Snapshot), EFI_UNSUPPORTED);
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

  Status = InitUnitTestFramework (&Framework, "FVB recovery", "FvbRecovery", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Recovery bootstrap", "Fvb.Recovery", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Build format header from store geometry", "Format", FormatHeader, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Format only wholly erased media", "Disposition", StorageDisposition, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Primary and spare snapshots", "Snapshot", RecoverySnapshot, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
