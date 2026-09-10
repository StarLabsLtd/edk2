/** @file
  Host checks for the MM FVB recovery bootstrap.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/UnitTestLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include "FvbInfo.c"
#include "FvbServiceStandaloneMm.c"

STATIC UINT8       mImage[SIZE_512KB];
STATIC EFI_STATUS  mReadStatus;

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
RecoverySnapshot (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  STORE_HEADER                             Snapshot;
  EFI_FIRMWARE_VOLUME_HEADER               *Fv;
  VARIABLE_STORE_HEADER                    *Variable;
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  *Workspace;
  UINTN                                    WorkingSize;

  UT_ASSERT_NOT_EFI_ERROR (SmmStoreGetFlashInfo (0xFF630000, SIZE_64KB, 8, &mFlashInfo));
  WorkingSize = (UINTN)mFlashInfo.FtwSpareLength;
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

  UT_ASSERT_STATUS_EQUAL (ReadStoreHeader (mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_SUCCESS);
  CopyMem (mImage + WorkingSize, mImage, WorkingSize);

  // A valid primary workspace cannot authorize replacing a damaged FV header.
  Fv->Signature = 0;
  UT_ASSERT_STATUS_EQUAL (ReadRecoveryHeader (&Snapshot), EFI_VOLUME_CORRUPTED);

  // FTW invalidates the workspace before starting the working-block erase.
  Workspace->WorkingBlockInvalid = FTW_VALID_STATE;
  SetMem (mImage, SIZE_64KB, MAX_UINT8);
  UT_ASSERT_STATUS_EQUAL (ReadRecoveryHeader (&Snapshot), EFI_SUCCESS);

  // Power loss after erasing the primary leaves the committed spare available.
  SetMem (mImage, WorkingSize, MAX_UINT8);
  UT_ASSERT_STATUS_EQUAL (ReadStoreHeader (mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_VOLUME_CORRUPTED);
  UT_ASSERT_STATUS_EQUAL (ReadRecoveryHeader (&Snapshot), EFI_SUCCESS);
  UT_ASSERT_MEM_EQUAL (Snapshot.Bytes, mImage + WorkingSize, sizeof (Snapshot.Bytes));

  // This checks the post-copy validator, not the FTW replay implementation.
  CopyMem (mImage, mImage + WorkingSize, WorkingSize);
  UT_ASSERT_STATUS_EQUAL (ReadStoreHeader (mFlashInfo.NvVariableBaseAddress, &Snapshot), EFI_SUCCESS);
  mReadStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (ReadRecoveryHeader (&Snapshot), EFI_DEVICE_ERROR);
  mReadStatus = EFI_SUCCESS;
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
    Status = AddTestCase (Suite, "Primary and spare snapshots", "Snapshot", RecoverySnapshot, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
