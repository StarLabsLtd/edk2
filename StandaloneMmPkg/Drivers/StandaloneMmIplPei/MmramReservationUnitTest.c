/** @file
  Host tests for standalone MM MMRAM allocation lifetime.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiPei.h>
#include <Guid/MmramMemoryReserve.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/UnitTestLib.h>
#include "StandaloneMmIplPei.h"

EFI_PHYSICAL_ADDRESS
MmIplAllocateMmramPage (
  IN  UINTN                           Pages,
  OUT EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  **NewBlock,
  IN  BOOLEAN                         PreserveMmramReservation
  );

typedef struct {
  EFI_HOB_GUID_TYPE               Hob;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  Block;
  EFI_MMRAM_DESCRIPTOR            Extra;
} MMRAM_HOB;

STATIC MMRAM_HOB  mPrevious;
STATIC MMRAM_HOB  mPersistent;
STATIC UINTN      mBuildCalls;
STATIC BOOLEAN    mGuidMatches;
STATIC UINTN      mRequestedSize;

VOID *
EFIAPI
GetFirstGuidHob (
  IN CONST EFI_GUID  *Guid
  )
{
  if (CompareGuid (Guid, &mPrevious.Hob.Name)) {
    return &mPrevious.Hob;
  }

  return NULL;
}

VOID *
EFIAPI
BuildGuidHob (
  IN CONST EFI_GUID  *Guid,
  IN UINTN           DataLength
  )
{
  mGuidMatches   = CompareGuid (Guid, &gEfiSmmSmramMemoryGuid);
  mRequestedSize = DataLength;
  mBuildCalls++;
  return &mPersistent.Block;
}

STATIC
VOID
InitializeHobs (
  VOID
  )
{
  ZeroMem (&mPrevious, sizeof (mPrevious));
  ZeroMem (&mPersistent, sizeof (mPersistent));
  CopyGuid (&mPrevious.Hob.Name, &gEfiSmmSmramMemoryGuid);
  mPrevious.Block.NumberOfMmReservedRegions = 1;
  mPrevious.Block.Descriptor[0].CpuStart    = 0x100000;
  mPrevious.Block.Descriptor[0].PhysicalStart = 0x100000;
  mPrevious.Block.Descriptor[0].PhysicalSize  = SIZE_1MB;
  mBuildCalls    = 0;
  mGuidMatches   = FALSE;
  mRequestedSize = 0;
}

STATIC
UNIT_TEST_STATUS
CheckAllocation (
  IN EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *Block
  )
{
  UT_ASSERT_EQUAL (Block->NumberOfMmReservedRegions, 2);
  UT_ASSERT_EQUAL (Block->Descriptor[0].PhysicalSize, SIZE_1MB - EFI_PAGES_TO_SIZE (2));
  UT_ASSERT_EQUAL (Block->Descriptor[1].CpuStart, 0x1fe000);
  UT_ASSERT_EQUAL (Block->Descriptor[1].PhysicalStart, 0x1fe000);
  UT_ASSERT_EQUAL (Block->Descriptor[1].PhysicalSize, EFI_PAGES_TO_SIZE (2));
  UT_ASSERT_EQUAL (Block->Descriptor[1].RegionState, EFI_ALLOCATED);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PeiAllocationReplacesTheHob (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *Block;
  EFI_PHYSICAL_ADDRESS            Address;

  InitializeHobs ();
  Address = MmIplAllocateMmramPage (2, &Block, TRUE);

  UT_ASSERT_EQUAL (Address, 0x1fe000);
  UT_ASSERT_TRUE (Block == &mPersistent.Block);
  UT_ASSERT_EQUAL (mBuildCalls, 1);
  UT_ASSERT_TRUE (mGuidMatches);
  UT_ASSERT_EQUAL (mRequestedSize, sizeof (EFI_MMRAM_HOB_DESCRIPTOR_BLOCK) + sizeof (EFI_MMRAM_DESCRIPTOR));
  UT_ASSERT_TRUE (IsZeroBuffer (&mPrevious.Hob.Name, sizeof (mPrevious.Hob.Name)));
  UT_ASSERT_EQUAL (mPrevious.Block.Descriptor[0].PhysicalSize, SIZE_1MB);
  return CheckAllocation (Block);
}

STATIC
UNIT_TEST_STATUS
EFIAPI
DxeAllocationUsesTemporaryPool (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UNIT_TEST_STATUS                 Status;
  EFI_MMRAM_HOB_DESCRIPTOR_BLOCK  *Block;
  EFI_PHYSICAL_ADDRESS            Address;

  InitializeHobs ();
  Address = MmIplAllocateMmramPage (2, &Block, FALSE);

  UT_ASSERT_EQUAL (Address, 0x1fe000);
  UT_ASSERT_TRUE (Block != NULL);
  UT_ASSERT_TRUE (Block != &mPrevious.Block);
  UT_ASSERT_EQUAL (mBuildCalls, 0);
  UT_ASSERT_TRUE (CompareGuid (&mPrevious.Hob.Name, &gEfiSmmSmramMemoryGuid));
  UT_ASSERT_EQUAL (mPrevious.Block.Descriptor[0].PhysicalSize, SIZE_1MB);
  Status = CheckAllocation (Block);
  FreePool (Block);
  return Status;
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

  Status = InitUnitTestFramework (&Framework, "MMRAM reservation", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Standalone MM IPL", "MmIpl.Mmram", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "PEI replaces the completed reservation HOB", "Pei", PeiAllocationReplacesTheHob, NULL, NULL, NULL);
    AddTestCase (Suite, "DXE retains a temporary reservation", "Dxe", DxeAllocationUsesTemporaryPool, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
