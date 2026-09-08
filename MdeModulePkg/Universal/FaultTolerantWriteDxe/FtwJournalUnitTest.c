/** @file
  Host checks for FTW journal traversal.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "FaultTolerantWrite.h"
#include <Library/UnitTestLib.h>

STATIC
UNIT_TEST_STATUS
EFIAPI
JournalStates (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8                                    Buffer[512];
  EFI_FAULT_TOLERANT_WORKING_BLOCK_HEADER  *Workspace;
  EFI_FAULT_TOLERANT_WRITE_HEADER          *Header;
  EFI_FAULT_TOLERANT_WRITE_HEADER          *LastHeader;
  EFI_FAULT_TOLERANT_WRITE_RECORD          *Record;
  EFI_FAULT_TOLERANT_WRITE_RECORD          *LastRecord;
  UINTN                                    Remaining;
  UINTN                                    Used;

  SetMem (Buffer, sizeof (Buffer), FTW_ERASED_BYTE);
  Workspace = (VOID *)Buffer;
  CopyGuid (&Workspace->Signature, &gEdkiiWorkingBlockSignatureGuid);
  Header    = (VOID *)(Workspace + 1);
  Record    = (VOID *)(Header + 1);
  Remaining = sizeof (Buffer) - sizeof (*Workspace);
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteHeader (Workspace, sizeof (Buffer), &LastHeader), EFI_SUCCESS);
  UT_ASSERT_TRUE (LastHeader == Header);
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteRecord (Header, Remaining, &LastRecord), EFI_SUCCESS);
  UT_ASSERT_TRUE (LastRecord == Record);

  Header->HeaderAllocated = FTW_VALID_STATE;
  Header->NumberOfWrites  = 1;
  Header->PrivateDataSize = 0;
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteHeader (Workspace, sizeof (Buffer), &LastHeader), EFI_BUFFER_TOO_SMALL);

  Header->WritesAllocated = FTW_VALID_STATE;
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteHeader (Workspace, sizeof (Buffer), &LastHeader), EFI_SUCCESS);
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteRecord (Header, Remaining, &LastRecord), EFI_SUCCESS);
  UT_ASSERT_TRUE (LastRecord == Record);

  Record->DestinationComplete = FTW_VALID_STATE;
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteRecord (Header, Remaining, &LastRecord), EFI_SUCCESS);
  UT_ASSERT_TRUE (LastRecord == Record);

  Header->Complete = FTW_VALID_STATE;
  Used             = sizeof (*Workspace) + sizeof (*Header) + sizeof (*Record);
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteHeader (Workspace, Used, &LastHeader), EFI_BUFFER_TOO_SMALL);
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteHeader (Workspace, sizeof (Buffer), &LastHeader), EFI_SUCCESS);
  UT_ASSERT_TRUE ((UINT8 *)LastHeader == Buffer + Used);

  // Legacy recovery could abort an allocation before WritesAllocated was set.
  Header->WritesAllocated = FTW_INVALID_STATE;
  UT_ASSERT_STATUS_EQUAL (FtwGetLastWriteHeader (Workspace, sizeof (Buffer), &LastHeader), EFI_SUCCESS);
  UT_ASSERT_TRUE ((UINT8 *)LastHeader == Buffer + Used);
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

  Status = InitUnitTestFramework (&Framework, "FTW journal", "FtwJournal", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Journal traversal", "Ftw.Journal", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Allocation and completion states", "States", JournalStates, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
