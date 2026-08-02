/** @file
  Host tests for Capsule On Disk BootNext restore metadata.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>

#include "CapsuleOnDiskBootNext.h"

#define UNIT_TEST_APP_NAME     "Capsule On Disk BootNext Unit Test"
#define UNIT_TEST_APP_VERSION  "1.0"

STATIC
UNIT_TEST_STATUS
EFIAPI
AbsentBootNextRoundTrips (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS             Status;
  COD_BOOT_NEXT_RESTORE  Restore;
  BOOLEAN                Present;
  UINT32                 Attributes;
  UINTN                  DataSize;

  Status = CoDBuildBootNextRestore (FALSE, 0, 0, NULL, &Restore);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Present    = TRUE;
  Attributes = MAX_UINT32;
  DataSize   = COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE;
  Status     = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, NULL);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_FALSE (Present);
  UT_ASSERT_EQUAL (Attributes, 0);
  UT_ASSERT_EQUAL (DataSize, 0);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PresentBootNextRestoresExactBytes (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS             Status;
  COD_BOOT_NEXT_RESTORE  Restore;
  UINT8                  Original[] = { 0x34, 0x12, 0xA5 };
  UINT8                  Restored[sizeof (Original)];
  BOOLEAN                Present;
  UINT32                 Attributes;
  UINTN                  DataSize;

  Status = CoDBuildBootNextRestore (
             TRUE,
             EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
             sizeof (Original),
             Original,
             &Restore
             );
  UT_ASSERT_NOT_EFI_ERROR (Status);

  ZeroMem (Restored, sizeof (Restored));
  Present    = FALSE;
  Attributes = 0;
  DataSize   = sizeof (Restored);
  Status     = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, Restored);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  UT_ASSERT_TRUE (Present);
  UT_ASSERT_EQUAL (
    Attributes,
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS
    );
  UT_ASSERT_EQUAL (DataSize, sizeof (Original));
  UT_ASSERT_MEM_EQUAL (Restored, Original, sizeof (Original));

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
OversizedBootNextIsRejected (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS             Status;
  COD_BOOT_NEXT_RESTORE  Restore;
  UINT8                  Data[COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE + 1U] = { 0 };

  Status = CoDBuildBootNextRestore (
             TRUE,
             EFI_VARIABLE_NON_VOLATILE,
             sizeof (Data),
             Data,
             &Restore
             );
  UT_ASSERT_STATUS_EQUAL (Status, EFI_BAD_BUFFER_SIZE);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
MalformedRestoreMetadataIsRejected (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS             Status;
  COD_BOOT_NEXT_RESTORE  Restore;
  UINT8                  Data[] = { 0x01, 0x00 };
  BOOLEAN                Present;
  UINT32                 Attributes;
  UINTN                  DataSize;

  Status = CoDBuildBootNextRestore (TRUE, EFI_VARIABLE_NON_VOLATILE, sizeof (Data), Data, &Restore);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  Restore.Signature = 0;
  DataSize          = sizeof (Data);
  Status            = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, Data);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_COMPROMISED_DATA);

  Status = CoDBuildBootNextRestore (TRUE, EFI_VARIABLE_NON_VOLATILE, sizeof (Data), Data, &Restore);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  Restore.Present = 2;
  DataSize        = sizeof (Data);
  Status          = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, Data);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_COMPROMISED_DATA);

  Status = CoDBuildBootNextRestore (TRUE, EFI_VARIABLE_NON_VOLATILE, sizeof (Data), Data, &Restore);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  Restore.DataSize = COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE + 1U;
  DataSize         = sizeof (Data);
  Status           = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, Data);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_COMPROMISED_DATA);

  Status = CoDBuildBootNextRestore (TRUE, EFI_VARIABLE_NON_VOLATILE, sizeof (Data), Data, &Restore);
  UT_ASSERT_NOT_EFI_ERROR (Status);
  Restore.Data[Restore.DataSize] = 0x5A;
  DataSize                       = sizeof (Data);
  Status                         = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, Data);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_COMPROMISED_DATA);

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
SmallRestoreBufferReportsRequiredSize (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_STATUS             Status;
  COD_BOOT_NEXT_RESTORE  Restore;
  UINT8                  Original[] = { 0x34, 0x12, 0xA5 };
  UINT8                  Restored[sizeof (Original) - 1U];
  BOOLEAN                Present;
  UINT32                 Attributes;
  UINTN                  DataSize;

  Status = CoDBuildBootNextRestore (TRUE, EFI_VARIABLE_NON_VOLATILE, sizeof (Original), Original, &Restore);
  UT_ASSERT_NOT_EFI_ERROR (Status);

  DataSize = sizeof (Restored);
  Status   = CoDReadBootNextRestore (&Restore, &Present, &Attributes, &DataSize, Restored);
  UT_ASSERT_STATUS_EQUAL (Status, EFI_BUFFER_TOO_SMALL);
  UT_ASSERT_EQUAL (DataSize, sizeof (Original));

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
  UNIT_TEST_SUITE_HANDLE      Suite;

  Framework = NULL;
  Suite     = NULL;
  Status    = InitUnitTestFramework (
                &Framework,
                UNIT_TEST_APP_NAME,
                gEfiCallerBaseName,
                UNIT_TEST_APP_VERSION
                );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = CreateUnitTestSuite (
             &Suite,
             Framework,
             "Capsule On Disk BootNext restore",
             "CapsuleOnDisk.BootNext",
             NULL,
             NULL
             );
  if (EFI_ERROR (Status)) {
    FreeUnitTestFramework (Framework);
    return Status;
  }

  AddTestCase (Suite, "Absent BootNext round-trips", "Absent", AbsentBootNextRoundTrips, NULL, NULL, NULL);
  AddTestCase (Suite, "Present BootNext restores exact bytes", "ExactBytes", PresentBootNextRestoresExactBytes, NULL, NULL, NULL);
  AddTestCase (Suite, "Oversized BootNext is rejected", "Oversized", OversizedBootNextIsRejected, NULL, NULL, NULL);
  AddTestCase (Suite, "Malformed restore metadata is rejected", "Malformed", MalformedRestoreMetadataIsRejected, NULL, NULL, NULL);
  AddTestCase (Suite, "Small restore buffer reports required size", "SmallBuffer", SmallRestoreBufferReportsRequiredSize, NULL, NULL, NULL);

  Status = RunAllTestSuites (Framework);
  FreeUnitTestFramework (Framework);
  return Status;
}

#define CapsuleOnDiskBootNextUnitTestMain  main

INT32
CapsuleOnDiskBootNextUnitTestMain (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  return UnitTestingEntry ();
}
