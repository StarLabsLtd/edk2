/** @file
  Host tests for BDS boot policy call ordering.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UnitTestLib.h>

#define UNIT_TEST_APP_NAME     "BDS Boot Policy Order Unit Test"
#define UNIT_TEST_APP_VERSION  "1.0"

#define BDS_ENTRY_RELATIVE_PATH         "MdeModulePkg/Universal/BdsDxe/BdsEntry.c"
#define BDS_ENTRY_FROM_HOST_BUILD_PATH  "../../../../../" BDS_ENTRY_RELATIVE_PATH
#define MAX_SOURCE_PATH                 1024

STATIC
FILE *
OpenBdsEntrySource (
  OUT CHAR8  *Path,
  IN  UINTN  PathSize
  )
{
  CONST CHAR8  *Workspace;
  FILE         *File;

  if ((Path == NULL) || (PathSize == 0)) {
    return NULL;
  }

  Workspace = getenv ("WORKSPACE");
  if (Workspace != NULL) {
    snprintf (Path, PathSize, "%s/%s", Workspace, BDS_ENTRY_RELATIVE_PATH);
    File = fopen (Path, "rb");
    if (File != NULL) {
      return File;
    }
  }

  snprintf (Path, PathSize, "%s", BDS_ENTRY_RELATIVE_PATH);
  File = fopen (Path, "rb");
  if (File != NULL) {
    return File;
  }

  snprintf (Path, PathSize, "%s", BDS_ENTRY_FROM_HOST_BUILD_PATH);
  return fopen (Path, "rb");
}

STATIC
CHAR8 *
ReadBdsEntrySource (
  VOID
  )
{
  CHAR8   Path[MAX_SOURCE_PATH];
  FILE    *File;
  long    FileSize;
  size_t  BytesRead;
  CHAR8   *Source;

  File = OpenBdsEntrySource (Path, sizeof (Path));
  if (File == NULL) {
    UT_LOG_ERROR ("Unable to open %a", BDS_ENTRY_RELATIVE_PATH);
    return NULL;
  }

  if (fseek (File, 0, SEEK_END) != 0) {
    fclose (File);
    return NULL;
  }

  FileSize = ftell (File);
  if (FileSize < 0) {
    fclose (File);
    return NULL;
  }

  if (fseek (File, 0, SEEK_SET) != 0) {
    fclose (File);
    return NULL;
  }

  Source = AllocateZeroPool ((UINTN)FileSize + 1);
  if (Source == NULL) {
    fclose (File);
    return NULL;
  }

  BytesRead = fread (Source, 1, (size_t)FileSize, File);
  fclose (File);
  if (BytesRead != (size_t)FileSize) {
    FreePool (Source);
    return NULL;
  }

  return Source;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
BootFwUiMenuRunsAfterBootWaitPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *BootFwUiBlock;
  CHAR8  *AfterBootWait;
  CHAR8  *BootManagerMenuBoot;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  BootFwUiBlock = strstr (Source, "if (BootFwUi) {");
  UT_ASSERT_NOT_NULL (BootFwUiBlock);

  AfterBootWait       = strstr (BootFwUiBlock, "PlatformBootManagerAfterBootWait ();");
  BootManagerMenuBoot = strstr (BootFwUiBlock, "EfiBootManagerBoot (&BootManagerMenu);");

  UT_ASSERT_NOT_NULL (AfterBootWait);
  UT_ASSERT_NOT_NULL (BootManagerMenuBoot);
  UT_ASSERT_TRUE (AfterBootWait < BootManagerMenuBoot);

  FreePool (Source);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
HotkeyBootRunsAfterBootWaitPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *Wait;
  CHAR8  *AfterBootWait;
  CHAR8  *HotkeyBoot;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  Wait = strstr (Source, "BdsWait (HotkeyTriggered);");
  UT_ASSERT_NOT_NULL (Wait);

  AfterBootWait = strstr (Wait, "PlatformBootManagerAfterBootWait ();");
  HotkeyBoot    = strstr (Wait, "EfiBootManagerHotkeyBoot ();");

  UT_ASSERT_NOT_NULL (AfterBootWait);
  UT_ASSERT_NOT_NULL (HotkeyBoot);
  UT_ASSERT_TRUE (AfterBootWait < HotkeyBoot);

  FreePool (Source);
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
             "BDS boot policy order",
             "Bds.BootPolicyOrder",
             NULL,
             NULL
             );
  if (EFI_ERROR (Status)) {
    FreeUnitTestFramework (Framework);
    return Status;
  }

  AddTestCase (
    Suite,
    "Boot Manager Menu runs after boot policy",
    "BootFwUiMenuPolicy",
    BootFwUiMenuRunsAfterBootWaitPolicy,
    NULL,
    NULL,
    NULL
    );
  AddTestCase (
    Suite,
    "Hotkey boot runs after boot policy",
    "HotkeyBootPolicy",
    HotkeyBootRunsAfterBootWaitPolicy,
    NULL,
    NULL,
    NULL
    );

  Status = RunAllTestSuites (Framework);
  FreeUnitTestFramework (Framework);
  return Status;
}

#define BdsBootPolicyOrderUnitTestMain  main

INT32
BdsBootPolicyOrderUnitTestMain (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  return UnitTestingEntry ();
}
