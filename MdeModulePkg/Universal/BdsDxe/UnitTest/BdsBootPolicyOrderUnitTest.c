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
BootFwUiMenuRunsAfterPreBootPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *BootFwUiBlock;
  CHAR8  *BeforeBoot;
  CHAR8  *BootManagerMenuBoot;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  BootFwUiBlock = strstr (Source, "if (BootFwUi) {");
  UT_ASSERT_NOT_NULL (BootFwUiBlock);

  BeforeBoot          = strstr (BootFwUiBlock, "BdsPlatformBeforeBoot ();");
  BootManagerMenuBoot = strstr (BootFwUiBlock, "EfiBootManagerBoot (&BootManagerMenu);");

  UT_ASSERT_NOT_NULL (BeforeBoot);
  UT_ASSERT_NOT_NULL (BootManagerMenuBoot);
  UT_ASSERT_TRUE (BeforeBoot < BootManagerMenuBoot);

  FreePool (Source);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
SysPrepRunsAfterPreBootPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *MainBootBlock;
  CHAR8  *BeforeBoot;
  CHAR8  *SysPrepLoadOptions;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  MainBootBlock = strstr (Source, "if (!PlatformRecovery) {");
  UT_ASSERT_NOT_NULL (MainBootBlock);

  BeforeBoot         = strstr (MainBootBlock, "BdsPlatformBeforeBoot ();");
  SysPrepLoadOptions = strstr (MainBootBlock, "LoadOptionTypeSysPrep");

  UT_ASSERT_NOT_NULL (BeforeBoot);
  UT_ASSERT_NOT_NULL (SysPrepLoadOptions);
  UT_ASSERT_TRUE (BeforeBoot < SysPrepLoadOptions);

  FreePool (Source);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
HotkeyBootRunsAfterPreBootPolicy (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *Wait;
  CHAR8  *AfterBootWait;
  CHAR8  *BeforeBoot;
  CHAR8  *HotkeyBoot;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  Wait = strstr (Source, "BdsWait (HotkeyTriggered);");
  UT_ASSERT_NOT_NULL (Wait);

  AfterBootWait = strstr (Wait, "PlatformBootManagerAfterBootWait ();");
  BeforeBoot    = strstr (Wait, "BdsPlatformBeforeBoot ();");
  HotkeyBoot    = strstr (Wait, "EfiBootManagerHotkeyBoot ();");

  UT_ASSERT_NOT_NULL (AfterBootWait);
  UT_ASSERT_NOT_NULL (BeforeBoot);
  UT_ASSERT_NOT_NULL (HotkeyBoot);
  UT_ASSERT_TRUE (AfterBootWait < HotkeyBoot);
  UT_ASSERT_TRUE (AfterBootWait < BeforeBoot);
  UT_ASSERT_TRUE (BeforeBoot < HotkeyBoot);

  FreePool (Source);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
AfterBootWaitRunsOnlyAfterBdsWait (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *Wait;
  CHAR8  *AfterBootWait;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  Wait = strstr (Source, "BdsWait (HotkeyTriggered);");
  UT_ASSERT_NOT_NULL (Wait);

  AfterBootWait = strstr (Source, "PlatformBootManagerAfterBootWait ();");
  UT_ASSERT_NOT_NULL (AfterBootWait);
  UT_ASSERT_TRUE (Wait < AfterBootWait);

  FreePool (Source);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
BootNextAndBootOrderRevalidateAfterReturn (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  CHAR8  *Source;
  CHAR8  *HotkeyBoot;
  CHAR8  *BeforeBoot;
  CHAR8  *BootNextBlock;
  CHAR8  *BeforeBootOrder;
  CHAR8  *BootNextRead;
  CHAR8  *BootOrderBoot;

  Source = ReadBdsEntrySource ();
  UT_ASSERT_NOT_NULL (Source);

  HotkeyBoot = strstr (Source, "EfiBootManagerHotkeyBoot ();");
  UT_ASSERT_NOT_NULL (HotkeyBoot);

  BeforeBoot    = strstr (HotkeyBoot, "BdsPlatformBeforeBoot ();");
  BootNextRead  = strstr (HotkeyBoot, "EFI_BOOT_NEXT_VARIABLE_NAME");
  BootNextBlock = strstr (HotkeyBoot, "if (BootNext != NULL) {");
  UT_ASSERT_NOT_NULL (BootNextBlock);

  BeforeBootOrder = strstr (BootNextBlock, "BdsPlatformBeforeBoot ();");
  BootOrderBoot   = strstr (BootNextBlock, "BootBootOptions");

  UT_ASSERT_NOT_NULL (BeforeBoot);
  UT_ASSERT_NOT_NULL (BeforeBootOrder);
  UT_ASSERT_NOT_NULL (BootNextRead);
  UT_ASSERT_NOT_NULL (BootOrderBoot);
  UT_ASSERT_TRUE (BeforeBoot < BootNextRead);
  UT_ASSERT_TRUE (BeforeBootOrder < BootOrderBoot);

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
    "Boot Manager Menu runs after pre-boot policy",
    "BootFwUiMenuPolicy",
    BootFwUiMenuRunsAfterPreBootPolicy,
    NULL,
    NULL,
    NULL
    );
  AddTestCase (
    Suite,
    "SysPrep runs after pre-boot policy",
    "SysPrepPolicy",
    SysPrepRunsAfterPreBootPolicy,
    NULL,
    NULL,
    NULL
    );
  AddTestCase (
    Suite,
    "Hotkey boot runs after pre-boot policy",
    "HotkeyBootPolicy",
    HotkeyBootRunsAfterPreBootPolicy,
    NULL,
    NULL,
    NULL
    );
  AddTestCase (
    Suite,
    "AfterBootWait remains after BdsWait",
    "AfterBootWaitAfterBdsWait",
    AfterBootWaitRunsOnlyAfterBdsWait,
    NULL,
    NULL,
    NULL
    );
  AddTestCase (
    Suite,
    "BootNext and BootOrder revalidate after returned policy paths",
    "BootOrderRevalidationPolicy",
    BootNextAndBootOrderRevalidateAfterReturn,
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
