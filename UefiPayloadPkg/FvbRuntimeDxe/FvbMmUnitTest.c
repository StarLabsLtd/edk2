/** @file
  Host checks for fixed-service MM FVB initialisation and publication.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UnitTestLib.h>

#include "FvbMm.c"

typedef struct {
  EFI_HOB_GUID_TYPE       Hob;
  VARIABLE_FLASH_INFO     Info;
} TEST_FLASH_INFO_HOB;

STATIC EFI_MM_SYSTEM_TABLE  mMmst;
EFI_MM_SYSTEM_TABLE         *gMmst = &mMmst;
EFI_FW_VOL_BLOCK_DEVICE     mFvbDeviceTemplate;
STATIC TEST_FLASH_INFO_HOB  mHob;
STATIC EFI_STATUS           mBackendStatus;
STATIC EFI_STATUS           mInspectStatus;
STATIC EFI_STATUS           mNotifyStatus;
STATIC EFI_STATUS           mInitializeStatus;
STATIC EFI_STATUS           mInstallStatus;
STATIC UINTN                mNotifyCalls;
STATIC UINTN                mUnregisterCalls;
STATIC UINTN                mInitializeCalls;
STATIC UINTN                mInstallCalls;

VOID *
EFIAPI
GetFirstGuidHob (
  IN CONST EFI_GUID  *Guid
  )
{
  return CompareGuid (Guid, &gVariableFlashInfoHobGuid) ? &mHob : NULL;
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceInit (
  VOID
  )
{
  return mBackendStatus;
}

EFI_STATUS
MmFvbValidateGeometry (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT VARIABLE_FLASH_INFO       *Validated
  )
{
  CopyMem (Validated, Info, sizeof (*Validated));
  return EFI_SUCCESS;
}

EFI_STATUS
MmFvbInspectStorage (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT MM_FVB_STORE_HEADER       *Store,
  OUT BOOLEAN                   *Format
  )
{
  *Format = FALSE;
  ZeroMem (Store, sizeof (*Store));
  return mInspectStatus;
}

EFI_STATUS
MmFvbReadStoreHeader (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  IN EFI_PHYSICAL_ADDRESS       Address,
  OUT MM_FVB_STORE_HEADER       *Store
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
FvbInitialize (
  IN EFI_FIRMWARE_VOLUME_HEADER  *ValidatedHeader OPTIONAL,
  IN CONST VARIABLE_FLASH_INFO   *FormatInfo OPTIONAL
  )
{
  mInitializeCalls++;
  return mInitializeStatus;
}

STATIC
EFI_STATUS
EFIAPI
RegisterProtocolNotify (
  IN CONST EFI_GUID    *Protocol,
  IN EFI_MM_NOTIFY_FN  Function,
  OUT VOID             **Registration
  )
{
  if (Function == NULL) {
    mUnregisterCalls++;
    return EFI_SUCCESS;
  }

  mNotifyCalls++;
  *Registration = &mHob;
  return mNotifyStatus;
}

STATIC
EFI_STATUS
EFIAPI
InstallProtocol (
  IN OUT EFI_HANDLE      *Handle,
  IN EFI_GUID            *Protocol,
  IN EFI_INTERFACE_TYPE  InterfaceType,
  IN VOID                *Interface
  )
{
  mInstallCalls++;
  return mInstallStatus;
}

STATIC
VOID
ResetMocks (
  VOID
  )
{
  ZeroMem (&mMmst, sizeof (mMmst));
  ZeroMem (&mHob, sizeof (mHob));
  mHob.Hob.Header.HobType   = EFI_HOB_TYPE_GUID_EXTENSION;
  mHob.Hob.Header.HobLength = sizeof (mHob);
  CopyGuid (&mHob.Hob.Name, &gVariableFlashInfoHobGuid);
  mBackendStatus    = EFI_SUCCESS;
  mInspectStatus    = EFI_SUCCESS;
  mNotifyStatus     = EFI_SUCCESS;
  mInitializeStatus = EFI_SUCCESS;
  mInstallStatus    = EFI_SUCCESS;
  mNotifyCalls      = 0;
  mUnregisterCalls  = 0;
  mInitializeCalls  = 0;
  mInstallCalls     = 0;
  mMmst.MmRegisterProtocolNotify = RegisterProtocolNotify;
  mMmst.MmInstallProtocolInterface = InstallProtocol;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
InitializationFailures (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mBackendStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (FvbMmInitialize (NULL, NULL), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mNotifyCalls, 0);
  UT_ASSERT_EQUAL (mInitializeCalls, 0);

  ResetMocks ();
  mInspectStatus = EFI_COMPROMISED_DATA;
  UT_ASSERT_STATUS_EQUAL (FvbMmInitialize (NULL, NULL), EFI_COMPROMISED_DATA);
  UT_ASSERT_EQUAL (mNotifyCalls, 0);
  UT_ASSERT_EQUAL (mInitializeCalls, 0);

  ResetMocks ();
  mNotifyStatus = EFI_OUT_OF_RESOURCES;
  UT_ASSERT_STATUS_EQUAL (FvbMmInitialize (NULL, NULL), EFI_OUT_OF_RESOURCES);
  UT_ASSERT_EQUAL (mInitializeCalls, 0);

  ResetMocks ();
  mInitializeStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (FvbMmInitialize (NULL, NULL), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mInitializeCalls, 1);
  UT_ASSERT_EQUAL (mUnregisterCalls, 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PublishFvbLast (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_FW_VOL_INSTANCE  Instance;

  ResetMocks ();
  UT_ASSERT_NOT_EFI_ERROR (FvbMmInitialize (NULL, NULL));
  UT_ASSERT_EQUAL (mNotifyCalls, 1);
  UT_ASSERT_EQUAL (mInitializeCalls, 1);

  UT_ASSERT_NOT_EFI_ERROR (InstallFvbProtocol (&Instance, 0));
  UT_ASSERT_EQUAL (mInstallCalls, 1);
  mInstallStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (InstallFvbProtocol (&Instance, 0), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mInstallCalls, 2);
  return UNIT_TEST_PASSED;
}

INT32
main (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;
  EFI_STATUS                  Status;

  Status = InitUnitTestFramework (&Framework, "MM FVB adapter", "FvbMm", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "MM publication", "FvbMm.Init", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Failures prevent FVB readiness", "Failure", InitializationFailures, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Publish the callable FVB interface last", "Publish", PublishFvbLast, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
