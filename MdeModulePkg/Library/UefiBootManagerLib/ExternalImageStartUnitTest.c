/** @file
  Host checks for deferred-image notification failure handling.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Protocol/DeferredImageLoad.h>
#include <Library/UnitTestLib.h>

#include "BmMisc.c"

STATIC EFI_BOOT_SERVICES                  mBootServices;
EFI_BOOT_SERVICES                         *gBS = &mBootServices;
EFI_HANDLE                                gImageHandle;
STATIC EFI_DEFERRED_IMAGE_LOAD_PROTOCOL   mDeferredImage;
STATIC EFI_STATUS                         mSignalStatus;
STATIC UINTN                              mGetImageCalls;
STATIC UINTN                              mStartCalls;
STATIC UINTN                              mUnloadCalls;
STATIC UINTN                              mWatchdogArmCalls;
STATIC UINTN                              mWatchdogClearCalls;
STATIC UINTN                              mSequence;
STATIC UINTN                              mSignalSequence;
STATIC UINTN                              mStartSequence;

EFI_STATUS
EFIAPI
EfiEventGroupSignal (
  IN CONST EFI_GUID  *EventGroup
  )
{
  mSignalSequence = ++mSequence;
  return mSignalStatus;
}

STATIC
EFI_STATUS
EFIAPI
GetImageInfo (
  IN EFI_DEFERRED_IMAGE_LOAD_PROTOCOL  *This,
  IN UINTN                             ImageIndex,
  OUT EFI_DEVICE_PATH_PROTOCOL         **ImageDevicePath,
  OUT VOID                             **Image,
  OUT UINTN                            *ImageSize,
  OUT BOOLEAN                          *BootOption
  )
{
  if (mGetImageCalls++ != 0) {
    return EFI_NOT_FOUND;
  }

  *ImageDevicePath = (VOID *)&mDeferredImage;
  *Image           = &mDeferredImage;
  *ImageSize       = sizeof (mDeferredImage);
  *BootOption      = FALSE;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
LocateHandleBuffer (
  IN EFI_LOCATE_SEARCH_TYPE  SearchType,
  IN EFI_GUID                *Protocol OPTIONAL,
  IN VOID                    *SearchKey OPTIONAL,
  OUT UINTN                  *NoHandles,
  OUT EFI_HANDLE             **Buffer
  )
{
  *NoHandles = 1;
  *Buffer    = AllocatePool (sizeof (**Buffer));
  **Buffer   = &mDeferredImage;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
HandleProtocol (
  IN EFI_HANDLE  Handle,
  IN EFI_GUID    *Protocol,
  OUT VOID       **Interface
  )
{
  *Interface = &mDeferredImage;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
LoadImage (
  IN BOOLEAN                   BootPolicy,
  IN EFI_HANDLE                ParentImageHandle,
  IN EFI_DEVICE_PATH_PROTOCOL  *DevicePath OPTIONAL,
  IN VOID                      *SourceBuffer OPTIONAL,
  IN UINTN                     SourceSize,
  OUT EFI_HANDLE               *ImageHandle
  )
{
  *ImageHandle = &mBootServices;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
StartImage (
  IN EFI_HANDLE  ImageHandle,
  OUT UINTN      *ExitDataSize OPTIONAL,
  OUT CHAR16     **ExitData OPTIONAL
  )
{
  mStartCalls++;
  mStartSequence = ++mSequence;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
UnloadImage (
  IN EFI_HANDLE  ImageHandle
  )
{
  mUnloadCalls++;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
SetWatchdogTimer (
  IN UINTN   Timeout,
  IN UINT64  WatchdogCode,
  IN UINTN   DataSize,
  IN CHAR16  *WatchdogData OPTIONAL
  )
{
  if (Timeout == 0) {
    mWatchdogClearCalls++;
  } else {
    mWatchdogArmCalls++;
  }

  return EFI_SUCCESS;
}

STATIC
VOID
ResetMocks (
  VOID
  )
{
  ZeroMem (&mBootServices, sizeof (mBootServices));
  mDeferredImage.GetImageInfo = GetImageInfo;
  mBootServices.LocateHandleBuffer = LocateHandleBuffer;
  mBootServices.HandleProtocol     = HandleProtocol;
  mBootServices.LoadImage          = LoadImage;
  mBootServices.StartImage         = StartImage;
  mBootServices.UnloadImage        = UnloadImage;
  mBootServices.SetWatchdogTimer   = SetWatchdogTimer;
  mSignalStatus       = EFI_SUCCESS;
  mGetImageCalls      = 0;
  mStartCalls         = 0;
  mUnloadCalls        = 0;
  mWatchdogArmCalls   = 0;
  mWatchdogClearCalls = 0;
  mSequence           = 0;
  mSignalSequence     = 0;
  mStartSequence      = 0;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
NotificationFailure (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mSignalStatus = EFI_OUT_OF_RESOURCES;
  UT_ASSERT_STATUS_EQUAL (EfiBootManagerDispatchDeferredImages (), EFI_OUT_OF_RESOURCES);
  UT_ASSERT_EQUAL (mStartCalls, 0);
  UT_ASSERT_EQUAL (mUnloadCalls, 1);
  UT_ASSERT_EQUAL (mWatchdogArmCalls, 1);
  UT_ASSERT_EQUAL (mWatchdogClearCalls, 1);

  ResetMocks ();
  mSignalStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (EfiBootManagerDispatchDeferredImages (), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mStartCalls, 0);
  UT_ASSERT_EQUAL (mUnloadCalls, 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
NotificationBeforeStart (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  UT_ASSERT_NOT_EFI_ERROR (EfiBootManagerDispatchDeferredImages ());
  UT_ASSERT_EQUAL (mStartCalls, 1);
  UT_ASSERT_TRUE (mSignalSequence < mStartSequence);
  UT_ASSERT_EQUAL (mUnloadCalls, 0);
  UT_ASSERT_EQUAL (mWatchdogClearCalls, 1);
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

  Status = InitUnitTestFramework (&Framework, "External image start", "ExternalImage", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Deferred image launch", "ExternalImage.Deferred", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Notification failure rejects and cleans up image", "Failure", NotificationFailure, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Notification completes before image starts", "Order", NotificationBeforeStart, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
