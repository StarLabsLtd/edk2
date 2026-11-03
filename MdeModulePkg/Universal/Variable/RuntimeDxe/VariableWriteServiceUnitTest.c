/** @file
  Host checks for mandatory variable-property registration.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/UnitTestLib.h>

#include "VariableWriteService.c"
#include "VariableWriteServiceSmm.c"

STATIC VARIABLE_MODULE_GLOBAL    mVariableGlobal;
typedef struct {
  VARIABLE_STORE_HEADER    Header;
  UINT8                    Tail[16];
} TEST_VARIABLE_STORE;

STATIC TEST_VARIABLE_STORE       mVariableStore;
STATIC VARIABLE_ENTRY_PROPERTY   mAuthEntries[5];
STATIC CHAR16                    mSecureBootEnable[] = L"SecureBootEnable";
STATIC CHAR16                    mCustomMode[]       = L"CustomMode";
STATIC CHAR16                    mVendorKeysNv[]     = L"VendorKeysNv";
STATIC CHAR16                    mCertDb[]           = L"certdb";
STATIC CHAR16                    mCertDbVolatile[]   = L"certdbv";
STATIC EFI_GUID                  mAuthGuid           = { 0x6e2f9c31, 0xc969, 0x4877, { 0xa5, 0x89, 0xb2, 0x17, 0xf5, 0x38, 0xcc, 0xb9 } };

VARIABLE_MODULE_GLOBAL     *mVariableModuleGlobal = &mVariableGlobal;
VARIABLE_STORE_HEADER      *mNvVariableCache      = &mVariableStore.Header;
AUTH_VAR_LIB_CONTEXT_IN    mAuthContextIn;
AUTH_VAR_LIB_CONTEXT_OUT   mAuthContextOut;

STATIC EFI_STATUS  mAuthStatus;
STATIC EFI_STATUS  mPropertyFailureStatus;
STATIC UINTN       mPropertyFailureIndex;
STATIC UINTN       mPropertyCalls;
STATIC UINTN       mAcquireCalls;
STATIC UINTN       mReleaseCalls;
STATIC UINTN       mFlushCalls;
STATIC UINTN       mReclaimCalls;
STATIC UINTN       mMorCalls;
STATIC UINTN       mWriteReadyCalls;
STATIC CHAR16      *mFailedPropertyName;
STATIC EFI_STATUS  mReclaimStatus;
STATIC UINTN       mReclaimInputOffset;

VOID
AcquireLockOnlyAtBootTime (
  IN EFI_LOCK  *Lock
  )
{
  mAcquireCalls++;
}

VOID
ReleaseLockOnlyAtBootTime (
  IN EFI_LOCK  *Lock
  )
{
  mReleaseCalls++;
}

EFI_STATUS
Reclaim (
  IN EFI_PHYSICAL_ADDRESS     VariableBase,
  OUT UINTN                   *LastVariableOffset,
  IN BOOLEAN                  IsVolatile,
  IN OUT VARIABLE_POINTER_TRACK  *UpdatingPtrTrack,
  IN VARIABLE_HEADER          *NewVariable,
  IN UINTN                    NewVariableSize
  )
{
  mReclaimCalls++;
  mReclaimInputOffset = *LastVariableOffset;
  return mReclaimStatus;
}

VOID
FlushHobVariableToFlash (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid
  )
{
  mFlushCalls++;
}

UINTN
GetVariableHeaderSize (
  IN BOOLEAN  AuthFormat
  )
{
  return sizeof (AUTHENTICATED_VARIABLE_HEADER);
}

EFI_STATUS
EFIAPI
AuthVariableLibInitialize (
  IN AUTH_VAR_LIB_CONTEXT_IN    *AuthVarLibContextIn,
  OUT AUTH_VAR_LIB_CONTEXT_OUT  *AuthVarLibContextOut
  )
{
  if (!EFI_ERROR (mAuthStatus)) {
    AuthVarLibContextOut->AuthVarEntry      = mAuthEntries;
    AuthVarLibContextOut->AuthVarEntryCount = ARRAY_SIZE (mAuthEntries);
  }

  return mAuthStatus;
}

EFI_STATUS
EFIAPI
VarCheckLibVariablePropertySet (
  IN CHAR16                       *Name,
  IN EFI_GUID                     *Guid,
  IN VAR_CHECK_VARIABLE_PROPERTY  *VariableProperty
  )
{
  UINTN  CallIndex;

  CallIndex = mPropertyCalls++;
  if (CallIndex == mPropertyFailureIndex) {
    mFailedPropertyName = Name;
    return mPropertyFailureStatus;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
MorLockInit (
  VOID
  )
{
  mMorCalls++;
  return EFI_SUCCESS;
}

EFI_STATUS
VariableNotifySmmWriteReady (
  VOID
  )
{
  mWriteReadyCalls++;
  return EFI_SUCCESS;
}

STATIC
VOID
ResetMocks (
  VOID
  )
{
  ZeroMem (&mVariableGlobal, sizeof (mVariableGlobal));
  SetMem (&mVariableStore, sizeof (mVariableStore), MAX_UINT8);
  ZeroMem (&mAuthContextIn, sizeof (mAuthContextIn));
  ZeroMem (&mAuthContextOut, sizeof (mAuthContextOut));
  ZeroMem (mAuthEntries, sizeof (mAuthEntries));

  mAuthEntries[0].Name = mSecureBootEnable;
  mAuthEntries[1].Name = mCustomMode;
  mAuthEntries[2].Name = mVendorKeysNv;
  mAuthEntries[3].Name = mCertDb;
  mAuthEntries[4].Name = mCertDbVolatile;
  for (UINTN Index = 0; Index < ARRAY_SIZE (mAuthEntries); Index++) {
    mAuthEntries[Index].Guid = &mAuthGuid;
  }

  mVariableGlobal.VariableGlobal.AuthFormat = TRUE;
  mVariableGlobal.MaxAuthVariableSize        = 4096;
  mVariableStore.Header.Size                    = sizeof (mVariableStore);
  mVariableGlobal.NonVolatileLastVariableOffset = sizeof (mVariableStore.Header);

  mAuthStatus            = EFI_SUCCESS;
  mPropertyFailureStatus = EFI_ACCESS_DENIED;
  mPropertyFailureIndex  = MAX_UINTN;
  mPropertyCalls         = 0;
  mAcquireCalls          = 0;
  mReleaseCalls          = 0;
  mFlushCalls            = 0;
  mReclaimCalls          = 0;
  mMorCalls              = 0;
  mWriteReadyCalls       = 0;
  mFailedPropertyName    = NULL;
  mReclaimStatus         = EFI_SUCCESS;
  mReclaimInputOffset    = MAX_UINTN;
}

STATIC
UNIT_TEST_STATUS
CheckPropertyFailure (
  IN UINTN       FailureIndex,
  IN EFI_STATUS  FailureStatus,
  IN CHAR16      *ExpectedName
  )
{
  EFI_STATUS  Status;

  ResetMocks ();
  mPropertyFailureIndex  = FailureIndex;
  mPropertyFailureStatus = FailureStatus;

  Status = VariableWriteServiceInitializeSmm ();
  UT_ASSERT_STATUS_EQUAL (Status, FailureStatus);
  UT_ASSERT_EQUAL (mPropertyCalls, FailureIndex + 1);
  UT_ASSERT_EQUAL (mAcquireCalls, 1);
  UT_ASSERT_EQUAL (mReleaseCalls, 1);
  UT_ASSERT_EQUAL (mFlushCalls, 1);
  UT_ASSERT_EQUAL (mReclaimCalls, 0);
  UT_ASSERT_EQUAL (mMorCalls, 0);
  UT_ASSERT_EQUAL (mWriteReadyCalls, 0);
  UT_ASSERT_NOT_NULL (mFailedPropertyName);
  UT_ASSERT_EQUAL (StrCmp (mFailedPropertyName, ExpectedName), 0);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PropertyFailuresStopInitialization (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UT_ASSERT_EQUAL (CheckPropertyFailure (0, EFI_OUT_OF_RESOURCES, mSecureBootEnable), UNIT_TEST_PASSED);
  UT_ASSERT_EQUAL (CheckPropertyFailure (2, EFI_ACCESS_DENIED, mVendorKeysNv), UNIT_TEST_PASSED);
  UT_ASSERT_EQUAL (CheckPropertyFailure (3, EFI_DEVICE_ERROR, mCertDb), UNIT_TEST_PASSED);
  UT_ASSERT_EQUAL (CheckPropertyFailure (4, EFI_WRITE_PROTECTED, mCertDbVolatile), UNIT_TEST_PASSED);
  UT_ASSERT_EQUAL (CheckPropertyFailure (5, EFI_ABORTED, VAR_ERROR_FLAG_NAME), UNIT_TEST_PASSED);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
SuccessPublishesWriteReadiness (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  UT_ASSERT_NOT_EFI_ERROR (VariableWriteServiceInitializeSmm ());
  UT_ASSERT_EQUAL (mPropertyCalls, 6);
  UT_ASSERT_EQUAL (mAcquireCalls, 1);
  UT_ASSERT_EQUAL (mReleaseCalls, 1);
  UT_ASSERT_EQUAL (mMorCalls, 1);
  UT_ASSERT_EQUAL (mWriteReadyCalls, 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
AuthInitializationFailureStopsReadiness (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mAuthStatus = EFI_OUT_OF_RESOURCES;
  UT_ASSERT_STATUS_EQUAL (VariableWriteServiceInitializeSmm (), EFI_OUT_OF_RESOURCES);
  UT_ASSERT_EQUAL (mPropertyCalls, 0);
  UT_ASSERT_EQUAL (mAcquireCalls, 1);
  UT_ASSERT_EQUAL (mReleaseCalls, 1);
  UT_ASSERT_EQUAL (mWriteReadyCalls, 0);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ReclaimFailureStopsReadiness (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  ResetMocks ();
  mVariableStore.Tail[0] = 0;
  mReclaimStatus         = EFI_DEVICE_ERROR;

  UT_ASSERT_STATUS_EQUAL (VariableWriteServiceInitializeSmm (), EFI_DEVICE_ERROR);
  UT_ASSERT_EQUAL (mReclaimCalls, 1);
  UT_ASSERT_EQUAL (mReclaimInputOffset, sizeof (mVariableStore.Header));
  UT_ASSERT_EQUAL (mAcquireCalls, 1);
  UT_ASSERT_EQUAL (mReleaseCalls, 1);
  UT_ASSERT_EQUAL (mFlushCalls, 0);
  UT_ASSERT_EQUAL (mWriteReadyCalls, 0);
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

  Status = InitUnitTestFramework (&Framework, "Variable write-service initialization", "VariableWriteService", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Property registration", "VariableWriteService.Properties", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Property failures stop initialization", "Failures", PropertyFailuresStopInitialization, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Success publishes write readiness", "Success", SuccessPublishesWriteReadiness, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Auth initialization failure stops readiness", "AuthFailure", AuthInitializationFailureStopsReadiness, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Reclaim failure stops readiness", "ReclaimFailure", ReclaimFailureStopsReadiness, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
