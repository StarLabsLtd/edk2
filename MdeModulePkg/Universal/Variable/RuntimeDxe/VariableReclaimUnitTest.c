/** @file
  Host checks for bounded recovery of interrupted variable appends.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/UnitTestLib.h>

#include "Variable.h"
#include "VariableParsing.h"
#include "VariableRuntimeCache.h"

#include "VariableParsing.c"

#define STORE_BUFFER_SIZE  1024

STATIC UINT64      mFlashBuffer[STORE_BUFFER_SIZE / sizeof (UINT64)];
STATIC UINT64      mCacheBuffer[STORE_BUFFER_SIZE / sizeof (UINT64)];
STATIC UINT64      mHobBuffer[STORE_BUFFER_SIZE / sizeof (UINT64)];
STATIC VARIABLE_MODULE_GLOBAL  mModuleGlobal;
STATIC EFI_STATUS  mFtwStatus;
STATIC UINTN       mFtwCalls;
STATIC UINTN       mSyncCalls;
STATIC BOOLEAN     mCorruptOnFtwFailure;
STATIC BOOLEAN     mInjectFindStatus;
STATIC EFI_STATUS  mFindStatus;
STATIC UINTN       mFindCalls;
STATIC UINTN       mStoreEndCalls;
STATIC EFI_STATUS  mUpdateStatus;
STATIC UINTN       mUpdateCalls;
STATIC UINTN       mAuthProcessCalls;
STATIC UINTN       mAcquireCalls;
STATIC UINTN       mReleaseCalls;
STATIC UINTN       mSecureBootHookCalls;

EFI_STATUS
__real_FindVariable (
  IN  CHAR16                  *VariableName,
  IN  EFI_GUID                *VendorGuid,
  OUT VARIABLE_POINTER_TRACK  *PtrTrack,
  IN  VARIABLE_GLOBAL         *Global,
  IN  BOOLEAN                 IgnoreRtCheck
  );

EFI_STATUS
__wrap_FindVariable (
  IN  CHAR16                  *VariableName,
  IN  EFI_GUID                *VendorGuid,
  OUT VARIABLE_POINTER_TRACK  *PtrTrack,
  IN  VARIABLE_GLOBAL         *Global,
  IN  BOOLEAN                 IgnoreRtCheck
  )
{
  mFindCalls++;
  if (mInjectFindStatus) {
    return mFindStatus;
  }

  return __real_FindVariable (VariableName, VendorGuid, PtrTrack, Global, IgnoreRtCheck);
}

EFI_STATUS
__real_GetVariableStoreEndPointer (
  IN  VARIABLE_STORE_HEADER  *VarStoreHeader,
  IN  VARIABLE_STORE_TYPE    StoreType,
  IN  UINTN                  NvEndOffset,
  OUT VARIABLE_HEADER        **EndPtr
  );

EFI_STATUS
__wrap_GetVariableStoreEndPointer (
  IN  VARIABLE_STORE_HEADER  *VarStoreHeader,
  IN  VARIABLE_STORE_TYPE    StoreType,
  IN  UINTN                  NvEndOffset,
  OUT VARIABLE_HEADER        **EndPtr
  )
{
  mStoreEndCalls++;
  if (mInjectFindStatus) {
    return mFindStatus;
  }

  return __real_GetVariableStoreEndPointer (VarStoreHeader, StoreType, NvEndOffset, EndPtr);
}

EFI_STATUS
__wrap_UpdateVariable (
  IN      CHAR16                  *VariableName,
  IN      EFI_GUID                *VendorGuid,
  IN      VOID                    *Data,
  IN      UINTN                   DataSize,
  IN      UINT32                  Attributes,
  IN      UINT32                  KeyIndex,
  IN      UINT64                  MonotonicCount,
  IN OUT  VARIABLE_POINTER_TRACK  *Variable,
  IN      EFI_TIME                *TimeStamp
  )
{
  mUpdateCalls++;
  return mUpdateStatus;
}

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

VOID
EFIAPI
SecureBootHook (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid
  )
{
  mSecureBootHookCalls++;
}

EFI_STATUS
SetVariableCheckHandlerMor (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN UINT32    Attributes,
  IN UINTN     DataSize,
  IN VOID      *Data
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VarCheckLibSetVariableCheck (
  IN CHAR16                    *VariableName,
  IN EFI_GUID                  *VendorGuid,
  IN UINT32                    Attributes,
  IN UINTN                     DataSize,
  IN VOID                      *Data,
  IN VAR_CHECK_REQUEST_SOURCE  RequestSource
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
AuthVariableLibProcessVariable (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN VOID      *Data,
  IN UINTN     DataSize,
  IN UINT32    Attributes
  )
{
  mAuthProcessCalls++;
  return EFI_SUCCESS;
}

VOID
VariableSpeculationBarrier (
  VOID
  )
{
}

UINT32
EFIAPI
InterlockedIncrement (
  IN volatile UINT32  *Value
  )
{
  return ++(*Value);
}

UINT32
EFIAPI
InterlockedDecrement (
  IN volatile UINT32  *Value
  )
{
  return --(*Value);
}

EFI_STATUS
FtwVariableSpace (
  IN EFI_PHYSICAL_ADDRESS   VariableBase,
  IN VARIABLE_STORE_HEADER  *VariableBuffer
  )
{
  mFtwCalls++;
  if (!EFI_ERROR (mFtwStatus)) {
    CopyMem ((VOID *)(UINTN)VariableBase, VariableBuffer, VariableBuffer->Size);
  } else if (mCorruptOnFtwFailure) {
    GetStartPointer ((VARIABLE_STORE_HEADER *)(UINTN)VariableBase)->State = 0;
  }

  return mFtwStatus;
}

EFI_STATUS
SynchronizeRuntimeVariableCache (
  IN VARIABLE_RUNTIME_CACHE  *VariableRuntimeCache,
  IN UINTN                   Offset,
  IN UINTN                   Length
  )
{
  mSyncCalls++;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
VarCheckLibVariablePropertyGet (
  IN  CHAR16                       *Name,
  IN  EFI_GUID                     *Guid,
  OUT VAR_CHECK_VARIABLE_PROPERTY  *VariableProperty
  )
{
  return EFI_NOT_FOUND;
}

BOOLEAN
AtRuntime (
  VOID
  )
{
  return FALSE;
}

STATIC
VARIABLE_STORE_HEADER *
InitializeStore (
  IN BOOLEAN  AuthFormat
  )
{
  VARIABLE_STORE_HEADER  *Store;

  SetMem (mFlashBuffer, sizeof (mFlashBuffer), MAX_UINT8);
  SetMem (mCacheBuffer, sizeof (mCacheBuffer), MAX_UINT8);
  Store = (VARIABLE_STORE_HEADER *)mFlashBuffer;
  CopyGuid (&Store->Signature, AuthFormat ? &gEfiAuthenticatedVariableGuid : &gEfiVariableGuid);
  Store->Size   = STORE_BUFFER_SIZE;
  Store->Format = VARIABLE_STORE_FORMATTED;
  Store->State  = VARIABLE_STORE_HEALTHY;
  return Store;
}

STATIC
VARIABLE_HEADER *
AppendRecord (
  IN VARIABLE_HEADER  *Variable,
  IN BOOLEAN          AuthFormat,
  IN UINT8            State,
  IN CONST CHAR16     *Name,
  IN UINT8            Value
  )
{
  CHAR16                         *StoredName;
  UINTN                          NameSize;
  AUTHENTICATED_VARIABLE_HEADER  *AuthVariable;

  Variable->StartId    = VARIABLE_DATA;
  Variable->State      = State;
  Variable->Reserved   = 0;
  Variable->Attributes = AuthFormat ? VARIABLE_ATTRIBUTE_NV_BS_RT_AT : VARIABLE_ATTRIBUTE_NV_BS_RT;
  NameSize             = StrSize (Name);
  SetNameSizeOfVariable (Variable, NameSize, AuthFormat);
  SetDataSizeOfVariable (Variable, sizeof (Value), AuthFormat);
  StoredName = GetVariableNamePtr (Variable, AuthFormat);
  CopyMem (StoredName, Name, NameSize);
  *GetVariableDataPtr (Variable, AuthFormat) = Value;
  if (AuthFormat) {
    AuthVariable                 = (AUTHENTICATED_VARIABLE_HEADER *)Variable;
    AuthVariable->PubKeyIndex    = 7;
    AuthVariable->MonotonicCount = 0x1122334455667788ULL;
  }

  return GetNextVariablePtr (Variable, AuthFormat);
}

STATIC
VOID
SetUpReclaim (
  IN VARIABLE_STORE_HEADER  *Store,
  IN BOOLEAN                AuthFormat
  )
{
  mVariableModuleGlobal = &mModuleGlobal;
  ZeroMem (mVariableModuleGlobal, sizeof (*mVariableModuleGlobal));
  CopyMem (mCacheBuffer, Store, Store->Size);
  mNvVariableCache = (VARIABLE_STORE_HEADER *)mCacheBuffer;
  mVariableModuleGlobal->VariableGlobal.NonVolatileVariableBase = (EFI_PHYSICAL_ADDRESS)(UINTN)Store;
  mVariableModuleGlobal->VariableGlobal.AuthFormat              = AuthFormat;
  mVariableModuleGlobal->CommonVariableSpace                    = STORE_BUFFER_SIZE;
  mVariableModuleGlobal->CommonMaxUserVariableSpace             = STORE_BUFFER_SIZE;
  mVariableModuleGlobal->CommonRuntimeVariableSpace             = STORE_BUFFER_SIZE;
  mFtwStatus = EFI_SUCCESS;
  mFtwCalls  = 0;
  mSyncCalls = 0;
  mCorruptOnFtwFailure = FALSE;
  mVariableModuleGlobal->MaxVariableSize         = STORE_BUFFER_SIZE / 2;
  mVariableModuleGlobal->MaxAuthVariableSize     = STORE_BUFFER_SIZE / 2;
  mVariableModuleGlobal->MaxVolatileVariableSize = STORE_BUFFER_SIZE / 2;
  mInjectFindStatus                              = FALSE;
  mFindCalls                                     = 0;
  mStoreEndCalls                                 = 0;
  mUpdateStatus                                  = EFI_SUCCESS;
  mUpdateCalls                                   = 0;
  mAuthProcessCalls                              = 0;
  mAcquireCalls                                  = 0;
  mReleaseCalls                                  = 0;
  mSecureBootHookCalls                           = 0;
}

STATIC
VOID
InitializeWriteInfo (
  OUT AUTH_VARIABLE_INFO  *Info,
  IN  CHAR16              *Name,
  IN  EFI_GUID            *VendorGuid,
  IN  UINT8               *Value
  )
{
  ZeroMem (Info, sizeof (*Info));
  Info->VariableName = Name;
  Info->VendorGuid   = VendorGuid;
  Info->Data         = Value;
  Info->DataSize     = sizeof (*Value);
  Info->Attributes   = VARIABLE_ATTRIBUTE_NV_BS_RT;
}

STATIC
UNIT_TEST_STATUS
AssertPublicLookupFailure (
  IN EFI_STATUS  LookupStatus,
  IN BOOLEAN     AuthSupport
  )
{
  EFI_GUID  VendorGuid;
  UINT8     Value;

  ZeroMem (&VendorGuid, sizeof (VendorGuid));
  Value = 0x5a;
  mVariableModuleGlobal->VariableGlobal.AuthSupport = AuthSupport;
  mInjectFindStatus                                 = TRUE;
  mFindStatus                                       = LookupStatus;

  UT_ASSERT_STATUS_EQUAL (
    VariableServiceSetVariable (
      L"Write",
      &VendorGuid,
      VARIABLE_ATTRIBUTE_NV_BS_RT,
      sizeof (Value),
      &Value
      ),
    LookupStatus
    );
  UT_ASSERT_EQUAL (mStoreEndCalls, 1);
  UT_ASSERT_EQUAL (mUpdateCalls, 0);
  UT_ASSERT_EQUAL (mAuthProcessCalls, 0);
  UT_ASSERT_EQUAL (mAcquireCalls, 1);
  UT_ASSERT_EQUAL (mReleaseCalls, 1);
  UT_ASSERT_EQUAL (mVariableModuleGlobal->VariableGlobal.ReentrantState, 0);
  UT_ASSERT_EQUAL (mSecureBootHookCalls, 0);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
WriteEntryPointsPreserveLookupStatus (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  STATIC CONST EFI_STATUS  ErrorStatuses[] = {
    EFI_VOLUME_CORRUPTED,
    EFI_DEVICE_ERROR,
    EFI_OUT_OF_RESOURCES
  };
  VARIABLE_STORE_HEADER    *Store;
  AUTH_VARIABLE_INFO       Info;
  EFI_GUID                 VendorGuid;
  UINT8                    Value;

  ZeroMem (&VendorGuid, sizeof (VendorGuid));
  Value = 0x5a;

  for (UINTN ErrorIndex = 0; ErrorIndex < ARRAY_SIZE (ErrorStatuses); ErrorIndex++) {
    for (UINTN AuthSupport = 0; AuthSupport <= 1; AuthSupport++) {
      Store = InitializeStore (FALSE);
      SetUpReclaim (Store, FALSE);
      mVariableModuleGlobal->NonVolatileLastVariableOffset = sizeof (*Store);
      UT_ASSERT_EQUAL (
        AssertPublicLookupFailure (ErrorStatuses[ErrorIndex], (BOOLEAN)AuthSupport),
        UNIT_TEST_PASSED
        );
    }

    Store = InitializeStore (FALSE);
    SetUpReclaim (Store, FALSE);
    mVariableModuleGlobal->NonVolatileLastVariableOffset = sizeof (*Store);
    InitializeWriteInfo (&Info, L"Write", &VendorGuid, &Value);
    mInjectFindStatus = TRUE;
    mFindStatus       = ErrorStatuses[ErrorIndex];
    UT_ASSERT_STATUS_EQUAL (VariableExLibUpdateVariable (&Info), ErrorStatuses[ErrorIndex]);
    UT_ASSERT_EQUAL (mFindCalls, 1);
    UT_ASSERT_EQUAL (mUpdateCalls, 0);
  }

  // EFI_NOT_FOUND remains the creation case for both entry points.
  Store = InitializeStore (FALSE);
  SetUpReclaim (Store, FALSE);
  mVariableModuleGlobal->NonVolatileLastVariableOffset = sizeof (*Store);
  mVariableModuleGlobal->VariableGlobal.AuthSupport    = TRUE;
  mInjectFindStatus = TRUE;
  mFindStatus       = EFI_NOT_FOUND;
  UT_ASSERT_NOT_EFI_ERROR (
    VariableServiceSetVariable (L"Write", &VendorGuid, VARIABLE_ATTRIBUTE_NV_BS_RT, sizeof (Value), &Value)
    );
  UT_ASSERT_EQUAL (mUpdateCalls, 0);
  UT_ASSERT_EQUAL (mAuthProcessCalls, 1);
  UT_ASSERT_EQUAL (mAcquireCalls, 1);
  UT_ASSERT_EQUAL (mReleaseCalls, 1);
  UT_ASSERT_EQUAL (mVariableModuleGlobal->VariableGlobal.ReentrantState, 0);
  UT_ASSERT_EQUAL (mSecureBootHookCalls, 1);

  SetUpReclaim (Store, FALSE);
  mVariableModuleGlobal->NonVolatileLastVariableOffset = sizeof (*Store);
  InitializeWriteInfo (&Info, L"Write", &VendorGuid, &Value);
  mInjectFindStatus = TRUE;
  mFindStatus       = EFI_NOT_FOUND;
  UT_ASSERT_NOT_EFI_ERROR (VariableExLibUpdateVariable (&Info));
  UT_ASSERT_EQUAL (mUpdateCalls, 1);

  // EFI_SUCCESS remains the existing-variable update case.
  Store = InitializeStore (FALSE);
  AppendRecord (GetStartPointer (Store), FALSE, VAR_ADDED, L"Write", 0x11);
  CopyGuid (GetVendorGuidPtr (GetStartPointer (Store), FALSE), &VendorGuid);
  SetUpReclaim (Store, FALSE);
  mVariableModuleGlobal->NonVolatileLastVariableOffset =
    (UINTN)GetNextVariablePtr (GetStartPointer (Store), FALSE) - (UINTN)Store;
  mVariableModuleGlobal->VariableGlobal.AuthSupport = TRUE;
  UT_ASSERT_NOT_EFI_ERROR (
    VariableServiceSetVariable (L"Write", &VendorGuid, VARIABLE_ATTRIBUTE_NV_BS_RT, sizeof (Value), &Value)
    );
  UT_ASSERT_EQUAL (mUpdateCalls, 0);
  UT_ASSERT_EQUAL (mAuthProcessCalls, 1);

  SetUpReclaim (Store, FALSE);
  mVariableModuleGlobal->NonVolatileLastVariableOffset =
    (UINTN)GetNextVariablePtr (GetStartPointer (Store), FALSE) - (UINTN)Store;
  InitializeWriteInfo (&Info, L"Write", &VendorGuid, &Value);
  UT_ASSERT_NOT_EFI_ERROR (VariableExLibUpdateVariable (&Info));
  UT_ASSERT_EQUAL (mUpdateCalls, 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
InterruptedReplacementRecovery (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER          *Store;
  VARIABLE_HEADER                *OldVariable;
  VARIABLE_HEADER                *DeletedVariable;
  VARIABLE_HEADER                *UncommittedVariable;
  AUTHENTICATED_VARIABLE_HEADER  *AuthVariable;
  VARIABLE_POINTER_TRACK         Track;
  EFI_GUID                       *VendorGuid;
  UINTN                          LastOffset;
  UINTN                          CommonSize;
  UINTN                          HwErrSize;

  for (UINTN AuthFormat = 0; AuthFormat <= 1; AuthFormat++) {
    Store               = InitializeStore ((BOOLEAN)AuthFormat);
    OldVariable         = GetStartPointer (Store);
    DeletedVariable     = AppendRecord (OldVariable, (BOOLEAN)AuthFormat, (VAR_IN_DELETED_TRANSITION & VAR_ADDED), L"Keep", 0x11);
    UncommittedVariable = AppendRecord (DeletedVariable, (BOOLEAN)AuthFormat, (VAR_DELETED & VAR_ADDED), L"Deleted", 0x22);
    AppendRecord (UncommittedVariable, (BOOLEAN)AuthFormat, VAR_ADDED, L"Keep", 0x33);
    UncommittedVariable->State = MAX_UINT8;

    UT_ASSERT_NOT_EFI_ERROR (
      ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
      );
    UT_ASSERT_EQUAL (LastOffset, (UINTN)UncommittedVariable - (UINTN)Store);

    SetUpReclaim (Store, (BOOLEAN)AuthFormat);
    mVariableModuleGlobal->CommonVariableTotalSize = CommonSize;
    mVariableModuleGlobal->HwErrVariableTotalSize  = HwErrSize;
    UT_ASSERT_NOT_EFI_ERROR (Reclaim ((EFI_PHYSICAL_ADDRESS)(UINTN)Store, &LastOffset, FALSE, NULL, NULL, 0));
    UT_ASSERT_EQUAL (mFtwCalls, 1);
    UT_ASSERT_EQUAL (mSyncCalls, 1);

    OldVariable = GetStartPointer (Store);
    UT_ASSERT_EQUAL (OldVariable->State, VAR_ADDED);
    UT_ASSERT_EQUAL (*GetVariableDataPtr (OldVariable, (BOOLEAN)AuthFormat), 0x11);
    if (AuthFormat) {
      AuthVariable = (AUTHENTICATED_VARIABLE_HEADER *)OldVariable;
      UT_ASSERT_EQUAL (AuthVariable->PubKeyIndex, 7);
      UT_ASSERT_EQUAL (AuthVariable->MonotonicCount, 0x1122334455667788ULL);
    }

    // The deleted record and uncommitted replacement are not resurrected.
    UT_ASSERT_EQUAL (LastOffset, (UINTN)GetNextVariablePtr (OldVariable, (BOOLEAN)AuthFormat) - (UINTN)Store);
    UT_ASSERT_EQUAL (
      mVariableModuleGlobal->CommonVariableTotalSize,
      (UINTN)GetNextVariablePtr (OldVariable, (BOOLEAN)AuthFormat) - (UINTN)OldVariable
      );
    UT_ASSERT_EQUAL (mVariableModuleGlobal->HwErrVariableTotalSize, 0);
    UT_ASSERT_EQUAL (((VARIABLE_HEADER *)((UINTN)Store + LastOffset))->StartId, MAX_UINT16);
    UT_ASSERT_NOT_EFI_ERROR (
      ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
      );
    mVariableModuleGlobal->NonVolatileLastVariableOffset = LastOffset;
    VendorGuid = GetVendorGuidPtr (OldVariable, (BOOLEAN)AuthFormat);
    ZeroMem (&Track, sizeof (Track));
    UT_ASSERT_NOT_EFI_ERROR (
      FindVariable (L"Keep", VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE)
      );
    UT_ASSERT_EQUAL (*GetVariableDataPtr (Track.CurrPtr, (BOOLEAN)AuthFormat), 0x11);
    ZeroMem (&Track, sizeof (Track));
    UT_ASSERT_STATUS_EQUAL (
      FindVariable (L"Deleted", VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE),
      EFI_NOT_FOUND
      );

    // The reclaimed offset accepts the writer's normal record-write followed
    // by state-byte commit, and both committed values remain visible.
    UncommittedVariable = (VARIABLE_HEADER *)((UINTN)Store + LastOffset);
    AppendRecord (UncommittedVariable, (BOOLEAN)AuthFormat, VAR_ADDED, L"After", 0x44);
    UncommittedVariable->State = MAX_UINT8;
    UncommittedVariable->State = VAR_ADDED;
    UT_ASSERT_NOT_EFI_ERROR (
      ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
      );
    CopyMem (mNvVariableCache, Store, Store->Size);
    mVariableModuleGlobal->NonVolatileLastVariableOffset = LastOffset;
    ZeroMem (&Track, sizeof (Track));
    UT_ASSERT_NOT_EFI_ERROR (
      FindVariable (
        L"After",
        GetVendorGuidPtr (UncommittedVariable, (BOOLEAN)AuthFormat),
        &Track,
        &mVariableModuleGlobal->VariableGlobal,
        FALSE
        )
      );
    UT_ASSERT_EQUAL (*GetVariableDataPtr (UncommittedVariable, (BOOLEAN)AuthFormat), 0x44);
  }

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ReclaimFailureCanBeRetried (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER  *Store;
  VARIABLE_HEADER        *Variable;
  UINTN                  LastOffset;
  UINTN                  CommonSize;
  UINTN                  HwErrSize;

  Store    = InitializeStore (FALSE);
  Variable = GetStartPointer (Store);
  Variable = AppendRecord (Variable, FALSE, VAR_ADDED, L"Keep", 0x11);
  AppendRecord (Variable, FALSE, VAR_ADDED, L"Pending", 0x22);
  Variable->State = MAX_UINT8;
  UT_ASSERT_NOT_EFI_ERROR (ValidateVariableStore (Store, Store->Size, FALSE, &LastOffset, &CommonSize, &HwErrSize));

  SetUpReclaim (Store, FALSE);
  mFtwStatus = EFI_DEVICE_ERROR;
  UT_ASSERT_STATUS_EQUAL (
    Reclaim ((EFI_PHYSICAL_ADDRESS)(UINTN)Store, &LastOffset, FALSE, NULL, NULL, 0),
    EFI_DEVICE_ERROR
    );
  UT_ASSERT_EQUAL (mFtwCalls, 1);

  mFtwStatus = EFI_SUCCESS;
  UT_ASSERT_NOT_EFI_ERROR (Reclaim ((EFI_PHYSICAL_ADDRESS)(UINTN)Store, &LastOffset, FALSE, NULL, NULL, 0));
  UT_ASSERT_EQUAL (mFtwCalls, 2);
  UT_ASSERT_NOT_EFI_ERROR (ValidateVariableStore (Store, Store->Size, FALSE, &LastOffset, &CommonSize, &HwErrSize));
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
FailedRecoveryInvalidatesReadBoundary (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER   *Store;
  VARIABLE_HEADER         *Variable;
  VARIABLE_POINTER_TRACK  Track;
  AUTH_VARIABLE_INFO      Info;
  EFI_GUID                *VendorGuid;
  UINT8                   Value;
  UINT8                   StoreAfterFailure[STORE_BUFFER_SIZE];
  UINTN                   LastOffset;
  UINTN                   CommonSize;
  UINTN                   HwErrSize;

  Value = 0x5a;
  for (UINTN AuthFormat = 0; AuthFormat <= 1; AuthFormat++) {
    Store      = InitializeStore ((BOOLEAN)AuthFormat);
    Variable   = GetStartPointer (Store);
    AppendRecord (Variable, (BOOLEAN)AuthFormat, VAR_ADDED, L"Keep", 0x11);
    VendorGuid = GetVendorGuidPtr (Variable, (BOOLEAN)AuthFormat);
    UT_ASSERT_NOT_EFI_ERROR (
      ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
      );

    SetUpReclaim (Store, (BOOLEAN)AuthFormat);
    mVariableModuleGlobal->NonVolatileLastVariableOffset = LastOffset;
    mFtwStatus                                            = EFI_DEVICE_ERROR;
    mCorruptOnFtwFailure                                  = TRUE;
    UT_ASSERT_STATUS_EQUAL (
      Reclaim (
        (EFI_PHYSICAL_ADDRESS)(UINTN)Store,
        &mVariableModuleGlobal->NonVolatileLastVariableOffset,
        FALSE,
        NULL,
        NULL,
        0
        ),
      EFI_DEVICE_ERROR
      );
    UT_ASSERT_EQUAL (mVariableModuleGlobal->NonVolatileLastVariableOffset, 0);
    CopyMem (StoreAfterFailure, Store, sizeof (StoreAfterFailure));
    ZeroMem (&Track, sizeof (Track));
    UT_ASSERT_STATUS_EQUAL (
      FindVariable (L"Keep", VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE),
      EFI_VOLUME_CORRUPTED
      );

    // Both production write entry points must preserve the invalid-boundary
    // error and avoid mutation after failed recovery.
    mFindCalls           = 0;
    mUpdateCalls         = 0;
    mAuthProcessCalls    = 0;
    mAcquireCalls        = 0;
    mReleaseCalls        = 0;
    mSecureBootHookCalls = 0;
    UT_ASSERT_STATUS_EQUAL (
      VariableServiceSetVariable (
        L"Write",
        VendorGuid,
        VARIABLE_ATTRIBUTE_NV_BS_RT,
        sizeof (Value),
        &Value
        ),
      EFI_VOLUME_CORRUPTED
      );
    UT_ASSERT_EQUAL (mUpdateCalls, 0);
    UT_ASSERT_EQUAL (mAuthProcessCalls, 0);
    UT_ASSERT_EQUAL (mAcquireCalls, 1);
    UT_ASSERT_EQUAL (mReleaseCalls, 1);
    UT_ASSERT_EQUAL (mVariableModuleGlobal->VariableGlobal.ReentrantState, 0);
    UT_ASSERT_EQUAL (mSecureBootHookCalls, 0);
    UT_ASSERT_EQUAL (CompareMem (StoreAfterFailure, Store, sizeof (StoreAfterFailure)), 0);

    InitializeWriteInfo (&Info, L"Write", VendorGuid, &Value);
    UT_ASSERT_STATUS_EQUAL (VariableExLibUpdateVariable (&Info), EFI_VOLUME_CORRUPTED);
    UT_ASSERT_EQUAL (mUpdateCalls, 0);
    UT_ASSERT_EQUAL (CompareMem (StoreAfterFailure, Store, sizeof (StoreAfterFailure)), 0);
  }

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ReadersStopAtInterruptedTail (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  STATIC CONST UINT8       InterruptedStates[] = {
    MAX_UINT8,
    VAR_HEADER_VALID_ONLY,
    (MAX_UINT8 & ~BIT6)
  };
  VARIABLE_STORE_HEADER    *Store;
  VARIABLE_STORE_HEADER    *HobStore;
  VARIABLE_STORE_HEADER    *StoreList[VariableStoreTypeMax];
  VARIABLE_HEADER          *Variable;
  VARIABLE_HEADER          *Tail;
  VARIABLE_HEADER          *Hidden;
  VARIABLE_HEADER          *Found;
  VARIABLE_POINTER_TRACK   Track;
  EFI_GUID                 VendorGuid;
  EFI_STATUS               Status;
  UINTN                    LastOffset;
  UINTN                    CommonSize;
  UINTN                    HwErrSize;
  UINT64                   MaximumStorageSize;
  UINT64                   RemainingStorageSize;
  UINT64                   MaximumVariableSize;

  ZeroMem (&VendorGuid, sizeof (VendorGuid));
  VendorGuid.Data1 = 1;

  for (UINTN AuthFormat = 0; AuthFormat <= 1; AuthFormat++) {
    for (UINTN StateIndex = 0; StateIndex < ARRAY_SIZE (InterruptedStates); StateIndex++) {
      Store    = InitializeStore ((BOOLEAN)AuthFormat);
      Variable = GetStartPointer (Store);
      Tail     = AppendRecord (Variable, (BOOLEAN)AuthFormat, VAR_ADDED, L"Keep", 0x11);
      CopyGuid (GetVendorGuidPtr (Variable, (BOOLEAN)AuthFormat), &VendorGuid);
      AppendRecord (Tail, (BOOLEAN)AuthFormat, VAR_ADDED, L"Pending", 0x22);
      Tail->State = InterruptedStates[StateIndex];

      // Put a valid-looking record exactly where an unsafe GetNextVariablePtr()
      // walk through the excluded tail would land.
      Hidden = GetNextVariablePtr (Tail, (BOOLEAN)AuthFormat);
      AppendRecord (Hidden, (BOOLEAN)AuthFormat, VAR_ADDED, L"Hidden", 0x33);
      CopyGuid (GetVendorGuidPtr (Hidden, (BOOLEAN)AuthFormat), &VendorGuid);

      UT_ASSERT_NOT_EFI_ERROR (
        ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
        );
      UT_ASSERT_EQUAL (LastOffset, (UINTN)Tail - (UINTN)Store);

      SetUpReclaim (Store, (BOOLEAN)AuthFormat);
      mVariableModuleGlobal->NonVolatileLastVariableOffset = LastOffset;

      ZeroMem (StoreList, sizeof (StoreList));
      StoreList[VariableStoreTypeNv] = mNvVariableCache;
      Found                          = NULL;
      UT_ASSERT_NOT_EFI_ERROR (
        VariableServiceGetNextVariableInternal (L"", &VendorGuid, StoreList, &Found, (BOOLEAN)AuthFormat, LastOffset)
        );
      UT_ASSERT_TRUE (Found == GetStartPointer (mNvVariableCache));

      ZeroMem (&Track, sizeof (Track));
      UT_ASSERT_NOT_EFI_ERROR (
        FindVariable (L"Keep", &VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE)
        );
      ZeroMem (&Track, sizeof (Track));
      UT_ASSERT_STATUS_EQUAL (
        FindVariable (L"Hidden", &VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE),
        EFI_NOT_FOUND
        );
      UT_ASSERT_NOT_EFI_ERROR (
        VariableServiceQueryVariableInfoInternal (
          VARIABLE_ATTRIBUTE_NV_BS_RT,
          &MaximumStorageSize,
          &RemainingStorageSize,
          &MaximumVariableSize
          )
        );
      UT_ASSERT_EQUAL (MaximumStorageSize - RemainingStorageSize, CommonSize);

      Found = NULL;
      Status                         = VariableServiceGetNextVariableInternal (
                                         L"Keep",
                                         &VendorGuid,
                                         StoreList,
                                         &Found,
                                         (BOOLEAN)AuthFormat,
                                         LastOffset
                                         );
      UT_ASSERT_STATUS_EQUAL (Status, EFI_NOT_FOUND);
      UT_ASSERT_TRUE (Found == NULL);

      if (StateIndex == 0) {
        SetMem (mHobBuffer, sizeof (mHobBuffer), MAX_UINT8);
        HobStore = (VARIABLE_STORE_HEADER *)mHobBuffer;
        CopyGuid (&HobStore->Signature, (BOOLEAN)AuthFormat ? &gEfiAuthenticatedVariableGuid : &gEfiVariableGuid);
        HobStore->Size   = STORE_BUFFER_SIZE;
        HobStore->Format = VARIABLE_STORE_FORMATTED;
        HobStore->State  = VARIABLE_STORE_HEALTHY;
        Variable         = GetStartPointer (HobStore);
        AppendRecord (Variable, (BOOLEAN)AuthFormat, VAR_ADDED, L"Keep", 0x44);
        CopyGuid (GetVendorGuidPtr (Variable, (BOOLEAN)AuthFormat), &VendorGuid);
        mVariableModuleGlobal->VariableGlobal.HobVariableBase = (EFI_PHYSICAL_ADDRESS)(UINTN)HobStore;
        StoreList[VariableStoreTypeHob]                        = HobStore;
        Found                                                  = NULL;
        Status                                                 = VariableServiceGetNextVariableInternal (
                                                                   L"Keep",
                                                                   &VendorGuid,
                                                                   StoreList,
                                                                   &Found,
                                                                   (BOOLEAN)AuthFormat,
                                                                   LastOffset
                                                                   );
        UT_ASSERT_STATUS_EQUAL (Status, EFI_NOT_FOUND);
        UT_ASSERT_TRUE (Found == NULL);
      }

      // Invalid boundary metadata must fail instead of falling back to the
      // complete declared capacity. Volatile stores remain unaffected.
      mVariableModuleGlobal->VariableGlobal.HobVariableBase = 0;
      mVariableModuleGlobal->NonVolatileLastVariableOffset = 0;
      ZeroMem (&Track, sizeof (Track));
      UT_ASSERT_STATUS_EQUAL (
        FindVariable (L"Keep", &VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE),
        EFI_VOLUME_CORRUPTED
        );
      UT_ASSERT_NOT_EFI_ERROR (
        GetVariableStoreEndPointer (mNvVariableCache, VariableStoreTypeVolatile, 0, &Found)
        );
      UT_ASSERT_TRUE (Found == GetEndPointer (mNvVariableCache));
    }
  }

  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ReadersPreserveTransitionCandidate (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER   *Store;
  VARIABLE_STORE_HEADER   *StoreList[VariableStoreTypeMax];
  VARIABLE_HEADER         *Deleted;
  VARIABLE_HEADER         *Candidate;
  VARIABLE_HEADER         *Tail;
  VARIABLE_HEADER         *Found;
  VARIABLE_POINTER_TRACK  Track;
  EFI_GUID                VendorGuid;
  UINTN                   LastOffset;
  UINTN                   CommonSize;
  UINTN                   HwErrSize;

  ZeroMem (&VendorGuid, sizeof (VendorGuid));
  VendorGuid.Data1 = 2;

  for (UINTN AuthFormat = 0; AuthFormat <= 1; AuthFormat++) {
    Store     = InitializeStore ((BOOLEAN)AuthFormat);
    Deleted   = GetStartPointer (Store);
    Candidate = AppendRecord (Deleted, (BOOLEAN)AuthFormat, (VAR_DELETED & VAR_ADDED), L"Deleted", 0x10);
    Tail = AppendRecord (
             Candidate,
             (BOOLEAN)AuthFormat,
             (VAR_IN_DELETED_TRANSITION & VAR_ADDED),
             L"Replace",
             0x20
             );
    AppendRecord (Tail, (BOOLEAN)AuthFormat, VAR_ADDED, L"Replace", 0x30);
    Tail->State = MAX_UINT8;
    CopyGuid (GetVendorGuidPtr (Deleted, (BOOLEAN)AuthFormat), &VendorGuid);
    CopyGuid (GetVendorGuidPtr (Candidate, (BOOLEAN)AuthFormat), &VendorGuid);

    UT_ASSERT_NOT_EFI_ERROR (
      ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
      );
    UT_ASSERT_EQUAL (LastOffset, (UINTN)Tail - (UINTN)Store);
    SetUpReclaim (Store, (BOOLEAN)AuthFormat);
    mVariableModuleGlobal->NonVolatileLastVariableOffset = LastOffset;

    ZeroMem (&Track, sizeof (Track));
    UT_ASSERT_NOT_EFI_ERROR (
      FindVariable (L"Replace", &VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE)
      );
    UT_ASSERT_EQUAL (Track.CurrPtr->State, (VAR_IN_DELETED_TRANSITION & VAR_ADDED));
    UT_ASSERT_EQUAL (*GetVariableDataPtr (Track.CurrPtr, (BOOLEAN)AuthFormat), 0x20);
    ZeroMem (&Track, sizeof (Track));
    UT_ASSERT_STATUS_EQUAL (
      FindVariable (L"Deleted", &VendorGuid, &Track, &mVariableModuleGlobal->VariableGlobal, FALSE),
      EFI_NOT_FOUND
      );

    ZeroMem (StoreList, sizeof (StoreList));
    StoreList[VariableStoreTypeNv] = mNvVariableCache;
    Found                          = NULL;
    UT_ASSERT_NOT_EFI_ERROR (
      VariableServiceGetNextVariableInternal (L"", &VendorGuid, StoreList, &Found, (BOOLEAN)AuthFormat, LastOffset)
      );
    UT_ASSERT_TRUE (Found == (VARIABLE_HEADER *)((UINTN)mNvVariableCache + ((UINTN)Candidate - (UINTN)Store)));
    UT_ASSERT_STATUS_EQUAL (
      VariableServiceGetNextVariableInternal (
        L"Replace",
        &VendorGuid,
        StoreList,
        &Found,
        (BOOLEAN)AuthFormat,
        LastOffset
        ),
      EFI_NOT_FOUND
      );
  }

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

  Status = InitUnitTestFramework (&Framework, "Variable interrupted-append recovery", "VariableRecovery", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Bounded reclaim", "VariableRecovery.Reclaim", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Interrupted replacement recovery",
               "Replacement",
               InterruptedReplacementRecovery,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Failed reclaim can be retried", "Retry", ReclaimFailureCanBeRetried, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Write entry points preserve lookup errors",
               "WriteErrors",
               WriteEntryPointsPreserveLookupStatus,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Failed recovery invalidates the read boundary",
               "InvalidBoundary",
               FailedRecoveryInvalidatesReadBoundary,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Readers stop at interrupted append tail",
               "Readers",
               ReadersStopAtInterruptedTail,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (
               Suite,
               "Readers preserve transition recovery candidate",
               "Transition",
               ReadersPreserveTransitionCandidate,
               NULL,
               NULL,
               NULL
               );
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
