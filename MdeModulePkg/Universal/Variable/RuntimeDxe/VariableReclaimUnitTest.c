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
STATIC VARIABLE_MODULE_GLOBAL  mModuleGlobal;
STATIC EFI_STATUS  mFtwStatus;
STATIC UINTN       mFtwCalls;
STATIC UINTN       mSyncCalls;

EFI_STATUS
FtwVariableSpace (
  IN EFI_PHYSICAL_ADDRESS   VariableBase,
  IN VARIABLE_STORE_HEADER  *VariableBuffer
  )
{
  mFtwCalls++;
  if (!EFI_ERROR (mFtwStatus)) {
    CopyMem ((VOID *)(UINTN)VariableBase, VariableBuffer, VariableBuffer->Size);
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

    // The reclaimed offset accepts the writer's normal record-write followed
    // by state-byte commit, and both committed values remain visible.
    UncommittedVariable = (VARIABLE_HEADER *)((UINTN)Store + LastOffset);
    AppendRecord (UncommittedVariable, (BOOLEAN)AuthFormat, VAR_ADDED, L"After", 0x44);
    UncommittedVariable->State = MAX_UINT8;
    UncommittedVariable->State = VAR_ADDED;
    UT_ASSERT_NOT_EFI_ERROR (
      ValidateVariableStore (Store, Store->Size, (BOOLEAN)AuthFormat, &LastOffset, &CommonSize, &HwErrSize)
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
    Status = AddTestCase (Suite, "Interrupted replacement recovery", "Replacement", InterruptedReplacementRecovery, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Failed reclaim can be retried", "Retry", ReclaimFailureCanBeRetried, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
