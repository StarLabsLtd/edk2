/** @file
  Host tests for bounded persisted-variable store validation.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/UnitTestLib.h>

#include "VariableParsing.c"

#define STORE_BUFFER_SIZE  1024

STATIC UINT64  mStoreBuffer[STORE_BUFFER_SIZE / sizeof (UINT64)];
STATIC UINT64  mAppendBuffer[STORE_BUFFER_SIZE / sizeof (UINT64)];

STATIC
VARIABLE_STORE_HEADER *
InitializeStore (
  IN UINTN  StoreSize
  )
{
  VARIABLE_STORE_HEADER  *Store;

  SetMem (mStoreBuffer, sizeof (mStoreBuffer), MAX_UINT8);
  Store       = (VARIABLE_STORE_HEADER *)mStoreBuffer;
  Store->Size = (UINT32)StoreSize;
  return Store;
}

STATIC
VARIABLE_HEADER *
AppendVariable (
  IN VARIABLE_HEADER  *Variable,
  IN BOOLEAN          AuthFormat,
  IN UINT8            State,
  IN UINT32           Attributes,
  IN CONST CHAR16     *Name,
  IN UINTN            DataSize
  )
{
  CHAR16  *StoredName;
  UINTN   NameSize;

  Variable->StartId   = VARIABLE_DATA;
  Variable->State     = State;
  Variable->Reserved  = 0;
  Variable->Attributes = Attributes;
  NameSize             = StrSize (Name);
  SetNameSizeOfVariable (Variable, NameSize, AuthFormat);
  SetDataSizeOfVariable (Variable, DataSize, AuthFormat);

  StoredName = GetVariableNamePtr (Variable, AuthFormat);
  CopyMem (StoredName, Name, NameSize);
  SetMem (GetVariableDataPtr (Variable, AuthFormat), DataSize, 0x5a);
  return GetNextVariablePtr (Variable, AuthFormat);
}

STATIC
UINTN
BuildAppendRecord (
  IN BOOLEAN       AuthFormat,
  IN UINT32        Attributes,
  IN CONST CHAR16  *Name,
  IN UINTN         DataSize
  )
{
  VARIABLE_HEADER  *Variable;
  UINTN            RecordSize;

  SetMem (mAppendBuffer, sizeof (mAppendBuffer), MAX_UINT8);
  Variable = (VARIABLE_HEADER *)mAppendBuffer;
  AppendVariable (Variable, AuthFormat, VAR_ADDED, Attributes, Name, DataSize);
  RecordSize      = (UINTN)GetNextVariablePtr (Variable, AuthFormat) - (UINTN)Variable;
  Variable->State = MAX_UINT8;
  return RecordSize;
}

STATIC
VOID
WriteAppendRecord (
  IN VARIABLE_HEADER  *Destination,
  IN UINTN            BytesToWrite
  )
{
  CopyMem (Destination, mAppendBuffer, BytesToWrite);
}

STATIC
EFI_STATUS
Validate (
  IN VARIABLE_STORE_HEADER  *Store,
  IN BOOLEAN                AuthFormat,
  OUT UINTN                 *LastOffset OPTIONAL,
  OUT UINTN                 *CommonSize OPTIONAL,
  OUT UINTN                 *HwErrSize OPTIONAL
  )
{
  UINTN  LocalLastOffset;
  UINTN  LocalCommonSize;
  UINTN  LocalHwErrSize;

  return ValidateVariableStore (
           Store,
           Store->Size,
           AuthFormat,
           (LastOffset != NULL) ? LastOffset : &LocalLastOffset,
           (CommonSize != NULL) ? CommonSize : &LocalCommonSize,
           (HwErrSize != NULL) ? HwErrSize : &LocalHwErrSize
           );
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ValidStores (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER  *Store;
  VARIABLE_HEADER        *First;
  VARIABLE_HEADER        *Next;
  VARIABLE_HEADER        *Second;
  UINTN                  LastOffset;
  UINTN                  CommonSize;
  UINTN                  HwErrSize;
  UINTN                  FirstSize;
  UINTN                  SecondSize;

  Store = InitializeStore (STORE_BUFFER_SIZE);
  UT_ASSERT_NOT_EFI_ERROR (Validate (Store, FALSE, &LastOffset, &CommonSize, &HwErrSize));
  UT_ASSERT_EQUAL (LastOffset, (UINTN)GetStartPointer (Store) - (UINTN)Store);
  UT_ASSERT_EQUAL (CommonSize, 0);
  UT_ASSERT_EQUAL (HwErrSize, 0);

  First     = GetStartPointer (Store);
  Next      = AppendVariable (First, FALSE, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT, L"First", 4);
  FirstSize = (UINTN)Next - (UINTN)First;
  UT_ASSERT_NOT_EFI_ERROR (Validate (Store, FALSE, &LastOffset, &CommonSize, &HwErrSize));
  UT_ASSERT_EQUAL (LastOffset, (UINTN)Next - (UINTN)Store);
  UT_ASSERT_EQUAL (CommonSize, FirstSize);
  UT_ASSERT_EQUAL (HwErrSize, 0);

  Second    = Next;
  Next      = AppendVariable (Second, FALSE, (VAR_DELETED & VAR_ADDED), VARIABLE_ATTRIBUTE_NV_BS_RT_HR, L"Deleted", 8);
  SecondSize = (UINTN)Next - (UINTN)Second;
  UT_ASSERT_NOT_EFI_ERROR (Validate (Store, FALSE, &LastOffset, &CommonSize, &HwErrSize));
  UT_ASSERT_EQUAL (LastOffset, (UINTN)Next - (UINTN)Store);
  UT_ASSERT_EQUAL (CommonSize, FirstSize);
  UT_ASSERT_EQUAL (HwErrSize, SecondSize);

  Store = InitializeStore (STORE_BUFFER_SIZE);
  First = GetStartPointer (Store);
  Next  = AppendVariable (First, TRUE, (VAR_IN_DELETED_TRANSITION & VAR_ADDED), VARIABLE_ATTRIBUTE_NV_BS_RT_AT, L"Auth", 16);
  UT_ASSERT_NOT_EFI_ERROR (Validate (Store, TRUE, &LastOffset, &CommonSize, &HwErrSize));
  UT_ASSERT_EQUAL (LastOffset, (UINTN)Next - (UINTN)Store);
  UT_ASSERT_EQUAL (CommonSize, (UINTN)Next - (UINTN)First);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PreservesInterruptedAppends (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER  *Store;
  VARIABLE_HEADER        *Variable;
  VARIABLE_HEADER        *Committed;
  VARIABLE_HEADER        *Tail;
  UINTN                  CommittedEnd;
  UINTN                  LastOffset;
  UINTN                  RecordSize;

  for (UINTN AuthFormat = 0; AuthFormat <= 1; AuthFormat++) {
    Store      = InitializeStore (STORE_BUFFER_SIZE);
    Tail       = GetStartPointer (Store);
    RecordSize = BuildAppendRecord ((BOOLEAN)AuthFormat, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Pending", 8);
    WriteAppendRecord (Tail, RecordSize);
    UT_ASSERT_NOT_EFI_ERROR (Validate (Store, (BOOLEAN)AuthFormat, &LastOffset, NULL, NULL));
    UT_ASSERT_EQUAL (LastOffset, (UINTN)Tail - (UINTN)Store);

    Store     = InitializeStore (STORE_BUFFER_SIZE);
    Committed = GetStartPointer (Store);
    Tail      = AppendVariable (Committed, (BOOLEAN)AuthFormat, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Committed", 4);
    CommittedEnd = (UINTN)Tail - (UINTN)Store;
    RecordSize   = BuildAppendRecord ((BOOLEAN)AuthFormat, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Pending", 8);
    WriteAppendRecord (Tail, RecordSize);
    UT_ASSERT_NOT_EFI_ERROR (Validate (Store, (BOOLEAN)AuthFormat, &LastOffset, NULL, NULL));
    UT_ASSERT_EQUAL (LastOffset, CommittedEnd);

    // The old value remains the recovery candidate if replacement stopped
    // after marking it in transition but before committing the new record.
    Committed->State = (VAR_IN_DELETED_TRANSITION & VAR_ADDED);
    UT_ASSERT_NOT_EFI_ERROR (Validate (Store, (BOOLEAN)AuthFormat, &LastOffset, NULL, NULL));
    UT_ASSERT_EQUAL (LastOffset, CommittedEnd);

    // Completing the separate state-byte write makes the append visible.
    Tail->State = VAR_ADDED;
    UT_ASSERT_NOT_EFI_ERROR (Validate (Store, (BOOLEAN)AuthFormat, &LastOffset, NULL, NULL));
    UT_ASSERT_EQUAL (LastOffset, CommittedEnd + RecordSize);
  }

  // Exercise every interruption point in the first record write for both
  // record formats. The validator must stop at the append start without
  // consuming any untrusted length field.
  for (UINTN AuthFormat = 0; AuthFormat <= 1; AuthFormat++) {
    Store      = InitializeStore (STORE_BUFFER_SIZE);
    Variable   = GetStartPointer (Store);
    RecordSize = BuildAppendRecord ((BOOLEAN)AuthFormat, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Pending", 8);
    for (UINTN Bytes = 1; Bytes < RecordSize; Bytes++) {
      SetMem (Variable, RecordSize, MAX_UINT8);
      WriteAppendRecord (Variable, Bytes);
      UT_ASSERT_NOT_EFI_ERROR (Validate (Store, (BOOLEAN)AuthFormat, &LastOffset, NULL, NULL));
      UT_ASSERT_EQUAL (LastOffset, (UINTN)Variable - (UINTN)Store);
    }
  }

  Store           = InitializeStore (STORE_BUFFER_SIZE);
  Variable        = GetStartPointer (Store);
  Variable->StartId = VARIABLE_DATA;
  Variable->State = VAR_HEADER_VALID_ONLY;
  UT_ASSERT_NOT_EFI_ERROR (Validate (Store, FALSE, &LastOffset, NULL, NULL));
  UT_ASSERT_EQUAL (LastOffset, (UINTN)Variable - (UINTN)Store);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RejectsTruncation (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER  *Store;
  VARIABLE_HEADER        *Variable;
  UINTN                  StartOffset;

  Store       = InitializeStore (STORE_BUFFER_SIZE);
  Variable    = GetStartPointer (Store);
  StartOffset = (UINTN)Variable - (UINTN)Store;
  *(UINT8 *)Variable = 0;
  Variable->State    = VAR_ADDED;
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store    = InitializeStore (STORE_BUFFER_SIZE);
  Variable = GetStartPointer (Store);
  AppendVariable (Variable, TRUE, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT_AT, L"Auth", 4);
  Store->Size = (UINT32)(StartOffset + sizeof (VARIABLE_HEADER));
  UT_ASSERT_STATUS_EQUAL (Validate (Store, TRUE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store    = InitializeStore (STORE_BUFFER_SIZE);
  Variable = GetStartPointer (Store);
  AppendVariable (Variable, FALSE, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Name", 4);
  Store->Size = (UINT32)(StartOffset + sizeof (VARIABLE_HEADER) + sizeof (CHAR16));
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store    = InitializeStore (STORE_BUFFER_SIZE);
  Variable = GetStartPointer (Store);
  AppendVariable (Variable, FALSE, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Data", 16);
  Store->Size = (UINT32)((UINTN)GetVariableDataPtr (Variable, FALSE) - (UINTN)Store + 8);
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RejectsMalformedLengths (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER  *Store;
  VARIABLE_HEADER        *Variable;
  VARIABLE_HEADER        *Next;
  UINTN                  LastOffset;
  UINTN                  CommonSize;
  UINTN                  HwErrSize;

  Store              = InitializeStore (STORE_BUFFER_SIZE);
  Variable           = GetStartPointer (Store);
  Variable->StartId  = VARIABLE_DATA;
  Variable->State    = VAR_ADDED;
  Variable->NameSize = MAX_UINT32;
  Variable->DataSize = 0;
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store              = InitializeStore (STORE_BUFFER_SIZE);
  Variable           = GetStartPointer (Store);
  Variable->StartId  = VARIABLE_DATA;
  Variable->State    = VAR_ADDED;
  Variable->NameSize = sizeof (CHAR16);
  Variable->DataSize = MAX_UINT32;
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store    = InitializeStore (STORE_BUFFER_SIZE);
  Variable = GetStartPointer (Store);
  Next     = AppendVariable (Variable, FALSE, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Good", 4);
  Next->StartId  = VARIABLE_DATA;
  Next->State    = VAR_ADDED;
  Next->NameSize = MAX_UINT32;
  Next->DataSize = MAX_UINT32;
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store    = InitializeStore (STORE_BUFFER_SIZE);
  Variable = GetStartPointer (Store);
  AppendVariable (Variable, FALSE, 0x5f, VARIABLE_ATTRIBUTE_NV_BS_RT, L"State", 4);
  UT_ASSERT_STATUS_EQUAL (Validate (Store, FALSE, NULL, NULL, NULL), EFI_VOLUME_CORRUPTED);

  Store = InitializeStore (MAX_UINT32);
  UT_ASSERT_STATUS_EQUAL (
    ValidateVariableStore (
      Store,
      sizeof (mStoreBuffer),
      FALSE,
      &LastOffset,
      &CommonSize,
      &HwErrSize
      ),
    EFI_INVALID_PARAMETER
    );
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RejectsUnterminatedNames (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  VARIABLE_STORE_HEADER  *Store;
  VARIABLE_HEADER        *Variable;
  CHAR16                 *Name;
  UINTN                  LastOffset;
  UINTN                  CommonSize;
  UINTN                  HwErrSize;

  Store    = InitializeStore (STORE_BUFFER_SIZE);
  Variable = GetStartPointer (Store);
  AppendVariable (Variable, FALSE, VAR_ADDED, VARIABLE_ATTRIBUTE_NV_BS_RT, L"Name", 4);
  Name = GetVariableNamePtr (Variable, FALSE);
  Name[(NameSizeOfVariable (Variable, FALSE) / sizeof (CHAR16)) - 1] = L'X';
  LastOffset = MAX_UINTN;
  CommonSize = MAX_UINTN;
  HwErrSize  = MAX_UINTN;
  UT_ASSERT_STATUS_EQUAL (
    Validate (Store, FALSE, &LastOffset, &CommonSize, &HwErrSize),
    EFI_VOLUME_CORRUPTED
    );
  UT_ASSERT_EQUAL (LastOffset, MAX_UINTN);
  UT_ASSERT_EQUAL (CommonSize, MAX_UINTN);
  UT_ASSERT_EQUAL (HwErrSize, MAX_UINTN);
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

  Status = InitUnitTestFramework (&Framework, "Variable-store validation", "VariableStore", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Bounded startup scan", "VariableStore.Bounds", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Valid stores", "Valid", ValidStores, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Interrupted append tails", "Interrupted", PreservesInterruptedAppends, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Truncated records", "Truncated", RejectsTruncation, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Malformed lengths", "Lengths", RejectsMalformedLengths, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Unterminated names", "Names", RejectsUnterminatedNames, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
