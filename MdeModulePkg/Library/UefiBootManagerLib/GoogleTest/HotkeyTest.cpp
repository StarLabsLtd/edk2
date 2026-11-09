/** @file
  Production hotkey registration and namespace traversal tests.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/GoogleTestLib.h>
#include <algorithm>
#include <string>
#include <vector>
extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/DevicePathLib.h>
  #include <Library/UefiBootManagerLib.h>
  #include <Library/UefiBootServicesTableLib.h>
  #include <Library/UefiRuntimeServicesTableLib.h>
  #include <Guid/GlobalVariable.h>
}
#define U16(Text)  reinterpret_cast<CONST CHAR16 *>(u##Text)
struct Variable {
  std::u16string        Name;
  std::vector<UINT8>    Data;
};

static std::vector<Variable>        mVariables;
static std::vector<std::u16string>  mReturned;
static EFI_BOOT_SERVICES            mBootServices;
static EFI_RUNTIME_SERVICES         mRuntimeServices;
static UINTN                        mWrites;
static std::u16string               mLastWrite;
static bool                         mReachedEnd;
static EFI_BOOT_MANAGER_KEY_OPTION  mAdded;

static auto
Find (
  CONST CHAR16  *Name
  )
{
  std::u16string  Key (reinterpret_cast<const char16_t *>(Name));

  return std::find_if (
                mVariables.begin (),
                mVariables.end (),
                [&](const Variable &V) {
    return V.Name == Key;
  }
                );
}

static EFI_STATUS EFIAPI
GetVariable (
  CHAR16    *Name,
  EFI_GUID  *Guid,
  UINT32    *Attributes,
  UINTN     *Size,
  VOID      *Data
  )
{
  if (!CompareGuid (Guid, &gEfiGlobalVariableGuid)) {
    return EFI_NOT_FOUND;
  }

  auto  V = Find (Name);

  if (V == mVariables.end ()) {
    return EFI_NOT_FOUND;
  }

  UINTN  Required = V->Data.size ();

  if (*Size < Required) {
    *Size = Required;
    return EFI_BUFFER_TOO_SMALL;
  }

  if (Data == nullptr) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Data, V->Data.data (), Required);
  *Size = Required;
  if (Attributes != nullptr) {
    *Attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS;
  }

  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GetNextVariableName (
  UINTN     *Size,
  CHAR16    *Name,
  EFI_GUID  *Guid
  )
{
  auto  V = mVariables.begin ();

  if (*Name != 0) {
    V = Find (Name);
    if (V == mVariables.end ()) {
      return EFI_INVALID_PARAMETER;
    }

    ++V;
  }

  if (V == mVariables.end ()) {
    mReachedEnd = true;
    return EFI_NOT_FOUND;
  }

  UINTN  Required = (V->Name.size () + 1) * sizeof (CHAR16);

  if (*Size < Required) {
    *Size = Required;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Name, V->Name.c_str (), Required);
  *Size = Required;
  CopyGuid (Guid, &gEfiGlobalVariableGuid);
  mReturned.push_back (V->Name);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
SetVariable (
  CHAR16    *Name,
  EFI_GUID  *Guid,
  UINT32    Attributes,
  UINTN     Size,
  VOID      *Data
  )
{
  EXPECT_TRUE (CompareGuid (Guid, &gEfiGlobalVariableGuid));
  auto  V = Find (Name);

  mWrites++;
  mLastWrite = std::u16string (reinterpret_cast<const char16_t *>(Name));
  if (Size == 0) {
    if (V == mVariables.end ()) {
      return EFI_NOT_FOUND;
    }

    mVariables.erase (V);
  } else {
    if (V == mVariables.end ()) {
      mVariables.push_back (
                   { std::u16string (reinterpret_cast<const char16_t *>(Name)), { }
                   }
                   );
      V = mVariables.end () - 1;
    }

    V->Data.assign (static_cast<UINT8 *>(Data), static_cast<UINT8 *>(Data) + Size);
  }

  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
Crc32 (
  VOID    *Data,
  UINTN   Size,
  UINT32  *Crc
  )
{
  *Crc = CalculateCrc32 (Data, Size);
  return EFI_SUCCESS;
}

extern "C" UINT64 EFIAPI
GetPerformanceCounter (
  VOID
  )
{
  return 0;
}

extern "C" UINT64 EFIAPI
GetPerformanceCounterProperties (
  UINT64  *Start,
  UINT64  *End
  )
{
  if (Start) {
    *Start = 0;
  }

  if (End) {
    *End = MAX_UINT64;
  }

  return 1000000;
}

extern "C" UINT64 EFIAPI
GetTimeInNanoSecond (
  UINT64  Ticks
  )
{
  return Ticks * 1000;
}

static EFI_TPL EFIAPI
RaiseTpl (
  EFI_TPL  NewTpl
  )
{
  return TPL_APPLICATION;
}

static VOID EFIAPI
RestoreTpl (
  EFI_TPL  OldTpl
  )
{
}

static EFI_STATUS EFIAPI
LocateProtocol (
  EFI_GUID  *Guid,
  VOID      *Registration,
  VOID      **Interface
  )
{
  return EFI_NOT_FOUND;
}

class HotkeyTest : public ::testing::Test {
protected:
  void
  Metrics (
    )
  {
    mWrites = 0;
    mReturned.clear ();
    mReachedEnd = false;
  }

  void
  Tail (
    UINTN  Count
    )
  {
    for (UINTN N = 0; N < Count; N++) {
      std::string     Number = std::to_string (mVariables.size ());
      std::u16string  Name   = u"Other";
      Name.append (Number.begin (), Number.end ());
      mVariables.push_back (
                   { Name, { 1 }
                   }
                   );
    }
  }

  EFI_STATUS
  Add (
    UINT16  Scan,
    UINT32  Modifier = 0
    )
  {
    EFI_INPUT_KEY  Key = { Scan, 0 };

    return EfiBootManagerAddKeyOptionVariable (&mAdded, 0, Modifier, &Key, static_cast<EFI_INPUT_KEY *>(nullptr));
  }

  void
  SetUp (
    ) override
  {
    mVariables.clear ();
    ZeroMem (&mBootServices, sizeof (mBootServices));
    ZeroMem (&mRuntimeServices, sizeof (mRuntimeServices));
    gBS                                  = &mBootServices;
    gRT                                  = &mRuntimeServices;
    mBootServices.CalculateCrc32         = Crc32;
    mBootServices.RaiseTPL               = RaiseTpl;
    mBootServices.RestoreTPL             = RestoreTpl;
    mBootServices.LocateProtocol         = LocateProtocol;
    mRuntimeServices.GetVariable         = GetVariable;
    mRuntimeServices.GetNextVariableName = GetNextVariableName;
    mRuntimeServices.SetVariable         = SetVariable;
    EFI_DEVICE_PATH_PROTOCOL      End = { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, { END_DEVICE_PATH_LENGTH, 0 }
    };
    EFI_BOOT_MANAGER_LOAD_OPTION  Boot;
    CHAR16                        Description[] = { 'F', 'i', 'x', 't', 'u', 'r', 'e', 0 };

    ASSERT_EQ (EfiBootManagerInitializeLoadOption (&Boot, 0, LoadOptionTypeBoot, LOAD_OPTION_ACTIVE, Description, &End, nullptr, 0), EFI_SUCCESS);
    ASSERT_EQ (EfiBootManagerLoadOptionToVariable (&Boot), EFI_SUCCESS);
    EXPECT_EQ (EfiBootManagerFreeLoadOption (&Boot), EFI_SUCCESS);
    Metrics ();
  }
};
TEST_F (HotkeyTest, ExistingValidKeyStopsBeforeUnusedNamespaceTail) {
  ASSERT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  Tail (64);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F2), EFI_ALREADY_STARTED);
  EXPECT_EQ (mReturned.size (), 2U);
  EXPECT_FALSE (mReachedEnd);
  EXPECT_EQ (mWrites, 0U);
}
TEST_F (HotkeyTest, LaterMatchPreservesPrefixAndStopsAfterMatch) {
  Tail (12);
  ASSERT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  Tail (64);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F2), EFI_ALREADY_STARTED);
  EXPECT_EQ (mReturned.size (), 14U);
  EXPECT_FALSE (mReachedEnd);
  EXPECT_EQ (mWrites, 0U);
}
TEST_F (HotkeyTest, AbsentKeyScansEverythingBeforeCreating) {
  Tail (12);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mWrites, 1U);
  EXPECT_EQ (mLastWrite, u"Key0000");
}
TEST_F (HotkeyTest, DifferentModifiersAreNotAMatch) {
  ASSERT_EQ (Add (SCAN_F2, EFI_BOOT_MANAGER_SHIFT_PRESSED), EFI_SUCCESS);
  Tail (16);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mLastWrite, u"Key0001");
}
TEST_F (HotkeyTest, InvalidCrcDoesNotShortCircuitValidation) {
  ASSERT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  Find (U16 ("Key0000"))->Data[OFFSET_OF (EFI_BOOT_MANAGER_KEY_OPTION, BootOptionCrc)] ^= 1;
  Tail (16);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mWrites, 1U);
}
TEST_F (HotkeyTest, InvalidLengthDoesNotShortCircuitValidation) {
  ASSERT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  Find (U16 ("Key0000"))->Data.push_back (0);
  Tail (16);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mWrites, 1U);
}
TEST_F (HotkeyTest, NoMatchRetainsTheLowestFreeOptionNumber) {
  ASSERT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  ASSERT_EQ (Add (SCAN_DOWN), EFI_SUCCESS);
  mVariables.erase (Find (U16 ("Key0000")));
  Tail (16);
  Metrics ();
  EXPECT_EQ (Add (SCAN_F3), EFI_SUCCESS);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mLastWrite, u"Key0000");
}
TEST_F (HotkeyTest, DeletionStillEnumeratesTheCompleteNamespace) {
  ASSERT_EQ (Add (SCAN_F2), EFI_SUCCESS);
  ASSERT_EQ (Add (SCAN_DOWN), EFI_SUCCESS);
  Tail (16);
  Metrics ();
  EFI_INPUT_KEY  Key = { SCAN_F2, 0 };

  EXPECT_EQ (EfiBootManagerDeleteKeyOptionVariable (nullptr, 0, &Key, static_cast<EFI_INPUT_KEY *>(nullptr)), EFI_SUCCESS);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mWrites, 1U);
  EXPECT_NE (Find (U16 ("Key0001")), mVariables.end ());
}
TEST_F (HotkeyTest, RecoveryCollectionStillVisitsTheEntireNamespace) {
  EFI_DEVICE_PATH_PROTOCOL  End = { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, { END_DEVICE_PATH_LENGTH, 0 }
  };
  CHAR16                    Description[] = { 'R', 'e', 'c', 'o', 'v', 'e', 'r', 'y', 0 };

  for (UINTN Number : { 3U, 1U }) {
    EFI_BOOT_MANAGER_LOAD_OPTION  Option;
    ASSERT_EQ (EfiBootManagerInitializeLoadOption (&Option, Number, LoadOptionTypePlatformRecovery, LOAD_OPTION_ACTIVE, Description, &End, nullptr, 0), EFI_SUCCESS);
    ASSERT_EQ (EfiBootManagerLoadOptionToVariable (&Option), EFI_SUCCESS);
    EXPECT_EQ (EfiBootManagerFreeLoadOption (&Option), EFI_SUCCESS);
  }

  Tail (16);
  Metrics ();
  UINTN                         Count;
  EFI_BOOT_MANAGER_LOAD_OPTION  *Options = EfiBootManagerGetLoadOptions (&Count, LoadOptionTypePlatformRecovery);

  ASSERT_NE (Options, nullptr);
  ASSERT_EQ (Count, 2U);
  EXPECT_EQ (Options[0].OptionNumber, 1U);
  EXPECT_EQ (Options[1].OptionNumber, 3U);
  EXPECT_TRUE (mReachedEnd);
  EXPECT_EQ (mReturned.size (), mVariables.size ());
  EXPECT_EQ (mWrites, 0U);
  EfiBootManagerFreeLoadOptions (Options, Count);
}

int
main (
  int   argc,
  char  *argv[]
  )
{
  ::testing::InitGoogleTest (&argc, argv);
  return RUN_ALL_TESTS ();
}
