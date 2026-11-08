/** @file
  Production HII language selection and variable-access tests.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/GoogleTestLib.h>
#include <string>

extern "C" {
  #include <Uefi.h>
  #include <Library/BaseLib.h>
  #include <Library/BaseMemoryLib.h>
  #include <Library/HiiLib.h>
  #include <Library/MemoryAllocationLib.h>
  #include <Protocol/HiiString.h>
}

static CONST CHAR16  mVariableName[] = { 'P', 'l', 'a', 't', 'f', 'o', 'r', 'm', 'L', 'a', 'n', 'g', 0 };
static CONST CHAR16  mValue[]        = { 'v', 'a', 'l', 'u', 'e', 0 };
static CONST CHAR8   *mLanguages;
static CONST CHAR8   *mPlatform;
static UINTN         mVariableReads;
static std::string   mSelected;
static EFI_STATUS    mLanguageStatus;
static EFI_STATUS    mStringStatus;

extern "C" EFI_STATUS EFIAPI
__wrap_GetEfiGlobalVariable2 (
  CONST CHAR16  *Name,
  VOID          **Value,
  UINTN         *Size
  )
{
  EXPECT_EQ (StrCmp (Name, mVariableName), 0);
  mVariableReads++;
  *Value = NULL;
  if (mPlatform == NULL) {
    return EFI_NOT_FOUND;
  }

  *Value = AllocateCopyPool (AsciiStrSize (mPlatform), mPlatform);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GetLanguages (
  CONST EFI_HII_STRING_PROTOCOL  *This,
  EFI_HII_HANDLE                 Handle,
  CHAR8                          *Languages,
  UINTN                          *Size
  )
{
  if (EFI_ERROR (mLanguageStatus)) {
    return mLanguageStatus;
  }

  UINTN  Required = AsciiStrSize (mLanguages);

  if (*Size < Required) {
    *Size = Required;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (Languages, mLanguages, Required);
  return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
GetString (
  CONST EFI_HII_STRING_PROTOCOL  *This,
  CONST CHAR8                    *Language,
  EFI_HII_HANDLE                 Handle,
  EFI_STRING_ID                  Id,
  EFI_STRING                     String,
  UINTN                          *Size,
  EFI_FONT_INFO                  **Font
  )
{
  mSelected = Language;
  if (EFI_ERROR (mStringStatus)) {
    return mStringStatus;
  }

  if (*Size < sizeof (mValue)) {
    *Size = sizeof (mValue);
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (String, mValue, sizeof (mValue));
  return EFI_SUCCESS;
}

static EFI_HII_STRING_PROTOCOL  mStringProtocol;
extern "C" {
  EFI_HII_STRING_PROTOCOL  *gHiiString = &mStringProtocol;
}

struct LanguageCase {
  CONST CHAR8    *Supported;
  CONST CHAR8    *Requested;
  CONST CHAR8    *Platform;
  BOOLEAN        TryBest;
  CONST CHAR8    *Expected;
  UINTN          Reads;
};

class HiiStringTest : public ::testing::Test {
protected:
  void
  SetUp (
    ) override
  {
    mLanguages     = "en-US";
    mPlatform      = "fr-FR";
    mVariableReads = 0;
    mSelected.clear ();
    mLanguageStatus = EFI_SUCCESS;
    mStringStatus   = EFI_SUCCESS;
    ZeroMem (&mStringProtocol, sizeof (mStringProtocol));
    mStringProtocol.GetLanguages = GetLanguages;
    mStringProtocol.GetString    = GetString;
  }

  EFI_STRING
  Read (
    CONST CHAR8  *Language,
    BOOLEAN      TryBest
    )
  {
    return HiiGetStringEx (reinterpret_cast<EFI_HII_HANDLE> (1), 1, Language, TryBest);
  }
};

class HiiLanguageCaseTest : public HiiStringTest,
  public ::testing::WithParamInterface<LanguageCase> { };

TEST_P (HiiLanguageCaseTest, PreservesSelectionAndAvoidsUnneededVariableReads) {
  CONST LanguageCase  &Case = GetParam ();

  mLanguages = Case.Supported;
  mPlatform  = Case.Platform;
  EFI_STRING  String = Read (Case.Requested, Case.TryBest);

  ASSERT_NE (String, nullptr);
  EXPECT_EQ (StrCmp (String, mValue), 0);
  EXPECT_EQ (mSelected, Case.Expected);
  EXPECT_EQ (mVariableReads, Case.Reads);
  FreePool (String);
}

INSTANTIATE_TEST_SUITE_P (
  Selection,
  HiiLanguageCaseTest,
  ::testing::Values (
               LanguageCase { "en-US", nullptr, "fr-FR", TRUE, "en-US", 0 },
               LanguageCase { "fr-FR", nullptr, "fr-FR", TRUE, "fr-FR", 0 },
               LanguageCase { "en-US", "de-DE", "fr-FR", TRUE, "en-US", 0 },
               LanguageCase { "en-US", "en", nullptr, TRUE, "en-US", 0 },
               LanguageCase { "en-US;fr-FR", nullptr, "fr-FR", TRUE, "fr-FR", 1 },
               LanguageCase { "en-US;fr-FR", "en-US", "fr-FR", TRUE, "en-US", 1 },
               LanguageCase { "en-US;fr-FR", "de-DE", "fr-FR", TRUE, "fr-FR", 1 },
               LanguageCase { "en-US;fr-FR", nullptr, nullptr, TRUE, "en-US", 1 },
               LanguageCase { "en-US;fr-FR", nullptr, "de-DE", TRUE, "en-US", 1 },
               LanguageCase { "en-US;fr-FR", "fr-CA", "en-US", TRUE, "fr-FR", 1 },
               LanguageCase { "en-US;fr-FR", "fr-FR", "en-US", FALSE, "fr-FR", 0 },
               LanguageCase { "en-US", "en-US", "fr-FR", FALSE, "en-US", 0 },
               LanguageCase { "en-US;", nullptr, "fr-FR", TRUE, "en-US", 1 }
               )
  );

TEST_F (HiiStringTest, MissingPackageDoesNotReadVariable) {
  mLanguageStatus = EFI_NOT_FOUND;
  EXPECT_EQ (Read (nullptr, TRUE), nullptr);
  EXPECT_EQ (mVariableReads, 0U);
}

TEST_F (HiiStringTest, EmptyLanguageListStillHasNoMatch) {
  mLanguages = "";
  EXPECT_EQ (Read (nullptr, TRUE), nullptr);
  EXPECT_TRUE (mSelected.empty ());
  EXPECT_EQ (mVariableReads, 0U);
}

TEST_F (HiiStringTest, StringLookupFailureIsPreserved) {
  mStringStatus = EFI_NOT_FOUND;
  EXPECT_EQ (Read (nullptr, TRUE), nullptr);
  EXPECT_EQ (mSelected, "en-US");
  EXPECT_EQ (mVariableReads, 0U);
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
