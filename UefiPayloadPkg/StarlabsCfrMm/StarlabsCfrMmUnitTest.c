/** @file
  Host checks for fixed-ID CFR variable access.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include "StarlabsCfrMm.c"

STATIC BOOLEAN  mPresent;
STATIC UINT32   mStoredValue;
STATIC UINTN    mWrites;
STATIC BOOLEAN  mWriteProtected;
STATIC EFI_MM_SYSTEM_TABLE  mMmServices;
EFI_MM_SYSTEM_TABLE         *gMmst = &mMmServices;

STATIC
EFI_STATUS
EFIAPI
GetVariable (
  IN CHAR16     *Name,
  IN EFI_GUID   *Guid,
  OUT UINT32    *Attributes,
  IN OUT UINTN  *Size,
  OUT VOID      *Data
  )
{
  if ((StrCmp (Name, L"trackpad_state") != 0) || !CompareGuid (Guid, &mCfrGuid)) {
    return EFI_INVALID_PARAMETER;
  }

  if (!mPresent) {
    return EFI_NOT_FOUND;
  }

  if (*Size < sizeof (mStoredValue)) {
    *Size = sizeof (mStoredValue);
    return EFI_BUFFER_TOO_SMALL;
  }

  *Size       = sizeof (mStoredValue);
  *Attributes = CFR_ATTRIBUTES;
  CopyMem (Data, &mStoredValue, sizeof (mStoredValue));
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
SetVariable (
  IN CHAR16    *Name,
  IN EFI_GUID  *Guid,
  IN UINT32    Attributes,
  IN UINTN     Size,
  IN VOID      *Data
  )
{
  if ((StrCmp (Name, L"trackpad_state") != 0) || !CompareGuid (Guid, &mCfrGuid) ||
      (Attributes != CFR_ATTRIBUTES) || (Size != sizeof (mStoredValue)))
  {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (&mStoredValue, Data, Size);
  mPresent = TRUE;
  mWrites++;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
ManageInterrupt (
  IN CONST EFI_GUID  *HandlerType,
  IN CONST VOID      *Context,
  IN OUT VOID        *CommBuffer,
  IN OUT UINTN       *CommBufferSize
  )
{
  SMM_VARIABLE_COMMUNICATE_HEADER           *Message;
  SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE  *Variable;
  UINTN                                    NameSize;

  NameSize = StrSize (L"trackpad_state");
  if (!CompareGuid (HandlerType, &gEfiSmmVariableProtocolGuid) ||
      (*CommBufferSize != SMM_VARIABLE_COMMUNICATE_HEADER_SIZE +
       OFFSET_OF (SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE, Name) +
       NameSize + sizeof (mStoredValue)))
  {
    return EFI_INVALID_PARAMETER;
  }

  Message  = CommBuffer;
  Variable = (VOID *)Message->Data;
  if ((Message->Function != SMM_VARIABLE_FUNCTION_SET_VARIABLE) ||
      (Variable->NameSize != NameSize))
  {
    return EFI_INVALID_PARAMETER;
  }

  Message->ReturnStatus = mWriteProtected ? EFI_WRITE_PROTECTED :
                          SetVariable (
                            Variable->Name,
                            &Variable->Guid,
                            Variable->Attributes,
                            Variable->DataSize,
                            (UINT8 *)Variable->Name + Variable->NameSize
                            );
  return EFI_SUCCESS;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
PreferenceAccess (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  EFI_SMM_VARIABLE_PROTOCOL  Variable;
  STARLABS_CFR_MAILBOX       Request;

  ZeroMem (&Variable, sizeof (Variable));
  Variable.SmmGetVariable = GetVariable;
  mMmServices.MmiManage   = ManageInterrupt;
  mWriteProtected         = FALSE;
  mVariable               = &Variable;
  mSupportedOptions       = 1U << CfrTrackpad;
  mPresent                = FALSE;
  mWrites                 = 0;
  ZeroMem (&Request, sizeof (Request));
  Request.Version = STARLABS_CFR_VERSION;
  Request.Command = STARLABS_CFR_GET;
  Request.Id      = CfrTrackpad;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_NOT_FOUND);

  Request.Command = STARLABS_CFR_SET;
  Request.Value   = 0x22;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_SUCCESS);
  UT_ASSERT_EQUAL (mWrites, 1);
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_SUCCESS);
  UT_ASSERT_EQUAL (mWrites, 1);

  Request.Command = STARLABS_CFR_GET;
  Request.Value   = 0;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_SUCCESS);
  UT_ASSERT_EQUAL (Request.Value, 0x22);
  mStoredValue = 0;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_SUCCESS);
  UT_ASSERT_EQUAL (Request.Value, 0);

  Request.Command = STARLABS_CFR_SET;
  Request.Value   = 1;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_INVALID_PARAMETER);
  Request.Id = CfrFnLock;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_UNSUPPORTED);
  UT_ASSERT_EQUAL (mWrites, 1);

  Request.Id      = CfrTrackpad;
  Request.Value   = 0x22;
  mWriteProtected = TRUE;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_WRITE_PROTECTED);
  UT_ASSERT_EQUAL (mWrites, 1);
  UT_ASSERT_EQUAL (mStoredValue, 0);

  Request.Command = STARLABS_CFR_CAPS;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_SUCCESS);
  UT_ASSERT_EQUAL (Request.Value, mSupportedOptions);
  Request.Version++;
  UT_ASSERT_STATUS_EQUAL (AccessOption (&Request), EFI_INVALID_PARAMETER);
  return UNIT_TEST_PASSED;
}

INT32
main (
  IN INT32  Argc,
  IN CHAR8  *Argv[]
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;

  Status = InitUnitTestFramework (&Framework, "CFR MM", "CfrMm", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Preference access", "Cfr.Access", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Read, save and validate preferences", "Access", PreferenceAccess, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
