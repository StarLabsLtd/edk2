/** @file
  Host tests for Secure Boot signature-list validation.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/UnitTestLib.h>

#include "AuthServiceSignature.c"

#define TEST_BUFFER_SIZE  1024

STATIC UINTN  mCertificateChecks;

BOOLEAN
EFIAPI
RsaGetPublicKeyFromX509 (
  IN CONST UINT8  *Cert,
  IN UINTN        CertSize,
  OUT VOID        **RsaContext
  )
{
  STATIC UINT8  Context;

  mCertificateChecks++;
  if ((CertSize < 4) || (Cert[0] != 0x30)) {
    return FALSE;
  }

  *RsaContext = &Context;
  return TRUE;
}

VOID
EFIAPI
RsaFree (
  IN VOID  *RsaContext
  )
{
}

STATIC
UINTN
BuildSignatureList (
  OUT UINT8           *Buffer,
  IN CONST EFI_GUID   *SignatureType,
  IN UINT32           SignatureSize,
  IN UINT32           SignatureCount,
  IN BOOLEAN          ValidCertificate
  )
{
  EFI_SIGNATURE_LIST  *List;
  UINT8               *Entry;
  UINT32              Index;

  List                      = (EFI_SIGNATURE_LIST *)Buffer;
  List->SignatureType       = *SignatureType;
  List->SignatureHeaderSize = 0;
  List->SignatureSize       = SignatureSize;
  List->SignatureListSize   = sizeof (*List) + (SignatureSize * SignatureCount);

  Entry = Buffer + sizeof (*List);
  for (Index = 0; Index < SignatureCount; Index++) {
    SetMem (Entry, SignatureSize, 0);
    if (ValidCertificate && (SignatureSize > sizeof (EFI_GUID))) {
      Entry[sizeof (EFI_GUID)] = 0x30;
    }

    Entry += SignatureSize;
  }

  return List->SignatureListSize;
}

STATIC
EFI_STATUS
CheckDb (
  IN VOID   *Data,
  IN UINTN  DataSize
  )
{
  return CheckSignatureListFormat (
           EFI_IMAGE_SECURITY_DATABASE,
           &gEfiImageSecurityDatabaseGuid,
           Data,
           DataSize
           );
}

STATIC
UNIT_TEST_STATUS
EFIAPI
ValidPayloads (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8     Buffer[TEST_BUFFER_SIZE];
  UINTN     Size;
  EFI_GUID  Sha256Type;
  EFI_GUID  X509Type;

  Sha256Type = (EFI_GUID)EFI_CERT_SHA256_GUID;
  X509Type   = (EFI_GUID)EFI_CERT_X509_GUID;

  UT_ASSERT_NOT_EFI_ERROR (CheckDb (NULL, 0));

  Size = BuildSignatureList (Buffer, &Sha256Type, sizeof (EFI_GUID) + 32, 1, FALSE);
  Size += BuildSignatureList (Buffer + Size, &Sha256Type, sizeof (EFI_GUID) + 32, 1, FALSE);
  UT_ASSERT_NOT_EFI_ERROR (CheckDb (Buffer, Size));

  Size = BuildSignatureList (Buffer, &Sha256Type, sizeof (EFI_GUID) + 32, 1, FALSE);
  UT_ASSERT_NOT_EFI_ERROR (
    CheckSignatureListFormat (EFI_PLATFORM_KEY_NAME, &gEfiGlobalVariableGuid, Buffer, Size)
    );
  UT_ASSERT_NOT_EFI_ERROR (
    CheckSignatureListFormat (EFI_KEY_EXCHANGE_KEY_NAME, &gEfiGlobalVariableGuid, Buffer, Size)
    );
  UT_ASSERT_NOT_EFI_ERROR (
    CheckSignatureListFormat (EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid, Buffer, Size)
    );
  UT_ASSERT_NOT_EFI_ERROR (
    CheckSignatureListFormat (EFI_IMAGE_SECURITY_DATABASE2, &gEfiImageSecurityDatabaseGuid, Buffer, Size)
    );

  mCertificateChecks = 0;
  Size               = BuildSignatureList (Buffer, &X509Type, sizeof (EFI_GUID) + 4, 1, TRUE);
  UT_ASSERT_NOT_EFI_ERROR (CheckDb (Buffer, Size));
  UT_ASSERT_EQUAL (mCertificateChecks, 1);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RejectsTruncatedHeaders (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8     Buffer[TEST_BUFFER_SIZE];
  UINTN     Size;
  EFI_GUID  Sha256Type;

  Sha256Type = (EFI_GUID)EFI_CERT_SHA256_GUID;
  SetMem (Buffer, sizeof (Buffer), 0);
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, 1), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (EFI_SIGNATURE_LIST) - 1), EFI_INVALID_PARAMETER);

  Size = BuildSignatureList (Buffer, &Sha256Type, sizeof (EFI_GUID) + 32, 1, FALSE);
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, Size + 1), EFI_INVALID_PARAMETER);
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RejectsInvalidListLengths (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8               Buffer[TEST_BUFFER_SIZE];
  EFI_SIGNATURE_LIST  *List;
  EFI_GUID            Sha256Type;

  Sha256Type = (EFI_GUID)EFI_CERT_SHA256_GUID;
  BuildSignatureList (Buffer, &Sha256Type, sizeof (EFI_GUID) + 32, 1, FALSE);
  List = (EFI_SIGNATURE_LIST *)Buffer;

  List->SignatureListSize = 0;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (*List)), EFI_INVALID_PARAMETER);
  List->SignatureListSize = sizeof (*List) - 1;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (*List)), EFI_INVALID_PARAMETER);
  List->SignatureListSize = sizeof (Buffer) + 1;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (Buffer)), EFI_INVALID_PARAMETER);

  List->SignatureListSize   = sizeof (*List);
  List->SignatureHeaderSize = 1;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (*List)), EFI_INVALID_PARAMETER);

  List->SignatureHeaderSize = 0;
  List->SignatureSize       = 0;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (*List)), EFI_INVALID_PARAMETER);
  List->SignatureSize = sizeof (EFI_GUID) - 1;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (*List)), EFI_INVALID_PARAMETER);

  List->SignatureSize     = sizeof (EFI_GUID) + 32;
  List->SignatureListSize = sizeof (*List) + List->SignatureSize + 1;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, List->SignatureListSize), EFI_INVALID_PARAMETER);

  List->SignatureListSize   = MAX_UINT32;
  List->SignatureHeaderSize = MAX_UINT32;
  List->SignatureSize       = MAX_UINT32;
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, sizeof (Buffer)), EFI_INVALID_PARAMETER);
  UT_ASSERT_STATUS_EQUAL (
    CheckDb ((VOID *)(MAX_UINTN - 1), sizeof (EFI_SIGNATURE_LIST)),
    EFI_INVALID_PARAMETER
    );
  return UNIT_TEST_PASSED;
}

STATIC
UNIT_TEST_STATUS
EFIAPI
RejectsInvalidX509AndPk (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UINT8     Buffer[TEST_BUFFER_SIZE];
  UINTN     Size;
  EFI_GUID  X509Type;
  EFI_GUID  Sha256Type;

  X509Type   = (EFI_GUID)EFI_CERT_X509_GUID;
  Sha256Type = (EFI_GUID)EFI_CERT_SHA256_GUID;

  Size = BuildSignatureList (Buffer, &X509Type, sizeof (EFI_GUID) + 4, 0, TRUE);
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, Size), EFI_INVALID_PARAMETER);

  mCertificateChecks = 0;
  Size               = BuildSignatureList (Buffer, &X509Type, sizeof (EFI_GUID) + 1, 1, TRUE);
  UT_ASSERT_STATUS_EQUAL (CheckDb (Buffer, Size), EFI_INVALID_PARAMETER);
  UT_ASSERT_EQUAL (mCertificateChecks, 1);

  Size = BuildSignatureList (Buffer, &Sha256Type, sizeof (EFI_GUID) + 32, 2, FALSE);
  UT_ASSERT_STATUS_EQUAL (
    CheckSignatureListFormat (EFI_PLATFORM_KEY_NAME, &gEfiGlobalVariableGuid, Buffer, Size),
    EFI_INVALID_PARAMETER
    );
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

  Status = InitUnitTestFramework (&Framework, "Signature-list validation", "AuthSignatureList", "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Bounded parsing", "AuthSignatureList.Bounds", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Valid payloads", "Valid", ValidPayloads, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Truncated headers", "Truncated", RejectsTruncatedHeaders, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Invalid list lengths", "Lengths", RejectsInvalidListLengths, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = AddTestCase (Suite, "Invalid X509 and PK", "X509Pk", RejectsInvalidX509AndPk, NULL, NULL, NULL);
  }

  if (!EFI_ERROR (Status)) {
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
