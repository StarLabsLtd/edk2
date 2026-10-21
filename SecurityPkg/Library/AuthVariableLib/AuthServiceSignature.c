/** @file
  Validate Secure Boot signature-list payloads.

  Copyright (c) 2009 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (c) Microsoft Corporation.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "AuthServiceInternal.h"

STATIC CONST EFI_SIGNATURE_ITEM  mSupportSigItem[] = {
  // {SigType,                       SigHeaderSize,   SigDataSize  }
  { EFI_CERT_SHA256_GUID,         0, 32            },
  { EFI_CERT_RSA2048_GUID,        0, 256           },
  { EFI_CERT_RSA2048_SHA256_GUID, 0, 256           },
  { EFI_CERT_SHA1_GUID,           0, 20            },
  { EFI_CERT_RSA2048_SHA1_GUID,   0, 256           },
  { EFI_CERT_X509_GUID,           0, MAX_UINT32    },
  { EFI_CERT_SHA224_GUID,         0, 28            },
  { EFI_CERT_SHA384_GUID,         0, 48            },
  { EFI_CERT_SHA512_GUID,         0, 64            },
  { EFI_CERT_X509_SHA256_GUID,    0, 48            },
  { EFI_CERT_X509_SHA384_GUID,    0, 64            },
  { EFI_CERT_X509_SHA512_GUID,    0, 80            }
};

/**
  Check input data form to make sure it is a valid EFI_SIGNATURE_LIST for PK/KEK/db/dbx/dbt variable.

  @param[in] VariableName  Name of the variable to check.
  @param[in] VendorGuid    Variable vendor GUID.
  @param[in] Data          Variable data to check.
  @param[in] DataSize      Size of Data.

  @retval EFI_INVALID_PARAMETER  Invalid signature-list format.
  @retval EFI_SUCCESS            Signature-list format is valid.
**/
EFI_STATUS
CheckSignatureListFormat (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN VOID      *Data,
  IN UINTN     DataSize
  )
{
  EFI_SIGNATURE_LIST  SigList;
  CONST UINT8         *Walker;
  CONST UINT8         *Signature;
  UINTN               Remaining;
  UINTN               EntryBytes;
  UINTN               EntryCount;
  UINTN               CertLen;
  UINT32              Index;
  UINT32              SigCount;
  BOOLEAN             IsPk;
  VOID                *RsaContext;

  if (DataSize == 0) {
    return EFI_SUCCESS;
  }

  if ((VariableName == NULL) || (VendorGuid == NULL) || (Data == NULL) ||
      ((UINTN)Data > (MAX_UINTN - DataSize)))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_PLATFORM_KEY_NAME) == 0)) {
    IsPk = TRUE;
  } else if ((CompareGuid (VendorGuid, &gEfiGlobalVariableGuid) && (StrCmp (VariableName, EFI_KEY_EXCHANGE_KEY_NAME) == 0)) ||
             (CompareGuid (VendorGuid, &gEfiImageSecurityDatabaseGuid) &&
              ((StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE) == 0) || (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE1) == 0) ||
               (StrCmp (VariableName, EFI_IMAGE_SECURITY_DATABASE2) == 0))))
  {
    IsPk = FALSE;
  } else {
    return EFI_SUCCESS;
  }

  Walker    = Data;
  Remaining = DataSize;
  SigCount  = 0;

  while (Remaining != 0) {
    if (Remaining < sizeof (SigList)) {
      return EFI_INVALID_PARAMETER;
    }

    CopyMem (&SigList, Walker, sizeof (SigList));
    if ((SigList.SignatureListSize < sizeof (SigList)) ||
        (SigList.SignatureListSize > Remaining))
    {
      return EFI_INVALID_PARAMETER;
    }

    EntryBytes = SigList.SignatureListSize - sizeof (SigList);
    if (SigList.SignatureHeaderSize > EntryBytes) {
      return EFI_INVALID_PARAMETER;
    }

    EntryBytes -= SigList.SignatureHeaderSize;
    if ((SigList.SignatureSize < sizeof (EFI_GUID)) ||
        ((EntryBytes % SigList.SignatureSize) != 0))
    {
      return EFI_INVALID_PARAMETER;
    }

    EntryCount = EntryBytes / SigList.SignatureSize;
    if ((EntryCount > MAX_UINT32) || (EntryCount > (MAX_UINT32 - SigCount))) {
      return EFI_INVALID_PARAMETER;
    }

    for (Index = 0; Index < ARRAY_SIZE (mSupportSigItem); Index++) {
      if (CompareGuid (&SigList.SignatureType, &mSupportSigItem[Index].SigType)) {
        if ((mSupportSigItem[Index].SigDataSize != MAX_UINT32) &&
            ((SigList.SignatureSize - sizeof (EFI_GUID)) != mSupportSigItem[Index].SigDataSize))
        {
          return EFI_INVALID_PARAMETER;
        }

        if ((mSupportSigItem[Index].SigHeaderSize != MAX_UINT32) &&
            (SigList.SignatureHeaderSize != mSupportSigItem[Index].SigHeaderSize))
        {
          return EFI_INVALID_PARAMETER;
        }

        break;
      }
    }

    if (Index == ARRAY_SIZE (mSupportSigItem)) {
      return EFI_INVALID_PARAMETER;
    }

    if (CompareGuid (&SigList.SignatureType, &gEfiCertX509Guid)) {
      CertLen = SigList.SignatureSize - sizeof (EFI_GUID);
      if ((EntryCount == 0) || (CertLen == 0)) {
        return EFI_INVALID_PARAMETER;
      }

      Signature = Walker + sizeof (SigList) + SigList.SignatureHeaderSize;
      for (Index = 0; Index < EntryCount; Index++) {
        RsaContext = NULL;
        if (!RsaGetPublicKeyFromX509 (Signature + sizeof (EFI_GUID), CertLen, &RsaContext)) {
          return EFI_INVALID_PARAMETER;
        }

        RsaFree (RsaContext);
        Signature += SigList.SignatureSize;
      }
    }

    SigCount  += (UINT32)EntryCount;
    Walker    += SigList.SignatureListSize;
    Remaining -= SigList.SignatureListSize;
  }

  if (IsPk && (SigCount > 1)) {
    return EFI_INVALID_PARAMETER;
  }

  return EFI_SUCCESS;
}
