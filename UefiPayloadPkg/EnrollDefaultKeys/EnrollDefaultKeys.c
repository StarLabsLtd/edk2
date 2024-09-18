/** @file
  Enroll default PK, KEK, db, dbx.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Guid/AuthenticatedVariableFormat.h>    // gEfiCustomModeEnableGuid
#include <Guid/GlobalVariable.h>                 // EFI_SETUP_MODE_NAME
#include <Guid/ImageAuthentication.h>            // EFI_IMAGE_SECURITY_DATABASE
#include <Guid/MicrosoftVendor.h>                // gMicrosoftVendorGuid
#include <Guid/OvmfPkKek1AppPrefix.h>            // gUefiPayloadPkKek1AppPrefixGuid
#include <IndustryStandard/SmBios.h>             // SMBIOS_HANDLE_PI_RESERVED
#include <Library/BaseLib.h>                     // GUID_STRING_LENGTH
#include <Library/BaseMemoryLib.h>               // CopyGuid()
#include <Library/DebugLib.h>                    // ASSERT(), DEBUG()
#include <Library/MemoryAllocationLib.h>         // FreePool(), AllocatePool()
#include <Library/PrintLib.h>                    // AsciiSPrint()
#include <Library/UefiBootServicesTableLib.h>    // gBS
#include <Library/UefiRuntimeServicesTableLib.h> // gRT
#include <Protocol/Smbios.h>                     // EFI_SMBIOS_PROTOCOL

#include "EnrollDefaultKeys.h"

/**
  Fetch the X509 certificate (to be used as Platform Key and first Key Exchange
  Key) from SMBIOS.

  @param[out] PkKek1        The X509 certificate in DER encoding from the
                            hypervisor, to be enrolled as PK and first KEK
                            entry. On success, the caller is responsible for
                            releasing PkKek1 with FreePool().

  @param[out] SizeOfPkKek1  The size of PkKek1 in bytes.

  @retval EFI_SUCCESS           PkKek1 and SizeOfPkKek1 have been set
                                successfully.

  @retval EFI_NOT_FOUND         An OEM String matching
                                OVMF_PK_KEK1_APP_PREFIX_GUID has not been
                                found.

  @retval EFI_PROTOCOL_ERROR    In the OEM String matching
                                OVMF_PK_KEK1_APP_PREFIX_GUID, the certificate
                                is empty, or it has invalid base64 encoding.

  @retval EFI_OUT_OF_RESOURCES  Memory allocation failed.

  @return                       Error codes from gBS->LocateProtocol().
**/
STATIC
EFI_STATUS
GetPkKek1 (
  OUT UINT8  **PkKek1,
  OUT UINTN  *SizeOfPkKek1
  )
{
  CONST CHAR8              *Base64Cert;
  CHAR8                    OvmfPkKek1AppPrefix[GUID_STRING_LENGTH + 1 + 1];
  EFI_STATUS               Status;
  EFI_SMBIOS_PROTOCOL      *Smbios;
  EFI_SMBIOS_HANDLE        Handle;
  EFI_SMBIOS_TYPE          Type;
  EFI_SMBIOS_TABLE_HEADER  *Header;
  SMBIOS_TABLE_TYPE11      *OemStringsTable;
  UINTN                    Base64CertLen;
  UINTN                    DecodedCertSize;
  UINT8                    *DecodedCert;

  Base64Cert = NULL;

  //
  // Format the application prefix, for OEM String matching.
  //
  AsciiSPrint (
    OvmfPkKek1AppPrefix,
    sizeof OvmfPkKek1AppPrefix,
    "%g:",
    &gUefiPayloadPkKek1AppPrefixGuid
    );

  //
  // Scan all "OEM Strings" tables.
  //
  Status = gBS->LocateProtocol (
                  &gEfiSmbiosProtocolGuid,
                  NULL,
                  (VOID **)&Smbios
                  );
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "GetPkKek1: Failed to locate EFI_SMBIOS_PROTOCOL: %r\n", Status));
    return Status;
  }

  Handle = SMBIOS_HANDLE_PI_RESERVED;
  Type   = SMBIOS_TYPE_OEM_STRINGS;
  for (Status = Smbios->GetNext (Smbios, &Handle, &Type, &Header, NULL);
       !EFI_ERROR (Status);
       Status = Smbios->GetNext (Smbios, &Handle, &Type, &Header, NULL))
  {
    CONST CHAR8  *OemString;
    UINTN        Idx;

    if (Header->Length < sizeof *OemStringsTable) {
      //
      // Malformed table header, skip to next.
      //
      continue;
    }

    OemStringsTable = (SMBIOS_TABLE_TYPE11 *)Header;

    //
    // Scan all strings in the unformatted area of the current "OEM Strings"
    // table.
    //
    OemString = (CONST CHAR8 *)(OemStringsTable + 1);
    for (Idx = 0; Idx < OemStringsTable->StringCount; ++Idx) {
      CHAR8  CandidatePrefix[sizeof OvmfPkKek1AppPrefix];

      //
      // NUL-terminate the candidate prefix for case-insensitive comparison.
      //
      AsciiStrnCpyS (
        CandidatePrefix,
        sizeof CandidatePrefix,
        OemString,
        GUID_STRING_LENGTH + 1
        );
      if (AsciiStriCmp (OvmfPkKek1AppPrefix, CandidatePrefix) == 0) {
        //
        // The current string matches the prefix.
        //
        Base64Cert = OemString + GUID_STRING_LENGTH + 1;
        break;
      }

      OemString += AsciiStrSize (OemString);
    }

    if (Idx < OemStringsTable->StringCount) {
      //
      // The current table has a matching string.
      //
      break;
    }
  }

  if (EFI_ERROR (Status)) {
    //
    // No table with a matching string has been found.
    //
    DEBUG((DEBUG_ERROR,
      "GetPkKek1: OEM String with app prefix %g not found: %r\n",
      &gUefiPayloadPkKek1AppPrefixGuid,
      Status
      ));
    return EFI_NOT_FOUND;
  }

  ASSERT (Base64Cert != NULL);
  Base64CertLen = AsciiStrLen (Base64Cert);

  //
  // Verify the base64 encoding, and determine the decoded size.
  //
  DecodedCertSize = 0;
  Status          = Base64Decode (Base64Cert, Base64CertLen, NULL, &DecodedCertSize);
  switch (Status) {
    case EFI_BUFFER_TOO_SMALL:
      ASSERT (DecodedCertSize > 0);
      break;
    case EFI_SUCCESS:
      DEBUG((DEBUG_ERROR,
        "GetPkKek1: Empty certificate after app prefix %g\n",
        &gUefiPayloadPkKek1AppPrefixGuid
        ));
      return EFI_PROTOCOL_ERROR;
    default:
      DEBUG((DEBUG_ERROR, 
        "GetPkKek1: Invalid base64 string after app prefix %g\n",
        &gUefiPayloadPkKek1AppPrefixGuid
        ));
      return EFI_PROTOCOL_ERROR;
  }

  //
  // Allocate the output buffer.
  //
  DecodedCert = AllocatePool (DecodedCertSize);
  if (DecodedCert == NULL) {
    DEBUG((DEBUG_ERROR, "GetPkKek1: Failed to allocate memory\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Decoding will succeed at this point.
  //
  Status = Base64Decode (
             Base64Cert,
             Base64CertLen,
             DecodedCert,
             &DecodedCertSize
             );
  ASSERT_EFI_ERROR (Status);

  *PkKek1       = DecodedCert;
  *SizeOfPkKek1 = DecodedCertSize;
  return EFI_SUCCESS;
}

/**
  Enroll a set of certificates in a global variable, overwriting it.

  The variable will be rewritten with NV+BS+RT+AT attributes.

  @param[in] VariableName  The name of the variable to overwrite.

  @param[in] VendorGuid    The namespace (ie. vendor GUID) of the variable to
                           overwrite.

  @param[in] CertType      The GUID determining the type of all the
                           certificates in the set that is passed in. For
                           example, gEfiCertX509Guid stands for DER-encoded
                           X.509 certificates, while gEfiCertSha256Guid stands
                           for SHA256 image hashes.

  @param[in] ...           A list of

                             IN CONST UINT8    *Cert,
                             IN UINTN          CertSize,
                             IN CONST EFI_GUID *OwnerGuid

                           triplets. If the first component of a triplet is
                           NULL, then the other two components are not
                           accessed, and processing is terminated. The list of
                           certificates is enrolled in the variable specified,
                           overwriting it. The OwnerGuid component identifies
                           the agent installing the certificate.

  @retval EFI_INVALID_PARAMETER  The triplet list is empty (ie. the first Cert
                                 value is NULL), or one of the CertSize values
                                 is 0, or one of the CertSize values would
                                 overflow the accumulated UINT32 data size.

  @retval EFI_OUT_OF_RESOURCES   Out of memory while formatting variable
                                 payload.

  @retval EFI_SUCCESS            Enrollment successful; the variable has been
                                 overwritten (or created).

  @return                        Error codes from gRT->GetTime() and
                                 gRT->SetVariable().
**/
STATIC
EFI_STATUS
EFIAPI
EnrollListOfCerts (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  IN EFI_GUID  *CertType,
  ...
  )
{
  UINTN             DataSize;
  SINGLE_HEADER     *SingleHeader;
  REPEATING_HEADER  *RepeatingHeader;
  VA_LIST           Marker;
  CONST UINT8       *Cert;
  EFI_STATUS        Status;
  UINT8             *Data;
  UINT8             *Position;

  Status = EFI_SUCCESS;

  //
  // Compute total size first, for UINT32 range check, and allocation
  //
  DataSize = sizeof *SingleHeader;
  VA_START (Marker, CertType);
  for (Cert = VA_ARG (Marker, CONST UINT8 *);
       Cert != NULL;
       Cert = VA_ARG (Marker, CONST UINT8 *))
  {
    UINTN  CertSize;

    CertSize = VA_ARG (Marker, UINTN);
    (VOID)VA_ARG (Marker, CONST EFI_GUID *);

    if ((CertSize == 0) ||
        (CertSize > MAX_UINT32 - sizeof *RepeatingHeader) ||
        (DataSize > MAX_UINT32 - sizeof *RepeatingHeader - CertSize))
    {
      Status = EFI_INVALID_PARAMETER;
      break;
    }

    DataSize += sizeof *RepeatingHeader + CertSize;
  }

  VA_END (Marker);

  if (DataSize == sizeof *SingleHeader) {
    Status = EFI_INVALID_PARAMETER;
  }

  if (EFI_ERROR (Status)) {
    goto Out;
  }

  Data = AllocatePool (DataSize);
  if (Data == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Out;
  }

  Position = Data;

  SingleHeader = (SINGLE_HEADER *)Position;
  Status       = gRT->GetTime (&SingleHeader->TimeStamp, NULL);
  if (EFI_ERROR (Status)) {
    goto FreeData;
  }

  SingleHeader->TimeStamp.Pad1       = 0;
  SingleHeader->TimeStamp.Nanosecond = 0;
  SingleHeader->TimeStamp.TimeZone   = 0;
  SingleHeader->TimeStamp.Daylight   = 0;
  SingleHeader->TimeStamp.Pad2       = 0;
 #if 0
  SingleHeader->dwLength = DataSize - sizeof SingleHeader->TimeStamp;
 #else
  //
  // This looks like a bug in edk2. According to the UEFI specification,
  // dwLength is "The length of the entire certificate, including the length of
  // the header, in bytes". That shouldn't stop right after CertType -- it
  // should include everything below it.
  //
  SingleHeader->dwLength = sizeof *SingleHeader
                           - sizeof SingleHeader->TimeStamp;
 #endif
  SingleHeader->wRevision        = 0x0200;
  SingleHeader->wCertificateType = WIN_CERT_TYPE_EFI_GUID;
  CopyGuid (&SingleHeader->CertType, &gEfiCertPkcs7Guid);
  Position += sizeof *SingleHeader;

  VA_START (Marker, CertType);
  for (Cert = VA_ARG (Marker, CONST UINT8 *);
       Cert != NULL;
       Cert = VA_ARG (Marker, CONST UINT8 *))
  {
    UINTN           CertSize;
    CONST EFI_GUID  *OwnerGuid;

    CertSize  = VA_ARG (Marker, UINTN);
    OwnerGuid = VA_ARG (Marker, CONST EFI_GUID *);

    RepeatingHeader = (REPEATING_HEADER *)Position;
    CopyGuid (&RepeatingHeader->SignatureType, CertType);
    RepeatingHeader->SignatureListSize =
      (UINT32)(sizeof *RepeatingHeader + CertSize);
    RepeatingHeader->SignatureHeaderSize = 0;
    RepeatingHeader->SignatureSize       =
      (UINT32)(sizeof RepeatingHeader->SignatureOwner + CertSize);
    CopyGuid (&RepeatingHeader->SignatureOwner, OwnerGuid);
    Position += sizeof *RepeatingHeader;

    CopyMem (Position, Cert, CertSize);
    Position += CertSize;
  }

  VA_END (Marker);

  ASSERT (Data + DataSize == Position);

  Status = gRT->SetVariable (
                  VariableName,
                  VendorGuid,
                  (EFI_VARIABLE_NON_VOLATILE |
                   EFI_VARIABLE_BOOTSERVICE_ACCESS |
                   EFI_VARIABLE_RUNTIME_ACCESS |
                   EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
                  DataSize,
                  Data
                  );

FreeData:
  FreePool (Data);

Out:
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, 
      "EnrollListOfCerts: Error enrolling \"%s\", %g: %r\n",
      VariableName,
      VendorGuid,
      Status
      ));
  }

  return Status;
}

/**
  Read a UEFI variable into a caller-allocated buffer, enforcing an exact size.

  @param[in] VariableName  The name of the variable to read; passed to
                           gRT->GetVariable().

  @param[in] VendorGuid    The vendor (namespace) GUID of the variable to read;
                           passed to gRT->GetVariable().

  @param[out] Data         The caller-allocated buffer that is supposed to
                           receive the variable's contents. On error, the
                           contents of Data are indeterminate.

  @param[in] DataSize      The size in bytes that the caller requires the UEFI
                           variable to have. The caller is responsible for
                           providing room for DataSize bytes in Data.

  @param[in] AllowMissing  If FALSE, the variable is required to exist. If
                           TRUE, the variable is permitted to be missing.

  @retval EFI_SUCCESS           The UEFI variable exists, has the required size
                                (DataSize), and has been read into Data.

  @retval EFI_SUCCESS           The UEFI variable doesn't exist, and
                                AllowMissing is TRUE. DataSize bytes in Data
                                have been zeroed out.

  @retval EFI_NOT_FOUND         The UEFI variable doesn't exist, and
                                AllowMissing is FALSE.

  @retval EFI_BUFFER_TOO_SMALL  The UEFI variable exists, but its size is
                                greater than DataSize.

  @retval EFI_PROTOCOL_ERROR    The UEFI variable exists, but its size is
                                smaller than DataSize.

  @return                       Error codes propagated from gRT->GetVariable().
**/
STATIC
EFI_STATUS
GetExact (
  IN CHAR16    *VariableName,
  IN EFI_GUID  *VendorGuid,
  OUT VOID     *Data,
  IN UINTN     DataSize,
  IN BOOLEAN   AllowMissing
  )
{
  UINTN       Size;
  EFI_STATUS  Status;

  Size   = DataSize;
  Status = gRT->GetVariable (VariableName, VendorGuid, NULL, &Size, Data);
  if (EFI_ERROR (Status)) {
    if ((Status == EFI_NOT_FOUND) && AllowMissing) {
      ZeroMem (Data, DataSize);
      return EFI_SUCCESS;
    }

    DEBUG((DEBUG_ERROR, 
      "GetExact: GetVariable(\"%s\", %g): %r\n",
      VariableName,
      VendorGuid,
      Status
      ));
    return Status;
  }

  if (Size != DataSize) {
    DEBUG((DEBUG_ERROR, 
      "GetExact: GetVariable(\"%s\", %g): expected size 0x%Lx, "
      "got 0x%Lx\n",
      VariableName,
      VendorGuid,
      (UINT64)DataSize,
      (UINT64)Size
      ));
    return EFI_PROTOCOL_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Populate a SETTINGS structure from the underlying UEFI variables.

  The following UEFI variables are standard variables:
  - L"SetupMode"  (EFI_SETUP_MODE_NAME)
  - L"SecureBoot" (EFI_SECURE_BOOT_MODE_NAME)
  - L"VendorKeys" (EFI_VENDOR_KEYS_VARIABLE_NAME)

  The following UEFI variables are edk2 extensions:
  - L"SecureBootEnable" (EFI_SECURE_BOOT_ENABLE_NAME)
  - L"CustomMode"       (EFI_CUSTOM_MODE_NAME)

  The L"SecureBootEnable" UEFI variable is permitted to be missing, in which
  case the corresponding field in the SETTINGS object will be zeroed out. The
  rest of the covered UEFI variables are required to exist; otherwise, the
  function will fail.

  @param[out] Settings  The SETTINGS object to fill.

  @retval EFI_SUCCESS  Settings has been populated.

  @return              Error codes propagated from the GetExact() function. The
                       contents of Settings are indeterminate.
**/
STATIC
EFI_STATUS
GetSettings (
  OUT SETTINGS  *Settings
  )
{
  EFI_STATUS  Status;

  Status = GetExact (
             EFI_SETUP_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &Settings->SetupMode,
             sizeof Settings->SetupMode,
             FALSE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = GetExact (
             EFI_SECURE_BOOT_MODE_NAME,
             &gEfiGlobalVariableGuid,
             &Settings->SecureBoot,
             sizeof Settings->SecureBoot,
             FALSE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = GetExact (
             EFI_SECURE_BOOT_ENABLE_NAME,
             &gEfiSecureBootEnableDisableGuid,
             &Settings->SecureBootEnable,
             sizeof Settings->SecureBootEnable,
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = GetExact (
             EFI_CUSTOM_MODE_NAME,
             &gEfiCustomModeEnableGuid,
             &Settings->CustomMode,
             sizeof Settings->CustomMode,
             FALSE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = GetExact (
             EFI_VENDOR_KEYS_VARIABLE_NAME,
             &gEfiGlobalVariableGuid,
             &Settings->VendorKeys,
             sizeof Settings->VendorKeys,
             FALSE
             );
  return Status;
}

/**
  Print the contents of a SETTINGS structure to the debug output.

  @param[in] Settings  The SETTINGS object to print the contents of.
**/
STATIC
VOID
PrintSettings (
  IN CONST SETTINGS  *Settings
  )
{
  DEBUG((DEBUG_INFO,
    "EnrollDefaultKeys: SetupMode=%d SecureBoot=%d SecureBootEnable=%d "
    "CustomMode=%d VendorKeys=%d\n",
    Settings->SetupMode,
    Settings->SecureBoot,
    Settings->SecureBootEnable,
    Settings->CustomMode,
    Settings->VendorKeys
    ));
}

/**
  Entry point of the driver.
**/
EFI_STATUS
EFIAPI
DriverEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  SETTINGS    Settings;
  UINT8       *PkKek1;
  UINTN       SizeOfPkKek1;

  DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Started\n"));


  //
  // If we're not in Setup Mode, we can't do anything.
  //
  Status = GetSettings (&Settings);
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Failed to get settings: %r\n", Status));
    return Status;
  }

  PrintSettings (&Settings);

  if (Settings.SetupMode != 1) {
    DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Already in User Mode\n"));
    return EFI_ABORTED;
  }

  //
  // Initialize PkKek1 and SizeOfPkKek1.
  //
  PkKek1       = NULL;
  SizeOfPkKek1 = 0;

  //
  // Fetch the X509 certificate (to be used as Platform Key and first Key
  // Exchange Key) from SMBIOS.
  //
  Status = GetPkKek1 (&PkKek1, &SizeOfPkKek1);
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Failed to get PK/KEK1: %r\n", Status));
    return Status;
  }

  //
  // Enter Custom Mode so we can enroll PK, KEK, db, and dbx without signature
  // checks on those variable writes.
  //
  if (Settings.CustomMode != CUSTOM_SECURE_BOOT_MODE) {
    Settings.CustomMode = CUSTOM_SECURE_BOOT_MODE;
    Status              = gRT->SetVariable (
                                 EFI_CUSTOM_MODE_NAME,
                                 &gEfiCustomModeEnableGuid,
                                 (EFI_VARIABLE_NON_VOLATILE |
                                  EFI_VARIABLE_BOOTSERVICE_ACCESS),
                                 sizeof Settings.CustomMode,
                                 &Settings.CustomMode
                                 );
    if (EFI_ERROR (Status)) {
      DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Error setting CustomMode: %r\n", Status));
      goto FreePkKek1;
    }
  }

  //
  // Enroll db.
  //
  Status = EnrollListOfCerts (
             EFI_IMAGE_SECURITY_DATABASE,
             &gEfiImageSecurityDatabaseGuid,
             &gEfiCertX509Guid,
             mMicrosoftPca,
             mSizeOfMicrosoftPca,
             &gMicrosoftVendorGuid,
             mMicrosoftUefiCa,
             mSizeOfMicrosoftUefiCa,
             &gMicrosoftVendorGuid,
             NULL
             );

  if (EFI_ERROR (Status)) {
    goto FreePkKek1;
  }

  //
  // Enroll dbx.
  //
  Status = EnrollListOfCerts (
             EFI_IMAGE_SECURITY_DATABASE1,
             &gEfiImageSecurityDatabaseGuid,
             &gEfiCertSha256Guid,
             mSha256OfDevNull,
             mSizeOfSha256OfDevNull,
             &gEfiCallerIdGuid,
             NULL
             );
  if (EFI_ERROR (Status)) {
    goto FreePkKek1;
  }

  //
  // Enroll KEK.
  //
  Status = EnrollListOfCerts (
             EFI_KEY_EXCHANGE_KEY_NAME,
             &gEfiGlobalVariableGuid,
             &gEfiCertX509Guid,
             PkKek1,
             SizeOfPkKek1,
             &gEfiCallerIdGuid,
             mMicrosoftKek,
             mSizeOfMicrosoftKek,
             &gMicrosoftVendorGuid,
             NULL
             );

  if (EFI_ERROR (Status)) {
    goto FreePkKek1;
  }

  //
  // Enroll PK, leaving Setup Mode (entering User Mode) at once.
  //
  Status = EnrollListOfCerts (
             EFI_PLATFORM_KEY_NAME,
             &gEfiGlobalVariableGuid,
             &gEfiCertX509Guid,
             PkKek1,
             SizeOfPkKek1,
             &gEfiGlobalVariableGuid,
             NULL
             );
  if (EFI_ERROR (Status)) {
    goto FreePkKek1;
  }

  //
  // Leave Custom Mode, so that updates to PK, KEK, db, and dbx require valid
  // signatures.
  //
  Settings.CustomMode = STANDARD_SECURE_BOOT_MODE;
  Status              = gRT->SetVariable (
                               EFI_CUSTOM_MODE_NAME,
                               &gEfiCustomModeEnableGuid,
                               EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS,
                               sizeof Settings.CustomMode,
                               &Settings.CustomMode
                               );
  if (EFI_ERROR (Status)) {
    DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Error resetting CustomMode: %r\n", Status));
    goto FreePkKek1;
  }

  //
  // Final sanity check.
  //
  Status = GetSettings (&Settings);
  if (EFI_ERROR (Status)) {
    goto FreePkKek1;
  }

  PrintSettings (&Settings);

  if ((Settings.SetupMode != 0) || (Settings.SecureBoot != 1) ||
      (Settings.SecureBootEnable != 1) || (Settings.CustomMode != 0) ||
      (Settings.VendorKeys != 0))
  {
    DEBUG((DEBUG_ERROR, "EnrollDefaultKeys: Unexpected settings after enrollment\n")); 
    Status = EFI_ABORTED;
    goto FreePkKek1;
  }

  DEBUG((DEBUG_INFO, "EnrollDefaultKeys: Success\n")); 

FreePkKek1:
  if (PkKek1 != NULL) {
    FreePool (PkKek1);
  }

  return Status;
}

