/** @file
  Publishes a TPM2 ACPI table that points at the EDK2 TPM event log.

  Copyright (c) 2026, Star Labs Ltd. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>

#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/Tpm2Acpi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/Tpm2DeviceLib.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/AcpiTable.h>

#pragma pack (1)

#define UEFI_PAYLOAD_TPM2_PARAMETERS_SIZE  \
  EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_4

typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER    Header;
  UINT32                         Flags;
  UINT64                         AddressOfControlArea;
  UINT32                         StartMethod;
  UINT8                          PlatformSpecificParameters[UEFI_PAYLOAD_TPM2_PARAMETERS_SIZE];
  UINT32                         Laml;
  UINT64                         Lasa;
} UEFI_PAYLOAD_TPM2_ACPI_TABLE;

#pragma pack ()

STATIC
EFI_STATUS
RemoveTpm2AcpiTables (
  IN EFI_ACPI_SDT_PROTOCOL    *AcpiSdt,
  IN EFI_ACPI_TABLE_PROTOCOL  *AcpiTable
  )
{
  EFI_ACPI_SDT_HEADER     *Table;
  EFI_ACPI_TABLE_VERSION  Version;
  EFI_STATUS              Status;
  UINTN                   Index;
  UINTN                   TableKey;

  Index = 0;
  while (TRUE) {
    Status = AcpiSdt->GetAcpiTable (Index, &Table, &Version, &TableKey);
    if (EFI_ERROR (Status)) {
      break;
    }

    if (Table->Signature != EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE) {
      Index++;
      continue;
    }

    Status = AcpiTable->UninstallAcpiTable (AcpiTable, TableKey);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "%a: failed to remove inherited TPM2 ACPI table: %r\n", __func__, Status));
      Index++;
    }
  }

  return EFI_SUCCESS;
}

STATIC
VOID
BuildTpm2AcpiTable (
  OUT UEFI_PAYLOAD_TPM2_ACPI_TABLE  *Table
  )
{
  TPM2_PTP_INTERFACE_TYPE  InterfaceType;
  UINT64                   OemTableId;
  UINT8                    Revision;

  ZeroMem (Table, sizeof (*Table));

  Revision = PcdGet8 (PcdTpm2AcpiTableRev);
  if (Revision < EFI_TPM2_ACPI_TABLE_REVISION_4) {
    Revision = EFI_TPM2_ACPI_TABLE_REVISION_4;
  } else if (Revision > EFI_TPM2_ACPI_TABLE_REVISION_4) {
    Revision = EFI_TPM2_ACPI_TABLE_REVISION_4;
  }

  Table->Header.Signature = EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE;
  Table->Header.Length    = sizeof (*Table);
  Table->Header.Revision  = Revision;
  CopyMem (Table->Header.OemId, PcdGetPtr (PcdAcpiDefaultOemId), sizeof (Table->Header.OemId));
  OemTableId = PcdGet64 (PcdAcpiDefaultOemTableId);
  CopyMem (&Table->Header.OemTableId, &OemTableId, sizeof (Table->Header.OemTableId));
  Table->Header.OemRevision     = PcdGet32 (PcdAcpiDefaultOemRevision);
  Table->Header.CreatorId       = PcdGet32 (PcdAcpiDefaultCreatorId);
  Table->Header.CreatorRevision = PcdGet32 (PcdAcpiDefaultCreatorRevision);

  Table->Flags = PcdGet8 (PcdTpmPlatformClass);

  InterfaceType = PcdGet8 (PcdActiveTpmInterfaceType);
  if (InterfaceType == Tpm2PtpInterfaceCrb) {
    Table->AddressOfControlArea = PcdGet64 (PcdTpmBaseAddress) + 0x40;
    Table->StartMethod          = EFI_TPM2_ACPI_TABLE_START_METHOD_COMMAND_RESPONSE_BUFFER_INTERFACE;
  } else {
    Table->StartMethod = EFI_TPM2_ACPI_TABLE_START_METHOD_TIS;
  }

  Table->Laml = PcdGet32 (PcdTpm2AcpiTableLaml);
  Table->Lasa = PcdGet64 (PcdTpm2AcpiTableLasa);
}

EFI_STATUS
EFIAPI
Tpm2AcpiTableDxeEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_ACPI_SDT_PROTOCOL        *AcpiSdt;
  EFI_ACPI_TABLE_PROTOCOL      *AcpiTable;
  EFI_STATUS                   Status;
  UEFI_PAYLOAD_TPM2_ACPI_TABLE Tpm2Table;
  UINTN                        TableKey;

  Status = gBS->LocateProtocol (&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&AcpiSdt);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->LocateProtocol (&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&AcpiTable);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  BuildTpm2AcpiTable (&Tpm2Table);
  if ((Tpm2Table.Laml == 0) || (Tpm2Table.Lasa == 0)) {
    DEBUG ((DEBUG_ERROR, "%a: TPM2 event log address is not available\n", __func__));
    return EFI_NOT_READY;
  }

  RemoveTpm2AcpiTables (AcpiSdt, AcpiTable);

  TableKey = 0;
  Status   = AcpiTable->InstallAcpiTable (
                          AcpiTable,
                          &Tpm2Table,
                          Tpm2Table.Header.Length,
                          &TableKey
                          );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: failed to install TPM2 ACPI table: %r\n", __func__, Status));
  }

  return Status;
}
