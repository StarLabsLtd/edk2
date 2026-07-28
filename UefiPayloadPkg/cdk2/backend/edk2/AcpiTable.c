/** @file


  Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "entry/Cdk2EfiEntry.h"

#define UEFI_PAYLOAD_MAX_TPM2_LOG_SIZE   (1024 * 1024)
#define UEFI_PAYLOAD_MAX_TPM_PCR_INDEX   23
#define UEFI_PAYLOAD_SPEC_ID_EVENT_NAME  "Spec ID Event"

STATIC
UINT16
GetDigestSizeFromAlgo (
  IN TPMI_ALG_HASH  HashAlg
  )
{
  switch (HashAlg) {
    case TPM_ALG_SHA1:
      return SHA1_DIGEST_SIZE;
    case TPM_ALG_SHA256:
      return SHA256_DIGEST_SIZE;
    case TPM_ALG_SHA384:
      return SHA384_DIGEST_SIZE;
    case TPM_ALG_SHA512:
      return SHA512_DIGEST_SIZE;
    case TPM_ALG_SM3_256:
      return SM3_256_DIGEST_SIZE;
    default:
      return 0;
  }
}

STATIC
BOOLEAN
GetTpm2AcpiEventLog (
  IN  EFI_ACPI_DESCRIPTION_HEADER  *Table,
  OUT UINT32                       *Laml,
  OUT EFI_PHYSICAL_ADDRESS         *Lasa
  )
{
  UINTN  LogAreaOffset;
  UINTN  ParametersSize;

  if ((Table == NULL) ||
      (Table->Signature != EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE) ||
      (Table->Revision < EFI_TPM2_ACPI_TABLE_REVISION_4) ||
      (Table->Length < sizeof (EFI_TPM2_ACPI_TABLE)))
  {
    return FALSE;
  }

  ParametersSize = EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_4;
  if (Table->Revision >= EFI_TPM2_ACPI_TABLE_REVISION_5) {
    ParametersSize = EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_5;
  }

  LogAreaOffset = sizeof (EFI_TPM2_ACPI_TABLE) + ParametersSize;
  if (Table->Length < LogAreaOffset + sizeof (*Laml) + sizeof (*Lasa)) {
    return FALSE;
  }

  *Laml = ReadUnaligned32 ((UINT32 *)((UINT8 *)Table + LogAreaOffset));
  *Lasa = ReadUnaligned64 ((UINT64 *)((UINT8 *)Table + LogAreaOffset + sizeof (*Laml)));

  return (BOOLEAN)((*Laml != 0) && (*Lasa != 0) && (*Laml <= UEFI_PAYLOAD_MAX_TPM2_LOG_SIZE));
}

STATIC
BOOLEAN
GetTcgPcrEvent2Size (
  IN  CONST UINT8  *Event,
  IN  UINTN        Remaining,
  OUT UINTN        *EventSize,
  OUT UINTN        *EventDataOffset,
  OUT UINT32       *EventDataSize
  )
{
  UINT32         Count;
  UINT16         DigestSize;
  TPMI_ALG_HASH  HashAlg;
  UINTN          Index;
  UINTN          Offset;
  UINT32         PcrIndex;

  if ((Event == NULL) ||
      (EventSize == NULL) ||
      (EventDataOffset == NULL) ||
      (EventDataSize == NULL))
  {
    return FALSE;
  }

  Offset = sizeof (TCG_PCRINDEX) + sizeof (TCG_EVENTTYPE);
  if (Remaining < Offset + sizeof (Count) + sizeof (*EventDataSize)) {
    return FALSE;
  }

  PcrIndex = ReadUnaligned32 ((UINT32 *)Event);
  if (PcrIndex > UEFI_PAYLOAD_MAX_TPM_PCR_INDEX) {
    return FALSE;
  }

  Count  = ReadUnaligned32 ((UINT32 *)(Event + Offset));
  Offset += sizeof (Count);
  if ((Count == 0) || (Count > HASH_COUNT)) {
    return FALSE;
  }

  for (Index = 0; Index < Count; Index++) {
    if (Remaining < Offset + sizeof (HashAlg)) {
      return FALSE;
    }

    HashAlg = ReadUnaligned16 ((UINT16 *)(Event + Offset));
    Offset += sizeof (HashAlg);

    DigestSize = GetDigestSizeFromAlgo (HashAlg);
    if ((DigestSize == 0) || (Remaining < Offset + DigestSize)) {
      return FALSE;
    }

    Offset += DigestSize;
  }

  if (Remaining < Offset + sizeof (*EventDataSize)) {
    return FALSE;
  }

  *EventDataSize = ReadUnaligned32 ((UINT32 *)(Event + Offset));
  Offset        += sizeof (*EventDataSize);
  if (Remaining < Offset + *EventDataSize) {
    return FALSE;
  }

  *EventDataOffset = Offset;
  *EventSize       = Offset + *EventDataSize;

  return TRUE;
}

STATIC
BOOLEAN
IsSpecIdEvent (
  IN CONST UINT8  *EventData,
  IN UINT32       EventSize
  )
{
  if (EventSize < sizeof (UEFI_PAYLOAD_SPEC_ID_EVENT_NAME) - 1) {
    return FALSE;
  }

  return (BOOLEAN)(CompareMem (
                    EventData,
                    UEFI_PAYLOAD_SPEC_ID_EVENT_NAME,
                    sizeof (UEFI_PAYLOAD_SPEC_ID_EVENT_NAME) - 1
                    ) == 0);
}

STATIC
UINTN
GetFirstTcgPcrEvent2Offset (
  IN CONST UINT8  *EventLog,
  IN UINTN        EventLogSize
  )
{
  UINT32  EventDataSize;
  UINTN   EventSizeOffset;
  UINTN   FirstEventOffset;

  if ((EventLog == NULL) || (EventLogSize < sizeof (TCG_PCR_EVENT_HDR))) {
    return 0;
  }

  if (ReadUnaligned32 ((UINT32 *)(EventLog + sizeof (TCG_PCRINDEX))) != EV_NO_ACTION) {
    return 0;
  }

  EventSizeOffset = sizeof (TCG_PCRINDEX) + sizeof (TCG_EVENTTYPE) + sizeof (TCG_DIGEST);
  EventDataSize   = ReadUnaligned32 ((UINT32 *)(EventLog + EventSizeOffset));
  FirstEventOffset = sizeof (TCG_PCR_EVENT_HDR) + EventDataSize;
  if ((EventLogSize < FirstEventOffset) ||
      !IsSpecIdEvent (EventLog + sizeof (TCG_PCR_EVENT_HDR), EventDataSize))
  {
    return 0;
  }

  return FirstEventOffset;
}

STATIC
VOID
BuildTpmEventHobsFromAcpi (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Tpm2Table
  )
{
  UINT8                 *EventLog;
  UINTN                 EventDataOffset;
  UINT32                EventDataSize;
  UINTN                 EventSize;
  VOID                  *HobData;
  UINT32                Laml;
  EFI_PHYSICAL_ADDRESS  Lasa;
  UINT32                EventType;
  UINT32                PcrIndex;
  UINTN                 Offset;
  UINTN                 TpmEventCount;

  if (!GetTpm2AcpiEventLog (Tpm2Table, &Laml, &Lasa)) {
    return;
  }

  EventLog      = (UINT8 *)(UINTN)Lasa;
  Offset        = GetFirstTcgPcrEvent2Offset (EventLog, Laml);
  TpmEventCount = 0;
  while (Offset < Laml) {
    if (!GetTcgPcrEvent2Size (
           EventLog + Offset,
           Laml - Offset,
           &EventSize,
           &EventDataOffset,
           &EventDataSize
           ))
    {
      break;
    }

    PcrIndex  = ReadUnaligned32 ((UINT32 *)(EventLog + Offset));
    EventType = ReadUnaligned32 ((UINT32 *)(EventLog + Offset + sizeof (TCG_PCRINDEX)));
    if ((PcrIndex != 0) &&
        ((EventType != EV_NO_ACTION) || !IsSpecIdEvent (EventLog + Offset + EventDataOffset, EventDataSize)))
    {
      HobData = BuildGuidHob (&gTcgEvent2EntryHobGuid, EventSize);
      if (HobData == NULL) {
        DEBUG ((DEBUG_ERROR, "%a: failed to build TPM event HOB\n", __func__));
        break;
      }

      CopyMem (HobData, EventLog + Offset, EventSize);
      TpmEventCount++;
    }

    Offset += EventSize;
  }

  DEBUG ((DEBUG_INFO, "%a: imported %u TPM2 event log entries\n", __func__, TpmEventCount));
}

/**
  Find the board related info from ACPI table

  @param  AcpiTableBase          ACPI table start address in memory
  @param  AcpiBoardInfo          Pointer to the acpi board info structure

  @retval RETURN_SUCCESS     Successfully find out all the required information.
  @retval RETURN_NOT_FOUND   Failed to find the required info.

**/
RETURN_STATUS
ParseAcpiInfo (
  IN   UINT64           AcpiTableBase,
  OUT  ACPI_BOARD_INFO  *AcpiBoardInfo
  )
{
  EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER                                           *Rsdp;
  EFI_ACPI_DESCRIPTION_HEADER                                                            *Rsdt;
  UINT32                                                                                 *Entry32;
  UINTN                                                                                  Entry32Num;
  EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE                                              *Fadt;
  EFI_ACPI_DESCRIPTION_HEADER                                                            *Xsdt;
  UINT64                                                                                 *Entry64;
  UINTN                                                                                  Entry64Num;
  UINTN                                                                                  Idx;
  UINT32                                                                                 *Signature;
  EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER                         *MmCfgHdr;
  EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE  *MmCfgBase;
  EFI_ACPI_DESCRIPTION_HEADER                                                            *Tpm2Table;
  UINTN                                                                                  TPM2TablePresent;
  UINTN                                                                                  TCPATablePresent;

  Rsdp = (EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)(UINTN)AcpiTableBase;
  DEBUG ((DEBUG_INFO, "Rsdp at 0x%p\n", Rsdp));
  DEBUG ((DEBUG_INFO, "Rsdt at 0x%x, Xsdt at 0x%lx\n", Rsdp->RsdtAddress, Rsdp->XsdtAddress));

  Tpm2Table        = NULL;
  TPM2TablePresent = 0;
  TCPATablePresent = 0;

  //
  // Search Rsdt First
  //
  Fadt     = NULL;
  MmCfgHdr = NULL;
  Rsdt     = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)(Rsdp->RsdtAddress);
  if (Rsdt != NULL) {
    Entry32    = (UINT32 *)(Rsdt + 1);
    Entry32Num = (Rsdt->Length - sizeof (EFI_ACPI_DESCRIPTION_HEADER)) >> 2;
    for (Idx = 0; Idx < Entry32Num; Idx++) {
      Signature = (UINT32 *)(UINTN)Entry32[Idx];
      if (*Signature == EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE) {
        Fadt = (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)Signature;
        DEBUG ((DEBUG_INFO, "Found Fadt in Rsdt\n"));
      }

      if (*Signature == EFI_ACPI_5_0_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE) {
        MmCfgHdr = (EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *)Signature;
        DEBUG ((DEBUG_INFO, "Found MM config address in Rsdt\n"));
      }

      if (*Signature == EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE) {
        TPM2TablePresent = 1;
        if (Tpm2Table == NULL) {
          Tpm2Table = (EFI_ACPI_DESCRIPTION_HEADER *)Signature;
        }
      }

      if (*Signature == EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_ALLIANCE_CAPABILITIES_TABLE_SIGNATURE) {
        TCPATablePresent = 1;
      }

     if ((Fadt != NULL) && (MmCfgHdr != NULL) && (TPM2TablePresent || TCPATablePresent ))   {
        goto TpmDectectDone;
      }
    }
  }

  //
  // Search Xsdt Second
  //
  Xsdt = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)(Rsdp->XsdtAddress);
  if (Xsdt != NULL) {
    Entry64    = (UINT64 *)(Xsdt + 1);
    Entry64Num = (Xsdt->Length - sizeof (EFI_ACPI_DESCRIPTION_HEADER)) >> 3;
    for (Idx = 0; Idx < Entry64Num; Idx++) {
      Signature = (UINT32 *)(UINTN)ReadUnaligned64 (&Entry64[Idx]);
      if (*Signature == EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE) {
        Fadt = (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)Signature;
        DEBUG ((DEBUG_INFO, "Found Fadt in Xsdt\n"));
      }

      if (*Signature == EFI_ACPI_5_0_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE) {
        MmCfgHdr = (EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *)Signature;
        DEBUG ((DEBUG_INFO, "Found MM config address in Xsdt\n"));
      }

      if (*Signature == EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE) {
        TPM2TablePresent = 1;
        if (Tpm2Table == NULL) {
          Tpm2Table = (EFI_ACPI_DESCRIPTION_HEADER *)Signature;
        }
      }

      if (*Signature == EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_ALLIANCE_CAPABILITIES_TABLE_SIGNATURE) {
        TCPATablePresent = 1;
      }

      if ((Fadt != NULL) && (MmCfgHdr != NULL) && (TPM2TablePresent || TCPATablePresent)) {
        goto TpmDectectDone;
      }
    }
  }

  if (Fadt == NULL) {
    return RETURN_NOT_FOUND;
  }

TpmDectectDone:

  AcpiBoardInfo->TPM20Present = TPM2TablePresent;
  AcpiBoardInfo->TPM12Present = TCPATablePresent;

  AcpiBoardInfo->PmCtrlRegBase   = Fadt->Pm1aCntBlk;
  AcpiBoardInfo->PmTimerRegBase  = Fadt->PmTmrBlk;
  AcpiBoardInfo->ResetRegAddress = Fadt->ResetReg.Address;
  AcpiBoardInfo->ResetValue      = Fadt->ResetValue;
  AcpiBoardInfo->PmEvtBase       = Fadt->Pm1aEvtBlk;
  AcpiBoardInfo->PmGpeEnBase     = Fadt->Gpe0Blk + Fadt->Gpe0BlkLen / 2;

  if (MmCfgHdr != NULL) {
    MmCfgBase                      = (EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE *)((UINT8 *)MmCfgHdr + sizeof (*MmCfgHdr));
    AcpiBoardInfo->PcieBaseAddress = MmCfgBase->BaseAddress;
    AcpiBoardInfo->PcieBaseSize    = (MmCfgBase->EndBusNumber + 1 - MmCfgBase->StartBusNumber) * 4096 * 32 * 8;
  } else {
    AcpiBoardInfo->PcieBaseAddress = 0;
    AcpiBoardInfo->PcieBaseSize    = 0;
  }

  DEBUG ((DEBUG_INFO, "PmCtrl  Reg 0x%lx\n", AcpiBoardInfo->PmCtrlRegBase));
  DEBUG ((DEBUG_INFO, "PmTimer Reg 0x%lx\n", AcpiBoardInfo->PmTimerRegBase));
  DEBUG ((DEBUG_INFO, "Reset   Reg 0x%lx\n", AcpiBoardInfo->ResetRegAddress));
  DEBUG ((DEBUG_INFO, "Reset   Value 0x%x\n", AcpiBoardInfo->ResetValue));
  DEBUG ((DEBUG_INFO, "PmEvt   Reg 0x%lx\n", AcpiBoardInfo->PmEvtBase));
  DEBUG ((DEBUG_INFO, "PmGpeEn Reg 0x%lx\n", AcpiBoardInfo->PmGpeEnBase));
  DEBUG ((DEBUG_INFO, "PcieBaseAddr 0x%lx\n", AcpiBoardInfo->PcieBaseAddress));
  DEBUG ((DEBUG_INFO, "PcieBaseSize 0x%lx\n", AcpiBoardInfo->PcieBaseSize));
  DEBUG ((DEBUG_INFO, "TPM 2.0 present %x\n", AcpiBoardInfo->TPM20Present));
  DEBUG ((DEBUG_INFO, "TPM 1.2 present %x\n", AcpiBoardInfo->TPM12Present));

  BuildTpmEventHobsFromAcpi (Tpm2Table);

  return RETURN_SUCCESS;
}

/**
  Build ACPI board info HOB using infomation from ACPI table

  @param  AcpiTableBase      ACPI table start address in memory

  @retval  A pointer to ACPI board HOB ACPI_BOARD_INFO. Null if build HOB failure.
**/
ACPI_BOARD_INFO *
BuildHobFromAcpi (
  IN   UINT64  AcpiTableBase
  )
{
  EFI_STATUS       Status;
  ACPI_BOARD_INFO  AcpiBoardInfo;
  ACPI_BOARD_INFO  *NewAcpiBoardInfo;

  NewAcpiBoardInfo = NULL;
  Status           = ParseAcpiInfo (AcpiTableBase, &AcpiBoardInfo);
  ASSERT_EFI_ERROR (Status);
  if (!EFI_ERROR (Status)) {
    NewAcpiBoardInfo = BuildGuidHob (&gUefiAcpiBoardInfoGuid, sizeof (ACPI_BOARD_INFO));
    ASSERT (NewAcpiBoardInfo != NULL);
    CopyMem (NewAcpiBoardInfo, &AcpiBoardInfo, sizeof (ACPI_BOARD_INFO));
    DEBUG ((DEBUG_INFO, "Create acpi board info guid hob\n"));
  }

  return NewAcpiBoardInfo;
}
