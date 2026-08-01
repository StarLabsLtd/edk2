/** @file

  Coreboot platform adapter for the native cdk2 stage.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>
#include <Guid/AcpiBoardInfoGuid.h>
#include <Guid/CbMemTableHob.h>
#include <Guid/CfrSetupMenuGuid.h>
#include <Guid/FirmwareInfoGuid.h>
#include <Guid/GraphicsInfoHob.h>
#include <Guid/SerialPortInfoGuid.h>
#include <Guid/SmmStoreInfoGuid.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h>
#include <IndustryStandard/Tpm20.h>
#include <IndustryStandard/Tpm2Acpi.h>
#include <IndustryStandard/UefiTcgPlatform.h>
#include <Guid/TcgPhysicalPresenceGuid.h>
#include <UniversalPayload/AcpiTable.h>
#include <UniversalPayload/SerialPortInfo.h>
#include <UniversalPayload/SmbiosTable.h>
#include <cdk2/config.h>

#include <cdk2/coreboot_hobs.h>
#include <cdk2/fv.h>
#include <cdk2/pe.h>
#include <cdk2/printk.h>

#define CDK2_COREBOOT_HOB_REGION_SIZE  (0x04000000U)
#define CDK2_COREBOOT_DXE_MAX_PAGES    (0x2000U)
#define CDK2_COREBOOT_TEMP_MAP_LIMIT   (0x2000000000ULL)

#define CDK2_COREBOOT_MAX_TPM2_LOG_SIZE   (1024U * 1024U)
#define CDK2_COREBOOT_MAX_TPM_PCR_INDEX   23U
#define CDK2_COREBOOT_SPEC_ID_EVENT_NAME  "Spec ID Event"
#define CDK2_COREBOOT_CFR_MAX_DEPTH       32U
#define CDK2_COREBOOT_CFR_OPTION_FLAGS_MASK \
  (CFR_OPTFLAG_READONLY | CFR_OPTFLAG_INACTIVE | CFR_OPTFLAG_SUPPRESS | \
   CFR_OPTFLAG_VOLATILE | CFR_OPTFLAG_RUNTIME)

#define CDK2_COREBOOT_8259_COMMAND_REGISTER_MASTER  0x20U
#define CDK2_COREBOOT_8259_MASK_REGISTER_MASTER     0x21U
#define CDK2_COREBOOT_8259_COMMAND_REGISTER_SLAVE   0xA0U
#define CDK2_COREBOOT_8259_MASK_REGISTER_SLAVE      0xA1U
#define CDK2_COREBOOT_8259_EOI                      0x20U
#define CDK2_COREBOOT_IOAPIC_BASE_ADDRESS           0xFEC00000U
#define CDK2_COREBOOT_IOAPIC_VERSION_REGISTER       0x01U
#define CDK2_COREBOOT_IOAPIC_REDIR_TABLE_BASE       0x10U
#define CDK2_COREBOOT_IOAPIC_REDIR_LOW(Index)       \
  (CDK2_COREBOOT_IOAPIC_REDIR_TABLE_BASE + ((Index) * 2U))
#define CDK2_COREBOOT_IOAPIC_REDIR_MASK             BIT16
#define CDK2_COREBOOT_HPET_BASE_ADDRESS             0xFED00000U
#define CDK2_COREBOOT_HPET_CAPABILITIES_OFFSET      0x000U
#define CDK2_COREBOOT_HPET_CONFIGURATION_OFFSET     0x010U
#define CDK2_COREBOOT_HPET_INTERRUPT_STATUS_OFFSET  0x020U
#define CDK2_COREBOOT_HPET_TIMER_BASE_OFFSET        0x100U
#define CDK2_COREBOOT_HPET_TIMER_STRIDE             0x020U
#define CDK2_COREBOOT_HPET_TIMER_CONFIGURATION      0x000U
#define CDK2_COREBOOT_HPET_MAIN_COUNTER_ENABLE      BIT0
#define CDK2_COREBOOT_HPET_LEGACY_ROUTE_ENABLE      BIT1
#define CDK2_COREBOOT_HPET_TIMER_INTERRUPT_ENABLE   BIT2
#define CDK2_COREBOOT_HPET_TIMER_MSI_ENABLE         BIT14
#define CDK2_COREBOOT_SERIAL_LINE_STATUS_OFFSET     5U
#define CDK2_COREBOOT_SERIAL_THR_EMPTY              BIT5
#define CDK2_COREBOOT_SERIAL_POLL_LIMIT             100000U

#if defined (__GNUC__)
#define CDK2_COREBOOT_NORETURN  __attribute__ ((noreturn))
#else
#define CDK2_COREBOOT_NORETURN
#endif

STATIC CDK2_COREBOOT_HANDOFF  mCorebootHandoff;

STATIC CONST EFI_GUID  mCdk2GraphicsInfoHobGuid =
  { 0x39f62cce, 0x6825, 0x4669, { 0xbb, 0x56, 0x54, 0x1a, 0xba, 0x75, 0x3a, 0x07 } };
STATIC CONST EFI_GUID  mCdk2SmmStoreInfoHobGuid =
  { 0xf585ca19, 0x881b, 0x44fb, { 0x3f, 0x3d, 0x81, 0x89, 0x7c, 0x57, 0xbb, 0x01 } };
STATIC CONST EFI_GUID  mCdk2FirmwareInfoHobGuid =
  { 0xe0653829, 0x274e, 0x4b1e, { 0x87, 0x2d, 0xa2, 0x20, 0xf5, 0xaf, 0x8f, 0x3d } };
STATIC CONST EFI_GUID  mCdk2TcgPhysicalPresenceInfoHobGuid =
  { 0xf367be59, 0x5891, 0x40eb, { 0x21, 0x44, 0xed, 0x2e, 0xac, 0x57, 0xfd, 0x14 } };
STATIC CONST EFI_GUID  mCdk2AcpiBoardInfoHobGuid =
  { 0x0ad3d31b, 0xb3d8, 0x4506, { 0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f } };
STATIC CONST EFI_GUID  mCdk2SerialPortInfoGuid =
  { 0xaa7e190d, 0xbe21, 0x4409, { 0x8e, 0x67, 0xa2, 0xcd, 0x0f, 0x61, 0xe1, 0x70 } };
STATIC CONST EFI_GUID  mCdk2LegacySerialPortInfoGuid =
  { 0x6c6872fe, 0x56a9, 0x4403, { 0xbb, 0x98, 0x95, 0x8d, 0x62, 0xde, 0x87, 0xf1 } };
STATIC CONST EFI_GUID  mCdk2AcpiTableGuid =
  { 0x9f9a9506, 0x5597, 0x4515, { 0xba, 0xb6, 0x8b, 0xcd, 0xe7, 0x84, 0xba, 0x87 } };
STATIC CONST EFI_GUID  mCdk2SmbiosTableGuid =
  { 0x590a0d26, 0x06e5, 0x4d20, { 0x8a, 0x82, 0x59, 0xea, 0x1b, 0x34, 0x98, 0x2d } };
STATIC CONST EFI_GUID  mCdk2CorebootTableGuid =
  { 0x9e0d4b6f, 0xa8e8, 0x4d7e, { 0x9a, 0x2d, 0x31, 0x0d, 0x4c, 0x9a, 0x8f, 0x2b } };
STATIC CONST EFI_GUID  mCdk2CfrSetupMenuFormGuid =
  { 0xfbc3b1de, 0xd17c, 0x44de, { 0x98, 0x47, 0x2b, 0xbf, 0x9e, 0xfd, 0xbd, 0x8e } };
STATIC CONST EFI_GUID  mCdk2TcgEvent2EntryHobGuid =
  { 0xd26c221e, 0x2430, 0x4c8a, { 0x91, 0x70, 0x3f, 0xcb, 0x45, 0x00, 0x41, 0x3f } };

#define CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE  (1024U * 1024U)

STATIC
VOID
Cdk2CorebootCopyBytes (
  OUT VOID        *Destination,
  IN  CONST VOID  *Source,
  IN  UINTN        Length
  );

STATIC
UINT16
Cdk2CorebootRead16 (
  IN CONST VOID  *Source
  )
{
  UINT16  Value;

  Cdk2CorebootCopyBytes (&Value, Source, sizeof (Value));
  return Value;
}

STATIC
UINT32
Cdk2CorebootRead32 (
  IN CONST VOID  *Source
  )
{
  UINT32  Value;

  Cdk2CorebootCopyBytes (&Value, Source, sizeof (Value));
  return Value;
}

STATIC
UINT64
Cdk2CorebootRead64 (
  IN CONST VOID  *Source
  )
{
  UINT64  Value;

  Cdk2CorebootCopyBytes (&Value, Source, sizeof (Value));
  return Value;
}

STATIC
UINT32
Cdk2CorebootAcpiRead32 (
  IN CONST VOID  *Source
  )
{
  return Cdk2CorebootRead32 (Source);
}

STATIC
UINT64
Cdk2CorebootAcpiRead64 (
  IN CONST VOID  *Source
  )
{
  return Cdk2CorebootRead64 (Source);
}

STATIC
BOOLEAN
Cdk2CorebootBytesEqual (
  IN CONST VOID  *Left,
  IN CONST VOID  *Right,
  IN UINTN        Length
  )
{
  CONST UINT8  *LeftBytes;
  CONST UINT8  *RightBytes;
  UINTN        Index;

  if (Left == NULL || Right == NULL) {
    return FALSE;
  }

  LeftBytes  = (CONST UINT8 *)Left;
  RightBytes = (CONST UINT8 *)Right;
  for (Index = 0; Index < Length; Index++) {
    if (LeftBytes[Index] != RightBytes[Index]) {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
UINT32
Cdk2CorebootCrc32 (
  IN CONST VOID  *Buffer,
  IN UINTN        Length
  )
{
  CONST UINT8  *Bytes;
  UINT32       Crc;
  UINTN        Index;
  UINTN        BitIndex;

  if (Buffer == NULL) {
    return 0;
  }

  Bytes = (CONST UINT8 *)Buffer;
  Crc   = 0;
  for (Index = 0; Index < Length; Index++) {
    Crc ^= (UINT32)Bytes[Index] << 24;
    for (BitIndex = 0; BitIndex < 8; BitIndex++) {
      if ((Crc & BIT31) != 0) {
        Crc = (Crc << 1) ^ 0x04C11DB7U;
      } else {
        Crc <<= 1;
      }
    }
  }

  return Crc;
}

STATIC
BOOLEAN
Cdk2CorebootAcpiFieldPresent (
  IN CONST EFI_ACPI_DESCRIPTION_HEADER  *Table,
  IN UINTN                              Offset,
  IN UINTN                              Size
  )
{
  return Table != NULL && Table->Length >= Offset && Size <= Table->Length - Offset;
}

STATIC
EFI_STATUS
Cdk2CorebootAcpiInspectTable (
  IN  EFI_PHYSICAL_ADDRESS                                     Address,
  OUT EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE              **Fadt,
  OUT EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER **Mcfg,
  OUT BOOLEAN                                                  *Tpm2Present,
  OUT BOOLEAN                                                  *TcpaPresent,
  OUT EFI_ACPI_DESCRIPTION_HEADER                             **Tpm2Table
  )
{
  EFI_ACPI_DESCRIPTION_HEADER  *Header;

  if (Address == 0 || Fadt == NULL || Mcfg == NULL || Tpm2Present == NULL ||
      TcpaPresent == NULL || Tpm2Table == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }

  Header = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Address;
  if (Header->Length < sizeof (*Header) || Header->Length > CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE) {
    return EFI_COMPROMISED_DATA;
  }

  switch (Header->Signature) {
    case EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE:
      if (!Cdk2CorebootAcpiFieldPresent (
             Header,
             OFFSET_OF (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE, Gpe0BlkLen),
             sizeof (((EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)0)->Gpe0BlkLen)
             ))
      {
        return EFI_COMPROMISED_DATA;
      }

      *Fadt = (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE *)Header;
      break;

    case EFI_ACPI_6_6_PCI_EXPRESS_MEMORY_MAPPED_CONFIGURATION_SPACE_BASE_ADDRESS_DESCRIPTION_TABLE_SIGNATURE:
      if (Header->Length < sizeof (*Header) + sizeof (EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE)) {
        return EFI_COMPROMISED_DATA;
      }

      *Mcfg = (EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *)Header;
      break;

    case EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE:
      *Tpm2Present = TRUE;
      if (*Tpm2Table == NULL) {
        *Tpm2Table = Header;
      }

      break;

    case EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_ALLIANCE_CAPABILITIES_TABLE_SIGNATURE:
      *TcpaPresent = TRUE;
      break;

    default:
      break;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAcpiInspectRoot (
  IN  EFI_PHYSICAL_ADDRESS                                     Address,
  IN  BOOLEAN                                                  Extended,
  OUT EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE              **Fadt,
  OUT EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER **Mcfg,
  OUT BOOLEAN                                                  *Tpm2Present,
  OUT BOOLEAN                                                  *TcpaPresent,
  OUT EFI_ACPI_DESCRIPTION_HEADER                             **Tpm2Table
  )
{
  EFI_ACPI_DESCRIPTION_HEADER  *Header;
  UINTN                        EntryCount;
  UINTN                        EntrySize;
  UINTN                        Index;
  UINT64                       TableAddress;
  EFI_STATUS                   Status;

  if (Address == 0 || Fadt == NULL || Mcfg == NULL || Tpm2Present == NULL ||
      TcpaPresent == NULL || Tpm2Table == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }

  Header = (EFI_ACPI_DESCRIPTION_HEADER *)(UINTN)Address;
  EntrySize = Extended ? sizeof (UINT64) : sizeof (UINT32);
  if (Header->Length < sizeof (*Header) ||
      Header->Length > CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE ||
      ((Header->Length - sizeof (*Header)) % EntrySize) != 0)
  {
    return EFI_COMPROMISED_DATA;
  }

  EntryCount = (Header->Length - sizeof (*Header)) / EntrySize;
  for (Index = 0; Index < EntryCount; Index++) {
    if (Extended) {
      TableAddress = Cdk2CorebootAcpiRead64 ((UINT8 *)(Header + 1) + Index * EntrySize);
    } else {
      TableAddress = Cdk2CorebootAcpiRead32 ((UINT8 *)(Header + 1) + Index * EntrySize);
    }

    Status = Cdk2CorebootAcpiInspectTable (
               TableAddress,
               Fadt,
               Mcfg,
               Tpm2Present,
               TcpaPresent,
               Tpm2Table
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootBuildAcpiBoardInfo (
  IN  CONST struct cb_acpi_rsdp  *Record,
  OUT ACPI_BOARD_INFO            *BoardInfo,
  OUT EFI_PHYSICAL_ADDRESS       *RsdpBase OPTIONAL,
  OUT EFI_ACPI_DESCRIPTION_HEADER **Tpm2Table OPTIONAL
  )
{
  EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER              *Rsdp;
  EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE                 *Fadt;
  EFI_ACPI_MEMORY_MAPPED_CONFIGURATION_BASE_ADDRESS_TABLE_HEADER *Mcfg;
  EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE *McfgBase;
  UINT64                                                     RsdpAddress;
  UINTN                                                      AllocationCount;
  BOOLEAN                                                    Tpm2Present;
  BOOLEAN                                                    TcpaPresent;
  EFI_ACPI_DESCRIPTION_HEADER                                *LocalTpm2Table;
  EFI_STATUS                                                 Status;

  if (Record == NULL || BoardInfo == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  RsdpAddress = (UINT64)Record->rsdp_pointer.lo | ((UINT64)Record->rsdp_pointer.hi << 32);
  if (RsdpAddress == 0) {
    return EFI_NOT_FOUND;
  }

  Rsdp = (EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER *)(UINTN)RsdpAddress;
  if (Rsdp->Signature != EFI_ACPI_3_0_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE) {
    return EFI_COMPROMISED_DATA;
  }

  Fadt        = NULL;
  Mcfg        = NULL;
  Tpm2Present = FALSE;
  TcpaPresent = FALSE;
  LocalTpm2Table = NULL;

  if (Rsdp->RsdtAddress != 0) {
    Status = Cdk2CorebootAcpiInspectRoot (
               Rsdp->RsdtAddress,
               FALSE,
               &Fadt,
               &Mcfg,
               &Tpm2Present,
               &TcpaPresent,
               &LocalTpm2Table
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  if (Rsdp->XsdtAddress != 0) {
    Status = Cdk2CorebootAcpiInspectRoot (
               Rsdp->XsdtAddress,
               TRUE,
               &Fadt,
               &Mcfg,
               &Tpm2Present,
               &TcpaPresent,
               &LocalTpm2Table
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  if (Fadt == NULL) {
    return EFI_NOT_FOUND;
  }

  *BoardInfo = (ACPI_BOARD_INFO){ 0 };
  BoardInfo->PmCtrlRegBase = Fadt->Pm1aCntBlk;
  BoardInfo->PmTimerRegBase = Fadt->PmTmrBlk;
  BoardInfo->PmEvtBase = Fadt->Pm1aEvtBlk;
  BoardInfo->PmGpeEnBase = Fadt->Gpe0Blk + Fadt->Gpe0BlkLen / 2;
  if (Cdk2CorebootAcpiFieldPresent (
        &Fadt->Header,
        OFFSET_OF (EFI_ACPI_3_0_FIXED_ACPI_DESCRIPTION_TABLE, ResetReg),
        sizeof (Fadt->ResetReg)
        ))
  {
    BoardInfo->ResetRegAddress = Fadt->ResetReg.Address;
    BoardInfo->ResetValue      = Fadt->ResetValue;
  }

  BoardInfo->TPM20Present = Tpm2Present;
  BoardInfo->TPM12Present = TcpaPresent;
  if (Mcfg != NULL) {
    AllocationCount = (Mcfg->Header.Length - sizeof (*Mcfg)) /
                      sizeof (EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE);
    if (AllocationCount == 0) {
      return EFI_COMPROMISED_DATA;
    }

    McfgBase = (EFI_ACPI_MEMORY_MAPPED_ENHANCED_CONFIGURATION_SPACE_BASE_ADDRESS_ALLOCATION_STRUCTURE *)(Mcfg + 1);
    if (McfgBase->EndBusNumber < McfgBase->StartBusNumber) {
      return EFI_COMPROMISED_DATA;
    }

    BoardInfo->PcieBaseAddress = McfgBase->BaseAddress;
    BoardInfo->PcieBaseSize =
      (UINT64)(McfgBase->EndBusNumber + 1 - McfgBase->StartBusNumber) * 4096 * 32 * 8;
  }

  if (RsdpBase != NULL) {
    *RsdpBase = RsdpAddress;
  }

  if (Tpm2Table != NULL) {
    *Tpm2Table = LocalTpm2Table;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendAcpiTableHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         RsdpBase
  )
{
  UNIVERSAL_PAYLOAD_ACPI_TABLE  AcpiTable;

  if (RsdpBase == 0) {
    return EFI_INVALID_PARAMETER;
  }

  AcpiTable = (UNIVERSAL_PAYLOAD_ACPI_TABLE){ 0 };
  AcpiTable.Header.Revision = UNIVERSAL_PAYLOAD_ACPI_TABLE_REVISION;
  AcpiTable.Header.Length   = sizeof (AcpiTable);
  AcpiTable.Rsdp            = RsdpBase;

  return Cdk2CorebootAppendGuidHob (
           Handoff,
           &mCdk2AcpiTableGuid,
           &AcpiTable,
           sizeof (AcpiTable)
           );
}

STATIC
UINT16
Cdk2CorebootTpmDigestSize (
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
Cdk2CorebootGetTpm2AcpiEventLog (
  IN  CONST EFI_ACPI_DESCRIPTION_HEADER  *Table,
  OUT UINT32                             *Laml,
  OUT EFI_PHYSICAL_ADDRESS               *Lasa
  )
{
  UINTN  LogAreaOffset;
  UINTN  ParametersSize;

  if (Table == NULL || Laml == NULL || Lasa == NULL ||
      Table->Signature != EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE ||
      Table->Revision < EFI_TPM2_ACPI_TABLE_REVISION_4 ||
      Table->Length < sizeof (EFI_TPM2_ACPI_TABLE))
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

  *Laml = Cdk2CorebootRead32 ((CONST UINT8 *)Table + LogAreaOffset);
  *Lasa = Cdk2CorebootRead64 ((CONST UINT8 *)Table + LogAreaOffset + sizeof (*Laml));
  return *Laml != 0 && *Lasa != 0 && *Laml <= CDK2_COREBOOT_MAX_TPM2_LOG_SIZE;
}

STATIC
BOOLEAN
Cdk2CorebootGetTcgPcrEvent2Size (
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

  if (Event == NULL || EventSize == NULL || EventDataOffset == NULL || EventDataSize == NULL) {
    return FALSE;
  }

  Offset = sizeof (TCG_PCRINDEX) + sizeof (TCG_EVENTTYPE);
  if (Remaining < Offset + sizeof (Count) + sizeof (*EventDataSize)) {
    return FALSE;
  }

  PcrIndex = Cdk2CorebootRead32 (Event);
  if (PcrIndex > CDK2_COREBOOT_MAX_TPM_PCR_INDEX) {
    return FALSE;
  }

  Count  = Cdk2CorebootRead32 (Event + Offset);
  Offset += sizeof (Count);
  if (Count == 0 || Count > HASH_COUNT) {
    return FALSE;
  }

  for (Index = 0; Index < Count; Index++) {
    if (Remaining < Offset + sizeof (HashAlg)) {
      return FALSE;
    }

    HashAlg = Cdk2CorebootRead16 (Event + Offset);
    Offset += sizeof (HashAlg);

    DigestSize = Cdk2CorebootTpmDigestSize (HashAlg);
    if (DigestSize == 0 || Remaining < Offset + DigestSize) {
      return FALSE;
    }

    Offset += DigestSize;
  }

  if (Remaining < Offset + sizeof (*EventDataSize)) {
    return FALSE;
  }

  *EventDataSize = Cdk2CorebootRead32 (Event + Offset);
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
Cdk2CorebootIsSpecIdEvent (
  IN CONST UINT8  *EventData,
  IN UINT32       EventSize
  )
{
  if (EventSize < sizeof (CDK2_COREBOOT_SPEC_ID_EVENT_NAME) - 1) {
    return FALSE;
  }

  return Cdk2CorebootBytesEqual (
           EventData,
           CDK2_COREBOOT_SPEC_ID_EVENT_NAME,
           sizeof (CDK2_COREBOOT_SPEC_ID_EVENT_NAME) - 1
           );
}

STATIC
UINTN
Cdk2CorebootGetFirstTcgPcrEvent2Offset (
  IN CONST UINT8  *EventLog,
  IN UINTN        EventLogSize
  )
{
  UINT32  EventDataSize;
  UINTN   EventSizeOffset;
  UINTN   FirstEventOffset;

  if (EventLog == NULL || EventLogSize < sizeof (TCG_PCR_EVENT_HDR)) {
    return 0;
  }

  if (Cdk2CorebootRead32 (EventLog + sizeof (TCG_PCRINDEX)) != EV_NO_ACTION) {
    return 0;
  }

  EventSizeOffset = sizeof (TCG_PCRINDEX) + sizeof (TCG_EVENTTYPE) + sizeof (TCG_DIGEST);
  EventDataSize   = Cdk2CorebootRead32 (EventLog + EventSizeOffset);
  FirstEventOffset = sizeof (TCG_PCR_EVENT_HDR) + EventDataSize;
  if (EventLogSize < FirstEventOffset ||
      !Cdk2CorebootIsSpecIdEvent (EventLog + sizeof (TCG_PCR_EVENT_HDR), EventDataSize))
  {
    return 0;
  }

  return FirstEventOffset;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendTpmEventHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE   *Handoff,
  IN     EFI_ACPI_DESCRIPTION_HEADER  *Tpm2Table
  )
{
  UINT8                 *EventLog;
  UINTN                 EventDataOffset;
  UINT32                EventDataSize;
  UINTN                 EventSize;
  UINT32                Laml;
  EFI_PHYSICAL_ADDRESS  Lasa;
  UINT32                EventType;
  UINTN                 Offset;
  EFI_STATUS            Status;

  if (Tpm2Table == NULL) {
    return EFI_SUCCESS;
  }

  if (!Cdk2CorebootGetTpm2AcpiEventLog (Tpm2Table, &Laml, &Lasa)) {
    return EFI_SUCCESS;
  }

  EventLog = (UINT8 *)(UINTN)Lasa;
  Offset   = Cdk2CorebootGetFirstTcgPcrEvent2Offset (EventLog, Laml);
  while (Offset < Laml) {
    if (!Cdk2CorebootGetTcgPcrEvent2Size (
           EventLog + Offset,
           Laml - Offset,
           &EventSize,
           &EventDataOffset,
           &EventDataSize
           ))
    {
      break;
    }

    EventType = Cdk2CorebootRead32 (EventLog + Offset + sizeof (TCG_PCRINDEX));
    if (EventType != EV_NO_ACTION ||
        !Cdk2CorebootIsSpecIdEvent (EventLog + Offset + EventDataOffset, EventDataSize))
    {
      Status = Cdk2CorebootAppendGuidHob (
                 Handoff,
                 &mCdk2TcgEvent2EntryHobGuid,
                 EventLog + Offset,
                 EventSize
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }

    Offset += EventSize;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendAcpiHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     CONST CDK2_COREBOOT_HANDOFF *Coreboot
  )
{
  CONST VOID                   *Record;
  ACPI_BOARD_INFO              BoardInfo;
  EFI_PHYSICAL_ADDRESS         RsdpBase;
  EFI_ACPI_DESCRIPTION_HEADER  *Tpm2Table;
  EFI_STATUS                   Status;

  Status = Cdk2CorebootFindRecord (
             Coreboot,
             CB_TAG_ACPI_RSDP,
             CDK2_COREBOOT_ACPI_RSDP_MIN_SIZE,
             &Record
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootBuildAcpiBoardInfo (
             (CONST struct cb_acpi_rsdp *)Record,
             &BoardInfo,
             &RsdpBase,
             &Tpm2Table
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendAcpiTableHob (Handoff, RsdpBase);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendGuidHob (
             Handoff,
             &mCdk2AcpiBoardInfoHobGuid,
             &BoardInfo,
             sizeof (BoardInfo)
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Cdk2CorebootAppendTpmEventHobs (Handoff, Tpm2Table);
}

STATIC
EFI_STATUS
Cdk2CorebootAppendCorebootTableHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE   *Handoff,
  IN     CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  COREBOOT_TABLE_HOB  TableHob;

  if (Coreboot == NULL || Coreboot->Header == NULL || Coreboot->TableSize > MAX_UINT32) {
    return EFI_INVALID_PARAMETER;
  }

  TableHob = (COREBOOT_TABLE_HOB){ 0 };
  TableHob.Address = (UINT64)(UINTN)Coreboot->Header;
  TableHob.Size    = (UINT32)Coreboot->TableSize;

  return Cdk2CorebootAppendGuidHob (
           Handoff,
           &mCdk2CorebootTableGuid,
           &TableHob,
           sizeof (TableHob)
           );
}

STATIC
EFI_STATUS
Cdk2CorebootFindCbmemEntry (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Coreboot,
  IN  UINT32                        Id,
  IN  UINT32                        MinimumSize,
  OUT EFI_PHYSICAL_ADDRESS         *Base,
  OUT UINT32                       *Size OPTIONAL
  )
{
  CONST struct cb_record       *Record;
  CONST struct cb_cbmem_entry  *Entry;
  CONST UINT8                  *Cursor;
  UINTN                        Remaining;
  UINTN                        Index;

  if (Coreboot == NULL || Coreboot->Header == NULL || Base == NULL ||
      Coreboot->Header->header_bytes > Coreboot->TableSize)
  {
    return EFI_INVALID_PARAMETER;
  }

  Cursor    = (CONST UINT8 *)Coreboot->Header + Coreboot->Header->header_bytes;
  Remaining = Coreboot->TableSize - Coreboot->Header->header_bytes;
  for (Index = 0; Index < Coreboot->RecordCount; Index++) {
    if (Remaining < sizeof (struct cb_record)) {
      return EFI_COMPROMISED_DATA;
    }

    Record = (CONST struct cb_record *)(CONST VOID *)Cursor;
    if (Record->size < sizeof (struct cb_record) || Record->size > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    if (Record->tag == CB_TAG_CBMEM_ENTRY) {
      if (Record->size < sizeof (*Entry)) {
        return EFI_COMPROMISED_DATA;
      }

      Entry = (CONST struct cb_cbmem_entry *)Record;
      if (Entry->id == Id) {
        *Base = (EFI_PHYSICAL_ADDRESS)Entry->address.lo |
                ((EFI_PHYSICAL_ADDRESS)Entry->address.hi << 32);
        if (*Base == 0 || Entry->entry_size < MinimumSize ||
            *Base > MAX_UINT64 - Entry->entry_size)
        {
          return EFI_COMPROMISED_DATA;
        }

        if (Size != NULL) {
          *Size = Entry->entry_size;
        }

        return EFI_SUCCESS;
      }
    }

    Cursor    += Record->size;
    Remaining -= Record->size;
  }

  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendSmbiosHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE   *Handoff,
  IN     CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  UNIVERSAL_PAYLOAD_SMBIOS_TABLE  SmbiosTable;
  EFI_PHYSICAL_ADDRESS            SmbiosBase;
  EFI_STATUS                      Status;

  Status = Cdk2CorebootFindCbmemEntry (
             Coreboot,
             SIGNATURE_32 ('T', 'B', 'M', 'S'),
             1,
             &SmbiosBase,
             NULL
             );
  if (Status == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  SmbiosTable = (UNIVERSAL_PAYLOAD_SMBIOS_TABLE){ 0 };
  SmbiosTable.Header.Revision  = UNIVERSAL_PAYLOAD_SMBIOS_TABLE_REVISION;
  SmbiosTable.Header.Length    = sizeof (SmbiosTable);
  SmbiosTable.SmBiosEntryPoint = SmbiosBase;

  return Cdk2CorebootAppendGuidHob (
           Handoff,
           &mCdk2SmbiosTableGuid,
           &SmbiosTable,
           sizeof (SmbiosTable)
           );
}

#if CONFIG_CDK2_CAPSULE
STATIC
EFI_STATUS
Cdk2CorebootAppendCapsuleHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE   *Handoff,
  IN     CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  CONST struct cb_record  *Record;
  CONST struct cb_range   *Range;
  CONST UINT8             *Cursor;
  UINTN                   Remaining;
  UINTN                   Index;
  EFI_STATUS              Status;

  if (Coreboot == NULL || Coreboot->Header == NULL ||
      Coreboot->Header->header_bytes > Coreboot->TableSize)
  {
    return EFI_INVALID_PARAMETER;
  }

  Cursor    = (CONST UINT8 *)Coreboot->Header + Coreboot->Header->header_bytes;
  Remaining = Coreboot->TableSize - Coreboot->Header->header_bytes;
  for (Index = 0; Index < Coreboot->RecordCount; Index++) {
    if (Remaining < sizeof (struct cb_record)) {
      return EFI_COMPROMISED_DATA;
    }

    Record = (CONST struct cb_record *)(CONST VOID *)Cursor;
    if (Record->size < sizeof (struct cb_record) || Record->size > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    if (Record->tag == CB_TAG_CAPSULE) {
      if (Record->size < sizeof (*Range)) {
        return EFI_COMPROMISED_DATA;
      }

      Range = (CONST struct cb_range *)Record;
      if (Range->range_start == 0 || Range->range_size == 0 ||
          Range->range_start > MAX_UINT64 - Range->range_size)
      {
        return EFI_COMPROMISED_DATA;
      }

      Status = Cdk2CorebootAppendCapsuleHob (
                 Handoff,
                 Range->range_start,
                 Range->range_size
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }

    Cursor    += Record->size;
    Remaining -= Record->size;
  }

  return EFI_SUCCESS;
}
#endif

STATIC
CFR_VARBINARY *
Cdk2CorebootCfrExtractVarBinary (
  IN     UINT8   *Buffer,
  IN OUT UINTN   *Offset,
  IN     UINTN   BufferSize,
  IN     UINT32  TargetTag
  )
{
  CFR_VARBINARY  *VarBinary;
  UINTN          RequiredSize;

  if (Buffer == NULL || Offset == NULL || *Offset > BufferSize ||
      BufferSize - *Offset < sizeof (*VarBinary))
  {
    return NULL;
  }

  VarBinary = (CFR_VARBINARY *)(Buffer + *Offset);
  if (VarBinary->tag != TargetTag) {
    return NULL;
  }

  if (VarBinary->size < sizeof (*VarBinary) ||
      VarBinary->size > BufferSize - *Offset ||
      VarBinary->data_length > VarBinary->size - sizeof (*VarBinary))
  {
    return NULL;
  }

  RequiredSize = (sizeof (*VarBinary) + VarBinary->data_length + 3U) & ~(UINTN)3U;
  if (VarBinary->size != RequiredSize) {
    return NULL;
  }

  if (TargetTag == CB_TAG_CFR_DEP_VALUES) {
    if ((VarBinary->data_length % sizeof (UINT32)) != 0) {
      return NULL;
    }
  } else if (VarBinary->data_length == 0 ||
             VarBinary->data[VarBinary->data_length - 1] != '\0')
  {
    return NULL;
  }

  *Offset += VarBinary->size;
  return VarBinary;
}

STATIC
EFI_STATUS
Cdk2CorebootCfrValidateVarBinary (
  IN     CONST UINT8  *Buffer,
  IN OUT UINTN        *Offset,
  IN     UINTN        BufferSize,
  IN     UINT32       Tag
  )
{
  if (Cdk2CorebootCfrExtractVarBinary ((UINT8 *)Buffer, Offset, BufferSize, Tag) == NULL) {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootCfrValidateObject (
  IN CONST UINT8  *Buffer,
  IN UINTN        BufferSize,
  IN UINTN        Depth
  )
{
  CONST CFR_OPTION_FORM     *Header;
  CONST CFR_OPTION_NUMERIC  *Numeric;
  CONST CFR_ENUM_VALUE      *EnumValue;
  CONST CFR_RUNTIME_APPLY   *RuntimeApply;
  UINTN                     Offset;
  UINTN                     EnumOffset;
  EFI_STATUS                Status;

  if (Depth > CDK2_COREBOOT_CFR_MAX_DEPTH || BufferSize < sizeof (*Header)) {
    return EFI_COMPROMISED_DATA;
  }

  Header = (CONST CFR_OPTION_FORM *)Buffer;
  if (Header->size < sizeof (*Header) || Header->size > BufferSize ||
      (Header->flags & ~CDK2_COREBOOT_CFR_OPTION_FLAGS_MASK) != 0)
  {
    return EFI_COMPROMISED_DATA;
  }

  switch (Header->tag) {
    case CB_TAG_CFR_OPTION_FORM:
      Offset = sizeof (CFR_OPTION_FORM);
      Status = Cdk2CorebootCfrValidateVarBinary (
                 Buffer,
                 &Offset,
                 Header->size,
                 CB_TAG_CFR_VARCHAR_UI_NAME
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_DEP_VALUES
        );

      while (Offset < Header->size) {
        Status = Cdk2CorebootCfrValidateObject (
                   Buffer + Offset,
                   Header->size - Offset,
                   Depth + 1
                   );
        if (EFI_ERROR (Status)) {
          return Status;
        }

        Offset += ((CONST CFR_OPTION_FORM *)(Buffer + Offset))->size;
      }

      return (Offset == Header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

    case CB_TAG_CFR_OPTION_ENUM:
    case CB_TAG_CFR_OPTION_NUMBER:
    case CB_TAG_CFR_OPTION_BOOL:
      if (Header->size < sizeof (CFR_OPTION_NUMERIC)) {
        return EFI_COMPROMISED_DATA;
      }

      Numeric = (CONST CFR_OPTION_NUMERIC *)Buffer;
      Offset  = sizeof (CFR_OPTION_NUMERIC);
      Status  = Cdk2CorebootCfrValidateVarBinary (
                  Buffer,
                  &Offset,
                  Header->size,
                  CB_TAG_CFR_VARCHAR_OPT_NAME
                  );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Status = Cdk2CorebootCfrValidateVarBinary (
                 Buffer,
                 &Offset,
                 Header->size,
                 CB_TAG_CFR_VARCHAR_UI_NAME
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_VARCHAR_UI_HELPTEXT
        );
      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_DEP_VALUES
        );

      if (Header->size - Offset >= sizeof (CFR_RUNTIME_APPLY)) {
        RuntimeApply = (CONST CFR_RUNTIME_APPLY *)(Buffer + Offset);
        if (RuntimeApply->tag == CB_TAG_CFR_RUNTIME_APPLY) {
          if (RuntimeApply->size != sizeof (CFR_RUNTIME_APPLY)) {
            return EFI_COMPROMISED_DATA;
          }

          Offset += RuntimeApply->size;
        }
      }

      if (Numeric->tag != CB_TAG_CFR_OPTION_ENUM) {
        return (Offset == Header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
      }

      while (Offset < Header->size) {
        if (Header->size - Offset < sizeof (CFR_ENUM_VALUE)) {
          return EFI_COMPROMISED_DATA;
        }

        EnumValue = (CONST CFR_ENUM_VALUE *)(Buffer + Offset);
        if (EnumValue->tag != CB_TAG_CFR_ENUM_VALUE ||
            EnumValue->size < sizeof (CFR_ENUM_VALUE) ||
            EnumValue->size > Header->size - Offset)
        {
          return EFI_COMPROMISED_DATA;
        }

        EnumOffset = sizeof (CFR_ENUM_VALUE);
        Status = Cdk2CorebootCfrValidateVarBinary (
                   (CONST UINT8 *)EnumValue,
                   &EnumOffset,
                   EnumValue->size,
                   CB_TAG_CFR_VARCHAR_UI_NAME
                   );
        if (EFI_ERROR (Status) || EnumOffset != EnumValue->size) {
          return EFI_COMPROMISED_DATA;
        }

        Offset += EnumValue->size;
      }

      return EFI_SUCCESS;

    case CB_TAG_CFR_OPTION_VARCHAR:
      Offset = sizeof (CFR_OPTION_VARCHAR);
      Status = Cdk2CorebootCfrValidateVarBinary (
                 Buffer,
                 &Offset,
                 Header->size,
                 CB_TAG_CFR_VARCHAR_DEF_VALUE
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Status = Cdk2CorebootCfrValidateVarBinary (
                 Buffer,
                 &Offset,
                 Header->size,
                 CB_TAG_CFR_VARCHAR_OPT_NAME
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Status = Cdk2CorebootCfrValidateVarBinary (
                 Buffer,
                 &Offset,
                 Header->size,
                 CB_TAG_CFR_VARCHAR_UI_NAME
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_VARCHAR_UI_HELPTEXT
        );
      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_DEP_VALUES
        );
      return (Offset == Header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

    case CB_TAG_CFR_OPTION_COMMENT:
      Offset = sizeof (CFR_OPTION_COMMENT);
      Status = Cdk2CorebootCfrValidateVarBinary (
                 Buffer,
                 &Offset,
                 Header->size,
                 CB_TAG_CFR_VARCHAR_UI_NAME
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_VARCHAR_UI_HELPTEXT
        );
      Cdk2CorebootCfrExtractVarBinary (
        (UINT8 *)Buffer,
        &Offset,
        Header->size,
        CB_TAG_CFR_DEP_VALUES
        );
      return (Offset == Header->size) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;

    default:
      return EFI_COMPROMISED_DATA;
  }
}

STATIC
EFI_STATUS
Cdk2CorebootCfrValidateForm (
  IN CONST CFR_OPTION_FORM  *Form,
  IN UINTN                  FormSize
  )
{
  EFI_STATUS  Status;

  if (Form == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2CorebootCfrValidateObject ((CONST UINT8 *)Form, FormSize, 0);
  if (EFI_ERROR (Status) || Form->tag != CB_TAG_CFR_OPTION_FORM || Form->size != FormSize) {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendCfrHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE   *Handoff,
  IN     CONST CDK2_COREBOOT_HANDOFF  *Coreboot
  )
{
  CONST VOID             *Record;
  CONST struct cb_cfr    *Root;
  CONST CFR_OPTION_FORM  *Form;
  UINTN                  ProcessedLength;
  EFI_STATUS             Status;

  Status = Cdk2CorebootFindRecord (
             Coreboot,
             CB_TAG_CFR_ROOT,
             sizeof (*Root),
             &Record
             );
  if (Status == EFI_NOT_FOUND) {
    return EFI_SUCCESS;
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Root = (CONST struct cb_cfr *)Record;
  if (Root->version != CB_CFR_VERSION ||
      Root->size < sizeof (*Root) ||
      Cdk2CorebootCrc32 (Root + 1, Root->size - sizeof (*Root)) != Root->checksum)
  {
    return EFI_COMPROMISED_DATA;
  }

  ProcessedLength = sizeof (*Root);
  while (ProcessedLength < Root->size) {
    if (Root->size - ProcessedLength < sizeof (*Form)) {
      return EFI_COMPROMISED_DATA;
    }

    Form = (CONST CFR_OPTION_FORM *)((CONST UINT8 *)Root + ProcessedLength);
    if (Form->size > Root->size - ProcessedLength) {
      return EFI_COMPROMISED_DATA;
    }

    Status = Cdk2CorebootCfrValidateForm (Form, Form->size);
    if (EFI_ERROR (Status)) {
      return EFI_COMPROMISED_DATA;
    }

    Status = Cdk2CorebootAppendGuidHob (
               Handoff,
               &mCdk2CfrSetupMenuFormGuid,
               Form,
               Form->size
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    ProcessedLength += Form->size;
  }

  return EFI_SUCCESS;
}

typedef struct {
  EFI_PHYSICAL_ADDRESS    EndOfHobList;
  EFI_PHYSICAL_ADDRESS    FreeMemoryBottom;
  EFI_HOB_GENERIC_HEADER  EndMarker;
} CDK2_COREBOOT_HOB_APPEND_STATE;

STATIC
UINT32
Cdk2CorebootPixelMask (
  IN UINT8  Size,
  IN UINT8  Position
  )
{
  if (Size == 0 || Position >= 32 || Size > 32 - Position) {
    return 0;
  }

  if (Size == 32) {
    return MAX_UINT32;
  }

  return ((1U << Size) - 1U) << Position;
}

STATIC
VOID
Cdk2CorebootCopyBytes (
  OUT VOID        *Destination,
  IN  CONST VOID  *Source,
  IN  UINTN        Length
  )
{
  UINT8        *DestinationBytes;
  CONST UINT8  *SourceBytes;
  UINTN         Index;

  DestinationBytes = (UINT8 *)Destination;
  SourceBytes      = (CONST UINT8 *)Source;
  for (Index = 0; Index < Length; Index++) {
    DestinationBytes[Index] = SourceBytes[Index];
  }
}

typedef struct {
  UINT16  OffsetLow;
  UINT16  Selector;
  UINT8   Ist;
  UINT8   Attributes;
  UINT16  OffsetMiddle;
  UINT32  OffsetHigh;
  UINT32  Reserved;
} CDK2_NATIVE_IDT_GATE;

typedef struct __attribute__ ((packed)) {
  UINT16  Limit;
  UINTN   Base;
} CDK2_NATIVE_IDTR;

#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  #if defined (__GNUC__)
STATIC CDK2_NATIVE_IDT_GATE  mCdk2NativeIdt[256]
  __attribute__ ((aligned (16)));
  #else
STATIC CDK2_NATIVE_IDT_GATE  mCdk2NativeIdt[256];
  #endif

extern VOID  Cdk2NativeExceptionDeadLoop (VOID);
#endif

extern UINT8  __cdk2_image_start[];
extern UINT8  __cdk2_image_end[];

#if defined (__GNUC__)
extern CONST UINT8  __cdk2_fv_start[] __attribute__ ((weak));
extern CONST UINT8  __cdk2_fv_end[]   __attribute__ ((weak));
#else
extern CONST UINT8  __cdk2_fv_start[];
extern CONST UINT8  __cdk2_fv_end[];
#endif

STATIC
VOID
Cdk2CorebootIoWrite8 (
  IN UINT16  Port,
  IN UINT8   Value
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  __asm__ volatile ("outb %0, %w1" : : "a" (Value), "Nd" (Port));
#else
  (void)Port;
  (void)Value;
#endif
}

#if CONFIG_CDK2_SERIAL
STATIC
UINT8
Cdk2CorebootIoRead8 (
  IN UINT16  Port
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  UINT8  Value;

  __asm__ volatile ("inb %w1, %0" : "=a" (Value) : "Nd" (Port));
  return Value;
#else
  (void)Port;
  return 0xFFU;
#endif
}

STATIC
VOID
Cdk2CorebootSerialWriteChar (
  IN UINT16  Base,
  IN CHAR8   Character
  )
{
  UINTN  Timeout;

  if (Character == '\n') {
    Cdk2CorebootSerialWriteChar (Base, '\r');
  }

  for (Timeout = 0; Timeout < CDK2_COREBOOT_SERIAL_POLL_LIMIT; Timeout++) {
    if ((Cdk2CorebootIoRead8 (Base + CDK2_COREBOOT_SERIAL_LINE_STATUS_OFFSET) &
         CDK2_COREBOOT_SERIAL_THR_EMPTY) != 0)
    {
      break;
    }
  }

  Cdk2CorebootIoWrite8 (Base, (UINT8)Character);
}
#endif

STATIC
VOID
EFIAPI
Cdk2CorebootLogWrite (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Level,
  IN     CONST CHAR8           *Buffer,
  IN     UINTN                 Length
  )
{
#if CONFIG_CDK2_SERIAL
  CONST VOID              *Record;
  CONST struct cb_serial  *Serial;
  EFI_STATUS              Status;
  UINTN                   Index;

  (void)Context;
  (void)Level;
  if (Buffer == NULL || Length == 0) {
    return;
  }

  Status = Cdk2CorebootFindRecord (
             &mCorebootHandoff,
             CB_TAG_SERIAL,
             CDK2_COREBOOT_SERIAL_MIN_SIZE,
             &Record
             );
  if (EFI_ERROR (Status)) {
    return;
  }

  Serial = (CONST struct cb_serial *)Record;
  if (Serial->type != CB_SERIAL_TYPE_IO_MAPPED ||
      Serial->regwidth != 1 ||
      Serial->baseaddr > MAX_UINT16)
  {
    return;
  }

  for (Index = 0; Index < Length; Index++) {
    Cdk2CorebootSerialWriteChar ((UINT16)Serial->baseaddr, Buffer[Index]);
  }
#else
  (void)Context;
  (void)Level;
  (void)Buffer;
  (void)Length;
#endif
}

STATIC
UINT32
Cdk2CorebootIoApicRead (
  IN UINT32  Register
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  volatile UINT32  *Index;
  volatile UINT32  *Data;

  Index = (volatile UINT32 *)(UINTN)(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x00U);
  Data  = (volatile UINT32 *)(UINTN)(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x10U);
  *Index = Register;
  return *Data;
#else
  (void)Register;
  return 0;
#endif
}

STATIC
VOID
Cdk2CorebootIoApicWrite (
  IN UINT32  Register,
  IN UINT32  Value
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  volatile UINT32  *Index;
  volatile UINT32  *Data;

  Index = (volatile UINT32 *)(UINTN)(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x00U);
  Data  = (volatile UINT32 *)(UINTN)(CDK2_COREBOOT_IOAPIC_BASE_ADDRESS + 0x10U);
  *Index = Register;
  *Data  = Value;
#else
  (void)Register;
  (void)Value;
#endif
}

STATIC
UINT64
Cdk2CorebootMmioRead64 (
  IN UINTN  Address
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  return *(volatile UINT64 *)(UINTN)Address;
#else
  (void)Address;
  return 0;
#endif
}

STATIC
VOID
Cdk2CorebootMmioWrite64 (
  IN UINTN   Address,
  IN UINT64  Value
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  *(volatile UINT64 *)(UINTN)Address = Value;
#else
  (void)Address;
  (void)Value;
#endif
}

STATIC
VOID
Cdk2CorebootDisableHpetInterrupts (
  VOID
  )
{
  UINT64  Capabilities;
  UINT64  Configuration;
  UINT64  TimerConfiguration;
  UINTN   TimerCount;
  UINTN   TimerIndex;
  UINTN   TimerAddress;

  Capabilities = Cdk2CorebootMmioRead64 (
                   CDK2_COREBOOT_HPET_BASE_ADDRESS + CDK2_COREBOOT_HPET_CAPABILITIES_OFFSET
                   );
  if ((Capabilities & 0xffU) == 0 || Capabilities == MAX_UINT64) {
    return;
  }

  Configuration = Cdk2CorebootMmioRead64 (
                    CDK2_COREBOOT_HPET_BASE_ADDRESS + CDK2_COREBOOT_HPET_CONFIGURATION_OFFSET
                    );
  Configuration &= ~(CDK2_COREBOOT_HPET_MAIN_COUNTER_ENABLE |
                     CDK2_COREBOOT_HPET_LEGACY_ROUTE_ENABLE);
  Cdk2CorebootMmioWrite64 (
    CDK2_COREBOOT_HPET_BASE_ADDRESS + CDK2_COREBOOT_HPET_CONFIGURATION_OFFSET,
    Configuration
    );

  // HPET interrupt status is write-one-to-clear.
  Cdk2CorebootMmioWrite64 (
    CDK2_COREBOOT_HPET_BASE_ADDRESS + CDK2_COREBOOT_HPET_INTERRUPT_STATUS_OFFSET,
    MAX_UINT64
    );

  TimerCount = ((Capabilities >> 8) & 0x1fU) + 1U;
  for (TimerIndex = 0; TimerIndex < TimerCount; TimerIndex++) {
    TimerAddress = CDK2_COREBOOT_HPET_BASE_ADDRESS +
                   CDK2_COREBOOT_HPET_TIMER_BASE_OFFSET +
                   TimerIndex * CDK2_COREBOOT_HPET_TIMER_STRIDE +
                   CDK2_COREBOOT_HPET_TIMER_CONFIGURATION;
    TimerConfiguration = Cdk2CorebootMmioRead64 (TimerAddress);
    TimerConfiguration &= ~(CDK2_COREBOOT_HPET_TIMER_INTERRUPT_ENABLE |
                            CDK2_COREBOOT_HPET_TIMER_MSI_ENABLE);
    Cdk2CorebootMmioWrite64 (TimerAddress, TimerConfiguration);
  }
}

STATIC
VOID
Cdk2CorebootMaskIoApicInterrupts (
  VOID
  )
{
  UINT32  IoApicVersion;
  UINT32  RedirectionCount;
  UINT32  Index;
  UINT32  RedirectionLow;

  IoApicVersion = Cdk2CorebootIoApicRead (CDK2_COREBOOT_IOAPIC_VERSION_REGISTER);
  if (IoApicVersion == 0 || IoApicVersion == MAX_UINT32) {
    return;
  }

  RedirectionCount = ((IoApicVersion >> 16) & 0xffU) + 1U;
  if (RedirectionCount > 0x100U) {
    RedirectionCount = 0x100U;
  }

  for (Index = 0; Index < RedirectionCount; Index++) {
    RedirectionLow = Cdk2CorebootIoApicRead (CDK2_COREBOOT_IOAPIC_REDIR_LOW (Index));
    Cdk2CorebootIoApicWrite (
      CDK2_COREBOOT_IOAPIC_REDIR_LOW (Index),
      RedirectionLow | CDK2_COREBOOT_IOAPIC_REDIR_MASK
      );
  }
}

STATIC
EFI_STATUS
EFIAPI
Cdk2CorebootBuildPlatformHobs (
  IN OUT CDK2_NATIVE_CONTEXT        *Context,
  OUT    EFI_HOB_HANDOFF_INFO_TABLE **Handoff
  )
{
  UINT8                              PhysicalAddressBits;
  UINT32                             MaximumFunction;
  UINT32                             Eax;
  EFI_STATUS                         Status;
  CONST VOID                         *Record;
  CONST struct cb_serial                 *Serial;
  CONST struct cb_framebuffer            *Framebuffer;
  CONST struct cb_smmstorev2             *SmmStore;
  CONST struct lb_efi_fw_info            *Firmware;
  CONST struct cb_tpm_physical_presence  *TpmPpi;
  CONST struct cb_string                 *Version;
  CONST struct cb_string                 *ExtraVersion;
  UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  SerialInfo;
  SERIAL_PORT_INFO                    LegacySerialInfo;
  EFI_PEI_GRAPHICS_INFO_HOB           GraphicsInfo;
  SMMSTORE_INFO                       SmmStoreInfo;
  FIRMWARE_INFO                       FirmwareInfo;
  TCG_PHYSICAL_PRESENCE_INFO          TpmPpiInfo;
  UINT32                              RedMask;
  UINT32                              GreenMask;
  UINT32                              BlueMask;
  UINT32                              ReservedMask;
  UINTN                               Length;
  UINTN                               VersionLength;

  if (Context == NULL || Handoff == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2CorebootBuildHobs (
             &mCorebootHandoff,
             Context->HobMemoryBottom,
             Context->HobMemoryTop,
             Context->HobFreeMemoryBottom,
             Context->HobFreeMemoryTop,
             CONFIG_CDK2_CAPSULE != 0,
             Handoff
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendMemoryAllocationHob (
             *Handoff,
             Context->PayloadBase,
             Context->PayloadSize,
             EfiBootServicesData
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  PhysicalAddressBits = 36;
#if defined (__x86_64__)
  __asm__ volatile (
    "cpuid"
    : "=a" (Eax)
    : "a" (0x80000000U)
    : "rbx", "rcx", "rdx"
    );
  MaximumFunction = Eax;
  if (MaximumFunction >= 0x80000008U) {
    __asm__ volatile (
      "cpuid"
      : "=a" (Eax)
      : "a" (0x80000008U)
      : "rbx", "rcx", "rdx"
      );
    PhysicalAddressBits = (UINT8)(Eax & 0xffU);
  }
#endif

  Status = Cdk2CorebootAppendCpuHob (*Handoff, PhysicalAddressBits, 16);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendCorebootTableHob (*Handoff, &mCorebootHandoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendAcpiHobs (*Handoff, &mCorebootHandoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendSmbiosHob (*Handoff, &mCorebootHandoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // CFR backs the optional setup UI. Match the legacy ParseMiscInfo() path by
  // continuing when the data is absent, unsupported, or malformed.
  //
  (VOID)Cdk2CorebootAppendCfrHobs (*Handoff, &mCorebootHandoff);

#if CONFIG_CDK2_CAPSULE
  Status = Cdk2CorebootAppendCapsuleHobs (*Handoff, &mCorebootHandoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }
#endif

  Status = Cdk2CorebootFindRecord (
             &mCorebootHandoff,
             CB_TAG_SERIAL,
             CDK2_COREBOOT_SERIAL_MIN_SIZE,
             &Record
             );
  if (!EFI_ERROR (Status)) {
    Serial = (CONST struct cb_serial *)Record;
    SerialInfo = (UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO){ 0 };
    SerialInfo.Header.Revision = UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION;
    SerialInfo.Header.Length   = sizeof (SerialInfo);
    SerialInfo.UseMmio         = (Serial->type == CB_SERIAL_TYPE_IO_MAPPED) ? FALSE : TRUE;
    SerialInfo.RegisterStride  = (UINT8)Serial->regwidth;
    SerialInfo.BaudRate        = Serial->baud;
    SerialInfo.RegisterBase    = Serial->baseaddr;
    Status = Cdk2CorebootAppendGuidHob (
               *Handoff,
               &mCdk2SerialPortInfoGuid,
               &SerialInfo,
               sizeof (SerialInfo)
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (Serial->size >= CDK2_COREBOOT_RECORD_FIELD_END (struct cb_serial, input_hertz) &&
        Serial->input_hertz != 0)
    {
      LegacySerialInfo = (SERIAL_PORT_INFO){ 0 };
      LegacySerialInfo.Revision   = 1;
      LegacySerialInfo.Type       = Serial->type;
      LegacySerialInfo.BaseAddr   = Serial->baseaddr;
      LegacySerialInfo.Baud       = Serial->baud;
      LegacySerialInfo.RegWidth   = Serial->regwidth;
      LegacySerialInfo.InputHertz = Serial->input_hertz;
      if (Serial->size >= CDK2_COREBOOT_RECORD_FIELD_END (struct cb_serial, uart_pci_addr)) {
        LegacySerialInfo.UartPciAddr = Serial->uart_pci_addr;
      }

      Status = Cdk2CorebootAppendGuidHob (
                 *Handoff,
                 &mCdk2LegacySerialPortInfoGuid,
                 &LegacySerialInfo,
                 sizeof (LegacySerialInfo)
                 );
      if (EFI_ERROR (Status)) {
        return Status;
      }
    }
  } else if (Status != EFI_NOT_FOUND) {
    return Status;
  }

  Status = Cdk2CorebootFindRecord (
             &mCorebootHandoff,
             CB_TAG_FRAMEBUFFER,
             CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE,
             &Record
             );
  if (!EFI_ERROR (Status)) {
    Framebuffer = (CONST struct cb_framebuffer *)Record;
    if (Framebuffer->bits_per_pixel == 0 || Framebuffer->bits_per_pixel > 32 ||
        Framebuffer->x_resolution == 0 || Framebuffer->y_resolution == 0 ||
        Framebuffer->bytes_per_line > MAX_UINT32 / Framebuffer->y_resolution ||
        Framebuffer->bytes_per_line > MAX_UINT32 / 8U)
    {
      return EFI_COMPROMISED_DATA;
    }

    RedMask      = Cdk2CorebootPixelMask (Framebuffer->red_mask_size, Framebuffer->red_mask_pos);
    GreenMask    = Cdk2CorebootPixelMask (Framebuffer->green_mask_size, Framebuffer->green_mask_pos);
    BlueMask     = Cdk2CorebootPixelMask (Framebuffer->blue_mask_size, Framebuffer->blue_mask_pos);
    ReservedMask = Cdk2CorebootPixelMask (Framebuffer->reserved_mask_size, Framebuffer->reserved_mask_pos);
    if ((Framebuffer->red_mask_size != 0 && RedMask == 0) ||
        (Framebuffer->green_mask_size != 0 && GreenMask == 0) ||
        (Framebuffer->blue_mask_size != 0 && BlueMask == 0) ||
        (Framebuffer->reserved_mask_size != 0 && ReservedMask == 0))
    {
      return EFI_COMPROMISED_DATA;
    }

    GraphicsInfo = (EFI_PEI_GRAPHICS_INFO_HOB){ 0 };
    GraphicsInfo.FrameBufferBase = Framebuffer->physical_address;
    GraphicsInfo.FrameBufferSize = (UINT64)Framebuffer->bytes_per_line * Framebuffer->y_resolution;
    GraphicsInfo.GraphicsMode.Version = 0;
    GraphicsInfo.GraphicsMode.HorizontalResolution = Framebuffer->x_resolution;
    GraphicsInfo.GraphicsMode.VerticalResolution = Framebuffer->y_resolution;
    GraphicsInfo.GraphicsMode.PixelsPerScanLine =
      (Framebuffer->bytes_per_line * 8U) / Framebuffer->bits_per_pixel;
    GraphicsInfo.GraphicsMode.PixelInformation.RedMask      = RedMask;
    GraphicsInfo.GraphicsMode.PixelInformation.GreenMask    = GreenMask;
    GraphicsInfo.GraphicsMode.PixelInformation.BlueMask     = BlueMask;
    GraphicsInfo.GraphicsMode.PixelInformation.ReservedMask = ReservedMask;
    GraphicsInfo.GraphicsMode.PixelFormat = PixelBitMask;
    if (Framebuffer->bits_per_pixel == 32 &&
        Framebuffer->red_mask_size == 8 && Framebuffer->green_mask_size == 8 &&
        Framebuffer->blue_mask_size == 8 && Framebuffer->reserved_mask_size == 8 &&
        Framebuffer->red_mask_pos == 0 && Framebuffer->green_mask_pos == 8 &&
        Framebuffer->blue_mask_pos == 16)
    {
      GraphicsInfo.GraphicsMode.PixelFormat = PixelRedGreenBlueReserved8BitPerColor;
    } else if (Framebuffer->bits_per_pixel == 32 &&
               Framebuffer->red_mask_size == 8 && Framebuffer->green_mask_size == 8 &&
               Framebuffer->blue_mask_size == 8 && Framebuffer->reserved_mask_size == 8 &&
               Framebuffer->blue_mask_pos == 0 && Framebuffer->green_mask_pos == 8 &&
               Framebuffer->red_mask_pos == 16)
    {
      GraphicsInfo.GraphicsMode.PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
    }

    Status = Cdk2CorebootAppendGuidHob (
               *Handoff,
               &mCdk2GraphicsInfoHobGuid,
               &GraphicsInfo,
               sizeof (GraphicsInfo)
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Status != EFI_NOT_FOUND) {
    return Status;
  }

  Status = Cdk2CorebootFindRecord (
             &mCorebootHandoff,
             CB_TAG_SMMSTOREV2,
             CDK2_COREBOOT_SMMSTOREV2_MIN_SIZE,
             &Record
             );
  if (!EFI_ERROR (Status)) {
    SmmStore = (CONST struct cb_smmstorev2 *)Record;
    SmmStoreInfo = (SMMSTORE_INFO){ 0 };
    SmmStoreInfo.ComBuffer     = SmmStore->com_buffer;
    SmmStoreInfo.ComBufferSize = SmmStore->com_buffer_size;
    SmmStoreInfo.NumBlocks     = SmmStore->num_blocks;
    SmmStoreInfo.BlockSize     = SmmStore->block_size;
    SmmStoreInfo.MmioAddress   = SmmStore->mmap_addr;
    SmmStoreInfo.ApmCmd        = SmmStore->apm_cmd;
    Status = Cdk2CorebootAppendGuidHob (
               *Handoff,
               &mCdk2SmmStoreInfoHobGuid,
               &SmmStoreInfo,
               sizeof (SmmStoreInfo)
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Status != EFI_NOT_FOUND) {
    return Status;
  }

  Status = Cdk2CorebootFindRecord (
             &mCorebootHandoff,
             CB_TAG_FW_INFO,
             CDK2_COREBOOT_FW_INFO_MIN_SIZE,
             &Record
             );
  if (!EFI_ERROR (Status)) {
    Firmware = (CONST struct lb_efi_fw_info *)Record;
    FirmwareInfo = (FIRMWARE_INFO){ 0 };
    VersionLength = 0;
    Cdk2CorebootCopyBytes (&FirmwareInfo.Type, Firmware->guid, sizeof (FirmwareInfo.Type));
    FirmwareInfo.Version                = Firmware->version;
    FirmwareInfo.LowestSupportedVersion = Firmware->lowest_supported_version;
    FirmwareInfo.ImageSize              = Firmware->fw_size;

    Status = Cdk2CorebootFindRecord (
               &mCorebootHandoff,
               CB_TAG_VERSION,
               sizeof (struct cb_record) + 1,
               (CONST VOID **)&Version
               );
    if (!EFI_ERROR (Status)) {
      Length = Version->size - sizeof (*Version);
      if (Length >= sizeof (FirmwareInfo.VersionStr)) {
        Length = sizeof (FirmwareInfo.VersionStr) - 1;
      }

      Cdk2CorebootCopyBytes (FirmwareInfo.VersionStr, Version->string, Length);
      VersionLength = Length;
    } else if (Status != EFI_NOT_FOUND) {
      return Status;
    }

    Status = Cdk2CorebootFindRecord (
               &mCorebootHandoff,
               CB_TAG_EXTRA_VERSION,
               sizeof (struct cb_record) + 1,
               (CONST VOID **)&ExtraVersion
    );
    if (!EFI_ERROR (Status)) {
      Length = ExtraVersion->size - sizeof (*ExtraVersion);
      if (Length > sizeof (FirmwareInfo.VersionStr) - 1 - VersionLength) {
        Length = sizeof (FirmwareInfo.VersionStr) - 1 - VersionLength;
      }

      Cdk2CorebootCopyBytes (
        &FirmwareInfo.VersionStr[VersionLength],
        ExtraVersion->string,
        Length
        );
      VersionLength += Length;
    } else if (Status != EFI_NOT_FOUND) {
      return Status;
    }

    FirmwareInfo.VersionStr[VersionLength] = '\0';

    Status = Cdk2CorebootAppendGuidHob (
               *Handoff,
               &mCdk2FirmwareInfoHobGuid,
               &FirmwareInfo,
               sizeof (FirmwareInfo)
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Status != EFI_NOT_FOUND) {
    return Status;
  }

  Status = Cdk2CorebootFindRecord (
             &mCorebootHandoff,
             CB_TAG_TPM_PPI_HANDOFF,
             CDK2_COREBOOT_TPM_PPI_MIN_SIZE,
             &Record
             );
  if (!EFI_ERROR (Status)) {
    TpmPpi = (CONST struct cb_tpm_physical_presence *)Record;
    TpmPpiInfo = (TCG_PHYSICAL_PRESENCE_INFO){ 0 };
    TpmPpiInfo.PpiAddress = TpmPpi->ppi_address;
    if (TpmPpi->tpm_version == LB_TPM_VERSION_TPM_VERSION_1_2) {
      TpmPpiInfo.TpmVersion = UEFIPAYLOAD_TPM_VERSION_1_2;
    } else if (TpmPpi->tpm_version == LB_TPM_VERSION_TPM_VERSION_2) {
      TpmPpiInfo.TpmVersion = UEFIPAYLOAD_TPM_VERSION_2;
    }

    if ((TpmPpi->ppi_version >> 4) == 1 && (TpmPpi->ppi_version & 0x0f) >= 3) {
      TpmPpiInfo.PpiVersion = UEFIPAYLOAD_TPM_PPI_VERSION_1_30;
    }

    Status = Cdk2CorebootAppendGuidHob (
               *Handoff,
               &mCdk2TcgPhysicalPresenceInfoHobGuid,
               &TpmPpiInfo,
               sizeof (TpmPpiInfo)
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Status != EFI_NOT_FOUND) {
    return Status;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
Cdk2CorebootFindHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT    UINTN                *HobMemBase
  )
{
  if (Context == NULL || HobMemBase == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // entry32.S maps 0..128 GiB while this stage builds HOBs and loads DXE.
  return Cdk2CorebootFindHobMemoryBase (
           &mCorebootHandoff,
           Context->PayloadBase,
           Context->PayloadSize,
           Context->HobRegionSize,
           CDK2_COREBOOT_TEMP_MAP_LIMIT,
           HobMemBase
           );
}

STATIC
EFI_STATUS
EFIAPI
Cdk2CorebootInitializeFloatingPoint (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  UINTN  Cr4;
  UINTN  Handler;
  UINTN  Index;
  CDK2_NATIVE_IDTR  Idtr;
#endif

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

#if defined (__x86_64__) && !defined (CDK2_COREBOOT_BACKEND_TEST)
  __asm__ volatile ("fninit");
  __asm__ volatile ("mov %%cr4, %0" : "=r" (Cr4));
  Cr4 |= BIT9;
  __asm__ volatile ("mov %0, %%cr4" : : "r" (Cr4) : "memory");

  Handler = (UINTN)Cdk2NativeExceptionDeadLoop;
  for (Index = 0; Index < ARRAY_SIZE (mCdk2NativeIdt); Index++) {
    mCdk2NativeIdt[Index].OffsetLow    = (UINT16)Handler;
    mCdk2NativeIdt[Index].Selector     = 0x18;
    mCdk2NativeIdt[Index].Ist          = 0;
    mCdk2NativeIdt[Index].Attributes   = 0x8e;
    mCdk2NativeIdt[Index].OffsetMiddle = (UINT16)(Handler >> 16);
    mCdk2NativeIdt[Index].OffsetHigh   = (UINT32)(Handler >> 32);
    mCdk2NativeIdt[Index].Reserved     = 0;
  }

  Idtr.Limit = sizeof (mCdk2NativeIdt) - 1;
  Idtr.Base  = (UINTN)mCdk2NativeIdt;
  __asm__ volatile ("lidt %0" : : "m" (Idtr));
#endif
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
Cdk2CorebootMaskLegacyInterrupts (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Cdk2CorebootDisableHpetInterrupts ();
  Cdk2CorebootMaskIoApicInterrupts ();
  Cdk2CorebootIoWrite8 (CDK2_COREBOOT_8259_MASK_REGISTER_MASTER, 0xFF);
  Cdk2CorebootIoWrite8 (CDK2_COREBOOT_8259_MASK_REGISTER_SLAVE, 0xFF);
  Cdk2CorebootIoWrite8 (CDK2_COREBOOT_8259_COMMAND_REGISTER_SLAVE, CDK2_COREBOOT_8259_EOI);
  Cdk2CorebootIoWrite8 (CDK2_COREBOOT_8259_COMMAND_REGISTER_MASTER, CDK2_COREBOOT_8259_EOI);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootSaveHobAppendState (
  IN  EFI_HOB_HANDOFF_INFO_TABLE       *Handoff,
  OUT CDK2_COREBOOT_HOB_APPEND_STATE  *State
  )
{
  EFI_HOB_GENERIC_HEADER  *End;

  if (Handoff == NULL || State == NULL || Handoff->EfiEndOfHobList == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Handoff->EfiEndOfHobList > (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - sizeof (*End))) {
    return EFI_COMPROMISED_DATA;
  }

  End = (EFI_HOB_GENERIC_HEADER *)(UINTN)Handoff->EfiEndOfHobList;
  if (End->HobType != EFI_HOB_TYPE_END_OF_HOB_LIST ||
      End->HobLength != sizeof (*End))
  {
    return EFI_COMPROMISED_DATA;
  }

  State->EndOfHobList     = Handoff->EfiEndOfHobList;
  State->FreeMemoryBottom = Handoff->EfiFreeMemoryBottom;
  State->EndMarker        = *End;
  return EFI_SUCCESS;
}

STATIC
VOID
Cdk2CorebootRestoreHobAppendState (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE             *Handoff,
  IN     CONST CDK2_COREBOOT_HOB_APPEND_STATE  *State
  )
{
  if (Handoff == NULL || State == NULL || State->EndOfHobList == 0) {
    return;
  }

  Handoff->EfiEndOfHobList     = State->EndOfHobList;
  Handoff->EfiFreeMemoryBottom = State->FreeMemoryBottom;
  *(EFI_HOB_GENERIC_HEADER *)(UINTN)State->EndOfHobList = State->EndMarker;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendLoadedDxeCoreHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         FvBase,
  IN     UINTN                        FvSize,
  IN     CONST EFI_GUID              *ModuleName,
  IN     EFI_PHYSICAL_ADDRESS         ImageBase,
  IN     UINTN                        ImageSize,
  IN     EFI_PHYSICAL_ADDRESS         EntryPoint
  )
{
  CDK2_COREBOOT_HOB_APPEND_STATE  AppendState;
  EFI_STATUS                      Status;

  Status = Cdk2CorebootSaveHobAppendState (Handoff, &AppendState);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendFvHob (Handoff, FvBase, FvSize);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = Cdk2CorebootAppendMemoryAllocationHob (
             Handoff,
             ImageBase,
             ImageSize,
             EfiBootServicesCode
             );
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = Cdk2CorebootAppendModuleHob (
             Handoff,
             ModuleName,
             ImageBase,
             ImageSize,
             EntryPoint
             );
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  return EFI_SUCCESS;

Failed:
  Cdk2CorebootRestoreHobAppendState (Handoff, &AppendState);
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
Cdk2CorebootLoadDxeCore (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT    EFI_PHYSICAL_ADDRESS *EntryPoint,
  OUT    EFI_PHYSICAL_ADDRESS *ImageBase,
  OUT    UINTN                *ImageSize
  )
{
  CDK2_NATIVE_DXE_CORE  DxeCore;
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_PHYSICAL_ADDRESS   Destination;
  EFI_PHYSICAL_ADDRESS   SavedAllocationBottom;
  EFI_PHYSICAL_ADDRESS   SavedAllocationTop;
  EFI_PHYSICAL_ADDRESS   SavedFreeMemoryTop;
  UINTN                  FvSize;
  UINTN                  AvailablePages;
  UINTN                  Pages;
  UINTN                  LoadedImageSize;
  EFI_STATUS             Status;

  if (Context == NULL || EntryPoint == NULL || ImageBase == NULL || ImageSize == NULL ||
      Context->HobList == NULL ||
      __cdk2_fv_start == NULL || __cdk2_fv_end == NULL ||
      &__cdk2_fv_end[0] <= &__cdk2_fv_start[0])
  {
    return EFI_NOT_FOUND;
  }

  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList;
  FvSize = (UINTN)(__cdk2_fv_end - __cdk2_fv_start);
  Status = Cdk2NativeFindDxeCore (__cdk2_fv_start, FvSize, &DxeCore);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Context->AllocationTop < Context->AllocationBottom) {
    return EFI_COMPROMISED_DATA;
  }

  AvailablePages = (Context->AllocationTop - Context->AllocationBottom) / EFI_PAGE_SIZE;
  Pages = (AvailablePages < CDK2_COREBOOT_DXE_MAX_PAGES) ? AvailablePages : CDK2_COREBOOT_DXE_MAX_PAGES;
  if (Pages == 0) {
    return EFI_OUT_OF_RESOURCES;
  }

  SavedAllocationBottom = Context->AllocationBottom;
  SavedAllocationTop    = Context->AllocationTop;
  SavedFreeMemoryTop    = Handoff->EfiFreeMemoryTop;
  Status = Cdk2NativeAllocatePages (Context, Pages, &Destination);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeLoadPe32Plus (
             DxeCore.Pe32Image,
             DxeCore.Pe32Size,
             Destination,
             Pages * EFI_PAGE_SIZE,
             ImageBase,
             ImageSize,
             EntryPoint
             );
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  LoadedImageSize = EFI_SIZE_TO_PAGES (*ImageSize) * EFI_PAGE_SIZE;
  Status = Cdk2CorebootAppendLoadedDxeCoreHobs (
             Handoff,
             (EFI_PHYSICAL_ADDRESS)(UINTN)__cdk2_fv_start,
             FvSize,
             &DxeCore.DxeCoreFile->Name,
             *ImageBase,
             LoadedImageSize,
             *EntryPoint
             );
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  return EFI_SUCCESS;

Failed:
  Context->AllocationBottom = SavedAllocationBottom;
  Context->AllocationTop    = SavedAllocationTop;
  Handoff->EfiFreeMemoryTop = SavedFreeMemoryTop;
  *EntryPoint = 0;
  *ImageBase  = 0;
  *ImageSize  = 0;
  return Status;
}

STATIC
VOID
CDK2_COREBOOT_NORETURN
Cdk2CorebootJumpToDxeCore (
  IN EFI_PHYSICAL_ADDRESS  EntryPoint,
  IN VOID                  *HobList,
  IN VOID                  *StackTop
  )
{
#if defined (__x86_64__)
  __asm__ volatile (
    "cli\n\t"
    "mov %[stack], %%rsp\n\t"
    "xor %%rbp, %%rbp\n\t"
    "mov %[hob], %%rcx\n\t"
    "xor %%rdx, %%rdx\n\t"
    "xor %%r8, %%r8\n\t"
    "xor %%r9, %%r9\n\t"
    "mov %[entry], %%rax\n\t"
    "jmp *%%rax\n\t"
    :
    : [stack] "r" (StackTop),
      [hob] "r" (HobList),
      [entry] "r" ((UINTN)EntryPoint)
    : "rax", "memory"
    );
#endif
  __builtin_unreachable ();
}

STATIC
EFI_STATUS
EFIAPI
Cdk2CorebootTransfer (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_PHYSICAL_ADDRESS         SavedAllocationBottom;
  EFI_PHYSICAL_ADDRESS         SavedAllocationTop;
  EFI_PHYSICAL_ADDRESS         SavedFreeMemoryTop;
  EFI_PHYSICAL_ADDRESS         StackBase;
  UINTN                        StackPages;
  EFI_STATUS                   Status;

  if (Context == NULL || Context->HobList == NULL || Context->ImageEntryPoint == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2NativeHandoff (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handoff               = (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList;
  SavedAllocationBottom = Context->AllocationBottom;
  SavedAllocationTop    = Context->AllocationTop;
  SavedFreeMemoryTop    = Handoff->EfiFreeMemoryTop;
  StackPages = 0x20;
  Status = Cdk2NativeAllocatePages (Context, StackPages, &StackBase);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootAppendStackHob (
             (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList,
             StackBase,
             StackPages * EFI_PAGE_SIZE
             );
  if (EFI_ERROR (Status)) {
    Context->AllocationBottom = SavedAllocationBottom;
    Context->AllocationTop    = SavedAllocationTop;
    Handoff->EfiFreeMemoryTop = SavedFreeMemoryTop;
    return Status;
  }

  Cdk2CorebootJumpToDxeCore (
    Context->ImageEntryPoint,
    Context->HobList,
    (VOID *)(UINTN)(StackBase + StackPages * EFI_PAGE_SIZE - 0x28)
    );
  return EFI_DEVICE_ERROR;
}

#if defined (CDK2_COREBOOT_BACKEND_TEST)
EFI_STATUS
EFIAPI
Cdk2CorebootTestTransfer (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  return Cdk2CorebootTransfer (Context);
}

EFI_STATUS
EFIAPI
Cdk2CorebootTestAppendLoadedDxeCoreHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         FvBase,
  IN     UINTN                        FvSize,
  IN     CONST EFI_GUID              *ModuleName,
  IN     EFI_PHYSICAL_ADDRESS         ImageBase,
  IN     UINTN                        ImageSize,
  IN     EFI_PHYSICAL_ADDRESS         EntryPoint
  )
{
  return Cdk2CorebootAppendLoadedDxeCoreHobs (
           Handoff,
           FvBase,
           FvSize,
           ModuleName,
           ImageBase,
           ImageSize,
           EntryPoint
           );
}
#endif

EFI_STATUS
EFIAPI
Cdk2PlatformInitializeNativeContext (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  )
{
  CDK2_COREBOOT_HANDOFF  Handoff;
  EFI_STATUS             Status;

  if (Context == NULL || &__cdk2_image_end[0] <= &__cdk2_image_start[0])
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2NativeInitializeStageContext (Context, BootloaderParameter);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2CorebootParse (BootloaderParameter, &Handoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mCorebootHandoff       = Handoff;
  Context->PayloadBase   = (EFI_PHYSICAL_ADDRESS)(UINTN)__cdk2_image_start;
  Context->PayloadSize   = (UINTN)(__cdk2_image_end - __cdk2_image_start);
  Context->HobRegionSize = CDK2_COREBOOT_HOB_REGION_SIZE;
  Context->Backend.BuildPlatformHobs       = Cdk2CorebootBuildPlatformHobs;
  Context->Backend.FindHobMemory             = Cdk2CorebootFindHobMemory;
  Context->Backend.InitializeFloatingPoint  = Cdk2CorebootInitializeFloatingPoint;
  Context->Backend.MaskLegacyInterrupts     = Cdk2CorebootMaskLegacyInterrupts;
  Context->Backend.LoadDxeCore               = Cdk2CorebootLoadDxeCore;
  Context->Backend.Transfer                  = Cdk2CorebootTransfer;
  Context->Backend.LogWrite                  = Cdk2CorebootLogWrite;
#if !defined (CDK2_COREBOOT_BACKEND_TEST)
  Cdk2Printk (
    Context,
    CDK2_BIOS_INFO,
    "cdk2: coreboot table=%p payload=%p size=%u\n",
    Handoff.Header,
    (CONST VOID *)(UINTN)Context->PayloadBase,
    Context->PayloadSize
    );
#endif
  return EFI_SUCCESS;
}
