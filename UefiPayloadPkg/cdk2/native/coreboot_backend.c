/** @file

  Coreboot platform adapter for the native cdk2 stage.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>
#include <Guid/AcpiBoardInfoGuid.h>
#include <Guid/FirmwareInfoGuid.h>
#include <Guid/GraphicsInfoHob.h>
#include <Guid/SmmStoreInfoGuid.h>
#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/MemoryMappedConfigurationSpaceAccessTable.h>
#include <Guid/TcgPhysicalPresenceGuid.h>
#include <UniversalPayload/SerialPortInfo.h>

#include "coreboot_hobs.h"
#include "fv.h"
#include "pe.h"

#define CDK2_COREBOOT_HOB_REGION_SIZE  (0x04000000U)
#define CDK2_COREBOOT_DXE_MAX_PAGES    (0x2000U)
#define CDK2_COREBOOT_TEMP_MAP_LIMIT   (0x2000000000ULL)

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

#define CDK2_COREBOOT_MAX_ACPI_TABLE_SIZE  (1024U * 1024U)

STATIC
VOID
Cdk2CorebootCopyBytes (
  OUT VOID        *Destination,
  IN  CONST VOID  *Source,
  IN  UINTN        Length
  );

STATIC
UINT32
Cdk2CorebootAcpiRead32 (
  IN CONST VOID  *Source
  )
{
  UINT32  Value;

  Cdk2CorebootCopyBytes (&Value, Source, sizeof (Value));
  return Value;
}

STATIC
UINT64
Cdk2CorebootAcpiRead64 (
  IN CONST VOID  *Source
  )
{
  UINT64  Value;

  Cdk2CorebootCopyBytes (&Value, Source, sizeof (Value));
  return Value;
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
  OUT BOOLEAN                                                  *TcpaPresent
  )
{
  EFI_ACPI_DESCRIPTION_HEADER  *Header;

  if (Address == 0 || Fadt == NULL || Mcfg == NULL || Tpm2Present == NULL || TcpaPresent == NULL) {
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
  OUT BOOLEAN                                                  *TcpaPresent
  )
{
  EFI_ACPI_DESCRIPTION_HEADER  *Header;
  UINTN                        EntryCount;
  UINTN                        EntrySize;
  UINTN                        Index;
  UINT64                       TableAddress;
  EFI_STATUS                   Status;

  if (Address == 0 || Fadt == NULL || Mcfg == NULL || Tpm2Present == NULL || TcpaPresent == NULL) {
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
               TcpaPresent
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
  OUT ACPI_BOARD_INFO            *BoardInfo
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

  if (Rsdp->RsdtAddress != 0) {
    Status = Cdk2CorebootAcpiInspectRoot (
               Rsdp->RsdtAddress,
               FALSE,
               &Fadt,
               &Mcfg,
               &Tpm2Present,
               &TcpaPresent
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
               &TcpaPresent
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

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootAppendAcpiBoardInfoHob (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     CONST CDK2_COREBOOT_HANDOFF *Coreboot
  )
{
  CONST VOID        *Record;
  ACPI_BOARD_INFO   BoardInfo;
  EFI_STATUS        Status;

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
             &BoardInfo
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Cdk2CorebootAppendGuidHob (
           Handoff,
           &mCdk2AcpiBoardInfoHobGuid,
           &BoardInfo,
           sizeof (BoardInfo)
           );
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

#if defined (__GNUC__)
STATIC CDK2_NATIVE_IDT_GATE  mCdk2NativeIdt[256]
  __attribute__ ((aligned (16)));
#else
STATIC CDK2_NATIVE_IDT_GATE  mCdk2NativeIdt[256];
#endif

extern VOID  Cdk2NativeExceptionDeadLoop (VOID);

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
  CONST struct cb_serial              *Serial;
  CONST struct cb_framebuffer         *Framebuffer;
  CONST struct cb_smmstorev2          *SmmStore;
  CONST struct lb_efi_fw_info         *Firmware;
  CONST struct cb_tpm_physical_presence *TpmPpi;
  CONST struct cb_string              *Version;
  CONST struct cb_string              *ExtraVersion;
  UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  SerialInfo;
  EFI_PEI_GRAPHICS_INFO_HOB           GraphicsInfo;
  SMMSTORE_INFO                       SmmStoreInfo;
  FIRMWARE_INFO                       FirmwareInfo;
  TCG_PHYSICAL_PRESENCE_INFO          TpmPpiInfo;
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

  Status = Cdk2CorebootAppendAcpiBoardInfoHob (*Handoff, &mCorebootHandoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }

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
    if (Framebuffer->bits_per_pixel == 0 || Framebuffer->y_resolution == 0 ||
        Framebuffer->bytes_per_line > MAX_UINT32 / Framebuffer->y_resolution ||
        Framebuffer->bytes_per_line > MAX_UINT32 / 8U)
    {
      return EFI_COMPROMISED_DATA;
    }

    GraphicsInfo = (EFI_PEI_GRAPHICS_INFO_HOB){ 0 };
    GraphicsInfo.FrameBufferBase = Framebuffer->physical_address;
    GraphicsInfo.FrameBufferSize = Framebuffer->bytes_per_line * Framebuffer->y_resolution;
    GraphicsInfo.GraphicsMode.Version = 0;
    GraphicsInfo.GraphicsMode.HorizontalResolution = Framebuffer->x_resolution;
    GraphicsInfo.GraphicsMode.VerticalResolution = Framebuffer->y_resolution;
    GraphicsInfo.GraphicsMode.PixelsPerScanLine =
      (Framebuffer->bytes_per_line * 8U) / Framebuffer->bits_per_pixel;
    GraphicsInfo.GraphicsMode.PixelInformation.RedMask =
      Cdk2CorebootPixelMask (Framebuffer->red_mask_size, Framebuffer->red_mask_pos);
    GraphicsInfo.GraphicsMode.PixelInformation.GreenMask =
      Cdk2CorebootPixelMask (Framebuffer->green_mask_size, Framebuffer->green_mask_pos);
    GraphicsInfo.GraphicsMode.PixelInformation.BlueMask =
      Cdk2CorebootPixelMask (Framebuffer->blue_mask_size, Framebuffer->blue_mask_pos);
    GraphicsInfo.GraphicsMode.PixelInformation.ReservedMask =
      Cdk2CorebootPixelMask (Framebuffer->reserved_mask_size, Framebuffer->reserved_mask_pos);
    if (Framebuffer->red_mask_pos == 0 && Framebuffer->green_mask_pos == 8 &&
        Framebuffer->blue_mask_pos == 16)
    {
      GraphicsInfo.GraphicsMode.PixelFormat = PixelRedGreenBlueReserved8BitPerColor;
    } else if (Framebuffer->blue_mask_pos == 0 && Framebuffer->green_mask_pos == 8 &&
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
  UINTN  Cr4;
  UINTN  Handler;
  UINTN  Index;
  CDK2_NATIVE_IDTR  Idtr;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

#if defined (__x86_64__)
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
  Context->Backend.LoadDxeCore               = Cdk2CorebootLoadDxeCore;
  Context->Backend.Transfer                  = Cdk2CorebootTransfer;
  return EFI_SUCCESS;
}
