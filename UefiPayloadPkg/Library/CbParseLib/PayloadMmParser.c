/** @file
  Translate the downstream coreboot MM handoff into standard MM HOBs.

  Copyright (c) 2025, 9elements GmbH.<BR>
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiPei.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include <Guid/MmCommBuffer.h>
#include <Guid/MmUnblockRegion.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <Guid/SmmS3CommunicationInfoGuid.h>
#include <Guid/SmramMemoryReserve.h>
#include <Guid/SpiFlashInfoGuid.h>
#include <Coreboot.h>
#include <IndustryStandard/Pci.h>
#include "PayloadMmParser.h"

VOID *
FindCbTag (
  IN UINT32  Tag
  );

UINT64
cb_unpack64 (
  IN struct cbuint64  Value
  );

STATIC
EFI_STATUS
UnblockMmRange (
  IN EFI_PHYSICAL_ADDRESS  Base,
  IN UINT64                Size
  )
{
  MM_UNBLOCK_REGION  Region;

  if ((Base == 0) || (Size == 0) || ((Base & EFI_PAGE_MASK) != 0) ||
      ((Size & EFI_PAGE_MASK) != 0) || (Size > MAX_UINT64 - Base))
  {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (&Region, sizeof (Region));
  CopyGuid (&Region.IdentifierGuid, &gEfiCallerIdGuid);
  Region.PhysicalStart = Base;
  Region.NumberOfPages = EFI_SIZE_TO_PAGES (Size);
  if (BuildGuidDataHob (&gMmUnblockRegionHobGuid, &Region, sizeof (Region)) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BuildMmCommunicationHob (
  VOID
  )
{
  MM_COMM_BUFFER  Buffer;
  EFI_STATUS      Status;

  ZeroMem (&Buffer, sizeof (Buffer));
  Buffer.NumberOfPages = FixedPcdGet32 (PcdMmCommBufferPages);
  if ((Buffer.NumberOfPages == 0) || (Buffer.NumberOfPages > MAX_UINTN / EFI_PAGE_SIZE)) {
    return EFI_INVALID_PARAMETER;
  }

  Buffer.PhysicalStart = (UINTN)AllocateRuntimePages ((UINTN)Buffer.NumberOfPages);
  Buffer.Status        = (UINTN)AllocateRuntimePages (1);
  if ((Buffer.PhysicalStart == 0) || (Buffer.Status == 0)) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem ((VOID *)(UINTN)Buffer.PhysicalStart, EFI_PAGES_TO_SIZE ((UINTN)Buffer.NumberOfPages));
  ZeroMem ((VOID *)(UINTN)Buffer.Status, EFI_PAGE_SIZE);
  Status = UnblockMmRange (Buffer.PhysicalStart, EFI_PAGES_TO_SIZE (Buffer.NumberOfPages));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = UnblockMmRange (Buffer.Status, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (BuildGuidDataHob (&gMmCommBufferHobGuid, &Buffer, sizeof (Buffer)) == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ParsePayloadMmFeatureInfo (
  VOID
  )
{
  struct cb_payload_mm_interface_info   *Interface;
  struct cb_payload_mm_smram_region     *Smram;
  struct cb_payload_mm_shared_mem       *Shared;
  struct cb_pld_mm_spi_controller_info  *Spi;
  PAYLOAD_MM_INTERFACE_INFO             InterfaceInfo;
  PLD_S3_COMMUNICATION                  SharedInfo;
  EFI_SMRAM_HOB_DESCRIPTOR_BLOCK        *SmramInfo;
  SPI_FLASH_INFO                        SpiInfo;
  VARIABLE_FLASH_INFO                   FlashInfo;
  EFI_PHYSICAL_ADDRESS                  SmramBase;
  UINT64                                SmramSize;
  UINT64                                SharedBase;
  UINT64                                StoreBase;
  UINT64                                SpiBase;
  UINT64                                HandlerBase;
  UINT64                                HandlerSize;
  UINT32                                SpiBar;
  EFI_STATUS                            Status;

  Interface = FindCbTag (CB_TAG_PAYLOAD_MM_INTERFACE_INFO);
  Smram     = FindCbTag (CB_TAG_PAYLOAD_MM_SMRAM_REGION);
  Shared    = FindCbTag (CB_TAG_PAYLOAD_MM_SHARED_MEM);
  Spi       = FindCbTag (CB_TAG_PLD_MM_SPI_CONTROLLER_INFO);
  if ((Interface == NULL) || (Smram == NULL) || (Shared == NULL) || (Spi == NULL)) {
    return EFI_NOT_FOUND;
  }

  if ((Interface->size != sizeof (*Interface)) || (Interface->revision != 0) ||
      (Interface->pad != 0) || (Interface->bootloader_smm_is_64bit > 1) ||
      (Interface->apm_cmd != PAYLOAD_MM_APM_COMMAND) || (Smram->size != sizeof (*Smram)) ||
      (Shared->size != sizeof (*Shared)) || (Spi->size != sizeof (*Spi)) ||
      (Spi->revision != 1) || (Spi->flags != 0) ||
      (Spi->spi_address.address_space_id != SPACE_ID_PCI_CONFIGURATION) ||
      (Spi->spi_address.register_bit_width != 32) ||
      (Spi->spi_address.register_bit_offset != 0) || (Spi->spi_address.reserved != 0) ||
      (cb_unpack64 (Spi->spi_address.value) != 0))
  {
    return EFI_UNSUPPORTED;
  }

  SmramBase   = cb_unpack64 (Smram->descriptor.physical_start);
  SmramSize   = cb_unpack64 (Smram->descriptor.physical_size);
  SharedBase  = cb_unpack64 (Shared->comm_buffer.physical_start);
  StoreBase   = cb_unpack64 (Spi->store_base);
  SpiBase     = cb_unpack64 (Spi->spi_address.address);
  HandlerBase = cb_unpack64 (Smram->handler.physical_start);
  HandlerSize = cb_unpack64 (Smram->handler.physical_size);
  if ((SharedBase == 0) || ((SharedBase & EFI_PAGE_MASK) != 0) ||
      (SharedBase > MAX_UINT32 - EFI_PAGE_SIZE) ||
      (cb_unpack64 (Shared->comm_buffer.physical_size) != EFI_PAGE_SIZE) ||
      (SmramBase != SharedBase + EFI_PAGE_SIZE) || (SmramSize == 0) ||
      ((SmramSize & EFI_PAGE_MASK) != 0) || (SmramSize > MAX_UINT32 - SmramBase) ||
      (HandlerBase == 0) || ((HandlerBase & EFI_PAGE_MASK) != 0) ||
      (HandlerSize == 0) || ((HandlerSize & EFI_PAGE_MASK) != 0) ||
      (HandlerBase >= SharedBase) || (HandlerSize != SharedBase - HandlerBase) ||
      (SpiBase == 0) || ((SpiBase & EFI_PAGE_MASK) != 0) ||
      (SpiBase > MAX_UINT32 - EFI_PAGE_SIZE) ||
      (Spi->block_size == 0) || ((Spi->block_size & EFI_PAGE_MASK) != 0) ||
      ((StoreBase & EFI_PAGE_MASK) != 0) || (Spi->store_size % Spi->block_size != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = SmmStoreGetFlashInfo (StoreBase, Spi->block_size, Spi->store_size / Spi->block_size, &FlashInfo);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // The downstream Intel flash driver uses the 32-bit BIOS mapping.
  if ((StoreBase > MAX_UINT32) || (Spi->store_size - 1 > MAX_UINT32 - StoreBase)) {
    return EFI_UNSUPPORTED;
  }

  ZeroMem (&InterfaceInfo, sizeof (InterfaceInfo));
  InterfaceInfo.Revision             = Interface->revision;
  InterfaceInfo.BootloaderSmmIs64Bit = Interface->bootloader_smm_is_64bit;
  InterfaceInfo.ApmCmd               = Interface->apm_cmd;
  InterfaceInfo.HandlerBase          = HandlerBase;
  InterfaceInfo.HandlerSize          = HandlerSize;
  InterfaceInfo.PayloadBase          = SharedBase;
  InterfaceInfo.PayloadSize          = SmramSize + EFI_PAGE_SIZE;
  ZeroMem (&SharedInfo, sizeof (SharedInfo));
  SharedInfo.CommBuffer.PhysicalStart = SharedBase;
  SharedInfo.CommBuffer.CpuStart      = SharedBase;
  SharedInfo.CommBuffer.PhysicalSize  = EFI_PAGE_SIZE;
  ZeroMem (&SpiInfo, sizeof (SpiInfo));
  SpiInfo.SpiAddress.AddressSpaceId   = SPACE_ID_PCI_CONFIGURATION;
  SpiInfo.SpiAddress.RegisterBitWidth = 32;
  SpiInfo.SpiAddress.AccessSize       = EFI_ACPI_3_0_DWORD;
  SpiInfo.SpiAddress.Address          = SpiBase;

  if ((BuildGuidDataHob (&gPayloadMmInterfaceInfoGuid, &InterfaceInfo, sizeof (InterfaceInfo)) == NULL) ||
      (BuildGuidDataHob (&gS3CommunicationGuid, &SharedInfo, sizeof (SharedInfo)) == NULL) ||
      (BuildGuidDataHob (&gSpiFlashInfoGuid, &SpiInfo, sizeof (SpiInfo)) == NULL) ||
      (BuildGuidDataHob (&gVariableFlashInfoHobGuid, &FlashInfo, sizeof (FlashInfo)) == NULL))
  {
    return EFI_OUT_OF_RESOURCES;
  }

  SmramInfo = BuildGuidHob (&gEfiSmmSmramMemoryGuid, sizeof (*SmramInfo) + sizeof (EFI_SMRAM_DESCRIPTOR));
  if (SmramInfo == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (SmramInfo, sizeof (*SmramInfo) + sizeof (EFI_SMRAM_DESCRIPTOR));
  SmramInfo->NumberOfSmmReservedRegions  = 2;
  SmramInfo->Descriptor[0]               = SharedInfo.CommBuffer;
  SmramInfo->Descriptor[0].RegionState   = EFI_ALLOCATED;
  SmramInfo->Descriptor[1].PhysicalStart = SmramBase;
  SmramInfo->Descriptor[1].CpuStart      = SmramBase;
  SmramInfo->Descriptor[1].PhysicalSize  = SmramSize;

  Status = BuildMmCommunicationHob ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = UnblockMmRange (SpiBase, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  SpiBar = MmioRead32 ((UINTN)SpiBase + PCI_BASE_ADDRESSREG_OFFSET);
  if ((SpiBar == MAX_UINT32) || ((SpiBar & EFI_PAGE_MASK) != 0) || (SpiBar == 0)) {
    return EFI_UNSUPPORTED;
  }

  Status = UnblockMmRange (SpiBar, EFI_PAGE_SIZE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // No EFI runtime cache: every frontend reads the same resident owner.
  return UnblockMmRange (StoreBase, Spi->store_size);
}
