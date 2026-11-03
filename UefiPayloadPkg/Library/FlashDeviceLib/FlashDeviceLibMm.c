/** @file
  Restrict the MM variable engine to its existing variable and FTW store.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FlashDeviceLib.h>
#include <Library/HobLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include <Library/SpiFlashLib.h>
#include <Library/StandaloneMmMemLib.h>
#include <Guid/CorebootVariableStoreInfo.h>
#include <Guid/SpiFlashInfoGuid.h>

STATIC UINTN   mStoreBase;
STATIC UINTN   mStoreSize;
STATIC UINT32  mBiosOffset;
STATIC UINTN   mSpiPciBase;
STATIC UINT32  mSpiMmioBase;

STATIC
BOOLEAN
ControllerValid (
  VOID
  )
{
  return MmIsBufferOutsideMmValid (mSpiPciBase, EFI_PAGE_SIZE) &&
         MmIsBufferOutsideMmValid (mSpiMmioBase, EFI_PAGE_SIZE);
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceInit (
  VOID
  )
{
  EFI_HOB_GUID_TYPE              *Hob;
  EFI_HOB_GUID_TYPE              *StoreHob;
  EFI_HOB_GUID_TYPE              *SpiHob;
  VARIABLE_FLASH_INFO            *Info;
  VARIABLE_FLASH_INFO            Expected;
  COREBOOT_VARIABLE_STORE_INFO   *StoreInfo;
  SPI_FLASH_INFO                 *SpiInfo;
  EFI_STATUS                     Status;
  UINT64                         StoreSize;
  UINT32                         Remainder;
  UINT32                         BiosBase;
  UINT32                         BiosSize;

  mStoreSize = 0;
  Hob        = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*Info))) {
    return EFI_NOT_FOUND;
  }

  Info = GET_GUID_HOB_DATA (Hob);
  StoreHob = GetFirstGuidHob (&gCorebootVariableStoreInfoGuid);
  if ((StoreHob == NULL) || (GET_GUID_HOB_DATA_SIZE (StoreHob) != sizeof (*StoreInfo))) {
    return EFI_NOT_FOUND;
  }

  StoreInfo = GET_GUID_HOB_DATA (StoreHob);
  SpiHob = GetFirstGuidHob (&gSpiFlashInfoGuid);
  if ((SpiHob == NULL) || (GET_GUID_HOB_DATA_SIZE (SpiHob) != sizeof (*SpiInfo))) {
    return EFI_NOT_FOUND;
  }

  SpiInfo = GET_GUID_HOB_DATA (SpiHob);
  if ((SpiInfo->SpiAddress.AddressSpaceId != EFI_ACPI_3_0_PCI_CONFIGURATION_SPACE) ||
      (SpiInfo->SpiAddress.Address == 0) || (SpiInfo->SpiAddress.Address > MAX_UINTN))
  {
    return EFI_INVALID_PARAMETER;
  }

  mSpiPciBase = (UINTN)SpiInfo->SpiAddress.Address;
  if (!MmIsBufferOutsideMmValid (mSpiPciBase, EFI_PAGE_SIZE)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = SpiFlashCacheMmioBase (mSpiPciBase, &mSpiMmioBase);
  if (EFI_ERROR (Status) || !ControllerValid ()) {
    return EFI_ERROR (Status) ? Status : EFI_SECURITY_VIOLATION;
  }

  if ((Info->NvVariableBaseAddress > MAX_UINT32) ||
      (Info->FtwSpareBaseAddress < Info->NvVariableBaseAddress) ||
      (Info->FtwSpareBaseAddress > MAX_UINT32) || (Info->FtwSpareLength == 0) ||
      (Info->FtwSpareLength - 1 > MAX_UINT32 - Info->FtwSpareBaseAddress) ||
      (Info->FtwWorkingLength == 0) || (Info->FtwWorkingLength > MAX_UINT32) ||
      (((Info->NvVariableBaseAddress | Info->FtwWorkingLength) & EFI_PAGE_MASK) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  StoreSize = Info->FtwSpareBaseAddress - Info->NvVariableBaseAddress + Info->FtwSpareLength;
  if ((StoreSize > MAX_UINT32) ||
      (DivU64x32Remainder (StoreSize, (UINT32)Info->FtwWorkingLength, &Remainder) > MAX_UINT32) ||
      (Remainder != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = SmmStoreGetFlashInfo (
             Info->NvVariableBaseAddress,
             Info->FtwWorkingLength,
             DivU64x32 (StoreSize, (UINT32)Info->FtwWorkingLength),
             &Expected
             );
  if (EFI_ERROR (Status) || (CompareMem (Info, &Expected, sizeof (Expected)) != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((StoreInfo->Revision != COREBOOT_VARIABLE_STORE_INFO_REVISION) ||
      (StoreInfo->StoreBase != Info->NvVariableBaseAddress) ||
      (StoreInfo->StoreSize != StoreSize) ||
      (StoreInfo->BlockSize != Info->FtwWorkingLength) ||
      (StoreInfo->StoreOffset % StoreInfo->BlockSize != 0) ||
      (StoreInfo->StoreOffset > MAX_UINT32 - StoreSize))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = SpiConstructor ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!ControllerValid ()) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = SpiGetRegionAddress (FlashRegionBios, &BiosBase, &BiosSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((StoreInfo->StoreOffset < BiosBase) ||
      (StoreInfo->StoreOffset - BiosBase > BiosSize) ||
      (StoreSize > BiosSize - (StoreInfo->StoreOffset - BiosBase)))
  {
    return EFI_INVALID_PARAMETER;
  }

  mStoreBase  = (UINTN)Info->NvVariableBaseAddress;
  mBiosOffset = StoreInfo->StoreOffset - BiosBase;
  mStoreSize  = (UINTN)StoreSize;
  return EFI_SUCCESS;
}

STATIC
BOOLEAN
StoreContains (
  IN UINTN  Address,
  IN UINTN  Size
  )
{
  return (mStoreSize != 0) && (Size != 0) && (Address >= mStoreBase) &&
         (Address - mStoreBase < mStoreSize) &&
         (Size <= mStoreSize - (Address - mStoreBase));
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceRead (
  IN UINTN      PAddress,
  IN OUT UINTN  *NumBytes,
  OUT UINT8     *Buffer
  )
{
  if ((NumBytes == NULL) || (Buffer == NULL) || !StoreContains (PAddress, *NumBytes) ||
      !ControllerValid () || !MmIsBufferOutsideMmValid (PAddress, *NumBytes))
  {
    return EFI_INVALID_PARAMETER;
  }

  return SpiFlashRead (FlashRegionBios, mBiosOffset + (UINT32)(PAddress - mStoreBase), (UINT32)*NumBytes, Buffer);
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceWrite (
  IN UINTN      PAddress,
  IN OUT UINTN  *NumBytes,
  IN UINT8      *Buffer
  )
{
  if ((NumBytes == NULL) || (Buffer == NULL) || !StoreContains (PAddress, *NumBytes) ||
      !ControllerValid () || !MmIsBufferOutsideMmValid (PAddress, *NumBytes))
  {
    return EFI_INVALID_PARAMETER;
  }

  return SpiFlashWrite (FlashRegionBios, mBiosOffset + (UINT32)(PAddress - mStoreBase), (UINT32)*NumBytes, Buffer);
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceBlockErase (
  IN UINTN  PAddress,
  IN UINTN  LbaLength
  )
{
  if (!StoreContains (PAddress, LbaLength) || (((PAddress | LbaLength) & EFI_PAGE_MASK) != 0) ||
      !ControllerValid () || !MmIsBufferOutsideMmValid (PAddress, LbaLength))
  {
    return EFI_INVALID_PARAMETER;
  }

  return SpiFlashErase (FlashRegionBios, mBiosOffset + (UINT32)(PAddress - mStoreBase), (UINT32)LbaLength);
}

EFI_STATUS
EFIAPI
LibFvbFlashDeviceBlockLock (
  IN UINTN    PAddress,
  IN UINTN    LbaLength,
  IN BOOLEAN  Lock
  )
{
  // The SPI library brackets each write; no persistent unlock is exposed here.
  return StoreContains (PAddress, LbaLength) ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}
