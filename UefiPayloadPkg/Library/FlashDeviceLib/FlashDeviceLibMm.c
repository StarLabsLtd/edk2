/** @file
  Restrict the MM variable engine to its existing variable and FTW store.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiMm.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FlashDeviceLib.h>
#include <Library/HobLib.h>
#include <Library/SmmStoreGeometryLib.h>
#include <Library/SpiFlashLib.h>

STATIC UINTN   mStoreBase;
STATIC UINTN   mStoreSize;
STATIC UINT32  mBiosOffset;

EFI_STATUS
EFIAPI
LibFvbFlashDeviceInit (
  VOID
  )
{
  EFI_HOB_GUID_TYPE    *Hob;
  VARIABLE_FLASH_INFO  *Info;
  VARIABLE_FLASH_INFO  Expected;
  EFI_STATUS           Status;
  UINT64               StoreSize;
  UINT64               BiosBase;
  UINT32               BiosSize;

  mStoreSize = 0;
  Hob        = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  if ((Hob == NULL) || (GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*Info))) {
    return EFI_NOT_FOUND;
  }

  Info = GET_GUID_HOB_DATA (Hob);
  if ((Info->NvVariableBaseAddress > MAX_UINT32) ||
      (Info->FtwSpareBaseAddress < Info->NvVariableBaseAddress) ||
      (Info->FtwSpareBaseAddress > MAX_UINT32) || (Info->FtwSpareLength == 0) ||
      (Info->FtwSpareLength - 1 > MAX_UINT32 - Info->FtwSpareBaseAddress) ||
      (Info->FtwWorkingLength == 0) ||
      (((Info->NvVariableBaseAddress | Info->FtwWorkingLength) & EFI_PAGE_MASK) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  StoreSize = Info->FtwSpareBaseAddress - Info->NvVariableBaseAddress + Info->FtwSpareLength;
  if ((StoreSize > MAX_UINT32) || (StoreSize % Info->FtwWorkingLength != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SmmStoreGetFlashInfo (
             Info->NvVariableBaseAddress,
             Info->FtwWorkingLength,
             StoreSize / Info->FtwWorkingLength,
             &Expected
             );
  if (EFI_ERROR (Status) || (CompareMem (Info, &Expected, sizeof (Expected)) != 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = SpiConstructor ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SpiGetRegionAddress (FlashRegionBios, NULL, &BiosSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  BiosBase = BASE_4GB - BiosSize;
  if ((Info->NvVariableBaseAddress < BiosBase) ||
      (StoreSize > BiosSize - (Info->NvVariableBaseAddress - BiosBase)))
  {
    return EFI_INVALID_PARAMETER;
  }

  mStoreBase  = (UINTN)Info->NvVariableBaseAddress;
  mBiosOffset = (UINT32)(mStoreBase - BiosBase);
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
  if ((NumBytes == NULL) || (Buffer == NULL) || !StoreContains (PAddress, *NumBytes)) {
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
  if ((NumBytes == NULL) || (Buffer == NULL) || !StoreContains (PAddress, *NumBytes)) {
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
  if (!StoreContains (PAddress, LbaLength) || (((PAddress | LbaLength) & EFI_PAGE_MASK) != 0)) {
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
