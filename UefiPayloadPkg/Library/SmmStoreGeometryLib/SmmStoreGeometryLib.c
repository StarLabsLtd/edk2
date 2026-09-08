/** @file
  Preserve SMMSTORE's on-flash layout when describing it to a variable engine.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/SafeIntLib.h>
#include <Library/SmmStoreGeometryLib.h>

EFI_STATUS
EFIAPI
SmmStoreGetFlashInfo (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINTN                 BlockSize,
  IN  UINTN                 BlockCount,
  OUT VARIABLE_FLASH_INFO   *FlashInfo
  )
{
  UINT64  StoreSize;
  UINT64  SpareSize;

  if ((FlashInfo == NULL) || (BaseAddress == 0) ||
      (BlockSize == 0) || (BlockCount < 3))
  {
    return EFI_INVALID_PARAMETER;
  }

  if (RETURN_ERROR (SafeUint64Mult (BlockCount, BlockSize, &StoreSize)))
  {
    return EFI_UNSUPPORTED;
  }

  if (StoreSize - 1 > MAX_UINT64 - BaseAddress) {
    return EFI_UNSUPPORTED;
  }

  SpareSize = (UINT64)(BlockCount / 2) * BlockSize;
  ZeroMem (FlashInfo, sizeof (*FlashInfo));
  FlashInfo->Version               = VARIABLE_FLASH_INFO_HOB_VERSION;
  FlashInfo->NvVariableBaseAddress = BaseAddress;
  FlashInfo->NvVariableLength      = StoreSize - SpareSize - BlockSize;
  FlashInfo->FtwWorkingBaseAddress = BaseAddress + FlashInfo->NvVariableLength;
  FlashInfo->FtwWorkingLength      = BlockSize;
  FlashInfo->FtwSpareBaseAddress   = FlashInfo->FtwWorkingBaseAddress + BlockSize;
  FlashInfo->FtwSpareLength        = SpareSize;
  return EFI_SUCCESS;
}
