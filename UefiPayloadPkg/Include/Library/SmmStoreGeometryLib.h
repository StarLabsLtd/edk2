/** @file
  Shared variable-store geometry for SMMSTORE and payload MM.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Guid/VariableFlashInfo.h>

/**
  Describe the existing SMMSTORE variable and FTW ranges without accessing flash.

  The working area occupies one erase block. The spare area occupies half
  the blocks, rounded down; the variable area occupies the remaining blocks.
  This is the on-flash layout used by SmmStoreFvbRuntimeDxe, not the smaller
  working area used by the reference payload MM implementation.

  @param[in]  BaseAddress  Physical base of the mapped store or its read cache.
  @param[in]  BlockSize    Erase block size in bytes.
  @param[in]  BlockCount   Number of erase blocks in the store.
  @param[out] FlashInfo    Standard variable flash information. Unchanged on error.

  @retval EFI_SUCCESS            The layout was returned.
  @retval EFI_INVALID_PARAMETER  The geometry or output pointer is invalid.
  @retval EFI_UNSUPPORTED        The size or address range overflows.
**/
EFI_STATUS
EFIAPI
SmmStoreGetFlashInfo (
  IN  EFI_PHYSICAL_ADDRESS  BaseAddress,
  IN  UINTN                 BlockSize,
  IN  UINTN                 BlockCount,
  OUT VARIABLE_FLASH_INFO   *FlashInfo
  );
