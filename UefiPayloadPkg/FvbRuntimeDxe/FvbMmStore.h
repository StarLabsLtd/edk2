/** @file
  Validation interface for the fixed MM variable store.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Guid/VariableFlashInfo.h>
#include <Guid/VariableFormat.h>

typedef union {
  UINT64    Alignment;
  UINT8     Bytes[sizeof (EFI_FIRMWARE_VOLUME_HEADER) + sizeof (EFI_FV_BLOCK_MAP_ENTRY) + sizeof (VARIABLE_STORE_HEADER)];
} MM_FVB_STORE_HEADER;

EFI_STATUS
MmFvbValidateGeometry (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT VARIABLE_FLASH_INFO       *Validated
  );

EFI_STATUS
MmFvbReadStoreHeader (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  IN EFI_PHYSICAL_ADDRESS       Address,
  OUT MM_FVB_STORE_HEADER       *Store
  );

EFI_STATUS
MmFvbInspectStorage (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT MM_FVB_STORE_HEADER       *Store,
  OUT BOOLEAN                   *Format
  );

EFI_STATUS
MmFvbReadRecoveryHeader (
  IN CONST VARIABLE_FLASH_INFO  *Info,
  OUT MM_FVB_STORE_HEADER       *Store
  );
