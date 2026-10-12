/** @file
  Flash coordinates supplied to the fixed variable service.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Base.h>

#define COREBOOT_VARIABLE_STORE_INFO_REVISION  1

typedef struct {
  UINT32    Revision;
  UINT32    StoreOffset;
  UINT64    StoreBase;
  UINT32    StoreSize;
  UINT32    BlockSize;
} COREBOOT_VARIABLE_STORE_INFO;

extern EFI_GUID  gCorebootVariableStoreInfoGuid;
