/** @file
  Defines the payload MM SPI store coordinate HOB.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef PAYLOAD_MM_SPI_STORE_INFO_GUID_H_
#define PAYLOAD_MM_SPI_STORE_INFO_GUID_H_

#include <Base.h>

extern EFI_GUID  gPayloadMmSpiStoreInfoGuid;

#define PAYLOAD_MM_SPI_STORE_INFO_REVISION  1

typedef struct {
  UINT32    Revision;
  UINT32    StoreOffset;
  UINT64    StoreBase;
  UINT32    StoreSize;
  UINT32    BlockSize;
} PAYLOAD_MM_SPI_STORE_INFO;

#endif
