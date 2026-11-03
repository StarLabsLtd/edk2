/** @file
  Shared FMAP parsing for capsule consumers and the protected owner.
  Copyright (c) 2016, Microsoft Corporation. All rights reserved.<BR>
  Copyright (c) 2018 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2025, 3mdeb Sp. z o.o. All rights reserved.<BR>
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Uefi.h>
#define FMAP_SIGNATURE  "__FMAP__"
#define FMAP_VER_MAJOR  1
#define FMAP_NAME_LEN   32

#pragma pack(1)
typedef struct {
  CHAR8     Signature[8];
  UINT8     VerMajor;
  UINT8     VerMinor;
  UINT64    Base;
  UINT32    Size;
  CHAR8     Name[FMAP_NAME_LEN];
  UINT16    AreaCount;
} FMAP_HEADER;

typedef struct {
  UINT32    Offset;
  UINT32    Size;
  CHAR8     Name[FMAP_NAME_LEN];
  UINT16    Flags;
} FMAP_AREA;
#pragma pack()
UINTN FmpFmapSize(CONST FMAP_HEADER *Header);
EFI_STATUS FmpLocateFmap(CONST UINT8 *Image, UINTN Size, UINTN *Offset, UINTN *Length);
EFI_STATUS FmpFindFmapRegion(CONST FMAP_HEADER *Header, CONST FMAP_AREA *Areas,
                             UINTN Count, CONST CHAR8 Name[16], UINTN *Offset, UINTN *Size);

#define INTEL_DESCRIPTOR_SIGNATURE      0x0ff0a55a
#define INTEL_DESCRIPTOR_SIGNATURE_OFF  0x10
#define INTEL_DESCRIPTOR_FLMAP0_OFF     0x14
#define INTEL_DESCRIPTOR_REGION_BIOS    1
#define INTEL_DESCRIPTOR_REGION_MASK    0x7fff
#define INTEL_DESCRIPTOR_REGION_SCALE   0x1000
EFI_STATUS FmpFindIntelDescriptorBiosRegion(CONST UINT8 *Image, UINTN Size,
                                            UINTN FlashSize, UINTN *Offset, UINTN *Length);
