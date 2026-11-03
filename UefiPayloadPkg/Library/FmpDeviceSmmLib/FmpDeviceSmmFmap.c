/** @file
  Shared FMAP parsing for capsule consumers and the protected owner.
  Copyright (c) 2016, Microsoft Corporation. All rights reserved.<BR>
  Copyright (c) 2018 - 2019, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2025, 3mdeb Sp. z o.o. All rights reserved.<BR>
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include "FmpDeviceSmmManifest.h"
#include "FmpDeviceSmmFmap.h"

UINTN
FmpFmapSize (
  IN CONST FMAP_HEADER  *FmapHeader
  )
{
  return sizeof (*FmapHeader) + ((UINTN)FmapHeader->AreaCount * sizeof (FMAP_AREA));
}

STATIC
BOOLEAN
FmapIsGraph (
  IN CHAR8  Character
  )
{
  return (Character > ' ') && (Character <= '~');
}

STATIC
BOOLEAN
FmapNameIsValid (
  IN CONST CHAR8  Name[FMAP_NAME_LEN]
  )
{
  UINTN  Index;

  for (Index = 0; Index < FMAP_NAME_LEN; ++Index) {
    if (Name[Index] == '\0') {
      return TRUE;
    }

    if (!FmapIsGraph (Name[Index])) {
      return FALSE;
    }
  }

  return FALSE;
}

EFI_STATUS
FmpLocateFmap (
  IN  CONST UINT8  *Image,
  IN  UINTN        ImageSize,
  OUT UINTN        *FmapOffset,
  OUT UINTN        *FmapLength
  )
{
  UINTN         Offset;
  CONST UINTN   HeaderSize = sizeof (FMAP_HEADER);
  CONST UINT32  MinAreas   = 1;
  UINTN         MapSize;

  if ((Image == NULL) || (FmapOffset == NULL) || (FmapLength == NULL)) {
    return EFI_NOT_FOUND;
  }

  if (ImageSize < HeaderSize) {
    return EFI_NOT_FOUND;
  }

  for (Offset = 0; Offset <= (ImageSize - HeaderSize); ++Offset) {
    CONST FMAP_HEADER  *Hdr = (CONST FMAP_HEADER *)(Image + Offset);

    if (CompareMem (Hdr->Signature, FMAP_SIGNATURE, sizeof (Hdr->Signature)) != 0) {
      continue;
    }

    if (Hdr->VerMajor != FMAP_VER_MAJOR) {
      continue;
    }

    MapSize = FmpFmapSize (Hdr);
    if ((Hdr->AreaCount < MinAreas) || (Hdr->Size < MapSize)) {
      continue;
    }

    if (MapSize > (ImageSize - Offset)) {
      continue;
    }

    if (!FmapNameIsValid (Hdr->Name)) {
      continue;
    }

    *FmapOffset = Offset;
    *FmapLength = MapSize;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
FmpFindFmapRegion (
  IN  CONST FMAP_HEADER  *FmapHeader,
  IN  CONST FMAP_AREA    *Areas,
  IN  UINTN              AreaCount,
  IN  CONST CHAR8        Name[16],
  OUT UINTN              *RegionOffset,
  OUT UINTN              *RegionSize
  )
{
  UINT64  Base;
  UINTN   Index;
  CHAR8   FmapName[33];
  CHAR8   ManifestName[REGION_MANIFEST_NAME_LEN + 1];

  if ((FmapHeader == NULL) || (Areas == NULL) || (Name == NULL) ||
      (RegionOffset == NULL) || (RegionSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  for (Index = 0; Index < AreaCount; ++Index) {
    //
    // Manifest names are 16-byte, zero-padded strings, while FMAP uses 32-byte
    // names. Convert both to NUL-terminated strings and compare.
    //
    CopyMem (FmapName, Areas[Index].Name, 32);
    FmapName[32] = '\0';
    CopyMem (ManifestName, Name, REGION_MANIFEST_NAME_LEN);
    ManifestName[REGION_MANIFEST_NAME_LEN] = '\0';

    if (AsciiStrCmp (FmapName, ManifestName) != 0) {
      continue;
    }

    Base = FmapHeader->Base;
    if ((Base > MAX_UINTN) || (Areas[Index].Offset > (MAX_UINTN - (UINTN)Base))) {
      return EFI_COMPROMISED_DATA;
    }

    *RegionOffset = (UINTN)Base + Areas[Index].Offset;
    *RegionSize   = Areas[Index].Size;
    return EFI_SUCCESS;
  }

  return EFI_NOT_FOUND;
}

STATIC
UINT32
ReadLe32 (
  IN CONST UINT8  *Data
  )
{
  return (UINT32)Data[0] |
         ((UINT32)Data[1] << 8) |
         ((UINT32)Data[2] << 16) |
         ((UINT32)Data[3] << 24);
}

EFI_STATUS
FmpFindIntelDescriptorBiosRegion (
  IN  CONST UINT8  *Image,
  IN  UINTN        ImageSize,
  IN  UINTN        FlashSize,
  OUT UINTN        *BiosOffset,
  OUT UINTN        *BiosSize
  )
{
  UINT32  Flmap0;
  UINT32  Flreg;
  UINTN   Frba;
  UINTN   FlregOffset;
  UINTN   BaseField;
  UINTN   LimitField;
  UINTN   RegionBase;
  UINTN   RegionLimit;
  UINTN   RegionSize;

  if ((Image == NULL) || (BiosOffset == NULL) || (BiosSize == NULL)) {
    return EFI_NOT_FOUND;
  }

  if (ImageSize < (INTEL_DESCRIPTOR_FLMAP0_OFF + sizeof (UINT32))) {
    return EFI_NOT_FOUND;
  }

  if (ReadLe32 (Image + INTEL_DESCRIPTOR_SIGNATURE_OFF) != INTEL_DESCRIPTOR_SIGNATURE) {
    return EFI_NOT_FOUND;
  }

  Flmap0      = ReadLe32 (Image + INTEL_DESCRIPTOR_FLMAP0_OFF);
  Frba        = ((Flmap0 >> 16) & 0xff) << 4;
  FlregOffset = Frba + (INTEL_DESCRIPTOR_REGION_BIOS * sizeof (UINT32));

  if ((FlregOffset + sizeof (UINT32)) > ImageSize) {
    return EFI_NOT_FOUND;
  }

  Flreg      = ReadLe32 (Image + FlregOffset);
  BaseField  = Flreg & INTEL_DESCRIPTOR_REGION_MASK;
  LimitField = (Flreg >> 16) & INTEL_DESCRIPTOR_REGION_MASK;

  if ((BaseField == INTEL_DESCRIPTOR_REGION_MASK) || (LimitField == 0) || (LimitField < BaseField)) {
    return EFI_NOT_FOUND;
  }

  RegionBase  = BaseField * INTEL_DESCRIPTOR_REGION_SCALE;
  RegionLimit = (LimitField * INTEL_DESCRIPTOR_REGION_SCALE) |
                (INTEL_DESCRIPTOR_REGION_SCALE - 1);
  RegionSize = RegionLimit - RegionBase + 1;

  if ((RegionBase >= FlashSize) || (RegionSize > (FlashSize - RegionBase))) {
    return EFI_NOT_FOUND;
  }

  *BiosOffset = RegionBase;
  *BiosSize   = RegionSize;
  return EFI_SUCCESS;
}
