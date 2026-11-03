/** @file
  Bind authenticated capsule bytes to an owner-resolved update plan.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include "Owner.h"
#include <Library/BaseMemoryLib.h>
#include "../Library/FmpDeviceSmmLib/FmpDeviceSmmManifest.h"
#include "../Library/FmpDeviceSmmLib/FmpDeviceSmmFmap.h"

STATIC
BOOLEAN
ReadImage(CAPSULE_OWNER *Owner, UINTN Offset, UINTN Size, VOID *Output)
{
  UINT8 *Destination = Output;
  UINTN Take;

  if (Offset > Owner->Verifier.ImageSize || Size > Owner->Verifier.ImageSize - Offset) {
    return FALSE;
  }
  while (Size) {
    if (!CapsuleReadVerifiedBlock(&Owner->Verifier, Offset / CAPSULE_BLOCK_SIZE)) {
      return FALSE;
    }
    Take = CAPSULE_BLOCK_SIZE - Offset % CAPSULE_BLOCK_SIZE;
    if (Take > Size) {
      Take = Size;
    }
    CopyMem(Destination, Owner->Verifier.Buffer + Offset % CAPSULE_BLOCK_SIZE, Take);
    Offset += Take;
    Destination += Take;
    Size -= Take;
  }
  return TRUE;
}

STATIC
EFI_STATUS
LoadImageFmap(CAPSULE_OWNER *Owner)
{
  FMAP_HEADER Header;
  UINT8 Magic[8];
  UINTN Block, Index, Offset, Length, Found, ValidLength;

  for (Block = 0; Block < Owner->Verifier.BlockCount; Block++) {
    if (!CapsuleReadVerifiedBlock(&Owner->Verifier, Block)) {
      return EFI_SECURITY_VIOLATION;
    }
    for (Index = 0; Index < CAPSULE_BLOCK_SIZE; Index++) {
      Offset = Block * CAPSULE_BLOCK_SIZE + Index;
      if (sizeof(Header) > Owner->Verifier.ImageSize - Offset) {
        return EFI_NOT_FOUND;
      }
      if (Owner->Verifier.Buffer[Index] != '_') {
        continue;
      }
      if (Index <= CAPSULE_BLOCK_SIZE - sizeof(Magic)) {
        CopyMem(Magic, Owner->Verifier.Buffer + Index, sizeof(Magic));
      } else {
        if (!ReadImage(Owner, Offset, sizeof(Magic), Magic) ||
            !CapsuleReadVerifiedBlock(&Owner->Verifier, Block)) {
          return EFI_SECURITY_VIOLATION;
        }
      }
      if (CompareMem(Magic, FMAP_SIGNATURE, sizeof(Magic))) {
        continue;
      }
      if (!ReadImage(Owner, Offset, sizeof(Header), &Header)) {
        return EFI_SECURITY_VIOLATION;
      }
      Length = FmpFmapSize(&Header);
      if (Length <= sizeof(Owner->ImageFmap) && Header.Size == Owner->Verifier.ImageSize &&
          Length <= Owner->Verifier.ImageSize - Offset) {
        if (!ReadImage(Owner, Offset, Length, Owner->ImageFmap)) {
          return EFI_SECURITY_VIOLATION;
        }
        if (!EFI_ERROR(FmpLocateFmap(Owner->ImageFmap, Length, &Found, &ValidLength)) &&
            !Found && ValidLength == Length) {
          return EFI_SUCCESS;
        }
      }
      if (!CapsuleReadVerifiedBlock(&Owner->Verifier, Block)) {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }
  return EFI_NOT_FOUND;
}

VOID
CapsuleOwnerClose(CAPSULE_OWNER *Owner)
{
  Owner->Active = FALSE;
  Owner->Verifier.Verified = FALSE;
  Owner->RangeCount = 0;
}

STATIC
EFI_STATUS
AddRegion(CAPSULE_OWNER *Owner, CONST CHAR8 Name[16])
{
  EFI_STATUS Status;
  CAPSULE_RANGE Range;

  if (Owner->RangeCount == CAPSULE_MAX_REGIONS) {
    return EFI_OUT_OF_RESOURCES;
  }
  Status = Owner->Policy->Resolve(Owner->Policy->Context, Name, &Range);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (!Range.Size || Range.Offset >= Owner->Policy->FlashSize ||
      Range.Size > Owner->Policy->FlashSize - Range.Offset) {
    return EFI_SECURITY_VIOLATION;
  }
  Owner->Ranges[Owner->RangeCount++] = Range;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
SelectBios(CAPSULE_OWNER *Owner)
{
  CONST CHAR8 Name[16] = "BIOS";
  UINTN Offset, Size;
  EFI_STATUS Status;

  Owner->RangeCount = 0;
  Status = AddRegion(Owner, Name);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (!CapsuleReadVerifiedBlock(&Owner->Verifier, 0)) {
    return EFI_SECURITY_VIOLATION;
  }
  Status = FmpFindIntelDescriptorBiosRegion(Owner->Verifier.Buffer, CAPSULE_BLOCK_SIZE,
             Owner->Verifier.ImageSize, &Offset, &Size);
  if (!EFI_ERROR(Status) &&
      (Offset != Owner->Ranges[0].Offset || Size != Owner->Ranges[0].Size)) {
    return EFI_INCOMPATIBLE_VERSION;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
CapsuleOwnerBegin(CAPSULE_OWNER *Owner, CONST UINT8 *Signature, UINTN Size)
{
  struct {
    UINT32 Signature;
    UINT32 HeaderSize;
    UINT32 Version;
    UINT32 LowestSupportedVersion;
    EFI_GUID ImageGuid;
  } Header;
  CONST REGION_MANIFEST_ENTRY *Entries;
  CONST FMAP_HEADER *ImageMap;
  CONST FMAP_AREA *Areas;
  BOOLEAN LayoutMismatch = FALSE;
  UINTN ImageOffset, ImageSize;
  UINTN Count;
  UINTN PrefixSize;
  UINTN Index;
  EFI_STATUS Status;

  if (Owner == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  CapsuleOwnerClose(Owner);
  if (Owner->Policy == NULL || Owner->Policy->Resolve == NULL ||
      Owner->Policy->Program == NULL || Owner->Verifier.ImageSize != Owner->Policy->FlashSize ||
      !CapsuleVerify(&Owner->Verifier, Signature, Size, Owner->Policy->Root,
                     Owner->Policy->RootSize)) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = EFI_COMPROMISED_DATA;
  if (Owner->Verifier.MetadataSize < sizeof(Header) + sizeof(UINT64)) {
    goto Failed;
  }
  CopyMem(&Header, Owner->Verifier.Metadata, sizeof(Header));
  if (Header.Signature != SIGNATURE_32('M', 'S', 'S', '1') ||
      Header.HeaderSize != sizeof(Header) || Header.HeaderSize != Owner->Verifier.ImageOffset ||
      Header.HeaderSize > Owner->Verifier.MetadataSize - sizeof(UINT64)) {
    goto Failed;
  }
  /* Only authenticated metadata identifies the target; the outer FMP GUID is public. */
  if (CompareMem(&Header.ImageGuid, &Owner->Policy->ImageGuid, sizeof(EFI_GUID))) {
    Status = EFI_SECURITY_VIOLATION;
    goto Failed;
  }
  if (Header.Version < Owner->Policy->LowestSupportedVersion ||
      Header.LowestSupportedVersion > Header.Version) {
    Status = EFI_INCOMPATIBLE_VERSION;
    goto Failed;
  }

  /* The running variable service owns this store until reset. Layout migration
     requires a separate recovery policy; ordinary updates preserve its blocks. */
  if (Owner->Policy->VariableStore.Size) {
    CONST CHAR8 StoreName[16] = "SMMSTORE";
    Status = LoadImageFmap(Owner);
    if (EFI_ERROR(Status)) {
      goto Failed;
    }
    ImageMap = (CONST FMAP_HEADER *)Owner->ImageFmap;
    Areas = (CONST FMAP_AREA *)(Owner->ImageFmap + sizeof(*ImageMap));
    Status = FmpFindFmapRegion(ImageMap, Areas, ImageMap->AreaCount,
                               StoreName, &ImageOffset, &ImageSize);
    if (EFI_ERROR(Status) || ImageOffset != Owner->Policy->VariableStore.Offset ||
        ImageSize != Owner->Policy->VariableStore.Size) {
      Status = EFI_INCOMPATIBLE_VERSION;
      goto Failed;
    }
  }

  /* The verifier retained header + manifest + count without the image.
     The normal manifest parser can therefore validate the private trailer. */
  Status = FmpDeviceLocateRegionManifest(Owner->Verifier.Metadata,
             Owner->Verifier.MetadataSize - sizeof(UINT64), &Count, &Entries, &PrefixSize);
  if (Status == EFI_NOT_FOUND &&
      Owner->Verifier.MetadataSize == Header.HeaderSize + sizeof(UINT64)) {
    Status = SelectBios(Owner);
  } else if (!EFI_ERROR(Status)) {
    if (PrefixSize != Header.HeaderSize || Count > CAPSULE_MAX_REGIONS) {
      Status = EFI_COMPROMISED_DATA;
      goto Failed;
    }
    if (!Owner->Policy->VariableStore.Size) {
      Status = LoadImageFmap(Owner);
      if (EFI_ERROR(Status)) {
        goto Failed;
      }
    }
    ImageMap = (CONST FMAP_HEADER *)Owner->ImageFmap;
    Areas = (CONST FMAP_AREA *)(Owner->ImageFmap + sizeof(*ImageMap));
    for (Index = 0; Index < Count; Index++) {
      Status = FmpFindFmapRegion(ImageMap, Areas, ImageMap->AreaCount,
                 Entries[Index].RegionName, &ImageOffset, &ImageSize);
      if (EFI_ERROR(Status) || !ImageSize || ImageOffset >= Owner->Verifier.ImageSize ||
          ImageSize > Owner->Verifier.ImageSize - ImageOffset) {
        Status = EFI_COMPROMISED_DATA;
        goto Failed;
      }
      Status = AddRegion(Owner, Entries[Index].RegionName);
      if (Status == EFI_NOT_FOUND) {
        LayoutMismatch = TRUE;
        continue;
      }
      if (EFI_ERROR(Status)) {
        goto Failed;
      }
      if (Owner->Ranges[Owner->RangeCount - 1].Offset != ImageOffset ||
          Owner->Ranges[Owner->RangeCount - 1].Size != ImageSize) {
        LayoutMismatch = TRUE;
      }
    }
    if (LayoutMismatch) {
      Status = SelectBios(Owner);
    }
  }
  if (EFI_ERROR(Status) || !Owner->RangeCount) {
    goto Failed;
  }
  /* Validate immutable erase blocks before any selected block can be changed.
     The native callback's check-only mode never erases or programs flash. */
  for (Index = 0; Index < Owner->Verifier.BlockCount; Index++) {
    UINTN Start = Index * CAPSULE_BLOCK_SIZE;
    UINTN Region;
    for (Region = 0; Region < Owner->RangeCount; Region++) {
      if (Start < Owner->Ranges[Region].Offset + Owner->Ranges[Region].Size &&
          Owner->Ranges[Region].Offset < Start + CAPSULE_BLOCK_SIZE) {
        if (!CapsuleReadVerifiedBlock(&Owner->Verifier, Index)) {
          Status = EFI_SECURITY_VIOLATION;
          goto Failed;
        }
        Status = Owner->Policy->Program(Owner->Policy->Context, Index,
                   Owner->Ranges, Owner->RangeCount, Owner->Verifier.Buffer, TRUE);
        if (EFI_ERROR(Status)) {
          goto Failed;
        }
        break;
      }
    }
  }
  Owner->Active = TRUE;
  return EFI_SUCCESS;
Failed:
  CapsuleOwnerClose(Owner);
  return Status;
}

EFI_STATUS
CapsuleOwnerProgram(CAPSULE_OWNER *Owner, UINTN Block)
{
  UINTN Start;
  UINTN Index;
  BOOLEAN Selected = FALSE;
  EFI_STATUS Status;

  if (Owner == NULL || !Owner->Active || Block >= Owner->Verifier.BlockCount) {
    return EFI_ACCESS_DENIED;
  }
  Start = Block * CAPSULE_BLOCK_SIZE;
  if (Owner->Policy->VariableStore.Size &&
      Start < Owner->Policy->VariableStore.Offset + Owner->Policy->VariableStore.Size &&
      Owner->Policy->VariableStore.Offset < Start + CAPSULE_BLOCK_SIZE) {
    return EFI_SUCCESS;
  }
  for (Index = 0; Index < Owner->RangeCount; Index++) {
    if (Start < Owner->Ranges[Index].Offset + Owner->Ranges[Index].Size &&
        Owner->Ranges[Index].Offset < Start + CAPSULE_BLOCK_SIZE) {
      Selected = TRUE;
      break;
    }
  }
  /* A full-chip walk is harmless outside the authenticated update plan. */
  if (!Selected) {
    return EFI_SUCCESS;
  }
  if (!CapsuleReadVerifiedBlock(&Owner->Verifier, Block)) {
    CapsuleOwnerClose(Owner);
    return EFI_SECURITY_VIOLATION;
  }

  /* The private programmer preserves all bytes outside the complete plan. */
  Status = Owner->Policy->Program(Owner->Policy->Context, Block,
              Owner->Ranges, Owner->RangeCount, Owner->Verifier.Buffer, FALSE);
  if (EFI_ERROR(Status)) {
    CapsuleOwnerClose(Owner);
  }
  return Status;
}
