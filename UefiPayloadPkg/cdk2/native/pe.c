/** @file

  Bounded PE32+ loading for native cdk2.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "pe.h"

STATIC
BOOLEAN
Cdk2NativeRangeValid (
  IN UINT64  Base,
  IN UINT64  Size,
  IN UINT64  Limit
  )
{
  return Base <= Limit && Size <= Limit - Base;
}

STATIC
VOID
Cdk2NativeZero (
  OUT VOID  *Buffer,
  IN  UINTN  Size
  )
{
  UINT8  *Bytes;
  UINTN   Index;

  Bytes = (UINT8 *)Buffer;
  for (Index = 0; Index < Size; Index++) {
    Bytes[Index] = 0;
  }
}

STATIC
VOID
Cdk2NativeCopy (
  OUT VOID       *Destination,
  IN  CONST VOID  *Source,
  IN  UINTN        Size
  )
{
  UINT8        *DestinationBytes;
  CONST UINT8  *SourceBytes;
  UINTN         Index;

  DestinationBytes = (UINT8 *)Destination;
  SourceBytes      = (CONST UINT8 *)Source;
  for (Index = 0; Index < Size; Index++) {
    DestinationBytes[Index] = SourceBytes[Index];
  }
}

STATIC
EFI_STATUS
Cdk2NativeApplyRelocations (
  IN OUT UINT8                            *LoadedImage,
  IN     UINT32                            ImageSize,
  IN     UINT64                            PreferredBase,
  IN     UINT64                            DestinationBase,
  IN     CONST EFI_IMAGE_DATA_DIRECTORY   *Relocations
  )
{
  UINT64                          Adjust;
  UINT32                          Offset;
  UINT32                          BlockSize;
  UINT32                          BlockEnd;
  UINT32                          FixupRva;
  UINTN                           EntryCount;
  UINTN                           EntryIndex;
  UINT16                          Entry;
  EFI_IMAGE_BASE_RELOCATION      *Block;
  UINT16                         *Entries;
  UINT64                         *Fixup;

  if (Relocations->Size == 0) {
    return (PreferredBase == DestinationBase) ? EFI_SUCCESS : EFI_UNSUPPORTED;
  }

  if (!Cdk2NativeRangeValid (
        Relocations->VirtualAddress,
        Relocations->Size,
        ImageSize
        ))
  {
    return EFI_COMPROMISED_DATA;
  }

  Adjust = DestinationBase - PreferredBase;
  if (Adjust == 0) {
    return EFI_SUCCESS;
  }

  Offset = Relocations->VirtualAddress;
  BlockEnd = Relocations->VirtualAddress + Relocations->Size;
  while (Offset < BlockEnd) {
    if (BlockEnd - Offset < sizeof (EFI_IMAGE_BASE_RELOCATION)) {
      return EFI_COMPROMISED_DATA;
    }

    Block = (EFI_IMAGE_BASE_RELOCATION *)(VOID *)(LoadedImage + Offset);
    BlockSize = Block->SizeOfBlock;
    if (BlockSize < sizeof (*Block) || BlockSize > BlockEnd - Offset ||
        ((BlockSize - sizeof (*Block)) & 1U) != 0)
    {
      return EFI_COMPROMISED_DATA;
    }

    EntryCount = (BlockSize - sizeof (*Block)) / sizeof (UINT16);
    Entries    = (UINT16 *)(VOID *)((UINT8 *)Block + sizeof (*Block));
    for (EntryIndex = 0; EntryIndex < EntryCount; EntryIndex++) {
      Entry = Entries[EntryIndex];
      if ((Entry >> 12) == EFI_IMAGE_REL_BASED_ABSOLUTE) {
        continue;
      }

      if ((Entry >> 12) != EFI_IMAGE_REL_BASED_DIR64) {
        return EFI_UNSUPPORTED;
      }

      FixupRva = Block->VirtualAddress + (Entry & 0x0fffU);
      if (!Cdk2NativeRangeValid (FixupRva, sizeof (UINT64), ImageSize)) {
        return EFI_COMPROMISED_DATA;
      }

      Fixup  = (UINT64 *)(VOID *)(LoadedImage + FixupRva);
      *Fixup = *Fixup + Adjust;
    }

    Offset += BlockSize;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2NativeLoadPe32Plus (
  IN  CONST VOID             *Image,
  IN  UINTN                   ImageSize,
  IN  EFI_PHYSICAL_ADDRESS    Destination,
  IN  UINTN                   DestinationSize,
  OUT EFI_PHYSICAL_ADDRESS   *LoadedBase,
  OUT UINTN                  *LoadedSize,
  OUT EFI_PHYSICAL_ADDRESS   *EntryPoint
  )
{
  CONST UINT8                       *ImageBytes;
  CONST EFI_IMAGE_DOS_HEADER        *DosHeader;
  CONST EFI_IMAGE_NT_HEADERS64      *NtHeaders;
  CONST EFI_IMAGE_SECTION_HEADER    *Sections;
  CONST EFI_IMAGE_SECTION_HEADER    *Section;
  CONST EFI_IMAGE_OPTIONAL_HEADER64 *Optional;
  UINTN                              PeOffset;
  UINTN                              SectionOffset;
  UINTN                              SectionTableSize;
  UINTN                              Index;
  UINTN                              OtherIndex;
  UINTN                              VirtualSize;
  UINTN                              SectionSpan;
  UINTN                              RawOffset;
  UINTN                              RawSize;
  UINT32                             EndRva;
  UINT32                             EntryRva;
  EFI_STATUS                         Status;

  if (Image == NULL || ImageSize == 0 || Destination == 0 ||
      LoadedBase == NULL || LoadedSize == NULL || EntryPoint == NULL)
  {
    return EFI_INVALID_PARAMETER;
  }

  ImageBytes = (CONST UINT8 *)Image;
  PeOffset   = 0;
  if (ImageSize >= sizeof (EFI_IMAGE_DOS_HEADER) &&
      ((CONST EFI_IMAGE_DOS_HEADER *)Image)->e_magic == EFI_IMAGE_DOS_SIGNATURE)
  {
    DosHeader = (CONST EFI_IMAGE_DOS_HEADER *)Image;
    PeOffset  = DosHeader->e_lfanew;
  }

  if (PeOffset > ImageSize || ImageSize - PeOffset < sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER)) {
    return EFI_COMPROMISED_DATA;
  }

  NtHeaders = (CONST EFI_IMAGE_NT_HEADERS64 *)(VOID *)(ImageBytes + PeOffset);
  if (NtHeaders->Signature != EFI_IMAGE_NT_SIGNATURE ||
      NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_X64 ||
      NtHeaders->FileHeader.NumberOfSections == 0 ||
      NtHeaders->FileHeader.NumberOfSections > 96 ||
      NtHeaders->FileHeader.SizeOfOptionalHeader < sizeof (EFI_IMAGE_OPTIONAL_HEADER64))
  {
    return EFI_UNSUPPORTED;
  }

  Optional = &NtHeaders->OptionalHeader;
  if (Optional->Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      Optional->SectionAlignment == 0 ||
      (Optional->SectionAlignment & (Optional->SectionAlignment - 1)) != 0 ||
      Optional->SizeOfImage == 0 ||
      Optional->SizeOfHeaders == 0 ||
      Optional->SizeOfHeaders > Optional->SizeOfImage ||
      Optional->SizeOfHeaders > ImageSize ||
      Optional->AddressOfEntryPoint >= Optional->SizeOfImage ||
      Optional->SizeOfImage > DestinationSize ||
      !Cdk2NativeRangeValid (Destination, Optional->SizeOfImage, MAX_UINTN))
  {
    return EFI_COMPROMISED_DATA;
  }

  SectionOffset = PeOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) +
                  NtHeaders->FileHeader.SizeOfOptionalHeader;
  SectionTableSize = (UINTN)NtHeaders->FileHeader.NumberOfSections * sizeof (EFI_IMAGE_SECTION_HEADER);
  if (SectionOffset > ImageSize || SectionTableSize > ImageSize - SectionOffset) {
    return EFI_COMPROMISED_DATA;
  }

  Sections = (CONST EFI_IMAGE_SECTION_HEADER *)(VOID *)(ImageBytes + SectionOffset);
  for (Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; Index++) {
    Section = &Sections[Index];
    VirtualSize = Section->Misc.VirtualSize;
    SectionSpan = (VirtualSize > Section->SizeOfRawData) ? VirtualSize : Section->SizeOfRawData;
    EndRva = Section->VirtualAddress + (UINT32)SectionSpan;
    if (SectionSpan == 0 || EndRva < Section->VirtualAddress || EndRva > Optional->SizeOfImage ||
        (Section->VirtualAddress & (Optional->SectionAlignment - 1)) != 0)
    {
      return EFI_COMPROMISED_DATA;
    }

    RawOffset = Section->PointerToRawData;
    RawSize   = Section->SizeOfRawData;
    if (RawSize > ImageSize || RawOffset > ImageSize - RawSize) {
      return EFI_COMPROMISED_DATA;
    }

    for (OtherIndex = 0; OtherIndex < Index; OtherIndex++) {
      UINTN  OtherSize;
      UINT32 OtherEnd;

      OtherSize = (Sections[OtherIndex].Misc.VirtualSize > Sections[OtherIndex].SizeOfRawData) ?
                  Sections[OtherIndex].Misc.VirtualSize : Sections[OtherIndex].SizeOfRawData;
      OtherEnd = Sections[OtherIndex].VirtualAddress + (UINT32)OtherSize;
      if ((Section->VirtualAddress < OtherEnd) &&
          (Sections[OtherIndex].VirtualAddress < EndRva))
      {
        return EFI_COMPROMISED_DATA;
      }
    }
  }

  Cdk2NativeZero ((VOID *)(UINTN)Destination, Optional->SizeOfImage);
  Cdk2NativeCopy ((VOID *)(UINTN)Destination, Image, Optional->SizeOfHeaders);
  for (Index = 0; Index < NtHeaders->FileHeader.NumberOfSections; Index++) {
    Section = &Sections[Index];
    if (Section->SizeOfRawData != 0) {
      Cdk2NativeCopy (
        (VOID *)(UINTN)(Destination + Section->VirtualAddress),
        ImageBytes + Section->PointerToRawData,
        Section->SizeOfRawData
        );
    }
  }

  if (Optional->NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC) {
    Status = Cdk2NativeApplyRelocations (
               (UINT8 *)(UINTN)Destination,
               Optional->SizeOfImage,
               Optional->ImageBase,
               Destination,
               &Optional->DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC]
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Optional->ImageBase != Destination) {
    return EFI_UNSUPPORTED;
  }

  EntryRva   = Optional->AddressOfEntryPoint;
  *LoadedBase = Destination;
  *LoadedSize = Optional->SizeOfImage;
  *EntryPoint = Destination + EntryRva;
  return EFI_SUCCESS;
}
