/** @file

  Native cdk2 firmware-volume packer.

  The EDK II build still produces PE/COFF module images and the DXE firmware
  volume reference. This tool owns the final payload FV assembly so the cdk2
  Make backend does not consume the FDF-generated PLDFV image. In flat mode,
  the retained DXE files are placed directly in the outer volume.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FV_HEADER_SIZE                 0x48U
#define FV_SIZE_DEFAULT                0x00A00000U
#define FV_BASE_ADDRESS                0x00800000U
#define FV_EXT_HEADER_OFFSET           0x60U
#define FV_EXT_HEADER_SIZE             0x14U
#define FFS_HEADER_SIZE                0x18U
#define FFS_PAD_TYPE                   0xF0U
#define FFS_STATE_VALID                0xF8U
#define FFS_FIXED_CHECKSUM             0xAAU
#define FFS_ATTRIB_DATA_ALIGNMENT_16   0x08U
#define FFS_ATTRIB_DATA_ALIGNMENT_128  0x10U
#define FFS_TYPE_SECURITY_CORE         0x03U
#define FFS_TYPE_DXE_CORE              0x05U
#define FFS_TYPE_FV_IMAGE              0x0BU
#define SECTION_TYPE_PE32              0x10U
#define SECTION_TYPE_FV_IMAGE          0x17U
#define SECTION_TYPE_RAW               0x19U

typedef struct {
  uint8_t  *Data;
  size_t   Size;
} BLOB;

typedef struct {
  char  *Path;
  BLOB  File;
} FFS_INPUT;

typedef struct {
  FFS_INPUT  *Items;
  size_t     Count;
} FFS_INPUTS;

static const uint8_t  mFfsPadGuid[16] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const uint8_t  mFileSystemGuid[16] = {
  0x78, 0xE5, 0x8C, 0x8C, 0x3D, 0x8A, 0x1C, 0x4F,
  0x99, 0x35, 0x89, 0x61, 0x85, 0xC3, 0x2D, 0xD3
};

static const uint8_t  mVolumeNameGuid[16] = {
  0x86, 0x59, 0xE7, 0x96, 0xDD, 0x6F, 0x1E, 0x49,
  0x9F, 0xD5, 0x35, 0xE2, 0x1A, 0xC4, 0x5B, 0x45
};

static const uint8_t  mPayloadEntryGuid[16] = {
  0xD7, 0xBB, 0x19, 0x21, 0x32, 0x94, 0x47, 0x4F,
  0xB5, 0xE2, 0x5C, 0x4E, 0xA3, 0x1B, 0x6B, 0xDC
};

static const uint8_t  mDxeVolumeFileGuid[16] = {
  0x93, 0xFD, 0x35, 0x4E, 0x72, 0x9C, 0x15, 0x4C,
  0x8C, 0x4B, 0xE7, 0x7F, 0x1D, 0xB2, 0xD7, 0x93
};

static void
Fail (
  const char  *Message
  )
{
  fprintf (stderr, "cdk2-fvpack: %s\n", Message);
  exit (EXIT_FAILURE);
}

static void *
Allocate (
  size_t  Size
  )
{
  void  *Buffer;

  Buffer = malloc (Size == 0 ? 1 : Size);
  if (Buffer == NULL) {
    Fail ("out of memory");
  }

  return Buffer;
}

static void
Put16 (
  uint8_t   *Buffer,
  uint16_t  Value
  )
{
  Buffer[0] = (uint8_t)Value;
  Buffer[1] = (uint8_t)(Value >> 8);
}

static void
Put32 (
  uint8_t   *Buffer,
  uint32_t  Value
  )
{
  Buffer[0] = (uint8_t)Value;
  Buffer[1] = (uint8_t)(Value >> 8);
  Buffer[2] = (uint8_t)(Value >> 16);
  Buffer[3] = (uint8_t)(Value >> 24);
}

static void
Put64 (
  uint8_t   *Buffer,
  uint64_t  Value
  )
{
  Put32 (Buffer, (uint32_t)Value);
  Put32 (Buffer + 4, (uint32_t)(Value >> 32));
}

static void
Put24 (
  uint8_t   *Buffer,
  size_t    Value
  )
{
  if (Value > 0xFFFFFFU) {
    Fail ("24-bit field overflow");
  }

  Buffer[0] = (uint8_t)Value;
  Buffer[1] = (uint8_t)(Value >> 8);
  Buffer[2] = (uint8_t)(Value >> 16);
}

static uint8_t
Checksum8 (
  const uint8_t  *Buffer,
  size_t         Size
  )
{
  uint8_t  Sum;
  size_t   Index;

  Sum = 0;
  for (Index = 0; Index < Size; Index++) {
    Sum = (uint8_t)(Sum + Buffer[Index]);
  }

  return (uint8_t)(0U - Sum);
}

static uint16_t
Checksum16 (
  const uint8_t  *Buffer,
  size_t         Size
  )
{
  uint32_t  Sum;
  size_t    Index;

  if ((Size & 1U) != 0) {
    Fail ("16-bit checksum has odd length");
  }

  Sum = 0;
  for (Index = 0; Index < Size; Index += 2) {
    Sum += (uint16_t)(Buffer[Index] | ((uint16_t)Buffer[Index + 1] << 8));
  }

  return (uint16_t)(0U - (uint16_t)Sum);
}

static size_t
AlignUp (
  size_t  Value,
  size_t  Alignment
  )
{
  if ((Alignment == 0) || ((Alignment & (Alignment - 1)) != 0)) {
    Fail ("invalid alignment");
  }

  return (Value + Alignment - 1) & ~(Alignment - 1);
}

static uint16_t
Get16 (
  const uint8_t  *Buffer
  )
{
  return (uint16_t)(Buffer[0] | ((uint16_t)Buffer[1] << 8));
}

static uint32_t
Get32 (
  const uint8_t  *Buffer
  )
{
  return (uint32_t)(Buffer[0] |
                    ((uint32_t)Buffer[1] << 8) |
                    ((uint32_t)Buffer[2] << 16) |
                    ((uint32_t)Buffer[3] << 24));
}

static size_t
Get24 (
  const uint8_t  *Buffer
  )
{
  return (size_t)(Buffer[0] |
                  ((size_t)Buffer[1] << 8) |
                  ((size_t)Buffer[2] << 16));
}

static uint64_t
Get64 (
  const uint8_t  *Buffer
  )
{
  return (uint64_t)Get32 (Buffer) | ((uint64_t)Get32 (Buffer + 4) << 32);
}

static size_t
RvaToFileOffset (
  const uint8_t  *Image,
  size_t          ImageSize,
  uint32_t        PeOffset,
  uint32_t        Rva
  )
{
  const uint8_t  *Coff;
  const uint8_t  *Optional;
  const uint8_t  *Section;
  uint16_t        SectionCount;
  uint16_t        OptionalSize;
  uint16_t        Index;
  uint32_t        VirtualAddress;
  uint32_t        VirtualSize;
  uint32_t        RawSize;
  uint32_t        RawOffset;
  uint32_t        Span;

  if ((PeOffset > ImageSize) || (ImageSize - PeOffset < 24)) {
    Fail ("PE header is outside the entry image");
  }

  Coff = Image + PeOffset + 4;
  SectionCount = Get16 (Coff + 2);
  OptionalSize = Get16 (Coff + 16);
  Optional = Coff + 20;
  Section = Optional + OptionalSize;
  if ((size_t)(Section - Image) > ImageSize) {
    Fail ("PE section table is outside the entry image");
  }

  for (Index = 0; Index < SectionCount; Index++) {
    if ((size_t)(Section + 40 - Image) > ImageSize) {
      Fail ("PE section header is outside the entry image");
    }

    VirtualSize = Get32 (Section + 8);
    VirtualAddress = Get32 (Section + 12);
    RawSize = Get32 (Section + 16);
    RawOffset = Get32 (Section + 20);
    Span = (VirtualSize > RawSize) ? VirtualSize : RawSize;
    if ((Rva >= VirtualAddress) && (Rva - VirtualAddress < Span)) {
      if ((Rva - VirtualAddress >= RawSize) ||
          (RawOffset > ImageSize) ||
          ((size_t)(Rva - VirtualAddress) > ImageSize - RawOffset)) {
        Fail ("PE relocation points outside the entry image");
      }

      return (size_t)RawOffset + (Rva - VirtualAddress);
    }

    Section += 40;
  }

  Fail ("PE relocation RVA is not in a section");
  return 0;
}

static void
RelocatePe (
  BLOB     *Image,
  uint64_t  TargetBase
  )
{
  uint32_t       PeOffset;
  uint64_t       OriginalBase;
  uint64_t       Delta;
  uint32_t       RelocRva;
  uint32_t       RelocSize;
  size_t         OptionalOffset;
  size_t         RelocOffset;
  size_t         RelocEnd;
  size_t         BlockOffset;
  size_t         DataDirectoryOffset;
  size_t         ImageBaseOffset;
  size_t         FixupSize;
  uint32_t       PageRva;
  uint32_t       BlockSize;
  uint16_t       Entry;
  uint16_t       Type;
  uint16_t       RelocType;
  uint16_t       Offset;
  uint16_t       OptionalMagic;
  size_t         FixupOffset;
  uint64_t       Value;

  if ((Image->Size < 0x40) || (Get16 (Image->Data) != 0x5A4D)) {
    Fail ("payload entry is not a PE image");
  }

  PeOffset = Get32 (Image->Data + 0x3C);
  if ((PeOffset > Image->Size) || (Image->Size - PeOffset < 24) ||
      (Get32 (Image->Data + PeOffset) != 0x00004550U)) {
    Fail ("payload entry has an invalid PE signature");
  }

  OptionalOffset = (size_t)PeOffset + 4 + 20;
  if ((OptionalOffset > Image->Size) || (Image->Size - OptionalOffset < 2)) {
    Fail ("payload entry optional header is outside the image");
  }

  OptionalMagic = Get16 (Image->Data + OptionalOffset);
  if (OptionalMagic == 0x010BU) {
    DataDirectoryOffset = 96;
    ImageBaseOffset     = 28;
    FixupSize           = sizeof (uint32_t);
    RelocType           = 3;
  } else if (OptionalMagic == 0x020BU) {
    DataDirectoryOffset = 112;
    ImageBaseOffset     = 24;
    FixupSize           = sizeof (uint64_t);
    RelocType           = 10;
  } else {
    Fail ("payload entry has an unsupported PE optional header");
  }

  if (Image->Size - OptionalOffset < DataDirectoryOffset + (6 * 8)) {
    Fail ("payload entry data directories are outside the image");
  }

  OriginalBase = (OptionalMagic == 0x020BU) ?
                 Get64 (Image->Data + OptionalOffset + ImageBaseOffset) :
                 Get32 (Image->Data + OptionalOffset + ImageBaseOffset);
  RelocRva  = Get32 (Image->Data + OptionalOffset + DataDirectoryOffset + (5 * 8));
  RelocSize = Get32 (Image->Data + OptionalOffset + DataDirectoryOffset + (5 * 8) + 4);
  if ((RelocRva == 0) || (RelocSize == 0)) {
    // EDK2's X64 PIE entry uses RIP-relative references and advertises an
    // image base of zero, so it does not need a relocation directory.
    if (OriginalBase == 0) {
      return;
    }

    Fail ("payload entry has no base relocation directory");
  }

  RelocOffset = RvaToFileOffset (Image->Data, Image->Size, PeOffset, RelocRva);
  if ((RelocOffset > Image->Size) || (RelocSize > Image->Size - RelocOffset)) {
    Fail ("payload relocation directory is outside the entry image");
  }

  if (TargetBase < OriginalBase) {
    Fail ("payload relocation would underflow");
  }

  Delta = TargetBase - OriginalBase;
  RelocEnd = RelocOffset + RelocSize;
  BlockOffset = RelocOffset;
  while (BlockOffset < RelocEnd) {
    if (RelocEnd - BlockOffset < 8) {
      Fail ("truncated payload relocation block");
    }

    PageRva = Get32 (Image->Data + BlockOffset);
    BlockSize = Get32 (Image->Data + BlockOffset + 4);
    if ((BlockSize < 8) || (BlockSize > RelocEnd - BlockOffset) ||
        (((BlockSize - 8) & 1U) != 0)) {
      Fail ("invalid payload relocation block");
    }

    for (size_t EntryOffset = 8; EntryOffset < BlockSize; EntryOffset += 2) {
      Entry = Get16 (Image->Data + BlockOffset + EntryOffset);
      Type = (uint16_t)(Entry >> 12);
      Offset = (uint16_t)(Entry & 0x0FFFU);
      if (Type == 0) {
        continue;
      }

      if (Type != RelocType) {
        Fail ("unsupported payload relocation type");
      }

      FixupOffset = RvaToFileOffset (Image->Data, Image->Size, PeOffset, PageRva + Offset);
      if (FixupOffset > Image->Size || Image->Size - FixupOffset < FixupSize) {
        Fail ("payload relocation fixup is outside the entry image");
      }

      if (FixupSize == sizeof (uint64_t)) {
        Value = Get64 (Image->Data + FixupOffset);
        if (Value > UINT64_MAX - Delta) {
          Fail ("payload relocation fixup overflows");
        }

        Put64 (Image->Data + FixupOffset, Value + Delta);
      } else {
        Value = Get32 (Image->Data + FixupOffset);
        if (Value > UINT32_MAX - (uint32_t)Delta) {
          Fail ("payload relocation fixup overflows");
        }

        Put32 (Image->Data + FixupOffset, (uint32_t)Value + (uint32_t)Delta);
      }
    }

    BlockOffset += BlockSize;
  }

  if (OptionalMagic == 0x020BU) {
    Put64 (Image->Data + OptionalOffset + ImageBaseOffset, TargetBase);
  } else {
    if (TargetBase > UINT32_MAX) {
      Fail ("PE32 relocation base overflows");
    }

    Put32 (Image->Data + OptionalOffset + ImageBaseOffset, (uint32_t)TargetBase);
  }
}

static BLOB
ReadFile (
  const char  *Path
  )
{
  BLOB    Result;
  FILE    *File;
  long    Length;

  File = fopen (Path, "rb");
  if (File == NULL) {
    fprintf (stderr, "cdk2-fvpack: cannot open %s: %s\n", Path, strerror (errno));
    exit (EXIT_FAILURE);
  }

  if (fseek (File, 0, SEEK_END) != 0) {
    Fail ("cannot seek input file");
  }

  Length = ftell (File);
  if (Length < 0) {
    Fail ("cannot determine input file size");
  }

  if (fseek (File, 0, SEEK_SET) != 0) {
    Fail ("cannot rewind input file");
  }

  Result.Size = (size_t)Length;
  Result.Data = Allocate (Result.Size);
  if (fread (Result.Data, 1, Result.Size, File) != Result.Size) {
    Fail ("cannot read input file");
  }

  fclose (File);
  return Result;
}

static char *
DuplicateString (
  const char  *String
  )
{
  size_t  Length;
  char    *Copy;

  Length = strlen (String) + 1;
  Copy   = Allocate (Length);
  memcpy (Copy, String, Length);
  return Copy;
}

static void
ReadFfsList (
  const char   *Path,
  FFS_INPUTS   *Inputs
  )
{
  FILE       *File;
  char        Line[4096];
  char       *End;
  FFS_INPUT  *Item;

  File = fopen (Path, "r");
  if (File == NULL) {
    fprintf (stderr, "cdk2-fvpack: cannot open FFS list %s: %s\n", Path, strerror (errno));
    exit (EXIT_FAILURE);
  }

  while (fgets (Line, sizeof (Line), File) != NULL) {
    End = Line + strlen (Line);
    while ((End > Line) && ((End[-1] == '\n') || (End[-1] == '\r'))) {
      End--;
      *End = '\0';
    }

    if ((Line[0] == '\0') || (Line[0] == '#')) {
      continue;
    }

    Item = realloc (Inputs->Items, (Inputs->Count + 1) * sizeof (*Item));
    if (Item == NULL) {
      Fail ("out of memory reading FFS list");
    }

    Inputs->Items = Item;
    Item = &Inputs->Items[Inputs->Count++];
    Item->Path = DuplicateString (Line);
    Item->File = ReadFile (Line);
    if (Item->File.Size < FFS_HEADER_SIZE) {
      Fail ("FFS input is smaller than its header");
    }
  }

  if (ferror (File) != 0) {
    Fail ("cannot read FFS list");
  }

  fclose (File);
}

static FFS_INPUT *
FindFfsInput (
  const FFS_INPUTS  *Inputs,
  const uint8_t     *Guid
  )
{
  size_t  Index;

  for (Index = 0; Index < Inputs->Count; Index++) {
    if (memcmp (Inputs->Items[Index].File.Data, Guid, 16) == 0) {
      return &Inputs->Items[Index];
    }
  }

  return NULL;
}

static void
PrintGuid (
  const uint8_t  *Guid
  )
{
  size_t  Index;

  for (Index = 0; Index < 16; Index++) {
    fprintf (stderr, "%02x", Guid[Index]);
  }
}

static void
FreeFfsInputs (
  FFS_INPUTS  *Inputs
  )
{
  size_t  Index;

  for (Index = 0; Index < Inputs->Count; Index++) {
    free (Inputs->Items[Index].Path);
    free (Inputs->Items[Index].File.Data);
  }

  free (Inputs->Items);
  Inputs->Items = NULL;
  Inputs->Count = 0;
}

static void
WriteFile (
  const char  *Path,
  const uint8_t  *Data,
  size_t        Size
  )
{
  FILE  *File;

  File = fopen (Path, "wb");
  if (File == NULL) {
    fprintf (stderr, "cdk2-fvpack: cannot create %s: %s\n", Path, strerror (errno));
    exit (EXIT_FAILURE);
  }

  if (fwrite (Data, 1, Size, File) != Size) {
    Fail ("cannot write output file");
  }

  if (fclose (File) != 0) {
    Fail ("cannot close output file");
  }
}

static BLOB
MakeFfs (
  const uint8_t  *Guid,
  uint8_t        Type,
  uint8_t        Attributes,
  const uint8_t  *Body,
  size_t         BodySize
  )
{
  BLOB     Result;
  uint8_t  HeaderChecksum;

  if (BodySize > 0xFFFFFFU - FFS_HEADER_SIZE) {
    Fail ("FFS file is too large");
  }

  Result.Size = FFS_HEADER_SIZE + BodySize;
  Result.Data = Allocate (Result.Size);
  memset (Result.Data, 0, Result.Size);
  memcpy (Result.Data, Guid, 16);
  Result.Data[18] = Type;
  Result.Data[19] = Attributes;
  Put24 (Result.Data + 20, Result.Size);
  Result.Data[23] = 0;

  HeaderChecksum = Checksum8 (Result.Data, FFS_HEADER_SIZE);
  Result.Data[16] = HeaderChecksum;
  Result.Data[17] = FFS_FIXED_CHECKSUM;
  Result.Data[23] = FFS_STATE_VALID;
  memcpy (Result.Data + FFS_HEADER_SIZE, Body, BodySize);
  return Result;
}

static BLOB
MakePad (
  size_t         Size,
  const uint8_t  *Extension
  )
{
  BLOB     Result;
  uint8_t  *Body;

  if (Size < FFS_HEADER_SIZE) {
    Fail ("padding file is smaller than an FFS header");
  }

  Body = Allocate (Size - FFS_HEADER_SIZE);
  memset (Body, 0xFF, Size - FFS_HEADER_SIZE);
  if (Extension != NULL) {
    if (Size - FFS_HEADER_SIZE < FV_EXT_HEADER_SIZE) {
      Fail ("padding file cannot contain the FV extension header");
    }

    memcpy (Body, Extension, FV_EXT_HEADER_SIZE);
  }

  Result = MakeFfs (mFfsPadGuid, FFS_PAD_TYPE, 0, Body, Size - FFS_HEADER_SIZE);
  free (Body);
  return Result;
}

static size_t
MakeSectionPrefix (
  size_t  FileOffset,
  size_t  SectionAlignment
  )
{
  size_t  RawSectionSize;

  RawSectionSize = 4;
  while (((FileOffset + FFS_HEADER_SIZE + RawSectionSize + 4) % SectionAlignment) != 0) {
    RawSectionSize += 4;
  }

  return RawSectionSize;
}

static BLOB
MakeSectionFile (
  const uint8_t  *Guid,
  uint8_t        Type,
  uint8_t        Attributes,
  size_t         FileOffset,
  size_t         SectionAlignment,
  uint8_t        SectionType,
  const BLOB     *Payload
  )
{
  BLOB    Result;
  size_t  RawSectionSize;
  size_t  BodySize;
  uint8_t  *Body;

  RawSectionSize = MakeSectionPrefix (FileOffset, SectionAlignment);

  BodySize = RawSectionSize + 4 + Payload->Size;
  Body = Allocate (BodySize);
  memset (Body, 0, BodySize);
  Put24 (Body, RawSectionSize);
  Body[3] = SECTION_TYPE_RAW;
  Put24 (Body + RawSectionSize, 4 + Payload->Size);
  Body[RawSectionSize + 3] = SectionType;
  memcpy (Body + RawSectionSize + 4, Payload->Data, Payload->Size);

  Result = MakeFfs (Guid, Type, Attributes, Body, BodySize);
  free (Body);
  return Result;
}

static size_t
FfsDataAlignment (
  uint8_t  Attributes
  )
{
  switch ((Attributes >> 3) & 0x07U) {
    case 0:
      return 1U << ((Attributes & 0x02U) ? 17 : 0);
    case 1:
      return 1U << ((Attributes & 0x02U) ? 18 : 4);
    case 2:
      return 1U << ((Attributes & 0x02U) ? 19 : 7);
    default:
      Fail ("unsupported FFS data alignment");
      return 0;
  }
}

static size_t
PlaceFfs (
  uint8_t       *Volume,
  size_t         VolumeSize,
  size_t         CurrentOffset,
  const BLOB     *File
  )
{
  size_t  Alignment;
  size_t  Start;

  Alignment = FfsDataAlignment (File->Data[19]);
  Start = AlignUp (CurrentOffset + FFS_HEADER_SIZE, Alignment) - FFS_HEADER_SIZE;
  if ((Start > CurrentOffset) && ((Start - CurrentOffset) < FFS_HEADER_SIZE)) {
    // A pad FFS must contain a complete header. GenFv skips to the next
    // aligned data slot when the first gap cannot hold one.
    Start += Alignment;
  }

  if (Start > CurrentOffset) {
    BLOB  Padding;
    size_t  PaddingSize;

    PaddingSize = Start - CurrentOffset;
    Padding = MakePad (PaddingSize, NULL);
    memcpy (Volume + CurrentOffset, Padding.Data, Padding.Size);
    free (Padding.Data);
    CurrentOffset = AlignUp (CurrentOffset + PaddingSize, 8);
  }

  if ((CurrentOffset != Start) || (Start + File->Size > VolumeSize)) {
    Fail ("FFS file does not fit in the firmware volume");
  }

  memcpy (Volume + Start, File->Data, File->Size);
  return AlignUp (Start + File->Size, 8);
}

static bool
IsErased (
  const uint8_t  *Data,
  size_t          Size
  )
{
  size_t  Index;

  for (Index = 0; Index < Size; Index++) {
    if (Data[Index] != 0xFF) {
      return false;
    }
  }

  return true;
}

static BLOB
PackDxeVolume (
  const BLOB        *Reference,
  const FFS_INPUTS  *Inputs
  )
{
  BLOB         Result;
  FFS_INPUT   *Input;
  size_t       VolumeSize;
  size_t       HeaderLength;
  size_t       ExtendedHeaderOffset;
  size_t       ExtendedHeaderSize;
  size_t       FfsOffset;
  size_t       ReferenceOffset;
  size_t       CurrentOffset;
  size_t       FileSize;
  uint8_t      FileType;
  const uint8_t  *ReferenceFile;

  if (Reference->Size < FV_HEADER_SIZE) {
    Fail ("DXE FV reference is smaller than its header");
  }

  VolumeSize  = (size_t)Get64 (Reference->Data + 0x20);
  HeaderLength = Get16 (Reference->Data + 0x30);
  if ((VolumeSize < HeaderLength) || (VolumeSize > Reference->Size) ||
      (HeaderLength < FV_HEADER_SIZE)) {
    Fail ("DXE FV reference has invalid volume bounds");
  }

  ExtendedHeaderOffset = Get16 (Reference->Data + 0x34);
  if (ExtendedHeaderOffset != 0) {
    if ((ExtendedHeaderOffset < HeaderLength) ||
        (ExtendedHeaderOffset > VolumeSize) ||
        (VolumeSize - ExtendedHeaderOffset < 20)) {
      Fail ("DXE FV reference has an invalid extended header offset");
    }

    ExtendedHeaderSize = (size_t)Get32 (Reference->Data + ExtendedHeaderOffset + 16);
    if ((ExtendedHeaderSize < FV_EXT_HEADER_SIZE) ||
        (ExtendedHeaderSize > VolumeSize - ExtendedHeaderOffset)) {
      Fail ("DXE FV reference has an invalid extended header size");
    }

    FfsOffset = AlignUp (ExtendedHeaderOffset + ExtendedHeaderSize, 8);
  } else {
    FfsOffset = AlignUp (HeaderLength, 8);
  }

  if (FfsOffset > VolumeSize) {
    Fail ("DXE FV reference has no room after its headers");
  }

  Result.Size = VolumeSize;
  Result.Data = Allocate (Result.Size);
  memset (Result.Data, 0xFF, Result.Size);
  memcpy (Result.Data, Reference->Data, FfsOffset);
  CurrentOffset = FfsOffset;

  for (ReferenceOffset = CurrentOffset;
       ReferenceOffset <= VolumeSize - FFS_HEADER_SIZE;
       ReferenceOffset = AlignUp (ReferenceOffset + FileSize, 8)) {
    ReferenceFile = Reference->Data + ReferenceOffset;
    if (IsErased (ReferenceFile, FFS_HEADER_SIZE)) {
      break;
    }

    FileSize = Get24 (ReferenceFile + 20);
    FileType = ReferenceFile[18];
    if ((FileSize < FFS_HEADER_SIZE) || (FileSize > VolumeSize - ReferenceOffset)) {
      Fail ("DXE FV reference contains an invalid FFS file");
    }

    if (FileType == FFS_PAD_TYPE) {
      if (ReferenceOffset != CurrentOffset) {
        Fail ("DXE FV native cursor diverged at an FFS pad file");
      }

      memcpy (Result.Data + ReferenceOffset, ReferenceFile, FileSize);
      CurrentOffset = AlignUp (ReferenceOffset + FileSize, 8);
      continue;
    }

    Input = FindFfsInput (Inputs, ReferenceFile);
    if ((Input == NULL) || (Input->File.Size != FileSize)) {
      fprintf (stderr, "cdk2-fvpack: DXE FV input mismatch: type=0x%02x size=0x%zx guid=", FileType, FileSize);
      PrintGuid (ReferenceFile);
      fputc ('\n', stderr);
      if (Input == NULL) {
        Fail ("DXE FV reference file is missing from the FFS input list");
      }

      Fail ("DXE FV FFS input size differs from the reference");
    }

    // GenFfs leaves the state byte in the build-time state; GenFv commits it.
    Input->File.Data[23] = FFS_STATE_VALID;
    CurrentOffset = PlaceFfs (Result.Data, Result.Size, CurrentOffset, &Input->File);
  }

  if (memcmp (Result.Data, Reference->Data, VolumeSize) != 0) {
    size_t  Difference;

    for (Difference = 0; Difference < VolumeSize; Difference++) {
      if (Result.Data[Difference] != Reference->Data[Difference]) {
        fprintf (stderr,
                 "cdk2-fvpack: first native DXE FV difference at 0x%zx: "
                 "native=0x%02x reference=0x%02x\n",
                 Difference,
                 Result.Data[Difference],
                 Reference->Data[Difference]);
        break;
      }
    }
    Fail ("native DXE FV does not match the GenFv reference");
  }

  return Result;
}

static size_t
GetFfsStartOffset (
  const BLOB  *Volume
  )
{
  size_t  VolumeLength;
  size_t  HeaderLength;
  size_t  ExtendedHeaderOffset;
  size_t  ExtendedHeaderSize;
  size_t  FfsOffset;

  if (Volume->Size < FV_HEADER_SIZE) {
    Fail ("firmware volume is smaller than its header");
  }

  VolumeLength = (size_t)Get64 (Volume->Data + 0x20);
  HeaderLength = (size_t)Get16 (Volume->Data + 0x30);
  if ((VolumeLength < HeaderLength) || (VolumeLength > Volume->Size) ||
      (HeaderLength < FV_HEADER_SIZE)) {
    Fail ("firmware volume has invalid bounds");
  }

  ExtendedHeaderOffset = (size_t)Get16 (Volume->Data + 0x34);
  if (ExtendedHeaderOffset == 0) {
    FfsOffset = AlignUp (HeaderLength, 8);
  } else {
    if ((ExtendedHeaderOffset < HeaderLength) ||
        (ExtendedHeaderOffset > VolumeLength) ||
        (VolumeLength - ExtendedHeaderOffset < FV_EXT_HEADER_SIZE)) {
      Fail ("firmware volume has an invalid extended header offset");
    }

    ExtendedHeaderSize = (size_t)Get32 (Volume->Data + ExtendedHeaderOffset + 16);
    if ((ExtendedHeaderSize < FV_EXT_HEADER_SIZE) ||
        (ExtendedHeaderSize > VolumeLength - ExtendedHeaderOffset)) {
      Fail ("firmware volume has an invalid extended header size");
    }

    FfsOffset = AlignUp (ExtendedHeaderOffset + ExtendedHeaderSize, 8);
  }

  if (FfsOffset > VolumeLength) {
    Fail ("firmware volume has no room after its headers");
  }

  return FfsOffset;
}

static BLOB
PackPayload (
  BLOB        *PayloadEntry,
  const BLOB  *DxeVolume,
  const FFS_INPUTS  *DxeInputs,
  bool         FlattenDxe,
  size_t      VolumeSize
  )
{
  BLOB     Result;
  BLOB     EntryFile;
  BLOB     DxeFile;
  FFS_INPUT  *Input;
  size_t   CurrentOffset;
  size_t   EntryOffset;
  size_t   EntryPrefixSize;
  size_t   DxeFfsOffset;
  size_t   ReferenceOffset;
  size_t   FileSize;
  uint8_t  FileType;
  bool     FoundDxeCore;
  uint8_t  ExtensionData[FV_EXT_HEADER_SIZE];

  if (VolumeSize < FV_HEADER_SIZE) {
    Fail ("firmware volume is smaller than its header");
  }

  Result.Size = VolumeSize;
  Result.Data = Allocate (Result.Size);
  memset (Result.Data, 0xFF, Result.Size);
  memset (Result.Data, 0, FV_HEADER_SIZE);
  memcpy (Result.Data + 0x10, mFileSystemGuid, sizeof (mFileSystemGuid));
  Put64 (Result.Data + 0x20, VolumeSize);
  memcpy (Result.Data + 0x28, "_FVH", 4);
  Put32 (Result.Data + 0x2C, 0x0007FEFFU);
  Put16 (Result.Data + 0x30, FV_HEADER_SIZE);
  Put16 (Result.Data + 0x32, 0);
  Put16 (Result.Data + 0x34, FV_EXT_HEADER_OFFSET);
  Result.Data[0x36] = 0;
  Result.Data[0x37] = 2;
  Put32 (Result.Data + 0x38, (uint32_t)(VolumeSize / 0x1000U));
  Put32 (Result.Data + 0x3C, 0x1000U);
  Put32 (Result.Data + 0x40, 0);
  Put32 (Result.Data + 0x44, 0);
  Put16 (Result.Data + 0x32, Checksum16 (Result.Data, FV_HEADER_SIZE));

  memcpy (ExtensionData, mVolumeNameGuid, sizeof (mVolumeNameGuid));
  Put32 (ExtensionData + 16, FV_EXT_HEADER_SIZE);
  CurrentOffset = FV_HEADER_SIZE;
  {
    BLOB  Padding;

    Padding = MakePad (FV_EXT_HEADER_OFFSET + FV_EXT_HEADER_SIZE - FV_HEADER_SIZE, ExtensionData);
    memcpy (Result.Data + CurrentOffset, Padding.Data, Padding.Size);
    free (Padding.Data);
    CurrentOffset = AlignUp (CurrentOffset + Padding.Size, 8);
  }

  EntryOffset = AlignUp (CurrentOffset + FFS_HEADER_SIZE, 128) - FFS_HEADER_SIZE;
  EntryPrefixSize = MakeSectionPrefix (EntryOffset, 32);
  RelocatePe (
    PayloadEntry,
    FV_BASE_ADDRESS + (uint64_t)(EntryOffset + FFS_HEADER_SIZE + EntryPrefixSize + 4)
    );

  EntryFile = MakeSectionFile (
                mPayloadEntryGuid,
                FFS_TYPE_SECURITY_CORE,
                FFS_ATTRIB_DATA_ALIGNMENT_128,
                EntryOffset,
                32,
                SECTION_TYPE_PE32,
                PayloadEntry
                );
  CurrentOffset = PlaceFfs (Result.Data, Result.Size, CurrentOffset, &EntryFile);
  free (EntryFile.Data);

  if (!FlattenDxe) {
    DxeFile = MakeSectionFile (
                mDxeVolumeFileGuid,
                FFS_TYPE_FV_IMAGE,
                FFS_ATTRIB_DATA_ALIGNMENT_16,
                AlignUp (CurrentOffset + FFS_HEADER_SIZE, 16) - FFS_HEADER_SIZE,
                16,
                SECTION_TYPE_FV_IMAGE,
                DxeVolume
                );
    CurrentOffset = PlaceFfs (Result.Data, Result.Size, CurrentOffset, &DxeFile);
    free (DxeFile.Data);
  } else {
    if (DxeInputs == NULL || DxeInputs->Count == 0) {
      Fail ("flat DXE FV requires an FFS input list");
    }

    DxeFfsOffset = GetFfsStartOffset (DxeVolume);

    FoundDxeCore = false;
    for (ReferenceOffset = DxeFfsOffset;
         ReferenceOffset <= DxeVolume->Size - FFS_HEADER_SIZE;
         ReferenceOffset = AlignUp (ReferenceOffset + FileSize, 8)) {
      const uint8_t  *ReferenceFile;

      ReferenceFile = DxeVolume->Data + ReferenceOffset;
      if (IsErased (ReferenceFile, FFS_HEADER_SIZE)) {
        break;
      }

      FileSize = Get24 (ReferenceFile + 20);
      FileType = ReferenceFile[18];
      if ((FileSize < FFS_HEADER_SIZE) ||
          (FileSize > DxeVolume->Size - ReferenceOffset)) {
        Fail ("flat DXE FV contains an invalid FFS file");
      }

      if (FileType == FFS_PAD_TYPE) {
        continue;
      }

      Input = FindFfsInput (DxeInputs, ReferenceFile);
      if ((Input == NULL) || (Input->File.Size != FileSize)) {
        Fail ("flat DXE FV input does not match the reference");
      }

      Input->File.Data[23] = FFS_STATE_VALID;
      CurrentOffset = PlaceFfs (Result.Data, Result.Size, CurrentOffset, &Input->File);
      FoundDxeCore = FoundDxeCore || (FileType == FFS_TYPE_DXE_CORE);
    }

    if (!FoundDxeCore) {
      Fail ("flat DXE FV does not contain a DXE core");
    }
  }

  /*
   * The requested volume size is a build-time upper bound.  Keeping the
   * unused tail in the linked image makes an otherwise small payload exceed
   * Coreboot's CBFS slot, and it needlessly mirrors erased bytes.  Emit only
   * the used FFS range, aligned to the FV block size, and make the header
   * describe the compact volume.
   */
  {
    size_t  CompactSize;

    CompactSize = AlignUp (CurrentOffset, 0x1000U);
    if (CompactSize > Result.Size) {
      Fail ("packed firmware volume exceeds the configured maximum size");
    }

    Put64 (Result.Data + 0x20, CompactSize);
    Put32 (Result.Data + 0x38, (uint32_t)(CompactSize / 0x1000U));
    Put16 (Result.Data + 0x32, 0);
    Put16 (Result.Data + 0x32, Checksum16 (Result.Data, FV_HEADER_SIZE));
    Result.Size = CompactSize;
  }

  fprintf (stdout, "cdk2 native FV%s: used=0x%zx free=0x%zx\n",
           FlattenDxe ? " (flat)" : "", CurrentOffset, Result.Size - CurrentOffset);
  return Result;
}

static void
Usage (
  const char  *Program
  )
{
  fprintf (stderr,
           "usage: %s --output FILE --entry-efi FILE --dxe-fv FILE "
           "[--dxe-ffs-list FILE] [--flatten-dxe] [--size BYTES]\n",
           Program);
}

int
main (
  int    Argc,
  char  **Argv
  )
{
  const char  *OutputPath;
  const char  *EntryPath;
  const char  *DxePath;
  const char  *DxeFfsListPath;
  bool         FlattenDxe;
  size_t      VolumeSize;
  int         Index;
  BLOB        Entry;
  BLOB        Dxe;
  BLOB        Volume;
  FFS_INPUTS  DxeInputs;

  OutputPath = NULL;
  EntryPath  = NULL;
  DxePath    = NULL;
  DxeFfsListPath = NULL;
  FlattenDxe = false;
  VolumeSize = FV_SIZE_DEFAULT;
  DxeInputs.Items = NULL;
  DxeInputs.Count = 0;
  for (Index = 1; Index < Argc; Index++) {
    if ((strcmp (Argv[Index], "--output") == 0) && (Index + 1 < Argc)) {
      OutputPath = Argv[++Index];
    } else if ((strcmp (Argv[Index], "--entry-efi") == 0) && (Index + 1 < Argc)) {
      EntryPath = Argv[++Index];
    } else if ((strcmp (Argv[Index], "--dxe-fv") == 0) && (Index + 1 < Argc)) {
      DxePath = Argv[++Index];
    } else if ((strcmp (Argv[Index], "--dxe-ffs-list") == 0) && (Index + 1 < Argc)) {
      DxeFfsListPath = Argv[++Index];
    } else if (strcmp (Argv[Index], "--flatten-dxe") == 0) {
      FlattenDxe = true;
    } else if ((strcmp (Argv[Index], "--size") == 0) && (Index + 1 < Argc)) {
      char  *End;

      VolumeSize = (size_t)strtoull (Argv[++Index], &End, 0);
      if ((*End != '\0') || (VolumeSize == 0)) {
        Usage (Argv[0]);
        return EXIT_FAILURE;
      }
    } else {
      Usage (Argv[0]);
      return EXIT_FAILURE;
    }
  }

  if ((OutputPath == NULL) || (EntryPath == NULL) || (DxePath == NULL) ||
      (FlattenDxe && (DxeFfsListPath == NULL))) {
    Usage (Argv[0]);
    return EXIT_FAILURE;
  }

  Entry  = ReadFile (EntryPath);
  Dxe    = ReadFile (DxePath);
  if (DxeFfsListPath != NULL) {
    ReadFfsList (DxeFfsListPath, &DxeInputs);
    {
      BLOB  NativeDxe;

      NativeDxe = PackDxeVolume (&Dxe, &DxeInputs);
      free (Dxe.Data);
      Dxe = NativeDxe;
    }
  }
  Volume = PackPayload (&Entry, &Dxe, &DxeInputs, FlattenDxe, VolumeSize);
  WriteFile (OutputPath, Volume.Data, Volume.Size);
  free (Entry.Data);
  free (Dxe.Data);
  free (Volume.Data);
  FreeFfsInputs (&DxeInputs);
  return EXIT_SUCCESS;
}
