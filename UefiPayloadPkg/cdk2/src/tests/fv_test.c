/** @file

  Host checks for native firmware-volume discovery.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <cdk2/fv.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FV_SIZE        0x200U
#define CDK2_FV_BLOCK_SIZE  0x1000U

static UINT32
Get24 (
  const UINT8  *Value
  )
{
  return (UINT32)Value[0] | ((UINT32)Value[1] << 8) | ((UINT32)Value[2] << 16);
}

static int
IsErased (
  const UINT8  *Data,
  UINTN         Size
  )
{
  UINTN  Index;

  for (Index = 0; Index < Size; Index++) {
    if (Data[Index] != 0xFF) {
      return 0;
    }
  }

  return 1;
}

static UINT16
Checksum16 (
  const UINT8  *Buffer,
  UINTN          Length
  )
{
  UINT32  Sum;
  UINTN   Index;

  Sum = 0;
  for (Index = 0; Index < Length; Index += 2) {
    Sum += (UINT32)Buffer[Index] | ((UINT32)Buffer[Index + 1] << 8);
  }

  return (UINT16)(0U - (UINT16)Sum);
}

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 FV test: %s\n", Message);
    return 1;
  }

  return 0;
}

static UINTN
BuildVolume (
  UINT8  *Storage,
  UINTN    StorageSize
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *Volume;
  EFI_FFS_FILE_HEADER          *File;
  EFI_COMMON_SECTION_HEADER    *Section;
  UINTN                         FileOffset;
  UINTN                         FileSize;

  memset (Storage, 0xff, StorageSize);
  Volume = (EFI_FIRMWARE_VOLUME_HEADER *)(VOID *)Storage;
  Volume->FvLength    = 0x180;
  Volume->Signature   = EFI_FVH_SIGNATURE;
  Volume->HeaderLength = sizeof (*Volume);
  Volume->Revision    = 2;
  FileOffset = (sizeof (*Volume) + 7U) & ~(UINTN)7U;
  File       = (EFI_FFS_FILE_HEADER *)(VOID *)(Storage + FileOffset);
  memset (File, 0, sizeof (*File));
  File->Type  = EFI_FV_FILETYPE_DXE_CORE;
  File->State = 0xf8;
  FileSize    = sizeof (*File) + sizeof (*Section) + 8;
  File->Size[0] = (UINT8)FileSize;
  File->Size[1] = (UINT8)(FileSize >> 8);
  File->Size[2] = (UINT8)(FileSize >> 16);
  Section = (EFI_COMMON_SECTION_HEADER *)(VOID *)((UINT8 *)File + sizeof (*File));
  Section->Size[0] = (UINT8)(sizeof (*Section) + 8);
  Section->Size[1] = (UINT8)((sizeof (*Section) + 8) >> 8);
  Section->Size[2] = 0;
  Section->Type    = EFI_SECTION_PE32;
  memcpy ((UINT8 *)Section + sizeof (*Section), "MZCDK2!!", 8);

  Volume->Checksum = 0;
  Volume->Checksum = Checksum16 (Storage, Volume->HeaderLength);
  return (UINTN)Volume->FvLength;
}

static UINTN
BuildLargeFileVolume (
  UINT8  *Storage,
  UINTN    StorageSize,
  UINTN    EncodedFileSize
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *Volume;
  EFI_FFS_FILE_HEADER2         *File;
  EFI_COMMON_SECTION_HEADER    *Section;
  UINTN                         FileOffset;
  UINTN                         FileSize;

  memset (Storage, 0xff, StorageSize);
  Volume = (EFI_FIRMWARE_VOLUME_HEADER *)(VOID *)Storage;
  Volume->FvLength    = 0x180;
  Volume->Signature   = EFI_FVH_SIGNATURE;
  Volume->HeaderLength = sizeof (*Volume);
  Volume->Revision    = 2;
  FileOffset = (sizeof (*Volume) + 7U) & ~(UINTN)7U;
  File       = (EFI_FFS_FILE_HEADER2 *)(VOID *)(Storage + FileOffset);
  memset (File, 0, sizeof (*File));
  File->Type       = EFI_FV_FILETYPE_DXE_CORE;
  File->Attributes = FFS_ATTRIB_LARGE_FILE;
  File->State      = 0xf8;
  FileSize         = sizeof (*File) + sizeof (*Section) + 8;
  File->Size[0]    = (UINT8)EncodedFileSize;
  File->Size[1]    = (UINT8)(EncodedFileSize >> 8);
  File->Size[2]    = (UINT8)(EncodedFileSize >> 16);
  File->ExtendedSize = FileSize;
  Section = (EFI_COMMON_SECTION_HEADER *)(VOID *)((UINT8 *)File + sizeof (*File));
  Section->Size[0] = (UINT8)(sizeof (*Section) + 8);
  Section->Size[1] = (UINT8)((sizeof (*Section) + 8) >> 8);
  Section->Size[2] = 0;
  Section->Type    = EFI_SECTION_PE32;
  memcpy ((UINT8 *)Section + sizeof (*Section), "MZCDK2!!", 8);

  Volume->Checksum = 0;
  Volume->Checksum = Checksum16 (Storage, Volume->HeaderLength);
  return (UINTN)Volume->FvLength;
}

static int
ValidateFile (
  const char  *Path
  )
{
  FILE                              *File;
  long                              Length;
  UINT8                             *Storage;
  const EFI_FIRMWARE_VOLUME_HEADER  *Volume;
  const EFI_FFS_FILE_HEADER         *FfsFile;
  CDK2_NATIVE_DXE_CORE              DxeCore;
  EFI_STATUS                        Status;
  UINTN                             FileOffset;
  UINTN                             FileSize;
  UINTN                             FileHeaderSize;
  UINTN                             OccupiedFileSize;
  UINTN                             Remaining;
  int                               Failures;
  int                               FoundPayloadEntry;
  int                               FoundDxeCore;
  int                               FoundNonPadFile;

  File = fopen (Path, "rb");
  if (File == NULL || fseek (File, 0, SEEK_END) != 0) {
    if (File != NULL) {
      fclose (File);
    }

    fprintf (stderr, "cdk2 FV test: cannot open %s\n", Path);
    return 1;
  }

  Length = ftell (File);
  if (Length <= 0 || fseek (File, 0, SEEK_SET) != 0) {
    fclose (File);
    fprintf (stderr, "cdk2 FV test: invalid size for %s\n", Path);
    return 1;
  }

  Storage = malloc ((size_t)Length);
  if (Storage == NULL || fread (Storage, 1, (size_t)Length, File) != (size_t)Length) {
    free (Storage);
    fclose (File);
    fprintf (stderr, "cdk2 FV test: cannot read %s\n", Path);
    return 1;
  }

  fclose (File);

  Failures = 0;
  if ((UINTN)Length < sizeof (EFI_FIRMWARE_VOLUME_HEADER)) {
    free (Storage);
    fprintf (stderr, "cdk2 FV test: %s is smaller than an FV header\n", Path);
    return 1;
  }

  Volume = (const EFI_FIRMWARE_VOLUME_HEADER *)(const void *)Storage;
  Failures += Expect (
                Volume->Signature == EFI_FVH_SIGNATURE,
                "native FV has an invalid signature"
                );
  Failures += Expect (
                (UINT64)(UINTN)Length == Volume->FvLength,
                "native FV file is not compact"
                );
  Failures += Expect (
                (((UINTN)Length & (CDK2_FV_BLOCK_SIZE - 1U)) == 0),
                "native FV file is not block aligned"
                );

  if (Volume->HeaderLength < sizeof (EFI_FIRMWARE_VOLUME_HEADER) ||
      Volume->HeaderLength > (UINTN)Length)
  {
    Failures += Expect (0, "native FV has invalid header bounds");
    FileOffset = (UINTN)Length;
  } else {
    FileOffset = (Volume->HeaderLength + 7U) & ~(UINTN)7U;
  }

  Remaining  = ((UINTN)Length > FileOffset) ? (UINTN)Length - FileOffset : 0;
  FoundPayloadEntry = 0;
  FoundDxeCore      = 0;
  FoundNonPadFile   = 0;
  while (Remaining >= sizeof (EFI_FFS_FILE_HEADER)) {
    FfsFile = (const EFI_FFS_FILE_HEADER *)(const void *)(Storage + FileOffset);
    if (IsErased ((const UINT8 *)FfsFile, sizeof (*FfsFile))) {
      break;
    }

    FileHeaderSize = sizeof (EFI_FFS_FILE_HEADER);
    FileSize       = Get24 (FfsFile->Size);
    if ((FfsFile->Attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
      FileHeaderSize = sizeof (EFI_FFS_FILE_HEADER2);
      if (Remaining >= FileHeaderSize) {
        FileSize = (UINTN)((const EFI_FFS_FILE_HEADER2 *)FfsFile)->ExtendedSize;
      }
    }

    if (FileSize < FileHeaderSize || FileSize > Remaining) {
      Failures += Expect (0, "native FV contains an invalid FFS file");
      break;
    }

    if (FfsFile->Type == EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE) {
      Failures += Expect (0, "native FV still contains a nested FV image file");
    } else if (FfsFile->Type != EFI_FV_FILETYPE_FFS_PAD) {
      if (!FoundNonPadFile) {
        Failures += Expect (
                      FfsFile->Type == EFI_FV_FILETYPE_SECURITY_CORE,
                      "native FV first payload file is not the entry image"
                      );
        FoundPayloadEntry = (FfsFile->Type == EFI_FV_FILETYPE_SECURITY_CORE);
      }

      FoundNonPadFile = 1;
      FoundDxeCore |= (FfsFile->Type == EFI_FV_FILETYPE_DXE_CORE);
    }

    OccupiedFileSize = (FileSize + 7U) & ~(UINTN)7U;
    if (OccupiedFileSize > Remaining) {
      Failures += Expect (0, "native FV FFS file alignment overflows");
      break;
    }

    FileOffset += OccupiedFileSize;
    Remaining  -= OccupiedFileSize;
  }

  Failures += Expect (FoundPayloadEntry, "native FV has no payload entry file");
  Failures += Expect (FoundDxeCore, "native FV has no flat DXE core file");

  Status = Cdk2NativeFindDxeCore (Storage, (UINTN)Length, &DxeCore);
  free (Storage);
  if (Status != EFI_SUCCESS || DxeCore.Pe32Image == NULL || DxeCore.Pe32Size == 0) {
    fprintf (stderr, "cdk2 FV test: no valid DXE core in %s\n", Path);
    return 1;
  }

  if (Failures != 0) {
    return 1;
  }

  printf ("cdk2 FV file: PASS (%s)\n", Path);
  return 0;
}

int
main (
  int          ArgumentCount,
  char       **Arguments
  )
{
  UINT8                 Storage[TEST_FV_SIZE];
  CDK2_NATIVE_DXE_CORE  DxeCore;
  UINTN                 VolumeSize;
  EFI_STATUS             Status;
  EFI_COMMON_SECTION_HEADER *Section;
  int                   Failures;

  if (ArgumentCount == 2) {
    return ValidateFile (Arguments[1]);
  }

  Failures  = 0;
  VolumeSize = BuildVolume (Storage, sizeof (Storage));
  Status = Cdk2NativeFindDxeCore (Storage, VolumeSize, &DxeCore);
  Failures += Expect (Status == EFI_SUCCESS, "valid FV rejected");
  Failures += Expect (DxeCore.Pe32Size == 8, "PE32 section size is wrong");
  Failures += Expect (memcmp (DxeCore.Pe32Image, "MZCDK2!!", 8) == 0, "PE32 section data is wrong");

  Status = Cdk2NativeFindDxeCore (Storage, VolumeSize - 1, &DxeCore);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "truncated FV accepted");

  Storage[offsetof (EFI_FIRMWARE_VOLUME_HEADER, Checksum)] ^= 1;
  Status = Cdk2NativeFindDxeCore (Storage, VolumeSize, &DxeCore);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "bad FV checksum accepted");
  VolumeSize = BuildVolume (Storage, sizeof (Storage));

  Section = (EFI_COMMON_SECTION_HEADER *)(VOID *)(
                                                   Storage +
                                                   ((sizeof (EFI_FIRMWARE_VOLUME_HEADER) + 7U) & ~(UINTN)7U) +
                                                   sizeof (EFI_FFS_FILE_HEADER)
                                                   );
  Section->Size[0] = 3;
  Status = Cdk2NativeFindDxeCore (Storage, VolumeSize, &DxeCore);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "short section accepted");

  VolumeSize = BuildLargeFileVolume (Storage, sizeof (Storage), 0);
  Status = Cdk2NativeFindDxeCore (Storage, VolumeSize, &DxeCore);
  Failures += Expect (Status == EFI_SUCCESS, "valid large FFS header rejected");

  VolumeSize = BuildLargeFileVolume (Storage, sizeof (Storage), sizeof (EFI_FFS_FILE_HEADER2));
  Status = Cdk2NativeFindDxeCore (Storage, VolumeSize, &DxeCore);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "large FFS header with nonzero size accepted");

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 FV test: PASS");
  return 0;
}
