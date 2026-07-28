/** @file

  Host checks for native firmware-volume discovery.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "fv.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FV_SIZE  0x200U

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

static int
ValidateFile (
  const char  *Path
  )
{
  FILE                 *File;
  long                  Length;
  UINT8                *Storage;
  CDK2_NATIVE_DXE_CORE  DxeCore;
  EFI_STATUS             Status;

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
  Status = Cdk2NativeFindDxeCore (Storage, (UINTN)Length, &DxeCore);
  free (Storage);
  if (Status != EFI_SUCCESS || DxeCore.Pe32Image == NULL || DxeCore.Pe32Size == 0) {
    fprintf (stderr, "cdk2 FV test: no valid DXE core in %s\n", Path);
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

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 FV test: PASS");
  return 0;
}
