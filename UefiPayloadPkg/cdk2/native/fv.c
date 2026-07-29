/** @file

  Bounds-checked firmware-volume discovery for native cdk2.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "fv.h"

STATIC
UINT32
Cdk2NativeGet24 (
  IN CONST UINT8  *Value
  )
{
  return (UINT32)Value[0] | ((UINT32)Value[1] << 8) | ((UINT32)Value[2] << 16);
}

STATIC
UINT16
Cdk2NativeChecksum16 (
  IN CONST VOID  *Buffer,
  IN UINTN        Length
  )
{
  CONST UINT8  *Bytes;
  UINT32        Sum;
  UINTN         Index;

  Bytes = (CONST UINT8 *)Buffer;
  Sum   = 0;
  for (Index = 0; Index < Length; Index += 2) {
    Sum += (UINT32)Bytes[Index] | ((UINT32)Bytes[Index + 1] << 8);
  }

  return (UINT16)(0U - (UINT16)Sum);
}

STATIC
EFI_STATUS
Cdk2NativeFindPe32Section (
  IN  CONST UINT8  *File,
  IN  UINTN          FileSize,
  OUT CONST VOID   **Pe32Image,
  OUT UINTN         *Pe32Size
  )
{
  CONST UINT8  *Section;
  UINTN         HeaderSize;
  UINTN         Remaining;
  UINTN         SectionSize;
  UINTN         OccupiedSize;

  if (File == NULL || Pe32Image == NULL || Pe32Size == NULL ||
      FileSize < sizeof (EFI_FFS_FILE_HEADER))
  {
    return EFI_INVALID_PARAMETER;
  }

  HeaderSize = sizeof (EFI_FFS_FILE_HEADER);
  if ((((CONST EFI_FFS_FILE_HEADER *)File)->Attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
    if (Cdk2NativeGet24 (((CONST EFI_FFS_FILE_HEADER *)File)->Size) != 0) {
      return EFI_COMPROMISED_DATA;
    }

    HeaderSize = sizeof (EFI_FFS_FILE_HEADER2);
    if (FileSize < HeaderSize) {
      return EFI_COMPROMISED_DATA;
    }
  }

  if (HeaderSize > FileSize) {
    return EFI_COMPROMISED_DATA;
  }

  Section   = File + HeaderSize;
  Remaining = FileSize - HeaderSize;
  while (Remaining != 0) {
    if (Remaining < sizeof (EFI_COMMON_SECTION_HEADER)) {
      return EFI_COMPROMISED_DATA;
    }

    SectionSize = Cdk2NativeGet24 (Section);
    if (SectionSize == 0x00ffffffU) {
      if (Remaining < sizeof (EFI_COMMON_SECTION_HEADER2)) {
        return EFI_COMPROMISED_DATA;
      }

      SectionSize = ((CONST EFI_COMMON_SECTION_HEADER2 *)Section)->ExtendedSize;
      HeaderSize  = sizeof (EFI_COMMON_SECTION_HEADER2);
    } else {
      HeaderSize = sizeof (EFI_COMMON_SECTION_HEADER);
    }

    if (SectionSize < HeaderSize || SectionSize > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    OccupiedSize = (SectionSize + 3U) & ~(UINTN)3U;
    if (OccupiedSize > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    if (Section[3] == EFI_SECTION_PE32) {
      *Pe32Image = Section + HeaderSize;
      *Pe32Size  = SectionSize - HeaderSize;
      return EFI_SUCCESS;
    }

    Section   += OccupiedSize;
    Remaining -= OccupiedSize;
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
Cdk2NativeFindDxeCore (
  IN  CONST VOID           *FirmwareVolume,
  IN  UINTN                 FirmwareVolumeSize,
  OUT CDK2_NATIVE_DXE_CORE *DxeCore
  )
{
  CONST EFI_FIRMWARE_VOLUME_HEADER  *Volume;
  CONST EFI_FFS_FILE_HEADER         *File;
  UINTN                              VolumeLength;
  UINTN                              HeaderLength;
  UINTN                              FileOffset;
  UINTN                              Remaining;
  UINTN                              FileSize;
  UINTN                              FileHeaderSize;
  UINTN                              OccupiedFileSize;
  CONST VOID                        *Pe32Image;
  UINTN                              Pe32Size;
  EFI_STATUS                         Status;

  if (FirmwareVolume == NULL || DxeCore == NULL ||
      FirmwareVolumeSize < sizeof (EFI_FIRMWARE_VOLUME_HEADER))
  {
    return EFI_INVALID_PARAMETER;
  }

  Volume       = (CONST EFI_FIRMWARE_VOLUME_HEADER *)FirmwareVolume;
  HeaderLength = Volume->HeaderLength;
  if (Volume->Signature != EFI_FVH_SIGNATURE ||
      (Volume->FvLength & 1U) != 0 ||
      Volume->FvLength < HeaderLength ||
      Volume->FvLength > FirmwareVolumeSize ||
      HeaderLength < sizeof (EFI_FIRMWARE_VOLUME_HEADER) ||
      HeaderLength > FirmwareVolumeSize ||
      (HeaderLength & 1U) != 0 ||
      Cdk2NativeChecksum16 (Volume, HeaderLength) != 0)
  {
    return EFI_COMPROMISED_DATA;
  }

  VolumeLength = (UINTN)Volume->FvLength;
  *DxeCore = (CDK2_NATIVE_DXE_CORE){ 0 };
  DxeCore->Volume     = Volume;
  DxeCore->VolumeSize = VolumeLength;

  FileOffset = (HeaderLength + 7U) & ~(UINTN)7U;
  if (FileOffset > VolumeLength) {
    return EFI_COMPROMISED_DATA;
  }

  Remaining = VolumeLength - FileOffset;
  while (Remaining >= sizeof (EFI_FFS_FILE_HEADER)) {
    File = (CONST EFI_FFS_FILE_HEADER *)((CONST UINT8 *)Volume + FileOffset);
    FileHeaderSize = sizeof (EFI_FFS_FILE_HEADER);
    FileSize       = Cdk2NativeGet24 (File->Size);
    if ((File->Attributes & FFS_ATTRIB_LARGE_FILE) != 0) {
      if (FileSize != 0) {
        return EFI_COMPROMISED_DATA;
      }

      FileHeaderSize = sizeof (EFI_FFS_FILE_HEADER2);
      if (Remaining < FileHeaderSize) {
        return EFI_COMPROMISED_DATA;
      }

      FileSize = (UINTN)((CONST EFI_FFS_FILE_HEADER2 *)File)->ExtendedSize;
    }

    if (FileSize == 0 || FileSize < FileHeaderSize || FileSize > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    if (File->Type == EFI_FV_FILETYPE_DXE_CORE) {
      Status = Cdk2NativeFindPe32Section (
                 (CONST UINT8 *)File,
                 FileSize,
                 &Pe32Image,
                 &Pe32Size
                 );
      if (!EFI_ERROR (Status)) {
        DxeCore->DxeCoreFile = File;
        DxeCore->Pe32Image   = Pe32Image;
        DxeCore->Pe32Size    = Pe32Size;
        return EFI_SUCCESS;
      }

      if (Status != EFI_NOT_FOUND) {
        return Status;
      }
    }

    OccupiedFileSize = (FileSize + 7U) & ~(UINTN)7U;
    if (OccupiedFileSize > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    FileOffset += OccupiedFileSize;
    Remaining  -= OccupiedFileSize;
  }

  return EFI_NOT_FOUND;
}
