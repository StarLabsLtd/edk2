/** @file
  Close the firmware Setup authorization window before external images run.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <PiDxe.h>
#include <Guid/EventGroup.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SecurityManagementLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/MmCommunication2.h>

STATIC BOOLEAN mClosed;

STATIC
BOOLEAN
FirmwareImage (
  IN CONST EFI_DEVICE_PATH_PROTOCOL *Path,
  IN CONST VOID                     *Buffer,
  IN UINTN                          Size
  )
{
  EFI_DEVICE_PATH_PROTOCOL             *Node;
  EFI_HANDLE                           Handle;
  EFI_FIRMWARE_VOLUME2_PROTOCOL        *Volume;
  MEDIA_FW_VOL_FILEPATH_DEVICE_PATH    *File;
  VOID                                 *Section;
  UINTN                                SectionSize;
  UINT32                               Authentication;
  EFI_STATUS                           Status;
  BOOLEAN                              Matches;

  if ((Path == NULL) || (Buffer == NULL) || (Size == 0)) {
    return FALSE;
  }

  Node = (EFI_DEVICE_PATH_PROTOCOL *)Path;
  Status = gBS->LocateDevicePath (&gEfiFirmwareVolume2ProtocolGuid, &Node, &Handle);
  if (EFI_ERROR (Status) || (DevicePathType (Node) != MEDIA_DEVICE_PATH) ||
      (DevicePathSubType (Node) != MEDIA_PIWG_FW_FILE_DP) ||
      (DevicePathNodeLength (Node) != sizeof (*File)) ||
      !IsDevicePathEnd (NextDevicePathNode (Node)))
  {
    return FALSE;
  }

  Status = gBS->HandleProtocol (Handle, &gEfiFirmwareVolume2ProtocolGuid, (VOID **)&Volume);
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  File = (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *)Node;
  Section = NULL;
  SectionSize = 0;
  Status = Volume->ReadSection (Volume, &File->FvFileName, EFI_SECTION_PE32, 0,
                                &Section, &SectionSize, &Authentication);
  if (Status == EFI_NOT_FOUND) {
    Status = Volume->ReadSection (Volume, &File->FvFileName, EFI_SECTION_TE, 0,
                                  &Section, &SectionSize, &Authentication);
  }

  Matches = !EFI_ERROR (Status) && (Section != NULL) && (SectionSize == Size) &&
            (CompareMem (Section, Buffer, Size) == 0);
  if (Section != NULL) {
    FreePool (Section);
  }

  return Matches;
}

STATIC
EFI_STATUS
EFIAPI
AuthorizeImage (
  IN UINT32                         AuthenticationStatus,
  IN CONST EFI_DEVICE_PATH_PROTOCOL *File OPTIONAL,
  IN VOID                           *FileBuffer,
  IN UINTN                          FileSize,
  IN BOOLEAN                        BootPolicy
  )
{
  EFI_MM_COMMUNICATION2_PROTOCOL *Communication;
  UINT8                         Buffer[OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + 1];
  EFI_MM_COMMUNICATE_HEADER      *Header;
  UINTN                         Size;
  EFI_STATUS                    Status;

  if (mClosed || FirmwareImage (File, FileBuffer, FileSize)) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (&gEfiMmCommunication2ProtocolGuid, NULL, (VOID **)&Communication);
  if (EFI_ERROR (Status)) {
    return EFI_ACCESS_DENIED;
  }

  ZeroMem (Buffer, sizeof (Buffer));
  Header = (VOID *)Buffer;
  CopyGuid (&Header->HeaderGuid, &gEfiEventReadyToBootGuid);
  Header->MessageLength = 1;
  Size = sizeof (Buffer);
  Status = Communication->Communicate (Communication, Buffer, Buffer, &Size);
  if (EFI_ERROR (Status)) {
    return EFI_ACCESS_DENIED;
  }

  mClosed = TRUE;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
CorebootImagePolicyConstructor (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  return RegisterSecurity2Handler (AuthorizeImage,
           EFI_AUTH_OPERATION_VERIFY_IMAGE | EFI_AUTH_OPERATION_IMAGE_REQUIRED);
}
