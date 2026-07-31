/** @file

  Bounds-checked firmware-volume discovery for native cdk2.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_FV_H_
#define CDK2_FV_H_

#include <Uefi.h>
#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>

typedef struct {
  CONST EFI_FIRMWARE_VOLUME_HEADER  *Volume;
  CONST EFI_FFS_FILE_HEADER         *DxeCoreFile;
  CONST VOID                        *Pe32Image;
  UINTN                              Pe32Size;
  UINTN                              VolumeSize;
} CDK2_NATIVE_DXE_CORE;

EFI_STATUS
Cdk2NativeFindDxeCore (
  IN  CONST VOID          *FirmwareVolume,
  IN  UINTN                FirmwareVolumeSize,
  OUT CDK2_NATIVE_DXE_CORE *DxeCore
  );

#endif
