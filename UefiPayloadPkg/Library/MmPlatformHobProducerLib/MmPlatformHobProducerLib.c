/** @file
  Null instance of MM Platform HOB Producer Library Class.

  CreateMmPlatformHob() function is called by StandaloneMm IPL to create all
  Platform specific HOBs that required by Standalone MM environment.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/HobLib.h>
#include <Library/MmPlatformHobProducerLib.h>
#include <Guid/AcpiBoardInfoGuid.h>
#include <Guid/FlashRegionMapInfoGuid.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <Guid/SmmS3CommunicationInfoGuid.h>
#include <Guid/SpiFlashInfoGuid.h>
#include <Guid/VariableFlashInfo.h>
#include <UniversalPayload/SerialPortInfo.h>

/**
  Copies a data buffer to a newly-built HOB for GUID HOB

  This function builds a customized HOB tagged with a GUID for identification, copies the
  input data to the HOB data field and returns the start address of the GUID HOB data.
  If new HOB buffer is NULL or the GUID HOB could not found, then ASSERT().

  @param[in]       HobBuffer            The pointer of HOB buffer.
  @param[in, out]  HobBufferSize        The available size of the HOB buffer when as input.
                                        The used size of when as output.
  @param[in]       Guid                 The GUID of the GUID type HOB.
  @param[in]       MultiInstances       TRUE indicating copying multiple HOBs with the same Guid.
**/
VOID
MmIplCopyGuidHob (
  IN UINT8      *HobBuffer,
  IN OUT UINTN  *HobBufferSize,
  IN EFI_GUID   *Guid,
  IN BOOLEAN    MultiInstances
  );

/**
  Create the platform specific HOBs needed by the Standalone MM environment.

  The following HOBs are created by StandaloneMm IPL common logic.
  Hence they should NOT be created by this function:
  * Single EFI_HOB_TYPE_FV to describe the Firmware Volume where MM Core resides.
  * Single GUIDed (gEfiSmmSmramMemoryGuid) HOB to describe the MM regions.
  * Single EFI_HOB_MEMORY_ALLOCATION_MODULE to describe the MM region used by MM Core.
  * Multiple EFI_HOB_RESOURCE_DESCRIPTOR to describe the non-MM regions and their access permissions.
    Note: All accessible non-MM regions should be described by EFI_HOB_RESOURCE_DESCRIPTOR HOBs.
  * Single GUIDed (gMmCommBufferHobGuid) HOB to identify MM Communication buffer in non-MM region.
  * Multiple GUIDed (gSmmBaseHobGuid) HOB to describe the SMM base address of each processor.
  * Multiple GUIDed (gMpInformation2HobGuid) HOB to describe the MP information.
  * Single GUIDed (gMmCpuSyncConfigHobGuid) HOB to describe how BSP synchronizes with APs in x86 SMM.
  * Single GUIDed (gMmAcpiS3EnableHobGuid) HOB to describe the ACPI S3 enable status.
  * Single GUIDed (gEfiAcpiVariableGuid) HOB to identify the S3 data root region in x86.
  * Single GUIDed (gMmProfileDataHobGuid) HOB to describe the MM profile data region.
  * Single GUIDed (gMmStatusCodeUseSerialHobGuid) HOB to describe the status code use serial port.

  @param[in]      Buffer            The free buffer to be used for HOB creation.
  @param[in, out] BufferSize        The buffer size.
                                    On return, the expected/used size.

  @retval RETURN_INVALID_PARAMETER  BufferSize is NULL.
  @retval RETURN_INVALID_PARAMETER  Buffer is NULL and BufferSize is not 0.
  @retval RETURN_BUFFER_TOO_SMALL   The buffer is too small for HOB creation.
                                    BufferSize is updated to indicate the expected buffer size.
                                    When the input BufferSize is bigger than the expected buffer size,
                                    the BufferSize value will be changed to the used buffer size.
  @retval RETURN_SUCCESS            The HOB list is created successfully.

**/
EFI_STATUS
EFIAPI
CreateMmPlatformHob (
  IN      VOID   *Buffer,
  IN OUT  UINTN  *BufferSize
  )
{
  EFI_HOB_GUID_TYPE  *GuidHob;
  UINTN              UsedSize;
  UINTN              Cursor;

  UsedSize = 0;

  if (BufferSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if ((*BufferSize != 0) && (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  GuidHob = GetFirstGuidHob (&gUniversalPayloadSerialPortInfoGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  GuidHob = GetFirstGuidHob (&gUefiAcpiBoardInfoGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  GuidHob = GetFirstGuidHob (&gPayloadMmInterfaceInfoGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  GuidHob = GetFirstGuidHob (&gS3CommunicationGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  GuidHob = GetFirstGuidHob (&gSpiFlashInfoGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  GuidHob = GetFirstGuidHob (&gEfiFlashRegionMapInfoHobGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  GuidHob = GetFirstGuidHob (&gVariableFlashInfoHobGuid);
  if (GuidHob != NULL) {
    UsedSize += GuidHob->Header.HobLength;
  }

  if (*BufferSize < UsedSize) {
    *BufferSize = UsedSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  Cursor = 0;
  UsedSize = *BufferSize;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gUniversalPayloadSerialPortInfoGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gUefiAcpiBoardInfoGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gPayloadMmInterfaceInfoGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gS3CommunicationGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gSpiFlashInfoGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gEfiFlashRegionMapInfoHobGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  MmIplCopyGuidHob (Buffer + Cursor, &UsedSize, &gVariableFlashInfoHobGuid, FALSE);
  Cursor += UsedSize;
  UsedSize = *BufferSize - Cursor;

  *BufferSize = Cursor;

  return EFI_SUCCESS;
}
