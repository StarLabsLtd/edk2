/** @file
  Copy the platform handoff into the resident MM environment.

  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/MmPlatformHobProducerLib.h>
#include <Library/SafeIntLib.h>
#include <Guid/AcpiBoardInfoGuid.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>
#include <Guid/PayloadMmSpiStoreInfoGuid.h>
#include <Guid/SmmS3CommunicationInfoGuid.h>
#include <Guid/SpiFlashInfoGuid.h>
#include <Guid/VariableFlashInfo.h>
#include <UniversalPayload/SerialPortInfo.h>
#include "SerialHobValidation.h"

EFI_STATUS
EFIAPI
CreateMmPlatformHob (
  IN     VOID   *Buffer,
  IN OUT UINTN  *BufferSize
  )
{
  EFI_GUID           *Guids[] = {
    &gUefiAcpiBoardInfoGuid,
    &gPayloadMmInterfaceInfoGuid,
    &gPayloadMmSpiStoreInfoGuid,
    &gS3CommunicationGuid,
    &gSpiFlashInfoGuid,
    &gVariableFlashInfoHobGuid,
    &gUniversalPayloadSerialPortInfoGuid
  };
  EFI_HOB_GUID_TYPE  *Hobs[ARRAY_SIZE (Guids)];
  UINTN              Size;
  UINTN              Index;
  UINTN              Offset;

  if ((BufferSize == NULL) || ((Buffer == NULL) && (*BufferSize != 0))) {
    return EFI_INVALID_PARAMETER;
  }

  Size = 0;
  for (Index = 0; Index < ARRAY_SIZE (Guids); Index++) {
    Hobs[Index] = GetFirstGuidHob (Guids[Index]);
    if (Hobs[Index] == NULL) {
      if (Guids[Index] == &gUniversalPayloadSerialPortInfoGuid) {
        continue;
      }

      return EFI_NOT_FOUND;
    }

    if ((Hobs[Index]->Header.HobLength < sizeof (EFI_HOB_GUID_TYPE)) ||
        RETURN_ERROR (SafeUintnAdd (Size, Hobs[Index]->Header.HobLength, &Size)))
    {
      return EFI_COMPROMISED_DATA;
    }

    if (Guids[Index] == &gUniversalPayloadSerialPortInfoGuid) {
      UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  *Serial;

      Serial = GET_GUID_HOB_DATA (Hobs[Index]);
      if ((GET_GUID_HOB_DATA_SIZE (Hobs[Index]) < sizeof (*Serial)) ||
          (Serial->Header.Length > GET_GUID_HOB_DATA_SIZE (Hobs[Index])) ||
          EFI_ERROR (PayloadMmValidateSerialInfo (Serial)))
      {
        return EFI_COMPROMISED_DATA;
      }
    }
  }

  if (*BufferSize < Size) {
    *BufferSize = Size;
    return EFI_BUFFER_TOO_SMALL;
  }

  Offset = 0;
  for (Index = 0; Index < ARRAY_SIZE (Guids); Index++) {
    if (Hobs[Index] == NULL) {
      continue;
    }

    CopyMem ((UINT8 *)Buffer + Offset, Hobs[Index], Hobs[Index]->Header.HobLength);
    Offset += Hobs[Index]->Header.HobLength;
  }

  *BufferSize = Size;
  return EFI_SUCCESS;
}
