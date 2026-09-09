/** @file
  Validate the serial handoff HOB before copying it to MM.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include "SerialHobValidation.h"

EFI_STATUS
EFIAPI
PayloadMmValidateSerialInfo (
  IN CONST UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  *Serial
  )
{
  if ((Serial == NULL) ||
      (Serial->Header.Revision != UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION) ||
      (Serial->Header.Length < sizeof (*Serial)) ||
      (Serial->BaudRate == 0) || (Serial->BaudRate > MAX_UINT32 / 16) ||
      (Serial->RegisterStride == 0) || (Serial->RegisterStride > 8) ||
      ((Serial->RegisterStride & (Serial->RegisterStride - 1)) != 0) ||
      (Serial->UseMmio &&
       (Serial->RegisterBase > MAX_UINT64 - 8 * Serial->RegisterStride)) ||
      (!Serial->UseMmio &&
       (Serial->RegisterBase > MAX_UINT16 - 8 * Serial->RegisterStride)))
  {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}
