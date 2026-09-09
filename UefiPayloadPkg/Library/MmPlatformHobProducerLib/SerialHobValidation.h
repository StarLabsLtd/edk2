/** @file
  Validation for the serial handoff HOB.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>
#include <UniversalPayload/SerialPortInfo.h>

EFI_STATUS
EFIAPI
PayloadMmValidateSerialInfo (
  IN CONST UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  *Serial
  );
