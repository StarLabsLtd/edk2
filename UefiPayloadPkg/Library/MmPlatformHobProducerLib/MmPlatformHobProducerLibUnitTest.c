/** @file
  Host checks for payload MM serial HOB validation.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UnitTestLib.h>
#include "SerialHobValidation.h"

STATIC
UNIT_TEST_STATUS
EFIAPI
SerialAddressBoundaries (
  IN UNIT_TEST_CONTEXT  Context
  )
{
  UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  Serial;

  ZeroMem (&Serial, sizeof (Serial));
  Serial.Header.Revision = UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION;
  Serial.Header.Length   = sizeof (Serial);
  Serial.BaudRate        = 115200;
  Serial.RegisterStride  = 1;
  Serial.UseMmio         = TRUE;
  Serial.RegisterBase    = BASE_4GB + 0x1000;
  UT_ASSERT_NOT_EFI_ERROR (PayloadMmValidateSerialInfo (&Serial));

  Serial.RegisterBase = MAX_UINT64 - 8;
  UT_ASSERT_NOT_EFI_ERROR (PayloadMmValidateSerialInfo (&Serial));
  Serial.RegisterBase = MAX_UINT64 - 7;
  UT_ASSERT_STATUS_EQUAL (PayloadMmValidateSerialInfo (&Serial), EFI_COMPROMISED_DATA);

  Serial.UseMmio      = FALSE;
  Serial.RegisterBase = MAX_UINT16 - 8;
  UT_ASSERT_NOT_EFI_ERROR (PayloadMmValidateSerialInfo (&Serial));
  Serial.RegisterBase = MAX_UINT16 - 7;
  UT_ASSERT_STATUS_EQUAL (PayloadMmValidateSerialInfo (&Serial), EFI_COMPROMISED_DATA);
  return UNIT_TEST_PASSED;
}

INT32
main (
  IN INT32   Argc,
  IN CHAR8  *Argv[]
  )
{
  EFI_STATUS                  Status;
  UNIT_TEST_FRAMEWORK_HANDLE  Framework;
  UNIT_TEST_SUITE_HANDLE      Suite;

  Status = InitUnitTestFramework (&Framework, "Payload MM serial HOB", gEfiCallerBaseName, "1.0");
  if (EFI_ERROR (Status)) {
    return 1;
  }

  Status = CreateUnitTestSuite (&Suite, Framework, "Serial HOB", "PayloadMm.Serial", NULL, NULL);
  if (!EFI_ERROR (Status)) {
    AddTestCase (Suite, "Accept 64-bit MMIO and bound I/O ports", "Boundary", SerialAddressBoundaries, NULL, NULL, NULL);
    Status = RunAllTestSuites (Framework);
  }

  FreeUnitTestFramework (Framework);
  return EFI_ERROR (Status) ? 1 : 0;
}
