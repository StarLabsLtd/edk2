/** @file
  Fixed ACPI preference mailbox shared with downstream coreboot.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef STARLABS_CFR_H_
#define STARLABS_CFR_H_

#include <Uefi.h>

#define STARLABS_CFR_VERSION      1
#define STARLABS_CFR_APM_PORT     0xB2
#define STARLABS_CFR_APM_COMMAND  0xE2
#define STARLABS_CFR_GET          1
#define STARLABS_CFR_SET          2
#define STARLABS_CFR_CAPS         3
#define STARLABS_CFR_PENDING      MAX_UINT32
#define STARLABS_CFR_SUCCESS      0
#define STARLABS_CFR_ERROR        1
#define STARLABS_CFR_INVALID      2
#define STARLABS_CFR_NOT_FOUND    3
#define STARLABS_CFR_UNSUPPORTED  4
#define STARLABS_CFR_DENIED       5
#define STARLABS_CFR_OPTION_MASK  (0x3FFE | BIT18)

typedef enum {
  CfrFnLock             = 1,
  CfrTrackpad           = 2,
  CfrKeyboardBrightness = 3,
  CfrKeyboardBacklight  = 4,
  CfrKeyboardTimeout    = 5,
  CfrFnCtrlSwap         = 6,
  CfrMaxCharge          = 7,
  CfrFanMode            = 8,
  CfrChargingSpeed      = 9,
  CfrLidSwitch          = 10,
  CfrPowerLed           = 11,
  CfrChargeLed          = 12,
  CfrPowerOnAc          = 13,
  CfrAutomaticStart     = 18
} STARLABS_CFR_OPTION;

typedef struct {
  UINT32    Command;
  UINT32    Id;
  UINT32    Value;
  UINT32    Status;
  UINT32    Version;
  UINT32    Reserved;
} STARLABS_CFR_MAILBOX;

STATIC_ASSERT (sizeof (STARLABS_CFR_MAILBOX) == 24, "CFR mailbox ABI");

#endif
