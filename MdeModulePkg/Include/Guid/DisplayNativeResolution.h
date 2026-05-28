/** @file
  GUID HOB for the native display resolution.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef DISPLAY_NATIVE_RESOLUTION_H_
#define DISPLAY_NATIVE_RESOLUTION_H_

#include <Uefi/UefiBaseType.h>

#define EDKII_DISPLAY_NATIVE_RESOLUTION_GUID \
  { \
    0x28b6d472, 0x1a6b, 0x41ca, { 0x92, 0x62, 0x26, 0xca, 0xef, 0xb6, 0xb0, 0x5e } \
  }

typedef struct {
  UINT32    HorizontalResolution;
  UINT32    VerticalResolution;
} EDKII_DISPLAY_NATIVE_RESOLUTION;

extern EFI_GUID  gEdkiiDisplayNativeResolutionGuid;

#endif
