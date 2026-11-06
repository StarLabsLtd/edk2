/** @file
  Handoff of an already displayed BMP image from the bootloader.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef EDKII_BOOT_LOGO_HOB_H_
#define EDKII_BOOT_LOGO_HOB_H_

#define EDKII_BOOT_LOGO_HOB_GUID \
  { 0x50c27557, 0x2fac, 0x460f, { 0x94, 0x9a, 0x40, 0x6d, 0x27, 0x52, 0x39, 0x55 } }

// The producer validates the image and reserves its storage through DXE.
// Coordinates and dimensions describe the physical framebuffer, not a UI mode.
typedef struct {
  EFI_PHYSICAL_ADDRESS    FrameBufferBase;
  EFI_PHYSICAL_ADDRESS    ImageAddress;
  UINT32                  ImageSize;
  UINT32                  DestinationX;
  UINT32                  DestinationY;
  UINT32                  Width;
  UINT32                  Height;
  UINT32                  Reserved;
} EDKII_BOOT_LOGO_HOB;

STATIC_ASSERT (sizeof (EDKII_BOOT_LOGO_HOB) == 40, "Boot logo HOB ABI");

extern EFI_GUID  gEdkiiBootLogoHobGuid;

#endif
