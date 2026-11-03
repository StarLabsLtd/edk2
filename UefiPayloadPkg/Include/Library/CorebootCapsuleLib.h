/** @file
  Boot-services client for the protected coreboot capsule owner.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#pragma once
#include <Uefi.h>
#include <Protocol/FirmwareManagement.h>
EFI_STATUS CorebootCapsuleGeometry(UINT32 *FlashSize, UINT32 *BlockSize);
EFI_STATUS CorebootCapsuleAuthenticate(EFI_FIRMWARE_IMAGE_AUTHENTICATION *Image, UINTN Size);
VOID CorebootCapsuleClose(VOID);

EFI_STATUS CorebootCapsuleApply(EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS Progress OPTIONAL);
BOOLEAN CorebootCapsuleIsProtected(VOID);
