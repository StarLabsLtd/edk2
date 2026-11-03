/** @file
  Leave legacy FMP backends on their existing update path.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Library/CorebootCapsuleLib.h>
EFI_STATUS
CorebootCapsuleApply(EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS Progress OPTIONAL)
{
  return EFI_UNSUPPORTED;
}

BOOLEAN CorebootCapsuleIsProtected(VOID) { return FALSE; }
