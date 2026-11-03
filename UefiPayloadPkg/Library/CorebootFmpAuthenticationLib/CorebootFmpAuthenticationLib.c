/** @file
  Delegate FMP authentication to the protected owner and its compiled trust store.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <Uefi.h>
#include <Library/CorebootCapsuleLib.h>
#include <Library/FmpAuthenticationLib.h>
RETURN_STATUS
EFIAPI
AuthenticateFmpImage(EFI_FIRMWARE_IMAGE_AUTHENTICATION *Image, UINTN ImageSize,
                      CONST UINT8 *PublicKeyData, UINTN PublicKeyDataLength)
{
  /* A caller-supplied key is not an authority for protected flash writes. */
  return CorebootCapsuleAuthenticate(Image, ImageSize);
}
