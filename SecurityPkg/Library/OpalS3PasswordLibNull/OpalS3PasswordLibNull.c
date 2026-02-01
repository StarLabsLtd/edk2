/** @file
  NULL instance of OpalS3PasswordLib.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Library/OpalS3PasswordLib.h>
#include <Uefi/UefiBaseType.h>

EFI_STATUS
EFIAPI
OpalS3PasswordLibSetSecret (
  IN EFI_DEVICE_PATH_PROTOCOL  *OpalDevicePath,
  IN UINT16                    OpalBaseComId,
  IN CONST VOID                *Password,
  IN UINTN                     PasswordLength
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
OpalS3PasswordLibClearSecret (
  VOID
  )
{
  return EFI_UNSUPPORTED;
}
