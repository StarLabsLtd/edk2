/** @file
  NULL implementation of OpalS3PasswordLib.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/OpalS3PasswordLib.h>

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
