/** @file
  OPAL S3 password handoff library.

  This library allows platform code to hand off an OPAL password to firmware
  components that can unlock OPAL NVMe devices during S3 resume when the
  boot manager is not executed on resume.

  The default instance is a NULL implementation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef OPAL_S3_PASSWORD_LIB_H_
#define OPAL_S3_PASSWORD_LIB_H_

#include <Uefi.h>

#include <Protocol/DevicePath.h>

#define OPAL_S3_PASSWORD_MAX_LEN  64

EFI_STATUS
EFIAPI
OpalS3PasswordLibSetSecret (
  IN EFI_DEVICE_PATH_PROTOCOL  *OpalDevicePath,
  IN UINT16                    OpalBaseComId,
  IN CONST VOID                *Password,
  IN UINTN                     PasswordLength
  );

EFI_STATUS
EFIAPI
OpalS3PasswordLibClearSecret (
  VOID
  );

#endif
