/** @file
  Private BootNext restore metadata for Capsule On Disk.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/BaseMemoryLib.h>

#include "CapsuleOnDiskBootNext.h"

EFI_STATUS
CoDBuildBootNextRestore (
  IN  BOOLEAN                Present,
  IN  UINT32                 Attributes,
  IN  UINTN                  DataSize,
  IN  CONST VOID             *Data OPTIONAL,
  OUT COD_BOOT_NEXT_RESTORE  *Restore
  )
{
  if (Restore == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Present && ((Attributes != 0) || (DataSize != 0) || (Data != NULL))) {
    return EFI_INVALID_PARAMETER;
  }

  if ((DataSize > COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE) ||
      ((DataSize != 0) && (Data == NULL)))
  {
    return (DataSize > COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE) ? EFI_BAD_BUFFER_SIZE : EFI_INVALID_PARAMETER;
  }

  ZeroMem (Restore, sizeof (*Restore));
  Restore->Signature  = COD_BOOT_NEXT_RESTORE_SIGNATURE;
  Restore->Version    = COD_BOOT_NEXT_RESTORE_VERSION;
  Restore->Present    = Present ? TRUE : FALSE;
  Restore->Attributes = Attributes;
  Restore->DataSize   = (UINT32)DataSize;
  if (DataSize != 0) {
    CopyMem (Restore->Data, Data, DataSize);
  }

  return EFI_SUCCESS;
}

EFI_STATUS
CoDReadBootNextRestore (
  IN     CONST COD_BOOT_NEXT_RESTORE  *Restore,
  OUT    BOOLEAN                      *Present,
  OUT    UINT32                       *Attributes,
  IN OUT UINTN                        *DataSize,
  OUT    VOID                         *Data OPTIONAL
  )
{
  if ((Restore == NULL) || (Present == NULL) || (Attributes == NULL) || (DataSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if ((Restore->Signature != COD_BOOT_NEXT_RESTORE_SIGNATURE) ||
      (Restore->Version != COD_BOOT_NEXT_RESTORE_VERSION) ||
      (Restore->Present > TRUE) ||
      (Restore->Reserved != 0) ||
      (Restore->DataSize > COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE) ||
      (!Restore->Present && ((Restore->Attributes != 0) || (Restore->DataSize != 0))))
  {
    return EFI_COMPROMISED_DATA;
  }

  *Present    = Restore->Present;
  *Attributes = Restore->Present ? Restore->Attributes : 0;

  if (!Restore->Present) {
    *DataSize = 0;
    return EFI_SUCCESS;
  }

  if (*DataSize < Restore->DataSize) {
    *DataSize = Restore->DataSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  if ((Restore->DataSize != 0) && (Data == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (Restore->DataSize != 0) {
    CopyMem (Data, Restore->Data, Restore->DataSize);
  }

  *DataSize = Restore->DataSize;
  return EFI_SUCCESS;
}
