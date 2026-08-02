/** @file
  Private BootNext restore metadata for Capsule On Disk.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#pragma once

#include <Uefi.h>

#define COD_BOOT_NEXT_RESTORE_VAR_NAME       L"CodBootNextRestore"
#define COD_BOOT_NEXT_RESTORE_VAR_ATTRS \
  (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE)
#define COD_BOOT_NEXT_RESTORE_SIGNATURE      SIGNATURE_32 ('C', 'B', 'N', 'R')
#define COD_BOOT_NEXT_RESTORE_VERSION        1U
#define COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE  64U

typedef struct {
  UINT32     Signature;
  UINT16     Version;
  BOOLEAN    Present;
  UINT8      Reserved;
  UINT32     Attributes;
  UINT32     DataSize;
  UINT8      Data[COD_BOOT_NEXT_RESTORE_DATA_MAX_SIZE];
} COD_BOOT_NEXT_RESTORE;

EFI_STATUS
CoDBuildBootNextRestore (
  IN  BOOLEAN                Present,
  IN  UINT32                 Attributes,
  IN  UINTN                  DataSize,
  IN  CONST VOID             *Data OPTIONAL,
  OUT COD_BOOT_NEXT_RESTORE  *Restore
  );

EFI_STATUS
CoDReadBootNextRestore (
  IN     CONST COD_BOOT_NEXT_RESTORE  *Restore,
  OUT    BOOLEAN                      *Present,
  OUT    UINT32                       *Attributes,
  IN OUT UINTN                        *DataSize,
  OUT    VOID                         *Data OPTIONAL
  );
