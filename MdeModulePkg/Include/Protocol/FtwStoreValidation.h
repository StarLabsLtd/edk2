/** @file
  Private MM validation used before reclaiming an FTW workspace.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

typedef
EFI_STATUS
(EFIAPI *EDKII_FTW_VALIDATE_STORE)(VOID);

typedef struct {
  EDKII_FTW_VALIDATE_STORE  Validate;
} EDKII_FTW_STORE_VALIDATION_PROTOCOL;

extern EFI_GUID  gEdkiiFtwStoreValidationProtocolGuid;
