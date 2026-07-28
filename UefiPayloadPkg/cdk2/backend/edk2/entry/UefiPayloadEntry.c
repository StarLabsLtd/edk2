/** @file

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>
#include "Cdk2EfiEntry.h"
#include "../Cdk2EfiBackend.h"

/**
  Entry point to the C language phase of UEFI payload.

  @param[in]   BootloaderParameter    The starting address of bootloader parameter block.

  @retval      It will not return if SUCCESS, and return error when passing bootloader parameter.
**/
EFI_STATUS
EFIAPI
_ModuleEntryPoint (
  IN UINTN  BootloaderParameter
  )
{
  EFI_STATUS  Status;

  Status = Cdk2NativePayloadEntry (
             BootloaderParameter,
             Cdk2EfiBackendInitializeContext
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "cdk2 native payload entry failed: %r\n", Status));
  }

  // Should not get here
  CpuDeadLoop ();
  return EFI_SUCCESS;
}
