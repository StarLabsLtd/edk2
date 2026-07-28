/** @file

  Copyright (c) 2014 - 2021, Intel Corporation. All rights reserved.<BR>
  Copyright (C) 2025 Advanced Micro Devices, Inc. All rights reserved.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>
#include "Cdk2EfiEntry.h"
#include "../Cdk2EfiBackend.h"

#ifndef CDK2_PECOFF_ALIGN
#define CDK2_PECOFF_ALIGN  64
#endif

#if defined (__GNUC__)
#define CDK2_PECOFF_ALIGN_ATTRIBUTE  __attribute__ ((aligned (CDK2_PECOFF_ALIGN)))
#else
#define CDK2_PECOFF_ALIGN_ATTRIBUTE
#endif

/**
  Entry point to the C language phase of UEFI payload.

  @param[in]   BootloaderParameter    The starting address of bootloader parameter block.

  @retval      It will not return if SUCCESS, and return error when passing bootloader parameter.
**/
EFI_STATUS
EFIAPI
CDK2_PECOFF_ALIGN_ATTRIBUTE
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
