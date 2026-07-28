/** @file

  EDK II backend adapter for the native cdk2 entry path.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Library/Cdk2NativeServices.h>

#include "Cdk2EfiBackend.h"
#include "entry/Cdk2EfiEntry.h"

STATIC
EFI_STATUS
EFIAPI
Cdk2EfiLoadDxeCore (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT EFI_PHYSICAL_ADDRESS    *EntryPoint,
  OUT EFI_PHYSICAL_ADDRESS    *ImageBase,
  OUT UINTN                   *ImageSize
  )
{
  (VOID)Context;
  return LoadDxeCore (EntryPoint, ImageBase, ImageSize);
}

EFI_STATUS
EFIAPI
Cdk2EfiBackendInitializeContext (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  )
{
  EFI_STATUS  Status;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2NativeInitializeStageContext (Context, BootloaderParameter);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Context->PayloadBase              = PcdGet32 (PcdPayloadFdMemBase);
  Context->PayloadSize              = PcdGet32 (PcdPayloadFdMemSize);
  Context->HobRegionSize            = FixedPcdGet32 (PcdSystemMemoryUefiRegionSize);
  Context->Backend.ConstructHobs           = HobConstructor;
  Context->Backend.PopulateHobs            = Cdk2EfiPopulateHobs;
  Context->Backend.BuildSerialHob          = Cdk2EfiBuildSerialHob;
  Context->Backend.ApplyBootMode           = Cdk2EfiApplyBootMode;
  Context->Backend.InitializeLibraries     = Cdk2EfiInitializeLibraries;
  Context->Backend.SetBootloaderParameter  = Cdk2EfiSetBootloaderParameter;
  Context->Backend.FindHobMemory            = Cdk2EfiFindHobMemory;
  Context->Backend.InitializeFloatingPoint = Cdk2EfiInitializeFloatingPoint;
  Context->Backend.MaskLegacyInterrupts    = Cdk2EfiMaskLegacyInterrupts;
  Context->Backend.LoadDxeCore              = Cdk2EfiLoadDxeCore;
  Context->Backend.Transfer                 = Cdk2EfiTransferToDxeCore;

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2EfiTransferToDxeCore (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  if (Context == NULL || Context->HobList == NULL || Context->ImageEntryPoint == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Hob.Raw = Context->HobList;
  HandOffToDxeCore (Context->ImageEntryPoint, Hob);
  return EFI_DEVICE_ERROR;
}
