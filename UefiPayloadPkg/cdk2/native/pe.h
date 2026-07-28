/** @file

  Bounded PE32+ loading for native cdk2.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_NATIVE_PE_H_
#define CDK2_NATIVE_PE_H_

#include <Uefi.h>
#include <IndustryStandard/PeImage.h>

EFI_STATUS
Cdk2NativeLoadPe32Plus (
  IN  CONST VOID             *Image,
  IN  UINTN                   ImageSize,
  IN  EFI_PHYSICAL_ADDRESS    Destination,
  IN  UINTN                   DestinationSize,
  OUT EFI_PHYSICAL_ADDRESS   *LoadedBase,
  OUT UINTN                  *LoadedSize,
  OUT EFI_PHYSICAL_ADDRESS   *EntryPoint
  );

#endif
