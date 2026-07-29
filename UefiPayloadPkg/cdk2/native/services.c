/** @file

  Native cdk2 HOB, image-range, and handoff services.

  These services deliberately stop short of transferring control. They make
  the native boundary validate the same invariants before the existing UEFI
  entry path is replaced.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>
#include <Library/Cdk2PlatformLib.h>

#include "services.h"

#if defined (__GNUC__)
STATIC UINT8  mCdk2NativeHobStorage[CDK2_NATIVE_HOB_BUFFER_SIZE]
  __attribute__ ((aligned (8)));
#else
STATIC UINT8  mCdk2NativeHobStorage[CDK2_NATIVE_HOB_BUFFER_SIZE];
#endif

STATIC
BOOLEAN
Cdk2NativeRangeContains (
  IN EFI_PHYSICAL_ADDRESS  Base,
  IN UINTN                  Size,
  IN EFI_PHYSICAL_ADDRESS  Address
  )
{
  EFI_PHYSICAL_ADDRESS  End;

  if (Size == 0 || Base > MAX_UINT64 - Size) {
    return FALSE;
  }

  End = Base + Size;
  return Address >= Base && Address < End;
}

EFI_STATUS
EFIAPI
Cdk2NativeInitializeServices (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Context->Services.BuildHobs = Cdk2NativeBuildHobs;
  Context->Services.PopulateHobs = Cdk2NativePopulateHobs;
  Context->Services.BuildSerialHob = Cdk2NativeBuildSerialHob;
  Context->Services.ApplyBootMode = Cdk2NativeApplyBootMode;
  Context->Services.InitializeLibraries = Cdk2NativeInitializeLibraries;
  Context->Services.SetBootloaderParameter = Cdk2NativeSetBootloaderParameter;
  Context->Services.FindHobMemory = Cdk2NativeFindHobMemory;
  Context->Services.InitializeFloatingPoint = Cdk2NativeInitializeFloatingPoint;
  Context->Services.MaskLegacyInterrupts = Cdk2NativeMaskLegacyInterrupts;
  Context->Services.LoadImage = Cdk2NativeLoadImage;
  Context->Services.Handoff   = Cdk2NativeHandoff;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeInitializeStageContext (
  OUT CDK2_NATIVE_CONTEXT  *Context,
  IN  UINTN                 BootloaderParameter
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Context = (CDK2_NATIVE_CONTEXT){ 0 };
  Context->BootloaderParameter = BootloaderParameter;
  return Cdk2NativeInitializeServices (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeValidateBackend (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

#define CDK2_REQUIRE_BACKEND_CALLBACK(Member) \
  if (Context->Backend.Member == NULL) { \
    return EFI_UNSUPPORTED; \
  }

  CDK2_REQUIRE_BACKEND_CALLBACK (PopulateHobs);
  CDK2_REQUIRE_BACKEND_CALLBACK (BuildSerialHob);
  CDK2_REQUIRE_BACKEND_CALLBACK (ApplyBootMode);
  CDK2_REQUIRE_BACKEND_CALLBACK (InitializeLibraries);
  CDK2_REQUIRE_BACKEND_CALLBACK (SetBootloaderParameter);
  CDK2_REQUIRE_BACKEND_CALLBACK (FindHobMemory);
  CDK2_REQUIRE_BACKEND_CALLBACK (InitializeFloatingPoint);
  CDK2_REQUIRE_BACKEND_CALLBACK (MaskLegacyInterrupts);
  CDK2_REQUIRE_BACKEND_CALLBACK (LoadDxeCore);
  CDK2_REQUIRE_BACKEND_CALLBACK (Transfer);

#undef CDK2_REQUIRE_BACKEND_CALLBACK
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeBuildHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_HOB_GENERIC_HEADER      *End;
  EFI_STATUS                   Status;

  if (Context == NULL || Context->PayloadBase == 0 || Context->PayloadSize == 0 ||
      Context->PayloadBase > MAX_UINT64 - Context->PayloadSize ||
      sizeof (*Handoff) + sizeof (*End) > CDK2_NATIVE_HOB_BUFFER_SIZE) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->Backend.BuildPlatformHobs != NULL) {
    Status = Context->Backend.BuildPlatformHobs (Context, &Handoff);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    return Cdk2NativeAdoptHobList (Context, Handoff);
  }

  if (Context->Backend.ConstructHobs != NULL) {
    Handoff = Context->Backend.ConstructHobs (
                 Context->HobMemoryBottom,
                 Context->HobMemoryTop,
                 Context->HobFreeMemoryBottom,
                 Context->HobFreeMemoryTop
                 );
    if (Handoff == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    return Cdk2NativeAdoptHobList (Context, Handoff);
  }

  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)(VOID *)mCdk2NativeHobStorage;
  End     = (EFI_HOB_GENERIC_HEADER *)(VOID *)(mCdk2NativeHobStorage + sizeof (*Handoff));

  Handoff->Header.HobType   = EFI_HOB_TYPE_HANDOFF;
  Handoff->Header.HobLength = sizeof (*Handoff);
  Handoff->Header.Reserved  = 0;
  Handoff->Version          = EFI_HOB_HANDOFF_TABLE_VERSION;
  Handoff->BootMode         = BOOT_WITH_FULL_CONFIGURATION;
  Handoff->EfiMemoryBottom  = Context->PayloadBase;
  Handoff->EfiMemoryTop    = Context->PayloadBase + Context->PayloadSize;
  Handoff->EfiFreeMemoryBottom = Context->PayloadBase;
  Handoff->EfiFreeMemoryTop    = Handoff->EfiMemoryTop;

  End->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  End->HobLength = sizeof (*End);
  End->Reserved  = 0;

  Context->HobList     = Handoff;
  Context->HobListSize = sizeof (*Handoff) + sizeof (*End);
  Handoff->EfiEndOfHobList = (EFI_PHYSICAL_ADDRESS)(UINTN)End;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativePopulateHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;

  if (Context == NULL || Context->Backend.PopulateHobs == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Context->Backend.PopulateHobs (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return Cdk2NativeAdoptHobList (
           Context,
           (EFI_HOB_HANDOFF_INFO_TABLE *)(VOID *)Context->HobList
           );
}

EFI_STATUS
EFIAPI
Cdk2NativeBuildSerialHob (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->Backend.BuildSerialHob == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.BuildSerialHob (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeApplyBootMode (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->Backend.ApplyBootMode == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.ApplyBootMode (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeInitializeLibraries (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->Backend.InitializeLibraries == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.InitializeLibraries (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeSetBootloaderParameter (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->Backend.SetBootloaderParameter == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.SetBootloaderParameter (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeFindHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  )
{
  if (Context == NULL || Context->Backend.FindHobMemory == NULL || HobMemBase == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.FindHobMemory (Context, HobMemBase);
}

EFI_STATUS
EFIAPI
Cdk2NativeInitializeFloatingPoint (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->Backend.InitializeFloatingPoint == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.InitializeFloatingPoint (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeMaskLegacyInterrupts (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->Backend.MaskLegacyInterrupts == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  return Context->Backend.MaskLegacyInterrupts (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativePrepareEntry (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_STATUS                  Status;
  EFI_PHYSICAL_ADDRESS        DxeCoreEntryPoint;
  UINTN                       HobMemBase;

  if (Context == NULL || Context->PayloadBase == 0 || Context->PayloadSize == 0 ||
      Context->PayloadBase > MAX_UINT64 - Context->PayloadSize ||
      Context->HobRegionSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Status = Cdk2NativeSetBootloaderParameter (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeInitializeFloatingPoint (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  HobMemBase = 0;
  Status = Cdk2NativeFindHobMemory (Context, &HobMemBase);
  if (EFI_ERROR (Status) && Status != EFI_NOT_FOUND) {
    return Status;
  }

  if (HobMemBase == 0) {
    HobMemBase = ALIGN_VALUE (
                   (UINTN)Context->PayloadBase + (UINTN)Context->PayloadSize,
                   SIZE_1MB
                   );
  }

  if (HobMemBase > MAX_UINTN - Context->HobRegionSize) {
    return EFI_INVALID_PARAMETER;
  }

  Context->HobMemoryBottom     = (VOID *)(UINTN)Context->PayloadBase;
  Context->HobMemoryTop        = (VOID *)(UINTN)(HobMemBase + Context->HobRegionSize);
  Context->HobFreeMemoryBottom = (VOID *)(UINTN)HobMemBase;
  Context->HobFreeMemoryTop    = Context->HobMemoryTop;
  Status = Cdk2NativeBuildHobs (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeBuildSerialHob (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // The library constructors might depend on serial port, so call it after serial port hob.
  Status = Cdk2NativeInitializeLibraries (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativePopulateHobs (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeLoadImage (Context, Cdk2NativeImageDxeCore, &DxeCoreEntryPoint);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeValidateEntry (
             Context,
             (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList,
             Context->ImageBase,
             Context->ImageSize,
             DxeCoreEntryPoint
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeApplyBootMode (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2NativeMaskLegacyInterrupts (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeLoadImage (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN CDK2_NATIVE_IMAGE         Image,
  OUT EFI_PHYSICAL_ADDRESS     *EntryPoint
  )
{
  EFI_STATUS  Status;

  if (Context == NULL || EntryPoint == NULL || Image >= Cdk2NativeImageMax) {
    return EFI_INVALID_PARAMETER;
  }

  if (Image == Cdk2NativeImageDxeCore) {
    if (Context->Backend.LoadDxeCore == NULL) {
      return EFI_UNSUPPORTED;
    }

    Status = Context->Backend.LoadDxeCore (
                 Context,
                 &Context->ImageEntryPoint,
                 &Context->ImageBase,
                 &Context->ImageSize
                 );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  } else if (Image == Cdk2NativeImagePayloadEntry) {
    if (Context->PayloadBase == 0 || Context->PayloadSize == 0 ||
        Context->PayloadBase > MAX_UINT64 - Context->PayloadSize) {
      return EFI_INVALID_PARAMETER;
    }

    Context->ImageBase = Context->PayloadBase;
    Context->ImageSize = Context->PayloadSize;
    if (Context->ImageEntryPoint == 0) {
      Context->ImageEntryPoint = Context->ImageBase;
    }
  } else {
    return EFI_INVALID_PARAMETER;
  }

  if (!Cdk2NativeRangeContains (
        Context->ImageBase,
        Context->ImageSize,
        Context->ImageEntryPoint
        )) {
    return EFI_SECURITY_VIOLATION;
  }

  *EntryPoint = Context->ImageEntryPoint;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeAllocatePages (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Pages,
  OUT    EFI_PHYSICAL_ADDRESS *Base
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_PHYSICAL_ADDRESS  Top;
  UINTN                  Size;

  if (Context == NULL || Pages == 0 || Base == NULL ||
      Pages > MAX_UINTN / EFI_PAGE_SIZE)
  {
    return EFI_INVALID_PARAMETER;
  }

  Size = Pages * EFI_PAGE_SIZE;
  Top  = Context->AllocationTop & ~(EFI_PHYSICAL_ADDRESS)(EFI_PAGE_SIZE - 1);
  if (Top < Context->AllocationBottom || Size > Top - Context->AllocationBottom) {
    return EFI_OUT_OF_RESOURCES;
  }

  Top -= Size;
  if (Context->HobList != NULL) {
    Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList;
    if (Handoff->Header.HobType != EFI_HOB_TYPE_HANDOFF ||
        Handoff->Header.HobLength != sizeof (*Handoff))
    {
      return EFI_COMPROMISED_DATA;
    }

    Handoff->EfiFreeMemoryTop = Top;
  }

  Context->AllocationTop = Top;
  *Base = Top;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeHandoff (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->HobList == NULL || Context->HobListSize == 0 ||
      Context->ImageBase == 0 || Context->ImageSize == 0 ||
      !Cdk2NativeRangeContains (Context->ImageBase, Context->ImageSize, Context->ImageEntryPoint)) {
    return EFI_NOT_READY;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeTransfer (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;

  if (Context == NULL || Context->Backend.Transfer == NULL) {
    return EFI_UNSUPPORTED;
  }

  Status = Cdk2NativeHandoff (Context);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  // Run the platform hook after handoff validation and immediately before
  // transferring control to DXE.
  Cdk2PlatformLateInit ();
  return Context->Backend.Transfer (Context);
}

EFI_STATUS
EFIAPI
Cdk2NativeAdoptHobList (
  IN OUT CDK2_NATIVE_CONTEXT        *Context,
  IN     EFI_HOB_HANDOFF_INFO_TABLE *Handoff
  )
{
  EFI_HOB_GENERIC_HEADER  *Hob;
  EFI_HOB_GENERIC_HEADER  *End;
  UINTN                   HobListSize;
  UINTN                   HobLength;

  if (Context == NULL || Handoff == NULL ||
      Handoff->Header.HobType != EFI_HOB_TYPE_HANDOFF ||
      Handoff->Header.HobLength != sizeof (*Handoff) ||
      Handoff->EfiEndOfHobList == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Handoff->EfiMemoryBottom > Handoff->EfiMemoryTop ||
      Handoff->EfiFreeMemoryBottom > Handoff->EfiFreeMemoryTop ||
      Handoff->EfiFreeMemoryBottom < Handoff->EfiMemoryBottom ||
      Handoff->EfiFreeMemoryTop > Handoff->EfiMemoryTop)
  {
    return EFI_COMPROMISED_DATA;
  }

  End = (EFI_HOB_GENERIC_HEADER *)(UINTN)Handoff->EfiEndOfHobList;
  if ((UINTN)End <= (UINTN)Handoff ||
      (UINTN)End > MAX_UINTN - sizeof (*End)) {
    return EFI_COMPROMISED_DATA;
  }

  HobListSize = ((UINTN)End - (UINTN)Handoff) + sizeof (*End);
  Hob       = (EFI_HOB_GENERIC_HEADER *)(VOID *)Handoff;
  while ((UINTN)Hob < (UINTN)End) {
    if ((UINTN)End - (UINTN)Hob < sizeof (*Hob)) {
      return EFI_COMPROMISED_DATA;
    }

    HobLength = Hob->HobLength;
    if (HobLength < sizeof (*Hob) || HobLength > (UINTN)End - (UINTN)Hob ||
        HobLength > MAX_UINTN - 7) {
      return EFI_COMPROMISED_DATA;
    }

    Hob = (EFI_HOB_GENERIC_HEADER *)(VOID *)((UINT8 *)Hob + ALIGN_VALUE (HobLength, 8));
  }

  if (Hob != End || End->HobType != EFI_HOB_TYPE_END_OF_HOB_LIST ||
      End->HobLength != sizeof (*End)) {
    return EFI_COMPROMISED_DATA;
  }

  if (Handoff->EfiFreeMemoryBottom > Handoff->EfiFreeMemoryTop) {
    return EFI_COMPROMISED_DATA;
  }

  Context->HobList     = Handoff;
  Context->HobListSize = HobListSize;
  Context->AllocationBottom = Handoff->EfiFreeMemoryBottom;
  Context->AllocationTop    = Handoff->EfiFreeMemoryTop;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
Cdk2NativeValidateEntry (
  IN OUT CDK2_NATIVE_CONTEXT        *Context,
  IN     EFI_HOB_HANDOFF_INFO_TABLE *Handoff,
  IN     EFI_PHYSICAL_ADDRESS        ImageBase,
  IN     UINTN                       ImageSize,
  IN     EFI_PHYSICAL_ADDRESS        ImageEntryPoint
  )
{
  EFI_STATUS  Status;

  if (Context == NULL || ImageBase == 0 || ImageSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  Context->ImageBase       = ImageBase;
  Context->ImageSize       = ImageSize;
  Context->ImageEntryPoint = ImageEntryPoint;

  Status = Cdk2NativeAdoptHobList (Context, Handoff);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Context->Services.Handoff == NULL) {
    return EFI_NOT_READY;
  }

  return Context->Services.Handoff (Context);
}
