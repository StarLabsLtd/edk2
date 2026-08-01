/** @file

  Native cdk2 entry services shared by the freestanding stage and UEFI entry.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef CDK2_NATIVE_SERVICES_API_H_
#define CDK2_NATIVE_SERVICES_API_H_

#include <Uefi.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _CDK2_NATIVE_CONTEXT  CDK2_NATIVE_CONTEXT;

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_INITIALIZE_CONTEXT)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  );

typedef enum {
  Cdk2NativeImageDxeCore,
  Cdk2NativeImagePayloadEntry,
  Cdk2NativeImageMax
} CDK2_NATIVE_IMAGE;

#define CDK2_NATIVE_HOB_BUFFER_SIZE  0x1000U

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_BUILD_HOBS)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_HOB_HANDOFF_INFO_TABLE *(EFIAPI *CDK2_NATIVE_CONSTRUCT_HOBS)(
  IN VOID  *EfiMemoryBottom,
  IN VOID  *EfiMemoryTop,
  IN VOID  *EfiFreeMemoryBottom,
  IN VOID  *EfiFreeMemoryTop
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_BUILD_PLATFORM_HOBS)(
  IN OUT CDK2_NATIVE_CONTEXT        *Context,
  OUT    EFI_HOB_HANDOFF_INFO_TABLE **Handoff
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_POPULATE_HOBS)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_BUILD_SERIAL_HOB)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_APPLY_BOOT_MODE)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_INITIALIZE_LIBRARIES)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_SET_BOOTLOADER_PARAMETER)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_FIND_HOB_MEMORY)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_INITIALIZE_FLOATING_POINT)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_MASK_LEGACY_INTERRUPTS)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_LOAD_IMAGE)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN CDK2_NATIVE_IMAGE         Image,
  OUT EFI_PHYSICAL_ADDRESS     *EntryPoint
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_LOAD_DXE_CORE)(
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT EFI_PHYSICAL_ADDRESS  *EntryPoint,
  OUT EFI_PHYSICAL_ADDRESS  *ImageBase,
  OUT UINTN                  *ImageSize
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_HANDOFF)(
  IN CDK2_NATIVE_CONTEXT  *Context
  );

typedef EFI_STATUS (EFIAPI *CDK2_NATIVE_TRANSFER)(
  IN CDK2_NATIVE_CONTEXT  *Context
  );

typedef struct {
  CDK2_NATIVE_CONSTRUCT_HOBS          ConstructHobs;
  CDK2_NATIVE_BUILD_PLATFORM_HOBS     BuildPlatformHobs;
  CDK2_NATIVE_POPULATE_HOBS           PopulateHobs;
  CDK2_NATIVE_BUILD_SERIAL_HOB        BuildSerialHob;
  CDK2_NATIVE_APPLY_BOOT_MODE         ApplyBootMode;
  CDK2_NATIVE_INITIALIZE_LIBRARIES    InitializeLibraries;
  CDK2_NATIVE_SET_BOOTLOADER_PARAMETER SetBootloaderParameter;
  CDK2_NATIVE_FIND_HOB_MEMORY         FindHobMemory;
  CDK2_NATIVE_INITIALIZE_FLOATING_POINT InitializeFloatingPoint;
  CDK2_NATIVE_MASK_LEGACY_INTERRUPTS  MaskLegacyInterrupts;
  CDK2_NATIVE_LOAD_DXE_CORE           LoadDxeCore;
  CDK2_NATIVE_TRANSFER                Transfer;
} CDK2_NATIVE_BACKEND;

typedef struct {
  CDK2_NATIVE_BUILD_HOBS        BuildHobs;
  CDK2_NATIVE_POPULATE_HOBS     PopulateHobs;
  CDK2_NATIVE_BUILD_SERIAL_HOB  BuildSerialHob;
  CDK2_NATIVE_APPLY_BOOT_MODE  ApplyBootMode;
  CDK2_NATIVE_INITIALIZE_LIBRARIES  InitializeLibraries;
  CDK2_NATIVE_SET_BOOTLOADER_PARAMETER  SetBootloaderParameter;
  CDK2_NATIVE_FIND_HOB_MEMORY  FindHobMemory;
  CDK2_NATIVE_INITIALIZE_FLOATING_POINT  InitializeFloatingPoint;
  CDK2_NATIVE_MASK_LEGACY_INTERRUPTS  MaskLegacyInterrupts;
  CDK2_NATIVE_LOAD_IMAGE     LoadImage;
  CDK2_NATIVE_HANDOFF        Handoff;
} CDK2_NATIVE_SERVICES;

struct _CDK2_NATIVE_CONTEXT {
  UINTN                  BootloaderParameter;
  EFI_PHYSICAL_ADDRESS   PayloadBase;
  UINTN                  PayloadSize;
  VOID                   *HobList;
  UINTN                  HobListSize;
  EFI_PHYSICAL_ADDRESS   ImageBase;
  UINTN                  ImageSize;
  EFI_PHYSICAL_ADDRESS   ImageEntryPoint;
  VOID                   *HobMemoryBottom;
  VOID                   *HobMemoryTop;
  VOID                   *HobFreeMemoryBottom;
  VOID                   *HobFreeMemoryTop;
  UINTN                  HobRegionSize;
  EFI_PHYSICAL_ADDRESS   AllocationBottom;
  EFI_PHYSICAL_ADDRESS   AllocationTop;
  CDK2_NATIVE_BACKEND    Backend;
  CDK2_NATIVE_SERVICES   Services;
};

EFI_STATUS
EFIAPI
Cdk2NativeInitializeServices (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

/**
  Initialize the common native-stage context and service table.

  This is the context boundary used by the freestanding stage. The EDK II
  backend uses the same helper before adding its payload-specific fields and
  callbacks, so both entry paths preserve the coreboot bootloader parameter.

  @param[out] Context             Context to initialize.
  @param[in]  BootloaderParameter Coreboot bootloader parameter address.

  @retval EFI_SUCCESS           The context and services were initialized.
  @retval EFI_INVALID_PARAMETER Context is NULL.
**/
EFI_STATUS
EFIAPI
Cdk2NativeInitializeStageContext (
  OUT CDK2_NATIVE_CONTEXT  *Context,
  IN  UINTN                 BootloaderParameter
  );

/**
  Verify that the backend provides every callback required by a real payload
  entry and transfer.

  The direct coreboot backend builds its complete payload handoff in one
  platform-HOB callback, while the EDK II adapter keeps separate callbacks for
  serial HOBs, boot-mode policy, library constructors, and bootloader PCDs.
  Only the common entry requirements are mandatory here; adapter-only callbacks
  are skipped when they are not registered.

  @param[in] Context  Context whose backend is being checked.

  @retval EFI_SUCCESS           The backend is complete.
  @retval EFI_INVALID_PARAMETER Context is NULL.
  @retval EFI_UNSUPPORTED       A required backend callback is missing.
**/
EFI_STATUS
EFIAPI
Cdk2NativeValidateBackend (
  IN CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativePayloadEntry (
  IN UINTN                          BootloaderParameter,
  IN CDK2_NATIVE_INITIALIZE_CONTEXT InitializeContext
  );

/**
  Run the validated native entry sequence for an initialized context.

  The freestanding stage and the UEFI adapter share this sequence. The
  caller owns context initialization and backend registration.

  @param[in,out] Context  Initialized context with a complete backend.

  @retval EFI_SUCCESS            The transfer callback returned.
  @retval EFI_INVALID_PARAMETER  Context is NULL.
  @retval EFI_UNSUPPORTED        A required backend callback is missing.
  @retval Other                  A preparation or transfer operation failed.
**/
EFI_STATUS
EFIAPI
Cdk2NativeRunEntry (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeBuildHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativePopulateHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeBuildSerialHob (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeApplyBootMode (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeInitializeLibraries (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeSetBootloaderParameter (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeFindHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  );

EFI_STATUS
EFIAPI
Cdk2NativeInitializeFloatingPoint (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeMaskLegacyInterrupts (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativePrepareEntry (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeLoadImage (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN CDK2_NATIVE_IMAGE         Image,
  OUT EFI_PHYSICAL_ADDRESS     *EntryPoint
  );

EFI_STATUS
EFIAPI
Cdk2NativeAllocatePages (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 Pages,
  OUT    EFI_PHYSICAL_ADDRESS *Base
  );

EFI_STATUS
EFIAPI
Cdk2NativeHandoff (
  IN CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeTransfer (
  IN CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2NativeAdoptHobList (
  IN OUT CDK2_NATIVE_CONTEXT       *Context,
  IN     EFI_HOB_HANDOFF_INFO_TABLE *Handoff
  );

EFI_STATUS
EFIAPI
Cdk2NativeValidateEntry (
  IN OUT CDK2_NATIVE_CONTEXT       *Context,
  IN     EFI_HOB_HANDOFF_INFO_TABLE *Handoff,
  IN     EFI_PHYSICAL_ADDRESS        ImageBase,
  IN     UINTN                       ImageSize,
  IN     EFI_PHYSICAL_ADDRESS        ImageEntryPoint
  );

#ifdef __cplusplus
}
#endif

#endif
