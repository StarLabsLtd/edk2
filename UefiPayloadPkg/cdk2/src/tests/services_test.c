/** @file

  Host checks for the native cdk2 service boundary.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <cdk2/services.h>

#include <stdio.h>

static UINT8  mTestHobStorage[CDK2_NATIVE_HOB_BUFFER_SIZE];
static UINTN  mConstructHobsCalls;
static UINTN  mPopulateHobsCalls;
static UINTN  mBuildSerialHobCalls;
static UINTN  mApplyBootModeCalls;
static UINTN  mInitializeLibrariesCalls;
static UINTN  mSetBootloaderParameterCalls;
static UINTN  mFindHobMemoryCalls;
static UINTN  mInitializeFloatingPointCalls;
static UINTN  mMaskLegacyInterruptsCalls;
static UINTN  mTransferCalls;
static UINTN  mLateInitCalls;
static BOOLEAN  mFailSetBootloaderParameter;
static BOOLEAN  mFailFindHobMemory;

VOID
EFIAPI
Cdk2PlatformLateInit (
  VOID
  )
{
  mLateInitCalls++;
}

static EFI_STATUS
EFIAPI
TestBuildSerialHob (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mBuildSerialHobCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestApplyBootMode (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mApplyBootModeCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestInitializeLibraries (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mInitializeLibrariesCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestSetBootloaderParameter (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (mFailSetBootloaderParameter) {
    return EFI_DEVICE_ERROR;
  }

  if (Context == NULL || Context->BootloaderParameter != 0x12345678) {
    return EFI_INVALID_PARAMETER;
  }

  mSetBootloaderParameterCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestFindHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  )
{
  if (mFailFindHobMemory) {
    return EFI_DEVICE_ERROR;
  }

  if (Context == NULL || HobMemBase == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *HobMemBase = 0x00200000;
  mFindHobMemoryCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestFindNoHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  )
{
  if (Context == NULL || HobMemBase == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *HobMemBase = 0;
  mFindHobMemoryCalls++;
  return EFI_NOT_FOUND;
}

static EFI_STATUS
EFIAPI
TestFindBelowPayloadHobMemory (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT UINTN                  *HobMemBase
  )
{
  if (Context == NULL || HobMemBase == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *HobMemBase = 0x00200000;
  mFindHobMemoryCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestInitializeFloatingPoint (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mInitializeFloatingPointCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestMaskLegacyInterrupts (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mMaskLegacyInterruptsCalls++;
  return EFI_SUCCESS;
}

static EFI_HOB_HANDOFF_INFO_TABLE *
EFIAPI
TestConstructHobs (
  IN VOID  *EfiMemoryBottom,
  IN VOID  *EfiMemoryTop,
  IN VOID  *EfiFreeMemoryBottom,
  IN VOID  *EfiFreeMemoryTop
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_HOB_GENERIC_HEADER      *End;

  if (EfiMemoryBottom == NULL || EfiMemoryTop == NULL ||
      EfiFreeMemoryBottom == NULL || EfiFreeMemoryTop == NULL) {
    return NULL;
  }

  mConstructHobsCalls++;
  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)(VOID *)mTestHobStorage;
  End     = (EFI_HOB_GENERIC_HEADER *)(VOID *)(mTestHobStorage + sizeof (*Handoff));

  Handoff->Header.HobType   = EFI_HOB_TYPE_HANDOFF;
  Handoff->Header.HobLength = sizeof (*Handoff);
  Handoff->Header.Reserved  = 0;
  Handoff->Version          = EFI_HOB_HANDOFF_TABLE_VERSION;
  Handoff->BootMode         = BOOT_WITH_FULL_CONFIGURATION;
  Handoff->EfiMemoryBottom  = (EFI_PHYSICAL_ADDRESS)(UINTN)EfiMemoryBottom;
  Handoff->EfiMemoryTop     = (EFI_PHYSICAL_ADDRESS)(UINTN)EfiMemoryTop;
  Handoff->EfiFreeMemoryBottom = (EFI_PHYSICAL_ADDRESS)(UINTN)EfiFreeMemoryBottom;
  Handoff->EfiFreeMemoryTop    = (EFI_PHYSICAL_ADDRESS)(UINTN)EfiFreeMemoryTop;
  Handoff->EfiEndOfHobList  = (EFI_PHYSICAL_ADDRESS)(UINTN)End;

  End->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  End->HobLength = sizeof (*End);
  End->Reserved  = 0;
  return Handoff;
}

static EFI_STATUS
EFIAPI
TestPopulateHobs (
  IN OUT CDK2_NATIVE_CONTEXT  *Context
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_HOB_GENERIC_HEADER      *Hob;
  EFI_HOB_GENERIC_HEADER      *End;

  if (Context == NULL || Context->HobList == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mPopulateHobsCalls++;
  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)Context->HobList;
  Hob     = (EFI_HOB_GENERIC_HEADER *)(VOID *)(mTestHobStorage + sizeof (*Handoff));
  End     = (EFI_HOB_GENERIC_HEADER *)(VOID *)((UINT8 *)Hob + sizeof (*Hob));

  Hob->HobType   = EFI_HOB_TYPE_UNUSED;
  Hob->HobLength = sizeof (*Hob);
  Hob->Reserved  = 0;
  End->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  End->HobLength = sizeof (*End);
  End->Reserved  = 0;
  Handoff->EfiEndOfHobList = (EFI_PHYSICAL_ADDRESS)(UINTN)End;
  return EFI_SUCCESS;
}

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 service test: %s\n", Message);
    return 1;
  }

  return 0;
}

static EFI_STATUS
EFIAPI
TestLoadDxeCore (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT EFI_PHYSICAL_ADDRESS  *EntryPoint,
  OUT EFI_PHYSICAL_ADDRESS  *ImageBase,
  OUT UINTN                  *ImageSize
  )
{
  if (Context == NULL || EntryPoint == NULL || ImageBase == NULL || ImageSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *ImageBase  = 0x00400000;
  *ImageSize  = 0x00020000;
  *EntryPoint = 0x00401000;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestLoadDxeCoreFailsAfterOutput (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  OUT EFI_PHYSICAL_ADDRESS  *EntryPoint,
  OUT EFI_PHYSICAL_ADDRESS  *ImageBase,
  OUT UINTN                  *ImageSize
  )
{
  if (Context == NULL || EntryPoint == NULL || ImageBase == NULL || ImageSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *ImageBase  = 0x00400000;
  *ImageSize  = 0x00020000;
  *EntryPoint = 0x00401000;
  return EFI_DEVICE_ERROR;
}

static EFI_STATUS
EFIAPI
TestTransfer (
  IN CDK2_NATIVE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  mTransferCalls++;
  return EFI_SUCCESS;
}

static EFI_STATUS
EFIAPI
TestInitializeContext (
  IN OUT CDK2_NATIVE_CONTEXT  *Context,
  IN     UINTN                 BootloaderParameter
  )
{
  if (Context == NULL || BootloaderParameter != 0x12345678) {
    return EFI_INVALID_PARAMETER;
  }

  *Context = (CDK2_NATIVE_CONTEXT){ 0 };
  Context->BootloaderParameter           = BootloaderParameter;
  Context->PayloadBase                   = 0x00100000;
  Context->PayloadSize                   = 0x00200000;
  Context->HobRegionSize                 = 0x00100000;
  Context->Backend.ConstructHobs         = TestConstructHobs;
  Context->Backend.PopulateHobs          = TestPopulateHobs;
  Context->Backend.BuildSerialHob        = TestBuildSerialHob;
  Context->Backend.ApplyBootMode         = TestApplyBootMode;
  Context->Backend.InitializeLibraries   = TestInitializeLibraries;
  Context->Backend.SetBootloaderParameter = TestSetBootloaderParameter;
  Context->Backend.FindHobMemory          = TestFindHobMemory;
  Context->Backend.InitializeFloatingPoint = TestInitializeFloatingPoint;
  Context->Backend.MaskLegacyInterrupts   = TestMaskLegacyInterrupts;
  Context->Backend.LoadDxeCore             = TestLoadDxeCore;
  Context->Backend.Transfer                = TestTransfer;
  return Cdk2NativeInitializeServices (Context);
}

int
main (void)
{
  CDK2_NATIVE_CONTEXT    Context = { 0 };
  CDK2_NATIVE_CONTEXT    Stage = { 0 };
  CDK2_NATIVE_CONTEXT    Prepared = { 0 };
  CDK2_NATIVE_CONTEXT    BelowPayload = { 0 };
  CDK2_NATIVE_CONTEXT    FallbackOverflow = { 0 };
  CDK2_NATIVE_CONTEXT    Optional = { 0 };
  CDK2_NATIVE_CONTEXT    Incomplete = { 0 };
  CDK2_NATIVE_CONTEXT    Failed = { 0 };
  CDK2_NATIVE_CONTEXT    Allocator = { 0 };
  EFI_HOB_HANDOFF_INFO_TABLE  *AllocatorHob;
  EFI_HOB_HANDOFF_INFO_TABLE  *BelowPayloadHob;
  EFI_HOB_HANDOFF_INFO_TABLE  RejectedHob;
  EFI_HOB_GENERIC_HEADER      *End;
  EFI_HOB_GENERIC_HEADER      *MalformedHob;
  EFI_HOB_GENERIC_HEADER      RejectedEnd;
  EFI_PHYSICAL_ADDRESS   EntryPoint;
  EFI_PHYSICAL_ADDRESS   AllocationBase;
  UINTN                  HobMemBase;
  UINTN                  LateInitBefore;
  UINTN                  TransferBefore;
  UINTN                  OptionalPopulateHobsCalls;
  UINTN                  OptionalBuildSerialHobCalls;
  UINTN                  OptionalApplyBootModeCalls;
  UINTN                  OptionalInitializeLibrariesCalls;
  UINTN                  OptionalSetBootloaderParameterCalls;
  UINTN                  OptionalMaskLegacyInterruptsCalls;
  int                    Failures;

  Context.PayloadBase      = 0x00100000;
  Context.PayloadSize      = 0x00200000;
  Context.ImageEntryPoint  = 0x00110000;
  Failures  = 0;
  Failures += Expect (Cdk2NativeInitializeServices (&Context) == EFI_SUCCESS, "service initialization");
  Failures += Expect (Context.Services.BuildHobs != NULL, "HOB service installed");
  Failures += Expect (Context.Services.PopulateHobs != NULL, "HOB population service installed");
  Failures += Expect (Context.Services.BuildSerialHob != NULL, "serial HOB service installed");
  Failures += Expect (Context.Services.ApplyBootMode != NULL, "boot-mode service installed");
  Failures += Expect (Context.Services.InitializeLibraries != NULL, "library service installed");
  Failures += Expect (Context.Services.SetBootloaderParameter != NULL, "bootloader PCD service installed");
  Failures += Expect (Context.Services.FindHobMemory != NULL, "HOB memory service installed");
  Failures += Expect (Context.Services.InitializeFloatingPoint != NULL, "floating-point service installed");
  Failures += Expect (Context.Services.MaskLegacyInterrupts != NULL, "interrupt service installed");
  Failures += Expect (Context.Services.LoadImage != NULL, "image service installed");
  Failures += Expect (Context.Services.Handoff != NULL, "handoff service installed");

  Stage.ImageBase = 0x00400000;
  Failures += Expect (
                Cdk2NativeInitializeStageContext (&Stage, 0xCAFEBABE) == EFI_SUCCESS,
                "native stage context initialization"
                );
  Failures += Expect (Stage.BootloaderParameter == 0xCAFEBABE, "stage bootloader parameter");
  Failures += Expect (Stage.ImageBase == 0, "stage context reset");
  Failures += Expect (Stage.Services.BuildHobs != NULL, "stage services installed");
  Failures += Expect (Cdk2NativeValidateBackend (&Context) == EFI_UNSUPPORTED, "incomplete backend rejected");
  Failures += Expect (Cdk2NativeTransfer (&Context) == EFI_UNSUPPORTED, "transfer requires architecture hook");
  Failures += Expect (Cdk2NativeBuildHobs (&Context) == EFI_SUCCESS, "HOB build");
  Context.HobMemoryBottom     = (VOID *)(UINTN)0x00100000;
  Context.HobMemoryTop        = (VOID *)(UINTN)0x00400000;
  Context.HobFreeMemoryBottom = (VOID *)(UINTN)0x00200000;
  Context.HobFreeMemoryTop    = (VOID *)(UINTN)0x00300000;
  Context.Backend.ConstructHobs = TestConstructHobs;
  Failures += Expect (Cdk2NativeBuildHobs (&Context) == EFI_SUCCESS, "callback HOB build");
  Failures += Expect (mConstructHobsCalls == 1, "HOB constructor callback");
  Failures += Expect (Context.HobList == (VOID *)mTestHobStorage, "callback HOB list");
  Context.Backend.PopulateHobs = TestPopulateHobs;
  Failures += Expect (Cdk2NativePopulateHobs (&Context) == EFI_SUCCESS, "HOB population");
  Failures += Expect (mPopulateHobsCalls == 1, "HOB population callback");
  Failures += Expect (Context.HobListSize == sizeof (EFI_HOB_HANDOFF_INFO_TABLE) +
                       2 * sizeof (EFI_HOB_GENERIC_HEADER), "expanded HOB list");
  Context.Backend.BuildSerialHob = TestBuildSerialHob;
  Failures += Expect (Cdk2NativeBuildSerialHob (&Context) == EFI_SUCCESS, "serial HOB service");
  Failures += Expect (mBuildSerialHobCalls == 1, "serial HOB callback");
  Context.Backend.ApplyBootMode = TestApplyBootMode;
  Failures += Expect (Cdk2NativeApplyBootMode (&Context) == EFI_SUCCESS, "boot-mode service");
  Failures += Expect (mApplyBootModeCalls == 1, "boot-mode callback");
  Context.Backend.InitializeLibraries = TestInitializeLibraries;
  Failures += Expect (Cdk2NativeInitializeLibraries (&Context) == EFI_SUCCESS, "library service");
  Failures += Expect (mInitializeLibrariesCalls == 1, "library callback");
  Context.BootloaderParameter = 0x12345678;
  Context.Backend.SetBootloaderParameter = TestSetBootloaderParameter;
  Failures += Expect (Cdk2NativeSetBootloaderParameter (&Context) == EFI_SUCCESS, "bootloader PCD service");
  Failures += Expect (mSetBootloaderParameterCalls == 1, "bootloader PCD callback");
  Context.Backend.FindHobMemory = TestFindHobMemory;
  HobMemBase = 0;
  Failures += Expect (Cdk2NativeFindHobMemory (&Context, &HobMemBase) == EFI_SUCCESS, "HOB memory service");
  Failures += Expect (HobMemBase == 0x00200000, "HOB memory callback");
  Failures += Expect (mFindHobMemoryCalls == 1, "HOB memory callback count");
  Context.Backend.InitializeFloatingPoint = TestInitializeFloatingPoint;
  Failures += Expect (Cdk2NativeInitializeFloatingPoint (&Context) == EFI_SUCCESS, "floating-point service");
  Failures += Expect (mInitializeFloatingPointCalls == 1, "floating-point callback");
  Context.Backend.MaskLegacyInterrupts = TestMaskLegacyInterrupts;
  Failures += Expect (Cdk2NativeMaskLegacyInterrupts (&Context) == EFI_SUCCESS, "interrupt service");
  Failures += Expect (mMaskLegacyInterruptsCalls == 1, "interrupt callback");
  Failures += Expect (Cdk2NativeLoadImage (&Context, Cdk2NativeImagePayloadEntry, &EntryPoint) == EFI_SUCCESS, "image load");
  Failures += Expect (EntryPoint == Context.ImageEntryPoint, "entry point");
  Failures += Expect (Cdk2NativeHandoff (&Context) == EFI_SUCCESS, "handoff validation");

  Context.Backend.LoadDxeCore = TestLoadDxeCore;
  Failures += Expect (Cdk2NativeLoadImage (&Context, Cdk2NativeImageDxeCore, &EntryPoint) == EFI_SUCCESS, "DXE core load");
  Failures += Expect (mLateInitCalls == 0, "late-init deferred until transfer");
  Failures += Expect (EntryPoint == 0x00401000, "DXE core entry point");
  Failures += Expect (Context.ImageBase == 0x00400000, "DXE core image base");
  Failures += Expect (Context.ImageSize == 0x00020000, "DXE core image size");
  Context.Backend.Transfer = TestTransfer;
  Failures += Expect (Cdk2NativeTransfer (&Context) == EFI_SUCCESS, "transfer service");
  Failures += Expect (mLateInitCalls == 1, "late-init hook");
  Failures += Expect (mTransferCalls == 1, "transfer callback");
  Context.Backend.LoadDxeCore = TestLoadDxeCoreFailsAfterOutput;
  LateInitBefore = mLateInitCalls;
  TransferBefore = mTransferCalls;
  Failures += Expect (
                Cdk2NativeLoadImage (&Context, Cdk2NativeImageDxeCore, &EntryPoint) == EFI_DEVICE_ERROR,
                "failed DXE core load status"
                );
  Failures += Expect (Context.ImageBase == 0, "failed DXE core load clears image base");
  Failures += Expect (Context.ImageSize == 0, "failed DXE core load clears image size");
  Failures += Expect (Context.ImageEntryPoint == 0, "failed DXE core load clears entry point");
  Failures += Expect (EntryPoint == 0, "failed DXE core load clears returned entry point");
  Failures += Expect (Cdk2NativeTransfer (&Context) == EFI_NOT_READY, "failed DXE core load blocks transfer");
  Failures += Expect (mLateInitCalls == LateInitBefore, "late-init skipped after failed DXE core load");
  Failures += Expect (mTransferCalls == TransferBefore, "transfer skipped after failed DXE core load");
  Context.Backend.LoadDxeCore = NULL;
  Failures += Expect (Cdk2NativeLoadImage (&Context, Cdk2NativeImageDxeCore, &EntryPoint) == EFI_UNSUPPORTED, "DXE core callback required");

  Context.ImageEntryPoint = Context.PayloadBase + Context.PayloadSize;
  Failures += Expect (Cdk2NativeLoadImage (&Context, Cdk2NativeImagePayloadEntry, &EntryPoint) == EFI_SECURITY_VIOLATION, "range rejection");

  Context.ImageEntryPoint = 0x00110000;
  Failures += Expect (Cdk2NativeLoadImage (&Context, Cdk2NativeImageMax, &EntryPoint) == EFI_INVALID_PARAMETER, "image selector rejection");

  Context.ImageBase       = 0x00400000;
  Context.ImageSize       = 0x00020000;
  Context.ImageEntryPoint = 0x00401000;
  Failures += Expect (Cdk2NativeValidateEntry (
                       &Context,
                       (EFI_HOB_HANDOFF_INFO_TABLE *)Context.HobList,
                       Context.ImageBase,
                       Context.ImageSize,
                       Context.ImageEntryPoint
                       ) == EFI_SUCCESS, "existing HOB handoff validation");

  RejectedHob = (EFI_HOB_HANDOFF_INFO_TABLE){ 0 };
  RejectedEnd = (EFI_HOB_GENERIC_HEADER){ 0 };
  RejectedHob.Header.HobType   = EFI_HOB_TYPE_HANDOFF;
  RejectedHob.Header.HobLength = sizeof (RejectedHob);
  RejectedHob.EfiMemoryBottom  = 0x00100000;
  RejectedHob.EfiMemoryTop     = 0x00400000;
  RejectedHob.EfiFreeMemoryBottom = 0x00300000;
  RejectedHob.EfiFreeMemoryTop    = 0x00200000;
  RejectedHob.EfiEndOfHobList  = (EFI_PHYSICAL_ADDRESS)(UINTN)&RejectedEnd;
  RejectedEnd.HobType          = EFI_HOB_TYPE_END_OF_HOB_LIST;
  RejectedEnd.HobLength        = sizeof (RejectedEnd);
  LateInitBefore = mLateInitCalls;
  TransferBefore = mTransferCalls;
  Failures += Expect (Cdk2NativeValidateEntry (
                       &Context,
                       &RejectedHob,
                       0x00500000,
                       0x00010000,
                       0x00501000
                       ) == EFI_COMPROMISED_DATA, "rejected HOB validation status");
  Failures += Expect (Context.ImageBase == 0, "rejected HOB validation clears image base");
  Failures += Expect (Context.ImageSize == 0, "rejected HOB validation clears image size");
  Failures += Expect (Context.ImageEntryPoint == 0, "rejected HOB validation clears entry point");
  Failures += Expect (Cdk2NativeTransfer (&Context) == EFI_NOT_READY, "rejected HOB validation blocks transfer");
  Failures += Expect (mLateInitCalls == LateInitBefore, "late-init skipped after rejected HOB validation");
  Failures += Expect (mTransferCalls == TransferBefore, "transfer skipped after rejected HOB validation");

  Failures += Expect (Cdk2NativeAdoptHobList (&Context, NULL) == EFI_INVALID_PARAMETER, "null HOB rejection");
  AllocatorHob = TestConstructHobs (
                   (VOID *)(UINTN)0x00100000,
                   (VOID *)(UINTN)0x00400000,
                   (VOID *)(UINTN)0x00200000,
                   (VOID *)(UINTN)0x00300000
                   );
  AllocatorHob->EfiFreeMemoryTop = MAX_UINT64;
  Failures += Expect (
                Cdk2NativeAdoptHobList (&Context, AllocatorHob) == EFI_COMPROMISED_DATA,
                "out-of-range HOB free top rejection"
                );

  AllocatorHob = TestConstructHobs (
                   (VOID *)(UINTN)0x00100000,
                   (VOID *)(UINTN)0x00400000,
                   (VOID *)(UINTN)0x00200000,
                   (VOID *)(UINTN)0x00300000
                   );
  MalformedHob = (EFI_HOB_GENERIC_HEADER *)(VOID *)(mTestHobStorage + sizeof (*AllocatorHob));
  End = (EFI_HOB_GENERIC_HEADER *)(VOID *)((UINT8 *)(VOID *)MalformedHob + 16);
  MalformedHob->HobType   = EFI_HOB_TYPE_UNUSED;
  MalformedHob->HobLength = sizeof (*MalformedHob) + 1;
  MalformedHob->Reserved  = 0;
  End->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  End->HobLength = sizeof (*End);
  End->Reserved  = 0;
  AllocatorHob->EfiEndOfHobList = (EFI_PHYSICAL_ADDRESS)(UINTN)End;
  Failures += Expect (
                Cdk2NativeAdoptHobList (&Context, AllocatorHob) == EFI_COMPROMISED_DATA,
                "unaligned adopted HOB length rejection"
                );

  AllocatorHob = TestConstructHobs (
                   (VOID *)(UINTN)0x00100000,
                   (VOID *)(UINTN)0x00400000,
                   (VOID *)(UINTN)0x00200000,
                   (VOID *)(UINTN)0x00300000
                   );
  MalformedHob = (EFI_HOB_GENERIC_HEADER *)(VOID *)(mTestHobStorage + sizeof (*AllocatorHob));
  End = (EFI_HOB_GENERIC_HEADER *)(VOID *)((UINT8 *)(VOID *)MalformedHob + sizeof (*MalformedHob));
  MalformedHob->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  MalformedHob->HobLength = sizeof (*MalformedHob);
  MalformedHob->Reserved  = 0;
  End->HobType   = EFI_HOB_TYPE_END_OF_HOB_LIST;
  End->HobLength = sizeof (*End);
  End->Reserved  = 0;
  AllocatorHob->EfiEndOfHobList = (EFI_PHYSICAL_ADDRESS)(UINTN)End;
  Failures += Expect (
                Cdk2NativeAdoptHobList (&Context, AllocatorHob) == EFI_COMPROMISED_DATA,
                "early adopted HOB end marker rejection"
                );

  Allocator.AllocationBottom = 0x00200000;
  Allocator.AllocationTop    = 0x00210000;
  Failures += Expect (
                Cdk2NativeAllocatePages (&Allocator, 1, &AllocationBase) == EFI_SUCCESS,
                "page allocation"
                );
  Failures += Expect (AllocationBase == 0x0020f000, "top-down page placement");
  Failures += Expect (Allocator.AllocationTop == AllocationBase, "allocator top update");
  Failures += Expect (
                Cdk2NativeAllocatePages (&Allocator, 15, &AllocationBase) == EFI_SUCCESS,
                "allocator exact exhaustion"
                );
  Failures += Expect (Allocator.AllocationTop == Allocator.AllocationBottom, "allocator exhaustion boundary");
  Failures += Expect (
                Cdk2NativeAllocatePages (&Allocator, 1, &AllocationBase) == EFI_OUT_OF_RESOURCES,
                "allocator exhaustion rejection"
                );
  AllocatorHob = (EFI_HOB_HANDOFF_INFO_TABLE *)(VOID *)mTestHobStorage;
  *AllocatorHob = (EFI_HOB_HANDOFF_INFO_TABLE){ 0 };
  AllocatorHob->Header.HobType   = EFI_HOB_TYPE_HANDOFF;
  AllocatorHob->Header.HobLength = sizeof (*AllocatorHob);
  AllocatorHob->EfiMemoryBottom  = 0x00200000;
  AllocatorHob->EfiMemoryTop     = 0x00210000;
  AllocatorHob->EfiFreeMemoryBottom = 0x00200000;
  AllocatorHob->EfiFreeMemoryTop = 0x00210000;
  Allocator = (CDK2_NATIVE_CONTEXT){ 0 };
  Allocator.HobList          = AllocatorHob;
  Allocator.AllocationBottom = 0x00200000;
  Allocator.AllocationTop    = 0x00210000;
  Failures += Expect (
                Cdk2NativeAllocatePages (&Allocator, 1, &AllocationBase) == EFI_SUCCESS,
                "HOB-backed page allocation"
                );
  Failures += Expect (Allocator.AllocationTop == AllocationBase, "HOB-backed allocator top update");
  Failures += Expect (AllocatorHob->EfiFreeMemoryTop == AllocationBase, "PHIT free memory top update");
  Allocator.HobList          = NULL;
  Allocator.AllocationBottom = 0x00300000;
  Allocator.AllocationTop    = 0x00200000;
  Failures += Expect (
                Cdk2NativeAllocatePages (&Allocator, 1, &AllocationBase) == EFI_OUT_OF_RESOURCES,
                "inverted allocator range rejection"
                );
  AllocatorHob = TestConstructHobs (
                   (VOID *)(UINTN)0x00200000,
                   (VOID *)(UINTN)0x00203000,
                   (VOID *)(UINTN)0x00200000,
                   (VOID *)(UINTN)0x00203000
                   );
  Allocator = (CDK2_NATIVE_CONTEXT){ 0 };
  Failures += Expect (
                Cdk2NativeAdoptHobList (&Allocator, AllocatorHob) == EFI_SUCCESS,
                "allocator HOB adoption"
                );
  AllocatorHob->EfiFreeMemoryBottom = 0x00202000;
  Failures += Expect (
                Cdk2NativeAllocatePages (&Allocator, 2, &AllocationBase) == EFI_OUT_OF_RESOURCES,
                "allocator stale PHIT free bottom rejection"
                );
  Failures += Expect (
                AllocatorHob->EfiFreeMemoryTop == 0x00203000,
                "failed allocator preserves PHIT free top"
                );

  Prepared.BootloaderParameter   = 0x12345678;
  Prepared.PayloadBase           = 0x00100000;
  Prepared.PayloadSize           = 0x00200000;
  Prepared.HobRegionSize         = 0x00100000;
  Prepared.Backend.ConstructHobs            = TestConstructHobs;
  Prepared.Backend.PopulateHobs             = TestPopulateHobs;
  Prepared.Backend.BuildSerialHob           = TestBuildSerialHob;
  Prepared.Backend.ApplyBootMode            = TestApplyBootMode;
  Prepared.Backend.InitializeLibraries      = TestInitializeLibraries;
  Prepared.Backend.SetBootloaderParameter   = TestSetBootloaderParameter;
  Prepared.Backend.FindHobMemory             = TestFindHobMemory;
  Prepared.Backend.InitializeFloatingPoint  = TestInitializeFloatingPoint;
  Prepared.Backend.MaskLegacyInterrupts     = TestMaskLegacyInterrupts;
  Prepared.Backend.LoadDxeCore               = TestLoadDxeCore;
  Failures += Expect (Cdk2NativeInitializeServices (&Prepared) == EFI_SUCCESS, "prepare service initialization");

  Optional = Prepared;
  Optional.Backend.PopulateHobs            = NULL;
  Optional.Backend.BuildSerialHob          = NULL;
  Optional.Backend.ApplyBootMode           = NULL;
  Optional.Backend.InitializeLibraries     = NULL;
  Optional.Backend.SetBootloaderParameter  = NULL;
  Optional.Backend.MaskLegacyInterrupts    = NULL;
  Optional.Backend.Transfer                = TestTransfer;
  Failures += Expect (Cdk2NativeValidateBackend (&Optional) == EFI_SUCCESS, "optional callbacks omitted");
  OptionalPopulateHobsCalls           = mPopulateHobsCalls;
  OptionalBuildSerialHobCalls         = mBuildSerialHobCalls;
  OptionalApplyBootModeCalls          = mApplyBootModeCalls;
  OptionalInitializeLibrariesCalls    = mInitializeLibrariesCalls;
  OptionalSetBootloaderParameterCalls = mSetBootloaderParameterCalls;
  OptionalMaskLegacyInterruptsCalls   = mMaskLegacyInterruptsCalls;
  Failures += Expect (Cdk2NativePrepareEntry (&Optional) == EFI_SUCCESS, "prepare entry with optional callbacks omitted");
  Failures += Expect (mPopulateHobsCalls == OptionalPopulateHobsCalls, "optional HOB population skipped");
  Failures += Expect (mBuildSerialHobCalls == OptionalBuildSerialHobCalls, "optional serial HOB skipped");
  Failures += Expect (mApplyBootModeCalls == OptionalApplyBootModeCalls, "optional boot mode skipped");
  Failures += Expect (mInitializeLibrariesCalls == OptionalInitializeLibrariesCalls, "optional library init skipped");
  Failures += Expect (mSetBootloaderParameterCalls == OptionalSetBootloaderParameterCalls, "optional bootloader PCD skipped");
  Failures += Expect (mMaskLegacyInterruptsCalls == OptionalMaskLegacyInterruptsCalls, "optional interrupt mask skipped");

  Failed = Prepared;
  mFailSetBootloaderParameter = TRUE;
  Failures += Expect (Cdk2NativePrepareEntry (&Failed) == EFI_DEVICE_ERROR, "bootloader parameter failure");
  mFailSetBootloaderParameter = FALSE;

  Failed = Prepared;
  mFailFindHobMemory = TRUE;
  Failures += Expect (Cdk2NativePrepareEntry (&Failed) == EFI_DEVICE_ERROR, "HOB memory discovery failure");
  mFailFindHobMemory = FALSE;

  FallbackOverflow = Prepared;
  FallbackOverflow.PayloadBase = (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - (SIZE_1MB / 2U));
  FallbackOverflow.PayloadSize = EFI_PAGE_SIZE;
  FallbackOverflow.Backend.FindHobMemory = TestFindNoHobMemory;
  Failures += Expect (
                Cdk2NativePrepareEntry (&FallbackOverflow) == EFI_INVALID_PARAMETER,
                "fallback HOB memory alignment overflow accepted"
                );

  BelowPayload = Prepared;
  BelowPayload.PayloadBase  = 0x00400000;
  BelowPayload.PayloadSize  = 0x00200000;
  BelowPayload.Backend.FindHobMemory = TestFindBelowPayloadHobMemory;
  Failures += Expect (
                Cdk2NativePrepareEntry (&BelowPayload) == EFI_SUCCESS,
                "below-payload HOB prepare entry"
                );
  BelowPayloadHob = (EFI_HOB_HANDOFF_INFO_TABLE *)BelowPayload.HobList;
  Failures += Expect (BelowPayloadHob != NULL, "below-payload prepared HOB list");
  Failures += Expect (
                BelowPayloadHob != NULL && BelowPayloadHob->EfiMemoryBottom == 0x00200000,
                "below-payload PHIT memory bottom"
                );
  Failures += Expect (
                BelowPayloadHob != NULL && BelowPayloadHob->EfiMemoryTop == 0x00600000,
                "below-payload PHIT memory top"
                );
  Failures += Expect (
                BelowPayloadHob != NULL && BelowPayloadHob->EfiFreeMemoryBottom == 0x00200000,
                "below-payload PHIT free bottom"
                );
  Failures += Expect (
                BelowPayloadHob != NULL && BelowPayloadHob->EfiFreeMemoryTop == 0x00300000,
                "below-payload PHIT free top"
                );

  Failures += Expect (Cdk2NativePrepareEntry (&Prepared) == EFI_SUCCESS, "prepare entry");
  Failures += Expect (Prepared.HobList != NULL, "prepared HOB list");
  Failures += Expect (Prepared.ImageEntryPoint == 0x00401000, "prepared DXE entry point");
  Failures += Expect (mLateInitCalls == 1, "prepare entry defers late-init");

  Incomplete = Prepared;
  Incomplete.Backend.Transfer = NULL;
  Failures += Expect (Cdk2NativeValidateBackend (&Incomplete) == EFI_UNSUPPORTED, "missing transfer rejected");

  mLateInitCalls = 0;
  mTransferCalls = 0;
  Failures += Expect (
                Cdk2NativePayloadEntry (0x12345678, TestInitializeContext) == EFI_SUCCESS,
                "native payload entry flow"
                );
  Failures += Expect (mLateInitCalls == 1, "native payload late-init hook");
  Failures += Expect (mTransferCalls == 1, "native payload transfer");

  return Failures == 0 ? 0 : 1;
}
