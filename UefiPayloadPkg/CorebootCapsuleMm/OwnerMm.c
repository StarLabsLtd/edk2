/** @file
  Protected capsule owner and bounded public MM command dispatch.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <PiMm.h>
#include "Owner.h"
#include "Source.h"
#include "../Library/FmpDeviceSmmLib/FmpDeviceSmmFmap.h"
#include <Guid/CorebootCapsule.h>
#include <Guid/EventGroup.h>
#include <Guid/FmpControllerState.h>
#include <Protocol/SmmVariable.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PcdLib.h>

STATIC COREBOOT_CAPSULE_PRIVATE_INFO *mInfo;
STATIC CAPSULE_OWNER mOwner;
STATIC CAPSULE_SOURCE mSource;
STATIC CAPSULE_POLICY mPolicy;
STATIC UINT8 mLiveMap[CAPSULE_BLOCK_SIZE];
STATIC CONST FMAP_HEADER *mMapHeader;
STATIC CONST FMAP_AREA *mMapAreas;
STATIC CAPSULE_RANGE mBios;
STATIC UINT32 mGeneration;
STATIC UINT32 mTransaction;
STATIC EFI_SMM_VARIABLE_PROTOCOL *mVariables;
STATIC BOOLEAN mFloorReady;

typedef UINT32 (EFIAPI *PRIVATE_READ)(UINT32 Offset, UINT32 Size);
typedef UINT32 (EFIAPI *PRIVATE_RESOLVE)(CONST CHAR8 Name[16], CAPSULE_RANGE *Range);
typedef UINT32 (EFIAPI *PRIVATE_PROGRAM)(UINT32 Offset, CONST CAPSULE_RANGE *Ranges,
                                       UINT32 Count, UINT8 *Image, UINT32 CheckOnly);
STATIC_ASSERT(sizeof(CAPSULE_RANGE) == 8, "Capsule native range ABI requires IA32");

STATIC
EFI_STATUS
Resolve(VOID *Context, CONST CHAR8 Name[16], CAPSULE_RANGE *Range)
{
  CONST CHAR8 BiosName[16] = "BIOS";
  if (!CompareMem(Name, BiosName, sizeof(BiosName))) {
    *Range = mBios;
    return EFI_SUCCESS;
  }
  return FmpFindFmapRegion(mMapHeader, mMapAreas, mMapHeader->AreaCount,
                           Name, &Range->Offset, &Range->Size);
}

STATIC
EFI_STATUS
Program(VOID *Context, UINTN Block, CONST CAPSULE_RANGE *Ranges, UINTN Count, UINT8 *Image, BOOLEAN CheckOnly)
{
  PRIVATE_PROGRAM Write = (PRIVATE_PROGRAM)(UINTN)mInfo->Program;
  return Write((UINT32)(Block * CAPSULE_BLOCK_SIZE), Ranges, (UINT32)Count, Image, CheckOnly) == 0 ?
           EFI_SUCCESS : EFI_DEVICE_ERROR;
}

STATIC
VOID
Close(VOID)
{
  CapsuleOwnerClose(&mOwner);
  mSource.Address = 0;
  mSource.Size = 0;
  mTransaction = 0;
}

/* ExitBootServices is a one-way boundary owned by the MM core. */
STATIC
EFI_STATUS
EFIAPI
ExitBootServices(CONST EFI_GUID *Protocol, VOID *Interface, EFI_HANDLE Handle)
{
  Close();
  return EFI_SUCCESS;
}

/* Snapshot the existing FMP floor before external DXE can edit its variables.
   Keep a private maximum across requests and S3; never invent a second store. */
STATIC
EFI_STATUS
RefreshFloor(VOID)
{
  FMP_CONTROLLER_STATE State;
  EFI_GUID *Guid = &mInfo->ImageGuid;
  UINTN Size = sizeof(State);
  UINT32 Floor;
  EFI_STATUS Status;

  Status = mVariables->SmmGetVariable(VARNAME_FMPSTATE, Guid, NULL, &Size, &State);
  if (!EFI_ERROR(Status) && Size == sizeof(State)) {
    Floor = State.LsvValid ? State.Lsv : 0;
  } else if (Status == EFI_NOT_FOUND || Status == EFI_BUFFER_TOO_SMALL ||
             (!EFI_ERROR(Status) && Size != sizeof(State))) {
    Size = sizeof(Floor);
    Status = mVariables->SmmGetVariable(VARNAME_LSV, Guid, NULL, &Size, &Floor);
    if (Status == EFI_NOT_FOUND || Status == EFI_BUFFER_TOO_SMALL ||
        (!EFI_ERROR(Status) && Size != sizeof(Floor))) {
      Floor = 0;
    } else if (EFI_ERROR(Status)) {
      return Status;
    }
  } else {
    return Status;
  }
  if (Floor > mPolicy.LowestSupportedVersion) {
    mPolicy.LowestSupportedVersion = Floor;
  }
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
VariableReady(CONST EFI_GUID *Protocol, VOID *Interface, EFI_HANDLE Handle)
{
  mVariables = Interface;
  mFloorReady = mVariables && !EFI_ERROR(RefreshFloor());
  return mFloorReady ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

STATIC
EFI_STATUS
Begin(CONST COREBOOT_CAPSULE_START *Request, CONST UINT8 *Signature)
{
  CONST UINT8 *Keys = PcdGetPtr(PcdFmpDevicePkcs7CertBufferXdr);
  UINTN KeysSize = PcdGetSize(PcdFmpDevicePkcs7CertBufferXdr);
  UINTN Position = 0;
  UINTN Size, Padded;
  EFI_STATUS Status = EFI_SECURITY_VIOLATION;
  VOID *Interface;

  Close();
  if (gMmst->MmLocateProtocol(&gEfiEventExitBootServicesGuid, NULL, &Interface) != EFI_NOT_FOUND) {
    return EFI_ACCESS_DENIED;
  }
  if (Request->SignedSize < mInfo->FlashSize ||
      Request->SignedSize - mInfo->FlashSize > CAPSULE_BLOCK_SIZE ||
      !CapsuleSourceInit(&mSource, Request->Address, Request->SignedSize)) {
    return EFI_SECURITY_VIOLATION;
  }
  if (!mFloorReady) {
    return EFI_NOT_READY;
  }
  Status = RefreshFloor();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  mOwner.Verifier.Read = CapsuleSourceRead;
  mOwner.Verifier.Context = &mSource;
  mOwner.Verifier.SignedSize = Request->SignedSize;
  mOwner.Verifier.ImageOffset = Request->ImageOffset;
  mOwner.Verifier.ImageSize = mInfo->FlashSize;
  while (Position <= KeysSize && KeysSize - Position >= sizeof(UINT32)) {
    Size = SwapBytes32(ReadUnaligned32((CONST UINT32 *)(Keys + Position)));
    Position += sizeof(UINT32);
    if (!Size || Size > KeysSize - Position || Size > MAX_UINTN - 3) {
      break;
    }
    Padded = ALIGN_VALUE(Size, 4);
    if (Padded > KeysSize - Position) {
      break;
    }
    mPolicy.Root = Keys + Position;
    mPolicy.RootSize = Size;
    Status = CapsuleOwnerBegin(&mOwner, Signature, Request->SignatureSize);
    if (!EFI_ERROR(Status)) {
      mGeneration++;
      if (!mGeneration) {
        mGeneration++;
      }
      mTransaction = mGeneration;
      return EFI_SUCCESS;
    }
    Position += Padded;
  }
  Close();
  return Status;
}

STATIC
EFI_STATUS
EFIAPI
Dispatch(IN EFI_HANDLE Handle, IN CONST VOID *Context OPTIONAL,
         IN OUT VOID *CommBuffer OPTIONAL, IN OUT UINTN *CommSize OPTIONAL)
{
  COREBOOT_CAPSULE_HEADER Header;
  COREBOOT_CAPSULE_START Request;
  COREBOOT_CAPSULE_BLOCK Block;
  COREBOOT_CAPSULE_GEOMETRY Geometry;
  UINT8 *Signature;
  UINTN InputSize;
  EFI_STATUS Status;

  /* The MM core owns this primary shadow. Nested source addresses remain untrusted. */
  if (!CommBuffer || !CommSize || *CommSize < sizeof(Header)) {
    return EFI_INVALID_PARAMETER;
  }
  InputSize = *CommSize;
  CopyMem(&Header, CommBuffer, sizeof(Header));
  if (Header.Revision != COREBOOT_CAPSULE_REVISION) {
    return EFI_UNSUPPORTED;
  }
  if (Header.Command == COREBOOT_CAPSULE_INFO) {
    if (InputSize != sizeof(Geometry)) {
      return EFI_INVALID_PARAMETER;
    }
    if (!mFloorReady) {
      return EFI_NOT_READY;
    }
    ZeroMem(&Geometry, sizeof(Geometry));
    Geometry.Header = Header;
    Geometry.FlashSize = mInfo->FlashSize;
    Geometry.BlockSize = mInfo->BlockSize;
    Geometry.LowestSupportedVersion = mPolicy.LowestSupportedVersion;
    CopyMem(CommBuffer, &Geometry, sizeof(Geometry));
    return EFI_SUCCESS;
  }
  if (Header.Command == COREBOOT_CAPSULE_BEGIN) {
    Close();
    if (InputSize < sizeof(Request)) {
      return EFI_INVALID_PARAMETER;
    }
    CopyMem(&Request, CommBuffer, sizeof(Request));
    if (!Request.SignatureSize || Request.SignatureSize > COREBOOT_CAPSULE_MAX_SIGNATURE ||
        Request.SignatureSize != InputSize - sizeof(Request)) {
      return EFI_INVALID_PARAMETER;
    }
    Signature = AllocatePool(Request.SignatureSize);
    if (!Signature) {
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem(Signature, (UINT8 *)CommBuffer + sizeof(Request), Request.SignatureSize);
    Status = Begin(&Request, Signature);
    FreePool(Signature);
    Request.Header.Transaction = mTransaction;
    CopyMem(CommBuffer, &Request, sizeof(Request));
    *CommSize = sizeof(Request);
    return Status;
  }
  if (!mOwner.Active || !mTransaction || Header.Transaction != mTransaction) {
    return EFI_ACCESS_DENIED;
  }
  switch (Header.Command) {
    case COREBOOT_CAPSULE_PROGRAM:
      if (InputSize != sizeof(Block)) {
        return EFI_INVALID_PARAMETER;
      }
      CopyMem(&Block, CommBuffer, sizeof(Block));
      Status = CapsuleOwnerProgram(&mOwner, Block.Block);
      if (!mOwner.Active) {
        Close();
      }
      return Status;
    case COREBOOT_CAPSULE_CLOSE:
      if (InputSize != sizeof(Header)) {
        return EFI_INVALID_PARAMETER;
      }
      Close();
      return EFI_SUCCESS;
    default:
      return EFI_UNSUPPORTED;
  }
}

EFI_STATUS
EFIAPI
CorebootCapsuleOwnerEntryPoint(VOID)
{
  EFI_HOB_GUID_TYPE *Hob;
  PRIVATE_RESOLVE Locate;
  PRIVATE_READ Read;
  CONST CHAR8 FmapName[16] = "FMAP";
  CONST CHAR8 BiosName[16] = "BIOS";
  CONST CHAR8 StoreName[16] = "SMMSTORE";
  CAPSULE_RANGE Map;
  UINTN Offset, Length;
  EFI_HANDLE Handler;
  VOID *Registration;
  EFI_STATUS Status;

  Hob = GetFirstGuidHob(&gCorebootCapsuleInfoGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob) != sizeof(*mInfo)) {
    return EFI_NOT_FOUND;
  }
  mInfo = GET_GUID_HOB_DATA(Hob);
  if (mInfo->Revision != 1 || mInfo->Size != sizeof(*mInfo) ||
      mInfo->BlockSize != CAPSULE_BLOCK_SIZE || !mInfo->FlashSize ||
      mInfo->FlashSize % CAPSULE_BLOCK_SIZE ||
      mInfo->FlashSize / CAPSULE_BLOCK_SIZE > CAPSULE_MAX_BLOCKS ||
      !mInfo->Read || !mInfo->Resolve || !mInfo->Program ||
      !mInfo->Buffer || mInfo->BufferSize != CAPSULE_BLOCK_SIZE ||
      mInfo->BufferSize - 1 > MAX_UINT32 - mInfo->Buffer) {
    return EFI_INVALID_PARAMETER;
  }
  Locate = (PRIVATE_RESOLVE)(UINTN)mInfo->Resolve;
  Read = (PRIVATE_READ)(UINTN)mInfo->Read;
  if (Locate(BiosName, &mBios) || !mBios.Size || mBios.Offset >= mInfo->FlashSize ||
      mBios.Size > mInfo->FlashSize - mBios.Offset || Locate(FmapName, &Map) ||
      !Map.Size || Map.Size > sizeof(mLiveMap) || Map.Offset >= mInfo->FlashSize ||
      Map.Size > mInfo->FlashSize - Map.Offset || Read((UINT32)Map.Offset, (UINT32)Map.Size)) {
    return EFI_DEVICE_ERROR;
  }
  CopyMem(mLiveMap, (VOID *)(UINTN)mInfo->Buffer, Map.Size);
  Status = FmpLocateFmap(mLiveMap, Map.Size, &Offset, &Length);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  mMapHeader = (CONST FMAP_HEADER *)(mLiveMap + Offset);
  mMapAreas = (CONST FMAP_AREA *)((CONST UINT8 *)mMapHeader + sizeof(*mMapHeader));
  if (mMapHeader->Size != mInfo->FlashSize) {
    return EFI_COMPROMISED_DATA;
  }
  Status = Resolve(NULL, StoreName, &mPolicy.VariableStore);
  if (EFI_ERROR(Status) || !mPolicy.VariableStore.Size ||
      mPolicy.VariableStore.Offset % CAPSULE_BLOCK_SIZE ||
      mPolicy.VariableStore.Size % CAPSULE_BLOCK_SIZE ||
      mPolicy.VariableStore.Offset >= mInfo->FlashSize ||
      mPolicy.VariableStore.Size > mInfo->FlashSize - mPolicy.VariableStore.Offset) {
    return EFI_COMPROMISED_DATA;
  }
  mPolicy.FlashSize = mInfo->FlashSize;
  mPolicy.LowestSupportedVersion = mInfo->LowestSupportedVersion;
  mPolicy.Resolve = Resolve;
  mPolicy.Program = Program;
  mOwner.Policy = &mPolicy;
  Status = gMmst->MmiHandlerRegister(Dispatch, &gCorebootCapsuleUpdateGuid, &Handler);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Status = gMmst->MmRegisterProtocolNotify(&gEfiEventExitBootServicesGuid,
                                          ExitBootServices, &Registration);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  /* Publish readiness only after the handler and lifecycle closure exist. */
  return gMmst->MmRegisterProtocolNotify(&gEfiSmmVariableProtocolGuid,
                                         VariableReady, &Registration);
}
