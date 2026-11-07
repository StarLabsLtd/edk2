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
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/MmServicesTableLib.h>
#include <Library/PcdLib.h>

STATIC COREBOOT_CAPSULE_PRIVATE_INFO *mInfo;
STATIC COREBOOT_CAPSULE_VBOOT_INFO *mVboot;
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
typedef UINT32 (EFIAPI *PRIVATE_COMMIT)(UINT32 Slot);
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
EFI_STATUS
Commit(VOID *Context, UINT32 Slot)
{
  PRIVATE_COMMIT Arm = (PRIVATE_COMMIT)(UINTN)mVboot->Commit;
  return Arm(Slot) == 0 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
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
  if (mVboot && mVboot->BootSlot && EFI_ERROR(Commit(NULL, 0))) {
    /* Notify return values cannot stop ExitBootServices. */
    DEBUG((DEBUG_ERROR, "VBOOT: could not confirm firmware boot acknowledgement\n"));
  }
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
BOOLEAN
TrustDataValid (VOID)
{
  CONST UINT8 *Keys = PcdGetPtr (PcdFmpDevicePkcs7CertBufferXdr);
  UINTN KeysSize = PcdGetSize (PcdFmpDevicePkcs7CertBufferXdr);
  UINTN Position = 0;
  UINTN Size;
  UINTN Padded;

  if ((Keys == NULL) || (KeysSize == 0)) {
    return FALSE;
  }
  while (Position < KeysSize) {
    if (KeysSize - Position < sizeof (UINT32)) {
      return FALSE;
    }
    Size = SwapBytes32 (ReadUnaligned32 ((CONST UINT32 *)(Keys + Position)));
    Position += sizeof (UINT32);
    if ((Size == 0) || (Size > MAX_UINTN - 3)) {
      return FALSE;
    }
    Padded = ALIGN_VALUE (Size, 4);
    if ((Padded > KeysSize - Position) || !CapsuleTrustValid (Keys + Position, Size)) {
      return FALSE;
    }
    for (UINTN Index = Size; Index < Padded; Index++) {
      if (Keys[Position + Index] != 0) {
        return FALSE;
      }
    }
    Position += Padded;
  }
  return TRUE;
}

STATIC
EFI_STATUS
EFIAPI
VariableReady(CONST EFI_GUID *Protocol, VOID *Interface, EFI_HANDLE Handle)
{
  mVariables = Interface;
  mFloorReady = mVariables && TrustDataValid () && !EFI_ERROR (RefreshFloor ());
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
  /* No verification attempt means authorization failed, even after RefreshFloor succeeded. */
  Status = EFI_SECURITY_VIOLATION;
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
    if (!EFI_ERROR(Status) && mOwner.Active) {
      mGeneration++;
      if (!mGeneration) {
        mGeneration++;
      }
      mTransaction = mGeneration;
      return EFI_SUCCESS;
    }
    if (!EFI_ERROR (Status)) {
      Status = EFI_SECURITY_VIOLATION;
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
  CONST UINT8 *Signature;
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
    /* The MM core already owns this bounded private shadow until dispatch returns.
       Verification does not dispatch a nested MM request or retain this pointer. */
    Signature = (CONST UINT8 *)CommBuffer + sizeof (Request);
    Status = Begin (&Request, Signature);
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

STATIC
EFI_STATUS
ReadPrivateHandoff(EFI_HOB_GUID_TYPE *Hob)
{
  if (!Hob || Hob->Header.HobLength < sizeof(*Hob) ||
      GET_GUID_HOB_DATA_SIZE(Hob) < sizeof(*mInfo)) {
    return EFI_NOT_FOUND;
  }
  mInfo = GET_GUID_HOB_DATA(Hob);
  mVboot = NULL;
  mPolicy.UpdateSlot = 0;
  mPolicy.Commit = NULL;
  if (mInfo->Revision == 2 && GET_GUID_HOB_DATA_SIZE(Hob) == sizeof(*mVboot) &&
      mInfo->Size == sizeof(*mVboot)) {
    mVboot = (VOID *)mInfo;
    if (mVboot->BootSlot > 2 || !mVboot->Commit) {
      return EFI_INVALID_PARAMETER;
    }
    mPolicy.UpdateSlot = mVboot->BootSlot == 1 ? 2 : 1;
    mPolicy.Commit = Commit;
  } else if (mInfo->Revision != 1 || GET_GUID_HOB_DATA_SIZE(Hob) != sizeof(*mInfo) ||
             mInfo->Size != sizeof(*mInfo)) {
    return EFI_INVALID_PARAMETER;
  }
  if (mInfo->BlockSize != CAPSULE_BLOCK_SIZE || !mInfo->FlashSize ||
      mInfo->FlashSize % CAPSULE_BLOCK_SIZE ||
      mInfo->FlashSize / CAPSULE_BLOCK_SIZE > CAPSULE_MAX_BLOCKS ||
      !mInfo->Read || !mInfo->Resolve || !mInfo->Program ||
      !mInfo->Buffer || mInfo->BufferSize != CAPSULE_BLOCK_SIZE ||
      mInfo->BufferSize - 1 > MAX_UINT32 - mInfo->Buffer) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
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

  if (!TrustDataValid ()) {
    return EFI_SECURITY_VIOLATION;
  }
  Hob = GetFirstGuidHob(&gCorebootCapsuleInfoGuid);
  Status = ReadPrivateHandoff(Hob);
  if (EFI_ERROR(Status)) {
    return Status;
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
  mPolicy.ImageGuid = mInfo->ImageGuid;
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
