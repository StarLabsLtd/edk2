/** @file
  Keep capsule source storage alive while the protected owner uses it.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <PiDxe.h>
#include <Guid/CorebootCapsule.h>
#include <Guid/WinCertificate.h>
#include <Guid/ImageAuthentication.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CorebootCapsuleLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MmCommunication2.h>

STATIC EFI_MM_COMMUNICATION2_PROTOCOL *mCommunication;
STATIC EFI_PHYSICAL_ADDRESS mSource;
STATIC UINTN mSourcePages;
STATIC UINT32 mTransaction;
STATIC UINT32 mFlashSize;
STATIC UINT32 mBlockSize;

STATIC
EFI_STATUS
Send(VOID *Packet, UINTN PacketSize, UINTN *ResponseSize)
{
  EFI_MM_COMMUNICATE_HEADER *Header;
  UINTN Size;
  EFI_STATUS Status;

  if (PacketSize > COREBOOT_CAPSULE_MAX_SIGNATURE + sizeof(COREBOOT_CAPSULE_START)) {
    return EFI_BAD_BUFFER_SIZE;
  }
  if (!mCommunication) {
    Status = gBS->LocateProtocol(&gEfiMmCommunication2ProtocolGuid, NULL,
                                 (VOID **)&mCommunication);
    if (EFI_ERROR(Status)) {
      return Status;
    }
  }
  Size = OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data) + PacketSize;
  Header = AllocateZeroPool(Size);
  if (!Header) {
    return EFI_OUT_OF_RESOURCES;
  }
  Header->HeaderGuid = gCorebootCapsuleUpdateGuid;
  Header->MessageLength = PacketSize;
  CopyMem(Header->Data, Packet, PacketSize);
  Status = mCommunication->Communicate(mCommunication, Header, Header, &Size);
  if (!EFI_ERROR(Status)) {
    if (Size < OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data) ||
        !CompareGuid(&Header->HeaderGuid, &gCorebootCapsuleUpdateGuid) ||
        Header->MessageLength > PacketSize ||
        Header->MessageLength > Size - OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data)) {
      Status = EFI_DEVICE_ERROR;
    } else {
      CopyMem(Packet, Header->Data, Header->MessageLength);
      *ResponseSize = Header->MessageLength;
    }
  }
  FreePool(Header);
  return Status;
}

EFI_STATUS
CorebootCapsuleGeometry(UINT32 *FlashSize, UINT32 *BlockSize)
{
  COREBOOT_CAPSULE_GEOMETRY Request;
  UINTN Size;
  EFI_STATUS Status;

  if (!mFlashSize) {
    ZeroMem(&Request, sizeof(Request));
    Request.Header.Revision = COREBOOT_CAPSULE_REVISION;
    Request.Header.Command = COREBOOT_CAPSULE_INFO;
    Status = Send(&Request, sizeof(Request), &Size);
    if (EFI_ERROR(Status)) {
      return Status;
    }
    if (Size != sizeof(Request) || Request.BlockSize != 65536 || !Request.FlashSize ||
        Request.FlashSize % Request.BlockSize || Request.FlashSize / Request.BlockSize > 512) {
      return EFI_DEVICE_ERROR;
    }
    mFlashSize = Request.FlashSize;
    mBlockSize = Request.BlockSize;
  }
  *FlashSize = mFlashSize;
  *BlockSize = mBlockSize;
  return EFI_SUCCESS;
}

VOID
CorebootCapsuleClose(VOID)
{
  COREBOOT_CAPSULE_HEADER Request;
  UINTN Size;

  if (mTransaction) {
    Request = (COREBOOT_CAPSULE_HEADER) {
      COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_CLOSE, mTransaction
    };
    Send(&Request, sizeof(Request), &Size);
    mTransaction = 0;
  }
  if (mSourcePages) {
    gBS->FreePages(mSource, mSourcePages);
    mSource = 0;
    mSourcePages = 0;
  }
}

EFI_STATUS
CorebootCapsuleAuthenticate(EFI_FIRMWARE_IMAGE_AUTHENTICATION *Image, UINTN Size)
{
  EFI_FIRMWARE_IMAGE_AUTHENTICATION Authentication;
  COREBOOT_CAPSULE_START *Request;
  UINTN PayloadOffset, PayloadSize, SignedSize, SignatureSize, ResponseSize;
  UINT32 FlashSize, BlockSize;
  EFI_PHYSICAL_ADDRESS Address;
  EFI_STATUS Status;

  CorebootCapsuleClose();
  if (!Image || Size < sizeof(Authentication)) {
    return EFI_INVALID_PARAMETER;
  }
  CopyMem(&Authentication, Image, sizeof(Authentication));
  if (Authentication.AuthInfo.Hdr.dwLength <= OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData) ||
      Authentication.AuthInfo.Hdr.dwLength > Size - sizeof(UINT64) ||
      Authentication.AuthInfo.Hdr.wRevision != 0x0200 ||
      Authentication.AuthInfo.Hdr.wCertificateType != WIN_CERT_TYPE_EFI_GUID ||
      !CompareGuid(&Authentication.AuthInfo.CertType, &gEfiCertPkcs7Guid)) {
    return EFI_SECURITY_VIOLATION;
  }
  Status = CorebootCapsuleGeometry(&FlashSize, &BlockSize);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  PayloadOffset = sizeof(UINT64) + Authentication.AuthInfo.Hdr.dwLength;
  PayloadSize = Size - PayloadOffset;
  if (PayloadSize < FlashSize + 16 || PayloadSize - FlashSize > 65536 - sizeof(UINT64)) {
    return EFI_BAD_BUFFER_SIZE;
  }
  SignatureSize = Authentication.AuthInfo.Hdr.dwLength - OFFSET_OF(WIN_CERTIFICATE_UEFI_GUID, CertData);
  if (SignatureSize > COREBOOT_CAPSULE_MAX_SIGNATURE) {
    return EFI_BAD_BUFFER_SIZE;
  }
  SignedSize = PayloadSize + sizeof(UINT64);
  Address = MAX_UINT32;
  Status = gBS->AllocatePages(AllocateMaxAddress, EfiBootServicesData,
                              EFI_SIZE_TO_PAGES(SignedSize), &Address);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  mSource = Address;
  mSourcePages = EFI_SIZE_TO_PAGES(SignedSize);
  CopyMem((VOID *)(UINTN)mSource, (UINT8 *)Image + PayloadOffset, PayloadSize);
  CopyMem((UINT8 *)(UINTN)mSource + PayloadSize, &Authentication.MonotonicCount, sizeof(UINT64));
  Request = AllocateZeroPool(sizeof(*Request) + SignatureSize);
  if (!Request) {
    CorebootCapsuleClose();
    return EFI_OUT_OF_RESOURCES;
  }
  Request->Header.Revision = COREBOOT_CAPSULE_REVISION;
  Request->Header.Command = COREBOOT_CAPSULE_BEGIN;
  Request->Address = mSource;
  Request->SignedSize = (UINT32)SignedSize;
  Request->ImageOffset = ReadUnaligned32((CONST UINT32 *)((CONST UINT8 *)(UINTN)mSource + 4));
  Request->SignatureSize = (UINT32)SignatureSize;
  CopyMem(Request->Signature, Image->AuthInfo.CertData, SignatureSize);
  Status = Send(Request, sizeof(*Request) + SignatureSize, &ResponseSize);
  if (!EFI_ERROR(Status)) {
    if (ResponseSize != sizeof(*Request) || !Request->Header.Transaction) {
      Status = EFI_DEVICE_ERROR;
    } else {
      mTransaction = Request->Header.Transaction;
    }
  }
  FreePool(Request);
  if (EFI_ERROR(Status)) {
    CorebootCapsuleClose();
  }
  return Status;
}

STATIC
EFI_STATUS
ProgramBlock(EFI_LBA Block)
{
  COREBOOT_CAPSULE_BLOCK Request;
  UINTN Size;

  if (!mTransaction || !mBlockSize || Block >= mFlashSize / mBlockSize) {
    return EFI_ACCESS_DENIED;
  }
  Request.Header = (COREBOOT_CAPSULE_HEADER) {
    COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_PROGRAM, mTransaction
  };
  Request.Block = (UINT32)Block;
  return Send(&Request, sizeof(Request), &Size);
}

/* The protected owner merges and verifies the complete plan once per block.
   Do not run the legacy per-region buffer verifier against that union. */
EFI_STATUS
CorebootCapsuleApply(EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS Progress OPTIONAL)
{
  UINT32 Flash, BlockSize;
  UINTN Block;
  EFI_STATUS Status;

  if (!mTransaction) {
    return EFI_ACCESS_DENIED;
  }
  Status = CorebootCapsuleGeometry(&Flash, &BlockSize);
  if (EFI_ERROR(Status)) {
    goto Done;
  }
  for (Block = 0; Block < Flash / BlockSize; Block++) {
    Status = ProgramBlock(Block);
    if (EFI_ERROR(Status)) {
      goto Done;
    }
    if (Progress) {
      Status = Progress((Block + 1) * 100 / (Flash / BlockSize));
      if (EFI_ERROR(Status)) {
        /* A failed display callback must not interrupt a firmware update. */
        Progress = NULL;
      }
    }
  }
  Status = EFI_SUCCESS;
Done:
  CorebootCapsuleClose();
  return Status;
}

BOOLEAN CorebootCapsuleIsProtected(VOID) { return TRUE; }
