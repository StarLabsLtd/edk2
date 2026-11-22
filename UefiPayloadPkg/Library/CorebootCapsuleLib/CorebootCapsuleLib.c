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
STATIC BOOLEAN mClosing;

typedef enum {
  RequestNotSent,
  RequestUnconfirmed,
  RequestReplied
} CAPSULE_DELIVERY;

STATIC
EFI_STATUS
Send(VOID *Packet, UINTN PacketSize, UINTN *ResponseSize, CAPSULE_DELIVERY *Delivery OPTIONAL)
{
  EFI_MM_COMMUNICATE_HEADER *Header;
  UINTN Size;
  EFI_STATUS Status;
  COREBOOT_CAPSULE_HEADER Reply;

  if (Delivery) {
    *Delivery = RequestNotSent;
  }
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
  if (Delivery) {
    *Delivery = RequestUnconfirmed;
  }
  Status = mCommunication->Communicate(mCommunication, Header, Header, &Size);
  if (!EFI_ERROR(Status)) {
    if (Size < OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data) ||
        !CompareGuid(&Header->HeaderGuid, &gCorebootCapsuleUpdateGuid) ||
        Header->MessageLength < sizeof(Reply) ||
        Header->MessageLength > PacketSize ||
        Header->MessageLength > Size - OFFSET_OF(EFI_MM_COMMUNICATE_HEADER, Data)) {
      Status = EFI_DEVICE_ERROR;
    } else {
      CopyMem(&Reply, Header->Data, sizeof(Reply));
      if (Reply.Revision != COREBOOT_CAPSULE_REVISION ||
          Reply.Command != ((COREBOOT_CAPSULE_HEADER *)Packet)->Command ||
          (Reply.Command != COREBOOT_CAPSULE_BEGIN &&
           Reply.Transaction != ((COREBOOT_CAPSULE_HEADER *)Packet)->Transaction)) {
        Status = EFI_DEVICE_ERROR;
      } else {
        CopyMem(Packet, Header->Data, Header->MessageLength);
        *ResponseSize = Header->MessageLength;
        if (Delivery) {
          *Delivery = RequestReplied;
        }
        Status = (Reply.Result & BIT31) ? EFIERR(Reply.Result & ~BIT31) : Reply.Result;
      }
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
    Status = Send(&Request, sizeof(Request), &Size, NULL);
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

STATIC
VOID
ReleaseSource(VOID)
{
  if (mSourcePages) {
    gBS->FreePages(mSource, mSourcePages);
  }
  mSource = 0;
  mSourcePages = 0;
  mTransaction = 0;
  mClosing = FALSE;
}

VOID
CorebootCapsuleClose(VOID)
{
  COREBOOT_CAPSULE_HEADER Request;
  UINTN Size;
  EFI_STATUS Status;
  CAPSULE_DELIVERY Delivery;

  if (!mSourcePages) {
    return;
  }
  mClosing = TRUE;
  /* A lost BEGIN token cannot be cancelled safely. Keep this allocation
     until MM closes boot access at ExitBootServices or the machine resets. */
  if (!mTransaction) {
    return;
  }
  Request = (COREBOOT_CAPSULE_HEADER) {
    COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_CLOSE, mTransaction, 0
  };
  Status = Send(&Request, sizeof(Request), &Size, &Delivery);
  /* An owner denial confirms that this token is no longer active. A
     transport denial does not prove that the request reached the owner. */
  if (Delivery == RequestReplied && (Status == EFI_SUCCESS || Status == EFI_ACCESS_DENIED)) {
    ReleaseSource();
  }
}

/* Choose low RAM without depending on the order of the firmware memory map.
   The protected owner independently checks its permitted source range. */
STATIC
EFI_STATUS
FindSourceAddress(CONST VOID *Map, UINTN Size, UINTN Stride, UINTN Pages,
                  EFI_PHYSICAL_ADDRESS Minimum, EFI_PHYSICAL_ADDRESS *Address)
{
  EFI_MEMORY_DESCRIPTOR Descriptor;
  UINT64 Start, End, Bytes;
  UINTN Offset;

  if (Stride < sizeof(Descriptor) || Size % Stride ||
      !Pages || Pages > (BASE_4GB - SIZE_1MB) / EFI_PAGE_SIZE) {
    return EFI_INVALID_PARAMETER;
  }
  Bytes = (UINT64)Pages * EFI_PAGE_SIZE;
  *Address = BASE_4GB;
  for (Offset = 0; Offset < Size; Offset += Stride) {
    CopyMem(&Descriptor, (CONST UINT8 *)Map + Offset, sizeof(Descriptor));
    if (Descriptor.Type != EfiConventionalMemory) {
      continue;
    }
    Start = Descriptor.PhysicalStart;
    if (!Descriptor.NumberOfPages) {
      continue;
    }
    if (Start % EFI_PAGE_SIZE || Descriptor.NumberOfPages - 1 >
        (MAX_UINT64 - Start) / EFI_PAGE_SIZE) {
      return EFI_DEVICE_ERROR;
    }
    if (Start >= BASE_4GB) {
      continue;
    }
    End = Start + MIN(Descriptor.NumberOfPages,
                      (BASE_4GB - Start) / EFI_PAGE_SIZE) * EFI_PAGE_SIZE;
    Start = MAX(Start, SIZE_1MB);
    if (Start < Minimum) {
      continue;
    }
    if (Start < End && Bytes <= End - Start && Start < *Address) {
      *Address = Start;
    }
  }
  return *Address < BASE_4GB ? EFI_SUCCESS : EFI_OUT_OF_RESOURCES;
}

STATIC
EFI_STATUS
AllocateSourcePages(UINTN Pages, EFI_PHYSICAL_ADDRESS *Address)
{
  EFI_MEMORY_DESCRIPTOR *Map;
  UINTN Size, Capacity, Key, Stride, Attempt, Required = 0;
  EFI_PHYSICAL_ADDRESS Minimum = SIZE_1MB, Rejected = BASE_4GB, Candidate;
  UINT32 Version;
  EFI_STATUS Status;

  /* Pool allocation can grow the map; AllocateAddress can race another user.
     Retry from a fresh map rather than falling back to high RAM. */
  for (Attempt = 0; Attempt < 8; Attempt++) {
    Size = 0;
    Status = gBS->GetMemoryMap(&Size, NULL, &Key, &Stride, &Version);
    Size = MAX(Size, Required);
    if (Status != EFI_BUFFER_TOO_SMALL || Stride < sizeof(*Map) ||
        Stride > MAX_UINTN / 2 || Size > MAX_UINTN - 2 * Stride) {
      return EFI_DEVICE_ERROR;
    }
    Capacity = Size + 2 * Stride;
    Map = AllocatePool(Capacity);
    if (!Map) {
      return EFI_OUT_OF_RESOURCES;
    }
    Size = Capacity;
    Status = gBS->GetMemoryMap(&Size, Map, &Key, &Stride, &Version);
    if (Status == EFI_BUFFER_TOO_SMALL) {
      Required = MAX(Required, Size);
    } else if (!EFI_ERROR(Status)) {
      if (Size > Capacity || Version != EFI_MEMORY_DESCRIPTOR_VERSION) {
        Status = EFI_DEVICE_ERROR;
      } else {
        Status = FindSourceAddress(Map, Size, Stride, Pages, Minimum, Address);
        if (!EFI_ERROR(Status)) {
          Candidate = *Address;
          Status = gBS->AllocatePages(AllocateAddress, EfiBootServicesData, Pages, &Candidate);
          if (Status == EFI_NOT_FOUND || Status == EFI_OUT_OF_RESOURCES) {
            /* Retry a raced range once, then try the next reported extent. */
            if (*Address == Rejected) {
              Minimum = *Address + EFI_PAGE_SIZE;
            }
            Rejected = *Address;
          }
        }
      }
    }
    FreePool(Map);
    if (Status != EFI_BUFFER_TOO_SMALL && Status != EFI_NOT_FOUND &&
        Status != EFI_OUT_OF_RESOURCES) {
      return Status;
    }
  }
  return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS
CorebootCapsuleAuthenticate(EFI_FIRMWARE_IMAGE_AUTHENTICATION *Image, UINTN Size)
{
  EFI_FIRMWARE_IMAGE_AUTHENTICATION Authentication;
  COREBOOT_CAPSULE_START *Request;
  UINTN PayloadOffset, PayloadSize, SignedSize, SignatureSize, ResponseSize;
  UINT32 FlashSize, BlockSize, ImageOffset;
  EFI_PHYSICAL_ADDRESS Address;
  EFI_STATUS Status;
  CAPSULE_DELIVERY Delivery;

  CorebootCapsuleClose();
  if (mSourcePages) {
    return EFI_NOT_READY;
  }
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
  Status = AllocateSourcePages(EFI_SIZE_TO_PAGES(SignedSize), &Address);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  mSource = Address;
  mSourcePages = EFI_SIZE_TO_PAGES(SignedSize);
  mClosing = TRUE;
  CopyMem((VOID *)(UINTN)mSource, (UINT8 *)Image + PayloadOffset, PayloadSize);
  CopyMem((UINT8 *)(UINTN)mSource + PayloadSize, &Authentication.MonotonicCount, sizeof(UINT64));
  Request = AllocateZeroPool(sizeof(*Request) + SignatureSize);
  if (!Request) {
    ReleaseSource();
    return EFI_OUT_OF_RESOURCES;
  }
  Request->Header.Revision = COREBOOT_CAPSULE_REVISION;
  Request->Header.Command = COREBOOT_CAPSULE_BEGIN;
  Request->Address = mSource;
  Request->SignedSize = (UINT32)SignedSize;
  ImageOffset = ReadUnaligned32((CONST UINT32 *)((CONST UINT8 *)(UINTN)mSource + 4));
  Request->ImageOffset = ImageOffset;
  Request->SignatureSize = (UINT32)SignatureSize;
  CopyMem(Request->Signature, Image->AuthInfo.CertData, SignatureSize);
  Status = Send(Request, sizeof(*Request) + SignatureSize, &ResponseSize, &Delivery);
  if (Delivery == RequestReplied &&
      (ResponseSize != sizeof(*Request) || Request->Address != mSource ||
       Request->SignedSize != SignedSize || Request->ImageOffset != ImageOffset ||
       Request->SignatureSize != SignatureSize ||
       (EFI_ERROR(Status) ? Request->Header.Transaction != 0 : Request->Header.Transaction == 0))) {
    Delivery = RequestUnconfirmed;
    Status = EFI_DEVICE_ERROR;
  }
  if (!EFI_ERROR(Status)) {
    mTransaction = Request->Header.Transaction;
    mClosing = FALSE;
  }
  if (Delivery == RequestNotSent ||
      (Delivery == RequestReplied && (Request->Header.Result & BIT31))) {
    ReleaseSource();
  }
  FreePool(Request);
  return Status;
}

STATIC
EFI_STATUS
ProgramBlock(EFI_LBA Block)
{
  COREBOOT_CAPSULE_BLOCK Request;
  UINTN Size;

  if (mClosing || !mTransaction || !mBlockSize || Block >= mFlashSize / mBlockSize) {
    return EFI_ACCESS_DENIED;
  }
  Request.Header = (COREBOOT_CAPSULE_HEADER) {
    COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_PROGRAM, mTransaction, 0
  };
  Request.Block = (UINT32)Block;
  return Send(&Request, sizeof(Request), &Size, NULL);
}

/* The protected owner merges and verifies the complete plan once per block.
   Do not run the legacy per-region buffer verifier against that union. */
EFI_STATUS
CorebootCapsuleApply(EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS Progress OPTIONAL)
{
  UINT32 Flash, BlockSize;
  UINTN Block;
  EFI_STATUS Status;

  if (mClosing || !mTransaction) {
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
  if (!EFI_ERROR(Status) && mSourcePages) {
    return EFI_DEVICE_ERROR;
  }
  return Status;
}

BOOLEAN CorebootCapsuleIsProtected(VOID) { return TRUE; }
