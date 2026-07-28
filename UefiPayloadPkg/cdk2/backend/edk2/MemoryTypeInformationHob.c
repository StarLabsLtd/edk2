/** @file

  Build the Memory Type Information HOB from the persisted variable store.

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "entry/Cdk2EfiEntry.h"

#include <Guid/VariableFormat.h>
#include <Guid/SmmStoreInfoGuid.h>

#define SMMSTORE_RET_SUCCESS      0
#define SMMSTORE_RET_FAILURE      1
#define SMMSTORE_RET_UNSUPPORTED  2
#define SMMSTORE_CMD_RAW_READ     5

#define PREVIOUS_MEMORY_TYPE_INFORMATION_VARIABLE_NAME  L"PreviousMemoryTypeInformation"

typedef struct {
  UINT32    BufSize;
  UINT32    BufOffset;
  UINT32    BlockId;
} SMM_STORE_PARAMS_READ;

typedef union {
  SMM_STORE_PARAMS_READ    Read;
} SMM_STORE_COM_BUF;

STATIC
BOOLEAN
MemoryTypeInformationResourceHobExists (
  VOID
  )
{
  EFI_HOB_RESOURCE_DESCRIPTOR  *ResourceHob;
  VOID                         *Hob;

  Hob = GetFirstHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  while (Hob != NULL) {
    ResourceHob = (EFI_HOB_RESOURCE_DESCRIPTOR *)Hob;
    if (CompareGuid (&ResourceHob->Owner, &gEfiMemoryTypeInformationGuid)) {
      return TRUE;
    }

    Hob = GET_NEXT_HOB (Hob);
    Hob = GetNextHob (EFI_HOB_TYPE_RESOURCE_DESCRIPTOR, Hob);
  }

  return FALSE;
}

STATIC
VOID
BuildMemoryTypeInformationResourceHob (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS         Base;
  UINT64                       Size;
  EFI_RESOURCE_ATTRIBUTE_TYPE  Attribute;

  Base = FixedPcdGet32 (PcdMemoryTypeInformationBinBase);
  Size = FixedPcdGet32 (PcdMemoryTypeInformationBinSize);

  if ((Base == 0) || (Size == 0) || MemoryTypeInformationResourceHobExists ()) {
    return;
  }

  Attribute = EFI_RESOURCE_ATTRIBUTE_PRESENT |
              EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
              EFI_RESOURCE_ATTRIBUTE_TESTED;

  BuildResourceDescriptorWithOwnerHob (
    EFI_RESOURCE_SYSTEM_MEMORY,
    Attribute,
    Base,
    Size,
    &gEfiMemoryTypeInformationGuid
    );

  DEBUG ((
    DEBUG_INFO,
    "Memory Type Information bin owner HOB: base = 0x%lx, size = 0x%lx\n",
    Base,
    Size
    ));
}

#if defined (MDE_CPU_X64)
UINTN
EFIAPI
TriggerSmi (
  IN UINTN  Cmd,
  IN UINTN  Arg,
  IN UINTN  Retry
  );

#endif

STATIC
BOOLEAN
ValidateMemoryTypeInfoVariable (
  IN EFI_MEMORY_TYPE_INFORMATION  *MemoryData,
  IN UINTN                        MemoryDataSize
  )
{
  UINTN  Count;
  UINTN  Index;

  if (MemoryData == NULL) {
    return FALSE;
  }

  Count = MemoryDataSize / sizeof (*MemoryData);
  if ((Count == 0) || (Count * sizeof (*MemoryData) != MemoryDataSize)) {
    return FALSE;
  }

  if (MemoryData[Count - 1].Type != EfiMaxMemoryType) {
    return FALSE;
  }

  for (Index = 0; Index < Count - 1; Index++) {
    if (MemoryData[Index].Type >= EfiMaxMemoryType) {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
VARIABLE_STORE_STATUS
GetVariableStoreStatus (
  IN VARIABLE_STORE_HEADER  *VariableStoreHeader
  )
{
  if ((CompareGuid (&VariableStoreHeader->Signature, &gEfiAuthenticatedVariableGuid) ||
       CompareGuid (&VariableStoreHeader->Signature, &gEfiVariableGuid)) &&
      (VariableStoreHeader->Format == VARIABLE_STORE_FORMATTED) &&
      (VariableStoreHeader->State == VARIABLE_STORE_HEALTHY))
  {
    return EfiValid;
  }

  return EfiInvalid;
}

STATIC
UINTN
GetVariableHeaderSize (
  IN BOOLEAN  Authenticated
  )
{
  return Authenticated ? sizeof (AUTHENTICATED_VARIABLE_HEADER) : sizeof (VARIABLE_HEADER);
}

STATIC
UINTN
NameSizeOfVariable (
  IN VARIABLE_HEADER  *Variable,
  IN BOOLEAN          Authenticated
  )
{
  AUTHENTICATED_VARIABLE_HEADER  *AuthenticatedVariable;

  AuthenticatedVariable = (AUTHENTICATED_VARIABLE_HEADER *)Variable;
  if (Authenticated) {
    if ((AuthenticatedVariable->State == (UINT8)-1) ||
        (AuthenticatedVariable->NameSize == MAX_UINT32) ||
        (AuthenticatedVariable->DataSize == MAX_UINT32) ||
        (AuthenticatedVariable->Attributes == MAX_UINT32))
    {
      return 0;
    }

    return AuthenticatedVariable->NameSize;
  }

  if ((Variable->State == (UINT8)-1) ||
      (Variable->NameSize == MAX_UINT32) ||
      (Variable->DataSize == MAX_UINT32) ||
      (Variable->Attributes == MAX_UINT32))
  {
    return 0;
  }

  return Variable->NameSize;
}

STATIC
UINTN
DataSizeOfVariable (
  IN VARIABLE_HEADER  *Variable,
  IN BOOLEAN          Authenticated
  )
{
  AUTHENTICATED_VARIABLE_HEADER  *AuthenticatedVariable;

  AuthenticatedVariable = (AUTHENTICATED_VARIABLE_HEADER *)Variable;
  if (Authenticated) {
    if ((AuthenticatedVariable->State == (UINT8)-1) ||
        (AuthenticatedVariable->NameSize == MAX_UINT32) ||
        (AuthenticatedVariable->DataSize == MAX_UINT32) ||
        (AuthenticatedVariable->Attributes == MAX_UINT32))
    {
      return 0;
    }

    return AuthenticatedVariable->DataSize;
  }

  if ((Variable->State == (UINT8)-1) ||
      (Variable->NameSize == MAX_UINT32) ||
      (Variable->DataSize == MAX_UINT32) ||
      (Variable->Attributes == MAX_UINT32))
  {
    return 0;
  }

  return Variable->DataSize;
}

STATIC
EFI_GUID *
GetVendorGuidPtr (
  IN VARIABLE_HEADER  *Variable,
  IN BOOLEAN          Authenticated
  )
{
  AUTHENTICATED_VARIABLE_HEADER  *AuthenticatedVariable;

  AuthenticatedVariable = (AUTHENTICATED_VARIABLE_HEADER *)Variable;
  return Authenticated ? &AuthenticatedVariable->VendorGuid : &Variable->VendorGuid;
}

STATIC
EFI_STATUS
ReadSmmStoreBytes (
  IN     UINTN  Offset,
  IN OUT UINTN  *Size,
  OUT    VOID   *Buffer
  );

STATIC
BOOLEAN
CompareSmmStoreBytes (
  IN UINTN       Offset,
  IN CONST VOID  *ExpectedBuffer,
  IN UINTN       ExpectedBufferSize
  )
{
  UINT8       ScratchBuffer[64];
  UINT8       *ExpectedByteBuffer;
  UINTN       ChunkSize;
  UINTN       ReadSize;
  EFI_STATUS  Status;

  if ((ExpectedBuffer == NULL) && (ExpectedBufferSize != 0)) {
    return FALSE;
  }

  ExpectedByteBuffer = (UINT8 *)ExpectedBuffer;
  while (ExpectedBufferSize > 0) {
    ChunkSize = MIN (ExpectedBufferSize, sizeof (ScratchBuffer));
    ReadSize  = ChunkSize;
    Status    = ReadSmmStoreBytes (Offset, &ReadSize, ScratchBuffer);
    if (EFI_ERROR (Status) || (ReadSize != ChunkSize)) {
      return FALSE;
    }

    if (CompareMem (ScratchBuffer, ExpectedByteBuffer, ChunkSize) != 0) {
      return FALSE;
    }

    Offset             += ChunkSize;
    ExpectedByteBuffer += ChunkSize;
    ExpectedBufferSize -= ChunkSize;
  }

  return TRUE;
}

STATIC
BOOLEAN
FindVariableInSmmStore (
  IN  UINTN                  VariableStoreOffset,
  IN  VARIABLE_STORE_HEADER  *VariableStoreHeader,
  IN  CHAR16                 *VariableName,
  IN  EFI_GUID               *VendorGuid,
  OUT UINTN                  *VariableDataOffset,
  OUT UINTN                  *VariableDataSize
  )
{
  AUTHENTICATED_VARIABLE_HEADER  VariableHeader;
  BOOLEAN                        Authenticated;
  UINTN                          CandidateDataOffset;
  UINTN                          CandidateDataSize;
  BOOLEAN                        FoundAdded;
  UINTN                          HeaderSize;
  UINTN                          NameOffset;
  UINTN                          NameSize;
  UINTN                          NextVariableOffset;
  UINTN                          ReadSize;
  EFI_STATUS                     Status;
  UINTN                          VariableOffset;
  UINTN                          VariableStoreEnd;

  if ((VariableStoreHeader == NULL) ||
      (VariableName == NULL) ||
      (VendorGuid == NULL) ||
      (VariableDataOffset == NULL) ||
      (VariableDataSize == NULL))
  {
    return FALSE;
  }

  if (GetVariableStoreStatus (VariableStoreHeader) != EfiValid) {
    return FALSE;
  }

  Authenticated       = CompareGuid (&VariableStoreHeader->Signature, &gEfiAuthenticatedVariableGuid);
  CandidateDataOffset = 0;
  CandidateDataSize   = 0;
  FoundAdded          = FALSE;
  HeaderSize          = GetVariableHeaderSize (Authenticated);
  NameSize            = StrSize (VariableName);
  VariableOffset      = HEADER_ALIGN (VariableStoreOffset + sizeof (*VariableStoreHeader));
  VariableStoreEnd    = HEADER_ALIGN (VariableStoreOffset + VariableStoreHeader->Size);

  while ((VariableOffset + HeaderSize) <= VariableStoreEnd) {
    ReadSize = HeaderSize;
    Status   = ReadSmmStoreBytes (VariableOffset, &ReadSize, &VariableHeader);
    if (EFI_ERROR (Status) || (ReadSize != HeaderSize) || (VariableHeader.StartId != VARIABLE_DATA)) {
      break;
    }

    if ((NameSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated) == NameSize) &&
        CompareGuid (GetVendorGuidPtr ((VARIABLE_HEADER *)&VariableHeader, Authenticated), VendorGuid))
    {
      NameOffset = VariableOffset + HeaderSize;
      if (CompareSmmStoreBytes (NameOffset, VariableName, NameSize)) {
        if (VariableHeader.State == VAR_ADDED) {
          CandidateDataOffset = NameOffset + NameSize + GET_PAD_SIZE (NameSize);
          CandidateDataSize   = DataSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated);
          FoundAdded          = TRUE;
        } else if ((VariableHeader.State == (VAR_IN_DELETED_TRANSITION & VAR_ADDED)) && !FoundAdded) {
          CandidateDataOffset = NameOffset + NameSize + GET_PAD_SIZE (NameSize);
          CandidateDataSize   = DataSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated);
        }
      }
    }

    NextVariableOffset  = VariableOffset + HeaderSize;
    NextVariableOffset += NameSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated);
    NextVariableOffset += GET_PAD_SIZE (NameSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated));
    NextVariableOffset += DataSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated);
    NextVariableOffset += GET_PAD_SIZE (DataSizeOfVariable ((VARIABLE_HEADER *)&VariableHeader, Authenticated));
    NextVariableOffset  = HEADER_ALIGN (NextVariableOffset);
    if ((NextVariableOffset <= VariableOffset) || (NextVariableOffset > VariableStoreEnd)) {
      break;
    }

    VariableOffset = NextVariableOffset;
  }

  if (CandidateDataSize == 0) {
    return FALSE;
  }

  *VariableDataOffset = CandidateDataOffset;
  *VariableDataSize   = CandidateDataSize;
  return TRUE;
}

#if defined (MDE_CPU_X64)
STATIC
EFI_STATUS
SmmStoreRawRead (
  IN CONST SMMSTORE_INFO  *SmmStoreInfo,
  IN SMM_STORE_COM_BUF    *CommandBuffer
  )
{
  UINTN  Result;
  UINTN  Command;

  Command = ((UINTN)SMMSTORE_CMD_RAW_READ << 8) | SmmStoreInfo->ApmCmd;
  Result  = TriggerSmi (Command, (UINTN)CommandBuffer, 5);
  if (Result == Command) {
    return EFI_NO_RESPONSE;
  }

  if (Result == SMMSTORE_RET_SUCCESS) {
    return EFI_SUCCESS;
  }

  if (Result == SMMSTORE_RET_UNSUPPORTED) {
    return EFI_UNSUPPORTED;
  }

  return EFI_DEVICE_ERROR;
}

STATIC
EFI_STATUS
ReadSmmStoreBytes (
  IN     UINTN  Offset,
  IN OUT UINTN  *Size,
  OUT    VOID   *Buffer
  )
{
  UINTN              Block;
  UINTN              BlockOffset;
  UINT8              *ByteBuffer;
  UINTN              ChunkSize;
  SMM_STORE_COM_BUF  CommandBuffer;
  EFI_HOB_GUID_TYPE  *GuidHob;
  UINTN              RemainingSize;
  EFI_STATUS         Status;
  SMMSTORE_INFO      *SmmStoreInfo;
  UINTN              TotalReadSize;

  if ((Size == NULL) || (Buffer == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  GuidHob = GetFirstGuidHob (&gEfiSmmStoreInfoHobGuid);
  if (GuidHob == NULL) {
    return EFI_NO_MEDIA;
  }

  SmmStoreInfo = (SMMSTORE_INFO *)GET_GUID_HOB_DATA (GuidHob);
  if ((SmmStoreInfo->BlockSize == 0) ||
      (SmmStoreInfo->NumBlocks == 0) ||
      (SmmStoreInfo->ComBufferSize == 0) ||
      (SmmStoreInfo->ComBuffer == 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  RemainingSize = *Size;
  TotalReadSize = 0;
  ByteBuffer    = (UINT8 *)Buffer;

  while (RemainingSize > 0) {
    Block       = Offset / SmmStoreInfo->BlockSize;
    BlockOffset = Offset % SmmStoreInfo->BlockSize;
    if (Block >= SmmStoreInfo->NumBlocks) {
      *Size = TotalReadSize;
      return EFI_END_OF_MEDIA;
    }

    ChunkSize = MIN (RemainingSize, (UINTN)SmmStoreInfo->BlockSize - BlockOffset);
    if (BlockOffset >= SmmStoreInfo->ComBufferSize) {
      *Size = TotalReadSize;
      return EFI_BAD_BUFFER_SIZE;
    }

    ChunkSize = MIN (ChunkSize, (UINTN)SmmStoreInfo->ComBufferSize - BlockOffset);
    ZeroMem (&CommandBuffer, sizeof (CommandBuffer));
    CommandBuffer.Read.BufSize   = (UINT32)ChunkSize;
    CommandBuffer.Read.BufOffset = (UINT32)BlockOffset;
    CommandBuffer.Read.BlockId   = (UINT32)Block;

    Status = SmmStoreRawRead (SmmStoreInfo, &CommandBuffer);
    if (EFI_ERROR (Status)) {
      *Size = TotalReadSize;
      return Status;
    }

    CopyMem (ByteBuffer, (VOID *)(UINTN)(SmmStoreInfo->ComBuffer + BlockOffset), ChunkSize);

    ByteBuffer    += ChunkSize;
    Offset        += ChunkSize;
    RemainingSize -= ChunkSize;
    TotalReadSize += ChunkSize;
  }

  *Size = TotalReadSize;
  return EFI_SUCCESS;
}

#else
STATIC
EFI_STATUS
ReadSmmStoreBytes (
  IN     UINTN  Offset,
  IN OUT UINTN  *Size,
  OUT    VOID   *Buffer
  )
{
  return EFI_UNSUPPORTED;
}

#endif

VOID
BuildMemoryTypeInformationHob (
  IN EFI_MEMORY_TYPE_INFORMATION  *DefaultMemoryTypeInformation,
  IN UINTN                        DefaultMemoryTypeInformationSize,
  IN EFI_BOOT_MODE                BootMode
  )
{
  EFI_FIRMWARE_VOLUME_HEADER   FirmwareVolumeHeader;
  EFI_MEMORY_TYPE_INFORMATION  MemoryTypeInformation[EfiMaxMemoryType + 1];
  CHAR16                       *MemoryTypeInformationVariableName;
  VARIABLE_STORE_HEADER        VariableStoreHeader;
  UINTN                        VariableDataOffset;
  UINTN                        VariableDataSize;
  UINTN                        VariableStoreOffset;
  EFI_STATUS                   Status;

  BuildMemoryTypeInformationResourceHob ();

  if (GetFirstGuidHob (&gEfiMemoryTypeInformationGuid) != NULL) {
    return;
  }

  MemoryTypeInformationVariableName = (BootMode == BOOT_ON_S4_RESUME) ?
                                      PREVIOUS_MEMORY_TYPE_INFORMATION_VARIABLE_NAME :
                                      EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME;

  VariableDataSize = sizeof (FirmwareVolumeHeader);
  Status           = ReadSmmStoreBytes (0, &VariableDataSize, &FirmwareVolumeHeader);
  if (!EFI_ERROR (Status) &&
      (FirmwareVolumeHeader.Signature == EFI_FVH_SIGNATURE) &&
      (FirmwareVolumeHeader.HeaderLength >= sizeof (EFI_FIRMWARE_VOLUME_HEADER)))
  {
    VariableStoreOffset = FirmwareVolumeHeader.HeaderLength;
    VariableDataSize    = sizeof (VariableStoreHeader);
    Status              = ReadSmmStoreBytes (
                            VariableStoreOffset,
                            &VariableDataSize,
                            &VariableStoreHeader
                            );
    if (!EFI_ERROR (Status) &&
        (GetVariableStoreStatus (&VariableStoreHeader) == EfiValid) &&
        (VariableStoreHeader.Size >= sizeof (VARIABLE_STORE_HEADER)) &&
        (VariableStoreHeader.Size <= SIZE_16MB))
    {
      if (FindVariableInSmmStore (
            VariableStoreOffset,
            &VariableStoreHeader,
            MemoryTypeInformationVariableName,
            &gEfiMemoryTypeInformationGuid,
            &VariableDataOffset,
            &VariableDataSize
            ) &&
          (VariableDataSize <= sizeof (MemoryTypeInformation)))
      {
        Status = ReadSmmStoreBytes (
                   VariableDataOffset,
                   &VariableDataSize,
                   MemoryTypeInformation
                   );
        if (!EFI_ERROR (Status) &&
            ValidateMemoryTypeInfoVariable (MemoryTypeInformation, VariableDataSize))
        {
          BuildGuidDataHob (
            &gEfiMemoryTypeInformationGuid,
            MemoryTypeInformation,
            VariableDataSize
            );
        }
      }
    }
  }

  if (GetFirstGuidHob (&gEfiMemoryTypeInformationGuid) == NULL) {
    BuildGuidDataHob (
      &gEfiMemoryTypeInformationGuid,
      DefaultMemoryTypeInformation,
      DefaultMemoryTypeInformationSize
      );
  }
}
