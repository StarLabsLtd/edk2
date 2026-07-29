/** @file

  Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "entry/Cdk2EfiEntry.h"

typedef struct {
  EFI_PHYSICAL_ADDRESS   EndOfHobList;
  EFI_PHYSICAL_ADDRESS   FreeMemoryBottom;
  EFI_PHYSICAL_ADDRESS   FreeMemoryTop;
  EFI_HOB_GENERIC_HEADER EndMarker;
} CDK2_EFI_HOB_APPEND_STATE;

STATIC
EFI_STATUS
Cdk2EfiSaveHobAppendState (
  OUT CDK2_EFI_HOB_APPEND_STATE  *State
  )
{
  EFI_HOB_GENERIC_HEADER      *End;
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;

  if (State == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)GetHobList ();
  if (Handoff == NULL ||
      Handoff->Header.HobType != EFI_HOB_TYPE_HANDOFF ||
      Handoff->Header.HobLength != sizeof (*Handoff) ||
      Handoff->EfiEndOfHobList == 0 ||
      Handoff->EfiEndOfHobList > (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - sizeof (*End)))
  {
    return EFI_COMPROMISED_DATA;
  }

  End = (EFI_HOB_GENERIC_HEADER *)(UINTN)Handoff->EfiEndOfHobList;
  if (End->HobType != EFI_HOB_TYPE_END_OF_HOB_LIST ||
      End->HobLength != sizeof (*End))
  {
    return EFI_COMPROMISED_DATA;
  }

  State->EndOfHobList     = Handoff->EfiEndOfHobList;
  State->FreeMemoryBottom = Handoff->EfiFreeMemoryBottom;
  State->FreeMemoryTop    = Handoff->EfiFreeMemoryTop;
  State->EndMarker        = *End;
  return EFI_SUCCESS;
}

STATIC
VOID
Cdk2EfiRestoreHobAppendState (
  IN CONST CDK2_EFI_HOB_APPEND_STATE  *State
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;

  if (State == NULL || State->EndOfHobList == 0) {
    return;
  }

  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)GetHobList ();
  if (Handoff == NULL) {
    return;
  }

  Handoff->EfiEndOfHobList     = State->EndOfHobList;
  Handoff->EfiFreeMemoryBottom = State->FreeMemoryBottom;
  Handoff->EfiFreeMemoryTop    = State->FreeMemoryTop;
  *(EFI_HOB_GENERIC_HEADER *)(UINTN)State->EndOfHobList = State->EndMarker;
}

STATIC
EFI_STATUS
Cdk2EfiRequireHobAppended (
  IN EFI_PHYSICAL_ADDRESS  PreviousEndOfHobList
  )
{
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;

  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)GetHobList ();
  if (Handoff == NULL || Handoff->EfiEndOfHobList == PreviousEndOfHobList) {
    return EFI_OUT_OF_RESOURCES;
  }

  return EFI_SUCCESS;
}

/**
  Allocate pages for code.

  @param[in] Pages      Number of pages to be allocated.

  @return Allocated memory.
**/
VOID *
AllocateCodePages (
  IN  UINTN  Pages
  )
{
  VOID                  *Alloc;
  EFI_PEI_HOB_POINTERS  Hob;

  Alloc = AllocatePages (Pages);
  if (Alloc == NULL) {
    return NULL;
  }

  // find the HOB we just created, and change the type to EfiBootServicesCode
  Hob.Raw = GetFirstHob (EFI_HOB_TYPE_MEMORY_ALLOCATION);
  while (Hob.Raw != NULL) {
    if (Hob.MemoryAllocation->AllocDescriptor.MemoryBaseAddress == (UINTN)Alloc) {
      Hob.MemoryAllocation->AllocDescriptor.MemoryType = EfiBootServicesCode;
      return Alloc;
    }

    Hob.Raw = GetNextHob (EFI_HOB_TYPE_MEMORY_ALLOCATION, GET_NEXT_HOB (Hob));
  }

  ASSERT (FALSE);

  FreePages (Alloc, Pages);
  return NULL;
}

/**
    Loads and relocates a PE/COFF image

  @param[in]  PeCoffImage     Point to a Pe/Coff image.
  @param[out]  ImageAddress   The image memory address after relocation.
  @param[out]  ImageSize      The image size.
  @param[out]  EntryPoint     The image entry point.

  @return EFI_SUCCESS    If the image is loaded and relocated successfully.
  @return Others         If the image failed to load or relocate.
**/
EFI_STATUS
LoadPeCoffImage (
  IN  VOID                  *PeCoffImage,
  OUT EFI_PHYSICAL_ADDRESS  *ImageAddress,
  OUT UINT64                *ImageSize,
  OUT EFI_PHYSICAL_ADDRESS  *EntryPoint
  )
{
  RETURN_STATUS                 Status;
  PE_COFF_LOADER_IMAGE_CONTEXT  ImageContext;
  VOID                          *Buffer;

  ZeroMem (&ImageContext, sizeof (ImageContext));

  ImageContext.Handle    = PeCoffImage;
  ImageContext.ImageRead = PeCoffLoaderImageReadFromMemory;

  Status = PeCoffLoaderGetImageInfo (&ImageContext);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  //
  // Allocate Memory for the image
  //
  Buffer = AllocateCodePages (EFI_SIZE_TO_PAGES ((UINT32)ImageContext.ImageSize));
  if (Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ImageContext.ImageAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)Buffer;

  //
  // Load the image to our new buffer
  //
  Status = PeCoffLoaderLoadImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  //
  // Relocate the image in our new buffer
  //
  Status = PeCoffLoaderRelocateImage (&ImageContext);
  if (EFI_ERROR (Status)) {
    ASSERT_EFI_ERROR (Status);
    return Status;
  }

  *ImageAddress = ImageContext.ImageAddress;
  *ImageSize    = ImageContext.ImageSize;
  *EntryPoint   = ImageContext.EntryPoint;

  return EFI_SUCCESS;
}

/**
  This function searchs a given file type with a given Guid within a valid FV.
  If input Guid is NULL, will locate the first section having the given file type

  @param FvHeader        A pointer to firmware volume header that contains the set of files
                         to be searched.
  @param FileType        File type to be searched.
  @param Guid            Will ignore if it is NULL.
  @param FileHeader      A pointer to the discovered file, if successful.

  @retval EFI_SUCCESS    Successfully found FileType
  @retval EFI_NOT_FOUND  File type can't be found.
**/
EFI_STATUS
FvFindFileByTypeGuid (
  IN  EFI_FIRMWARE_VOLUME_HEADER  *FvHeader,
  IN  EFI_FV_FILETYPE             FileType,
  IN  EFI_GUID                    *Guid           OPTIONAL,
  OUT EFI_FFS_FILE_HEADER         **FileHeader
  )
{
  EFI_PHYSICAL_ADDRESS  CurrentAddress;
  EFI_PHYSICAL_ADDRESS  EndOfFirmwareVolume;
  EFI_FFS_FILE_HEADER   *File;
  UINT32                Size;
  EFI_PHYSICAL_ADDRESS  EndOfFile;

  CurrentAddress      = (EFI_PHYSICAL_ADDRESS)(UINTN)FvHeader;
  EndOfFirmwareVolume = CurrentAddress + FvHeader->FvLength;

  //
  // Loop through the FFS files
  //
  for (EndOfFile = CurrentAddress + FvHeader->HeaderLength; ; ) {
    CurrentAddress = (EndOfFile + 7) & 0xfffffffffffffff8ULL;
    if (CurrentAddress > EndOfFirmwareVolume) {
      break;
    }

    File = (EFI_FFS_FILE_HEADER *)(UINTN)CurrentAddress;
    if (IS_FFS_FILE2 (File)) {
      Size = FFS_FILE2_SIZE (File);
      if (Size <= 0x00FFFFFF) {
        break;
      }
    } else {
      Size = FFS_FILE_SIZE (File);
      if (Size < sizeof (EFI_FFS_FILE_HEADER)) {
        break;
      }
    }

    EndOfFile = CurrentAddress + Size;
    if (EndOfFile > EndOfFirmwareVolume) {
      break;
    }

    //
    // Look for file type
    //
    if (File->Type == FileType) {
      if ((Guid == NULL) || CompareGuid (&File->Name, Guid)) {
        *FileHeader = File;
        return EFI_SUCCESS;
      }
    }
  }

  return EFI_NOT_FOUND;
}

/**
  This function searchs a given section type within a valid FFS file.

  @param  FileHeader            A pointer to the file header that contains the set of sections to
                                be searched.
  @param  SectionType            The value of the section type to search.
  @param  SectionData           A pointer to the discovered section, if successful.

  @retval EFI_SUCCESS           The section was found.
  @retval EFI_NOT_FOUND         The section was not found.

**/
EFI_STATUS
FileFindSection (
  IN EFI_FFS_FILE_HEADER  *FileHeader,
  IN EFI_SECTION_TYPE     SectionType,
  OUT VOID                **SectionData
  )
{
  UINT32                     FileSize;
  EFI_COMMON_SECTION_HEADER  *Section;
  UINT32                     SectionSize;
  UINT32                     Index;

  if (IS_FFS_FILE2 (FileHeader)) {
    FileSize = FFS_FILE2_SIZE (FileHeader);
    Section  = (EFI_COMMON_SECTION_HEADER *)(((EFI_FFS_FILE_HEADER2 *)FileHeader) + 1);
  } else {
    FileSize = FFS_FILE_SIZE (FileHeader);
    Section  = (EFI_COMMON_SECTION_HEADER *)(FileHeader + 1);
  }

  FileSize -= sizeof (EFI_FFS_FILE_HEADER);

  Index = 0;
  while (Index < FileSize) {
    if (Section->Type == SectionType) {
      if (IS_SECTION2 (Section)) {
        *SectionData = (VOID *)((UINT8 *)Section + sizeof (EFI_COMMON_SECTION_HEADER2));
      } else {
        *SectionData = (VOID *)((UINT8 *)Section + sizeof (EFI_COMMON_SECTION_HEADER));
      }

      return EFI_SUCCESS;
    }

    if (IS_SECTION2 (Section)) {
      SectionSize = SECTION2_SIZE (Section);
    } else {
      SectionSize = SECTION_SIZE (Section);
    }

    SectionSize = GET_OCCUPIED_SIZE (SectionSize, 4);
    ASSERT (SectionSize != 0);
    Index += SectionSize;

    Section = (EFI_COMMON_SECTION_HEADER *)((UINT8 *)Section + SectionSize);
  }

  return EFI_NOT_FOUND;
}

/**
  Find DXE core from FV and build DXE core HOBs.

  @param[out]  DxeCoreEntryPoint     DXE core entry point

  @retval EFI_SUCCESS        If it completed successfully.
  @retval EFI_NOT_FOUND      If it failed to load DXE FV.
**/
EFI_STATUS
LoadDxeCore (
  OUT PHYSICAL_ADDRESS  *DxeCoreEntryPoint,
  OUT PHYSICAL_ADDRESS  *DxeCoreImageBase,
  OUT UINTN             *DxeCoreImageSize
  )
{
  CDK2_EFI_HOB_APPEND_STATE   AppendState;
  EFI_STATUS                  Status;
  EFI_FIRMWARE_VOLUME_HEADER  *PayloadFv;
  EFI_FIRMWARE_VOLUME_HEADER  *DxeCoreFv;
  EFI_FFS_FILE_HEADER         *FileHeader;
  VOID                        *PeCoffImage;
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_PHYSICAL_ADDRESS        ImageAddress;
  EFI_PHYSICAL_ADDRESS        PreviousEndOfHobList;
  UINT64                      ImageSize;

  if (DxeCoreEntryPoint == NULL || DxeCoreImageBase == NULL || DxeCoreImageSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *DxeCoreEntryPoint = 0;
  *DxeCoreImageBase  = 0;
  *DxeCoreImageSize  = 0;

  PayloadFv = (EFI_FIRMWARE_VOLUME_HEADER *)(UINTN)PcdGet32 (PcdPayloadFdMemBase);

#if defined (CDK2_FLAT_DXE_FV)
  //
  // cdk2 places the retained DXE files directly in the payload FV.
  //
  DxeCoreFv = PayloadFv;
#else
  //
  // DXE FV is inside Payload FV. Here find DXE FV from Payload FV
  //
  Status = FvFindFileByTypeGuid (PayloadFv, EFI_FV_FILETYPE_FIRMWARE_VOLUME_IMAGE, NULL, &FileHeader);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FileFindSection (FileHeader, EFI_SECTION_FIRMWARE_VOLUME_IMAGE, (VOID **)&DxeCoreFv);
  if (EFI_ERROR (Status)) {
    return Status;
  }
#endif

  //
  // Report DXE FV to DXE core
  //
  Status = Cdk2EfiSaveHobAppendState (&AppendState);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handoff             = (EFI_HOB_HANDOFF_INFO_TABLE *)GetHobList ();
  PreviousEndOfHobList = Handoff->EfiEndOfHobList;
  BuildFvHob ((EFI_PHYSICAL_ADDRESS)(UINTN)DxeCoreFv, DxeCoreFv->FvLength);
  Status = Cdk2EfiRequireHobAppended (PreviousEndOfHobList);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // Find DXE core file from DXE FV
  //
  Status = FvFindFileByTypeGuid (DxeCoreFv, EFI_FV_FILETYPE_DXE_CORE, NULL, &FileHeader);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  Status = FileFindSection (FileHeader, EFI_SECTION_PE32, (VOID **)&PeCoffImage);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  //
  // Get DXE core info
  //
  Status = LoadPeCoffImage (PeCoffImage, &ImageAddress, &ImageSize, DxeCoreEntryPoint);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  *DxeCoreImageBase = ImageAddress;
  *DxeCoreImageSize = (UINTN)ImageSize;

  PreviousEndOfHobList = Handoff->EfiEndOfHobList;
  BuildModuleHob (&FileHeader->Name, ImageAddress, EFI_SIZE_TO_PAGES ((UINT32)ImageSize) * EFI_PAGE_SIZE, *DxeCoreEntryPoint);
  Status = Cdk2EfiRequireHobAppended (PreviousEndOfHobList);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  return EFI_SUCCESS;

Failed:
  Cdk2EfiRestoreHobAppendState (&AppendState);
  *DxeCoreEntryPoint = 0;
  *DxeCoreImageBase  = 0;
  *DxeCoreImageSize  = 0;
  return Status;
}

/**
  Find DXE core from FV and build DXE core HOBs.

  @param[in]   DxeFv                 The FV where to find the DXE core.
  @param[out]  DxeCoreEntryPoint     DXE core entry point

  @retval EFI_SUCCESS        If it completed successfully.
  @retval EFI_NOT_FOUND      If it failed to load DXE FV.
**/
EFI_STATUS
UniversalLoadDxeCore (
  IN  EFI_FIRMWARE_VOLUME_HEADER  *DxeFv,
  OUT PHYSICAL_ADDRESS            *DxeCoreEntryPoint
  )
{
  CDK2_EFI_HOB_APPEND_STATE  AppendState;
  EFI_STATUS                 Status;
  EFI_FFS_FILE_HEADER        *FileHeader;
  VOID                       *PeCoffImage;
  EFI_HOB_HANDOFF_INFO_TABLE  *Handoff;
  EFI_PHYSICAL_ADDRESS       ImageAddress;
  EFI_PHYSICAL_ADDRESS       PreviousEndOfHobList;
  UINT64                     ImageSize;

  if (DxeFv == NULL || DxeCoreEntryPoint == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *DxeCoreEntryPoint = 0;

  //
  // Find DXE core file from DXE FV
  //
  Status = FvFindFileByTypeGuid (DxeFv, EFI_FV_FILETYPE_DXE_CORE, NULL, &FileHeader);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FileFindSection (FileHeader, EFI_SECTION_PE32, (VOID **)&PeCoffImage);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = Cdk2EfiSaveHobAppendState (&AppendState);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)GetHobList ();

  //
  // Get DXE core info
  //
  Status = LoadPeCoffImage (PeCoffImage, &ImageAddress, &ImageSize, DxeCoreEntryPoint);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  PreviousEndOfHobList = Handoff->EfiEndOfHobList;
  BuildModuleHob (&FileHeader->Name, ImageAddress, EFI_SIZE_TO_PAGES ((UINT32)ImageSize) * EFI_PAGE_SIZE, *DxeCoreEntryPoint);
  Status = Cdk2EfiRequireHobAppended (PreviousEndOfHobList);
  if (EFI_ERROR (Status)) {
    goto Failed;
  }

  return EFI_SUCCESS;

Failed:
  Cdk2EfiRestoreHobAppendState (&AppendState);
  *DxeCoreEntryPoint = 0;
  return Status;
}
