/** @file

  Host checks for the freestanding coreboot table parser.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot.h"
#include "coreboot_hobs.h"

#include <Guid/MemoryAllocationHob.h>
#include <Library/HobLib.h>
#include <stdio.h>
#include <string.h>

#define TEST_TABLE_SIZE  4096U

static int
Expect (
  int          Condition,
  const char  *Message
  )
{
  if (!Condition) {
    fprintf (stderr, "cdk2 coreboot test: %s\n", Message);
    return 1;
  }

  return 0;
}

static UINTN
FinalizeTable (
  UINT8   *Storage,
  UINTN    StorageSize,
  UINTN    TableBytes,
  UINT32   TableEntries
  )
{
  struct cb_header  *Header;

  if (Storage == NULL || StorageSize < sizeof (struct cb_header) ||
      TableBytes > StorageSize - sizeof (struct cb_header) ||
      TableBytes > MAX_UINT32)
  {
    return 0;
  }

  Header = (struct cb_header *)(VOID *)Storage;
  Header->signature       = CB_HEADER_SIGNATURE;
  Header->header_bytes    = sizeof (*Header);
  Header->table_bytes     = (UINT32)TableBytes;
  Header->table_entries   = TableEntries;
  Header->table_checksum  = Cdk2CorebootChecksum16 (Storage + sizeof (*Header), TableBytes);
  Header->header_checksum = 0;
  Header->header_checksum = Cdk2CorebootChecksum16 (Header, sizeof (*Header));
  return sizeof (*Header) + TableBytes;
}

static UINTN
BuildMemoryTable (
  UINT8  *Storage,
  UINTN    StorageSize
  )
{
  struct cb_memory        *Memory;
  struct cb_memory_range  *Range;

  memset (Storage, 0, StorageSize);
  Memory = (struct cb_memory *)(VOID *)(Storage + sizeof (struct cb_header));
  Memory->tag  = CB_TAG_MEMORY;
  Memory->size = sizeof (*Memory) + 2 * sizeof (struct cb_memory_range);

  Range = &Memory->map[0];
  Range->start.lo = 0x00100000;
  Range->start.hi = 0;
  Range->size.lo  = 0x00300000;
  Range->size.hi  = 0;
  Range->type     = CB_MEM_RAM;

  Range = &Memory->map[1];
  Range->start.lo = 0x00000000;
  Range->start.hi = 1;
  Range->size.lo  = 0x01000000;
  Range->size.hi  = 0;
  Range->type     = CB_MEM_RESERVED;

  return FinalizeTable (Storage, StorageSize, Memory->size, 1);
}

static UINTN
BuildForwardTable (
  UINT8        *Storage,
  UINTN          StorageSize,
  CONST VOID    *Target
  )
{
  struct cb_forward *Forward;

  memset (Storage, 0, StorageSize);
  Forward = (struct cb_forward *)(VOID *)(Storage + sizeof (struct cb_header));
  Forward->tag     = CB_TAG_FORWARD;
  Forward->size    = sizeof (*Forward);
  Forward->forward = (UINT64)(UINTN)Target;

  return FinalizeTable (Storage, StorageSize, Forward->size, 1);
}

static UINTN
BuildLegacySerialTable (
  UINT8  *Storage,
  UINTN    StorageSize
  )
{
  struct cb_serial  *Serial;

  memset (Storage, 0, StorageSize);
  Serial = (struct cb_serial *)(VOID *)(Storage + sizeof (struct cb_header));
  Serial->tag      = CB_TAG_SERIAL;
  Serial->size     = CDK2_COREBOOT_SERIAL_MIN_SIZE;
  Serial->type     = CB_SERIAL_TYPE_IO_MAPPED;
  Serial->baseaddr = 0x3f8;
  Serial->baud     = 115200;
  Serial->regwidth = 1;
  return FinalizeTable (Storage, StorageSize, Serial->size, 1);
}

static UINTN
BuildLegacyFramebufferTable (
  UINT8  *Storage,
  UINTN    StorageSize
  )
{
  struct cb_framebuffer  *Framebuffer;

  memset (Storage, 0, StorageSize);
  Framebuffer = (struct cb_framebuffer *)(VOID *)(Storage + sizeof (struct cb_header));
  Framebuffer->tag                = CB_TAG_FRAMEBUFFER;
  Framebuffer->size               = CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE;
  Framebuffer->physical_address   = 0xfd000000ULL;
  Framebuffer->x_resolution       = 1024;
  Framebuffer->y_resolution       = 768;
  Framebuffer->bytes_per_line     = 4096;
  Framebuffer->bits_per_pixel     = 32;
  Framebuffer->red_mask_pos       = 16;
  Framebuffer->red_mask_size      = 8;
  Framebuffer->green_mask_pos     = 8;
  Framebuffer->green_mask_size    = 8;
  Framebuffer->blue_mask_pos      = 0;
  Framebuffer->blue_mask_size     = 8;
  Framebuffer->reserved_mask_pos  = 24;
  Framebuffer->reserved_mask_size = 8;
  return FinalizeTable (Storage, StorageSize, Framebuffer->size, 1);
}

int
main (
  void
  )
{
  UINT8                       Storage[TEST_TABLE_SIZE];
  UINT8                       ForwardStorage[TEST_TABLE_SIZE];
  UINT8                       TargetStorage[TEST_TABLE_SIZE];
  UINT8                       HobStorage[TEST_TABLE_SIZE];
  UINT8                       TinyHobStorage[64];
  CDK2_COREBOOT_HANDOFF       Handoff;
  EFI_HOB_HANDOFF_INFO_TABLE *HobInfo;
  EFI_HOB_GENERIC_HEADER     *Hob;
  EFI_PEI_HOB_POINTERS        HobWalker;
  UINTN                       HobCursor;
  UINTN                       ResourceCount;
  UINTN                       AllocationCount;
  UINTN                       StackCount;
  UINTN                       CpuCount;
  UINTN                       GuidCount;
  UINTN                       ApiGuidCount;
  UINTN                       WalkerCount;
  UINTN                       CodeAllocationCount;
  UINTN                       ModuleCount;
  UINTN                       TableSize;
  CONST VOID                 *Record;
  CONST struct cb_serial      *Serial;
  CONST struct cb_framebuffer *Framebuffer;
  EFI_GUID                    TestGuid;
  EFI_GUID                    StackGuid;
  EFI_GUID                    ModuleGuid;
  EFI_GUID                    DxeCoreGuid;
  EFI_GUID                    ZeroGuid;
  UINT8                       TestData[4];
  EFI_STATUS                  Status;
  int                         Failures;

  Failures = 0;
  TableSize = BuildMemoryTable (Storage, sizeof (Storage));
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "valid table rejected");
  Failures += Expect (Handoff.RecordCount == 1, "record count is wrong");
  Failures += Expect (Handoff.MemoryRangeCount == 2, "memory range count is wrong");
  Failures += Expect (Handoff.UsableRamCount == 1, "usable RAM count is wrong");
  Failures += Expect (Handoff.LargestUsableRamBase == 0x00100000, "usable RAM base is wrong");
  Failures += Expect (Handoff.LargestUsableRamSize == 0x00300000, "usable RAM size is wrong");

  Status = Cdk2CorebootFindRecord (
             &Handoff,
             CB_TAG_MEMORY,
             sizeof (struct cb_memory),
             &Record
             );
  Failures += Expect (Status == EFI_SUCCESS && Record != NULL, "record lookup failed");
  Status = Cdk2CorebootFindRecord (
             &Handoff,
             CB_TAG_MEMORY,
             sizeof (struct cb_memory) + 3 * sizeof (struct cb_memory_range),
             &Record
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "short record was accepted");

  TableSize = BuildLegacySerialTable (Storage, sizeof (Storage));
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "legacy serial table rejected");
  Status = Cdk2CorebootFindRecord (
             &Handoff,
             CB_TAG_SERIAL,
             CDK2_COREBOOT_SERIAL_MIN_SIZE,
             &Record
             );
  Failures += Expect (Status == EFI_SUCCESS && Record != NULL, "legacy serial lookup failed");
  Serial = (CONST struct cb_serial *)Record;
  Failures += Expect (Serial->type == CB_SERIAL_TYPE_IO_MAPPED, "legacy serial type is wrong");
  Failures += Expect (Serial->baseaddr == 0x3f8, "legacy serial base is wrong");
  Failures += Expect (Serial->baud == 115200, "legacy serial baud is wrong");
  Failures += Expect (Serial->regwidth == 1, "legacy serial regwidth is wrong");
  Status = Cdk2CorebootFindRecord (
             &Handoff,
             CB_TAG_SERIAL,
             CDK2_COREBOOT_RECORD_FIELD_END (struct cb_serial, input_hertz),
             &Record
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "legacy serial exposed input_hertz");

  TableSize = BuildLegacyFramebufferTable (Storage, sizeof (Storage));
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "legacy framebuffer table rejected");
  Status = Cdk2CorebootFindRecord (
             &Handoff,
             CB_TAG_FRAMEBUFFER,
             CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE,
             &Record
             );
  Failures += Expect (Status == EFI_SUCCESS && Record != NULL, "legacy framebuffer lookup failed");
  Framebuffer = (CONST struct cb_framebuffer *)Record;
  Failures += Expect (Framebuffer->physical_address == 0xfd000000ULL, "legacy framebuffer base is wrong");
  Failures += Expect (Framebuffer->x_resolution == 1024, "legacy framebuffer width is wrong");
  Failures += Expect (Framebuffer->y_resolution == 768, "legacy framebuffer height is wrong");
  Failures += Expect (Framebuffer->bytes_per_line == 4096, "legacy framebuffer stride is wrong");
  Failures += Expect (Framebuffer->bits_per_pixel == 32, "legacy framebuffer bpp is wrong");
  Failures += Expect (Framebuffer->red_mask_pos == 16, "legacy framebuffer red mask is wrong");
  Failures += Expect (Framebuffer->blue_mask_pos == 0, "legacy framebuffer blue mask is wrong");
  Status = Cdk2CorebootFindRecord (
             &Handoff,
             CB_TAG_FRAMEBUFFER,
             CDK2_COREBOOT_FRAMEBUFFER_MIN_SIZE + 1,
             &Record
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "legacy framebuffer exposed trailing bytes");

  Status = Cdk2CorebootParseTable (Storage, TableSize - 1, &Handoff);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "truncated table accepted");

  ((struct cb_header *)(VOID *)Storage)->table_checksum ^= 1;
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "bad checksum accepted");
  TableSize = BuildMemoryTable (Storage, sizeof (Storage));

  ((struct cb_header *)(VOID *)Storage)->table_bytes = CDK2_COREBOOT_MAX_TABLE_BYTES + 1;
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "oversized table accepted");
  TableSize = BuildMemoryTable (Storage, sizeof (Storage));

  ((struct cb_memory *)(VOID *)(Storage + sizeof (struct cb_header)))->size = sizeof (struct cb_record);
  ((struct cb_header *)(VOID *)Storage)->table_checksum = Cdk2CorebootChecksum16 (
                                                               Storage + sizeof (struct cb_header),
                                                               ((struct cb_header *)(VOID *)Storage)->table_bytes
                                                               );
  ((struct cb_header *)(VOID *)Storage)->header_checksum = 0;
  ((struct cb_header *)(VOID *)Storage)->header_checksum = Cdk2CorebootChecksum16 (
                                                                  Storage,
                                                                  sizeof (struct cb_header)
                                                                  );
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "short memory record accepted");

  TableSize = BuildMemoryTable (TargetStorage, sizeof (TargetStorage));
  (void)TableSize;
  BuildForwardTable (ForwardStorage, sizeof (ForwardStorage), TargetStorage);
  Status = Cdk2CorebootParse ((UINTN)(VOID *)ForwardStorage, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "forward table rejected");
  Failures += Expect (Handoff.MemoryRangeCount == 2, "forward target was not parsed");

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             HobStorage,
             HobStorage + sizeof (HobStorage),
             HobStorage,
             HobStorage + sizeof (HobStorage),
             &HobInfo
             );
  Failures += Expect (Status == EFI_SUCCESS, "HOB construction failed");
  Failures += Expect (HobInfo != NULL && HobInfo->Header.HobType == EFI_HOB_TYPE_HANDOFF, "PHIT is missing");
  ResourceCount = 0;
  HobCursor = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    Failures += Expect (Hob->HobLength >= sizeof (*Hob), "HOB length is invalid");
    if (Hob->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      ResourceCount++;
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }

  Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobInfo->EfiEndOfHobList;
  Failures += Expect (Hob->HobType == EFI_HOB_TYPE_END_OF_HOB_LIST, "HOB list has no end marker");
  Failures += Expect (ResourceCount == 2, "resource HOB count is wrong");
  Failures += Expect (HobInfo->EfiFreeMemoryBottom > HobInfo->EfiEndOfHobList, "HOB allocator did not advance");

  Status = Cdk2CorebootAppendMemoryAllocationHob (
             HobInfo,
             (EFI_PHYSICAL_ADDRESS)(UINTN)Storage,
             sizeof (Storage),
             EfiBootServicesData
             );
  Failures += Expect (Status == EFI_SUCCESS, "payload allocation HOB failed");
  Status = Cdk2CorebootAppendStackHob (
             HobInfo,
             0x00200000,
             EFI_PAGE_SIZE
             );
  Failures += Expect (Status == EFI_SUCCESS, "stack allocation HOB failed");
  Status = Cdk2CorebootAppendCpuHob (HobInfo, 36, 16);
  Failures += Expect (Status == EFI_SUCCESS, "CPU HOB failed");

  AllocationCount = 0;
  StackCount      = 0;
  CpuCount        = 0;
  StackGuid       = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_STACK_GUID;
  ZeroGuid        = (EFI_GUID){ 0 };
  HobCursor       = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    if (Hob->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      EFI_HOB_MEMORY_ALLOCATION  *Allocation;

      Allocation = (EFI_HOB_MEMORY_ALLOCATION *)(VOID *)Hob;
      AllocationCount++;
      if (memcmp (&Allocation->AllocDescriptor.Name, &StackGuid, sizeof (StackGuid)) == 0) {
        StackCount++;
      } else {
        Failures += Expect (
                      memcmp (&Allocation->AllocDescriptor.Name, &ZeroGuid, sizeof (ZeroGuid)) == 0,
                      "generic allocation HOB has an owner GUID"
                      );
      }
    } else if (Hob->HobType == EFI_HOB_TYPE_CPU) {
      CpuCount++;
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }
  Failures += Expect (AllocationCount == 2, "allocation HOB count is wrong");
  Failures += Expect (StackCount == 1, "stack HOB owner GUID is wrong");
  Failures += Expect (CpuCount == 1, "CPU HOB count is wrong");

  DxeCoreGuid = (EFI_GUID){ 0x86d70125, 0xbaa3, 0x4296, { 0xa6, 0x2f, 0x60, 0x2b, 0xeb, 0xbb, 0x90, 0x8e } };
  Status = Cdk2CorebootAppendMemoryAllocationHob (
             HobInfo,
             0x00400000,
             2 * EFI_PAGE_SIZE,
             EfiBootServicesCode
             );
  Failures += Expect (Status == EFI_SUCCESS, "loaded-image allocation HOB failed");
  Status = Cdk2CorebootAppendModuleHob (
             HobInfo,
             &DxeCoreGuid,
             0x00400000,
             2 * EFI_PAGE_SIZE,
             0x00401000
             );
  Failures += Expect (Status == EFI_SUCCESS, "module HOB failed");

  CodeAllocationCount = 0;
  ModuleCount         = 0;
  ModuleGuid          = (EFI_GUID)EFI_HOB_MEMORY_ALLOC_MODULE_GUID;
  HobCursor           = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    if (Hob->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      EFI_HOB_MEMORY_ALLOCATION         *Allocation;
      EFI_HOB_MEMORY_ALLOCATION_MODULE  *Module;

      Allocation = (EFI_HOB_MEMORY_ALLOCATION *)(VOID *)Hob;
      if (Allocation->AllocDescriptor.MemoryBaseAddress == 0x00400000 &&
          Allocation->AllocDescriptor.MemoryLength == 2 * EFI_PAGE_SIZE)
      {
        if (memcmp (&Allocation->AllocDescriptor.Name, &ZeroGuid, sizeof (ZeroGuid)) == 0) {
          Failures += Expect (
                        Allocation->AllocDescriptor.MemoryType == EfiBootServicesCode,
                        "loaded-image allocation type is wrong"
                        );
          CodeAllocationCount++;
        } else if (memcmp (&Allocation->AllocDescriptor.Name, &ModuleGuid, sizeof (ModuleGuid)) == 0) {
          Module = (EFI_HOB_MEMORY_ALLOCATION_MODULE *)(VOID *)Hob;
          Failures += Expect (
                        Module->MemoryAllocationHeader.MemoryType == EfiBootServicesCode,
                        "module allocation type is wrong"
                        );
          Failures += Expect (
                        memcmp (&Module->ModuleName, &DxeCoreGuid, sizeof (DxeCoreGuid)) == 0,
                        "module name is wrong"
                        );
          Failures += Expect (Module->EntryPoint == 0x00401000, "module entry point is wrong");
          ModuleCount++;
        }
      }
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }
  Failures += Expect (CodeAllocationCount == 1, "loaded-image allocation HOB count is wrong");
  Failures += Expect (ModuleCount == 1, "loaded-image module HOB count is wrong");

  TestGuid = (EFI_GUID){ 0x12345678, 0x9abc, 0xdef0, { 1, 2, 3, 4, 5, 6, 7, 8 } };
  TestData[0] = 0xaa;
  TestData[1] = 0xbb;
  TestData[2] = 0xcc;
  TestData[3] = 0xdd;
  Status = Cdk2CorebootAppendGuidHob (HobInfo, &TestGuid, TestData, sizeof (TestData));
  Failures += Expect (Status == EFI_SUCCESS, "GUID HOB construction failed");

  GuidCount = 0;
  HobCursor = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    if (Hob->HobType == EFI_HOB_TYPE_GUID_EXTENSION) {
      EFI_HOB_GUID_TYPE  *GuidHob;

      GuidHob = (EFI_HOB_GUID_TYPE *)(VOID *)Hob;
      if (memcmp (&GuidHob->Name, &TestGuid, sizeof (TestGuid)) == 0 &&
          memcmp (GuidHob + 1, TestData, sizeof (TestData)) == 0)
      {
        GuidCount++;
      }
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }
  Failures += Expect (GuidCount == 1, "GUID HOB data is wrong");

  ApiGuidCount = 0;
  WalkerCount  = 0;
  HobWalker.Raw = (UINT8 *)(VOID *)HobInfo;
  while (!END_OF_HOB_LIST (HobWalker) && WalkerCount < 64) {
    if (GET_HOB_LENGTH (HobWalker) < sizeof (EFI_HOB_GENERIC_HEADER)) {
      Failures += Expect (0, "EDK2 HOB traversal saw an invalid length");
      break;
    }

    Failures += Expect (
                  (GET_HOB_LENGTH (HobWalker) & 7U) == 0,
                  "HOB length is not EDK2 traversal aligned"
                  );
    if (GET_HOB_TYPE (HobWalker) == EFI_HOB_TYPE_GUID_EXTENSION) {
      if (memcmp (&HobWalker.Guid->Name, &TestGuid, sizeof (TestGuid)) == 0 &&
          memcmp (GET_GUID_HOB_DATA (HobWalker), TestData, sizeof (TestData)) == 0)
      {
        ApiGuidCount++;
      }
    }

    HobWalker.Raw = (UINT8 *)(VOID *)GET_NEXT_HOB (HobWalker);
    WalkerCount++;
  }

  Failures += Expect (END_OF_HOB_LIST (HobWalker), "EDK2 HOB traversal missed the end marker");
  Failures += Expect (ApiGuidCount == 1, "EDK2 HOB traversal missed the GUID HOB");

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             TinyHobStorage,
             TinyHobStorage + sizeof (TinyHobStorage),
             TinyHobStorage,
             TinyHobStorage + sizeof (TinyHobStorage),
             &HobInfo
             );
  Failures += Expect (Status == EFI_OUT_OF_RESOURCES, "HOB exhaustion was not rejected");

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             (VOID *)(UINTN)0x1000,
             (VOID *)(UINTN)MAX_UINTN,
             (VOID *)(UINTN)(MAX_UINTN - 3U),
             (VOID *)(UINTN)MAX_UINTN,
             &HobInfo
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "wrapped HOB free bottom accepted");

  Handoff = (CDK2_COREBOOT_HANDOFF){ 0 };
  Handoff.MemoryRangeCount        = 2;
  Handoff.MemoryRanges[0].Base    = 0x00200000;
  Handoff.MemoryRanges[0].Size    = 0x00400000;
  Handoff.MemoryRanges[0].Type    = CB_MEM_RAM;
  Handoff.MemoryRanges[1].Base    = 0x00300000;
  Handoff.MemoryRanges[1].Size    = 0x00100000;
  Handoff.MemoryRanges[1].Type    = CB_MEM_RESERVED;
  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             HobStorage,
             HobStorage + sizeof (HobStorage),
             HobStorage,
             HobStorage + sizeof (HobStorage),
             &HobInfo
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "overlapping memory ranges accepted");

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 coreboot test: PASS");
  return 0;
}
