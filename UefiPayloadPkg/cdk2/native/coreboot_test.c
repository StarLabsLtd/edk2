/** @file

  Host checks for the freestanding coreboot table parser.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot.h"
#include "coreboot_hobs.h"

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
BuildMemoryTable (
  UINT8  *Storage,
  UINTN    StorageSize
  )
{
  struct cb_header        *Header;
  struct cb_memory        *Memory;
  struct cb_memory_range  *Range;

  memset (Storage, 0, StorageSize);
  Header = (struct cb_header *)(VOID *)Storage;
  Memory = (struct cb_memory *)(VOID *)(Storage + sizeof (*Header));
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

  Header->signature       = CB_HEADER_SIGNATURE;
  Header->header_bytes    = sizeof (*Header);
  Header->table_bytes     = Memory->size;
  Header->table_entries   = 1;
  Header->table_checksum  = Cdk2CorebootChecksum16 (Memory, Memory->size);
  Header->header_checksum = Cdk2CorebootChecksum16 (Header, sizeof (*Header));
  return sizeof (*Header) + Memory->size;
}

static UINTN
BuildForwardTable (
  UINT8        *Storage,
  UINTN          StorageSize,
  CONST VOID    *Target
  )
{
  struct cb_header   *Header;
  struct cb_forward *Forward;

  memset (Storage, 0, StorageSize);
  Header  = (struct cb_header *)(VOID *)Storage;
  Forward = (struct cb_forward *)(VOID *)(Storage + sizeof (*Header));
  Forward->tag     = CB_TAG_FORWARD;
  Forward->size    = sizeof (*Forward);
  Forward->forward = (UINT64)(UINTN)Target;

  Header->signature       = CB_HEADER_SIGNATURE;
  Header->header_bytes    = sizeof (*Header);
  Header->table_bytes     = Forward->size;
  Header->table_entries   = 1;
  Header->table_checksum  = Cdk2CorebootChecksum16 (Forward, Forward->size);
  Header->header_checksum = Cdk2CorebootChecksum16 (Header, sizeof (*Header));
  return sizeof (*Header) + Forward->size;
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
  UINTN                       HobCursor;
  UINTN                       ResourceCount;
  UINTN                       AllocationCount;
  UINTN                       CpuCount;
  UINTN                       GuidCount;
  UINTN                       TableSize;
  CONST VOID                 *Record;
  EFI_GUID                    TestGuid;
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
  Status = Cdk2CorebootAppendCpuHob (HobInfo, 36, 16);
  Failures += Expect (Status == EFI_SUCCESS, "CPU HOB failed");

  AllocationCount = 0;
  CpuCount        = 0;
  HobCursor       = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    if (Hob->HobType == EFI_HOB_TYPE_MEMORY_ALLOCATION) {
      AllocationCount++;
    } else if (Hob->HobType == EFI_HOB_TYPE_CPU) {
      CpuCount++;
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }
  Failures += Expect (AllocationCount == 1, "allocation HOB count is wrong");
  Failures += Expect (CpuCount == 1, "CPU HOB count is wrong");

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

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             TinyHobStorage,
             TinyHobStorage + sizeof (TinyHobStorage),
             TinyHobStorage,
             TinyHobStorage + sizeof (TinyHobStorage),
             &HobInfo
             );
  Failures += Expect (Status == EFI_OUT_OF_RESOURCES, "HOB exhaustion was not rejected");

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 coreboot test: PASS");
  return 0;
}
