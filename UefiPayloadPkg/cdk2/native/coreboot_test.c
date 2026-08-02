/** @file

  Host checks for the freestanding coreboot table parser.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot.h"
#include "coreboot_hobs.h"
#include "services.h"

#include <Guid/MemoryAllocationHob.h>
#include <Library/HobLib.h>
#include <stdio.h>
#include <string.h>

#define TEST_TABLE_SIZE  4096U
#define TEST_HOB_REGION_SIZE  0x04000000U
#define TEST_TEMP_MAP_LIMIT   0x2000000000ULL
#define TEST_HOB_ALIGN8(Size)  (((Size) + 7U) & ~(UINTN)7U)
#define TEST_PRH_UNKNOWN_SECTION  0x7fffU

#if defined (__GNUC__)
static UINT8  mTransferHobStorage[EFI_PAGE_SIZE] __attribute__ ((aligned (EFI_PAGE_SIZE)));
#else
static UINT8  mTransferHobStorage[EFI_PAGE_SIZE];
#endif

EFI_STATUS
EFIAPI
Cdk2CorebootTestTransfer (
  IN CDK2_NATIVE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
Cdk2CorebootTestAppendLoadedDxeCoreHobs (
  IN OUT EFI_HOB_HANDOFF_INFO_TABLE  *Handoff,
  IN     EFI_PHYSICAL_ADDRESS         FvBase,
  IN     UINTN                        FvSize,
  IN     CONST EFI_GUID              *ModuleName,
  IN     EFI_PHYSICAL_ADDRESS         ImageBase,
  IN     UINTN                        ImageSize,
  IN     EFI_PHYSICAL_ADDRESS         EntryPoint
  );

VOID
EFIAPI
Cdk2PlatformLateInit (
  VOID
  )
{
}

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

typedef enum {
  TestPrhValid,
  TestPrhBadCrc,
  TestPrhShortHeader,
  TestPrhSectionOverflow,
  TestPrhSectionOverlap,
  TestPrhDuplicateType,
  TestPrhUnknownMandatory,
  TestPrhKnownMandatory,
  TestPrhMemoryZeroLength,
  TestPrhMemoryWrap,
  TestPrhMemoryOverlap,
  TestPrhCacheCountMismatch,
  TestPrhMissingLifetime,
  TestPrhMemoryProtectionNoPaging,
  TestPrhFramebufferBadMask,
  TestPrhPciBadBar,
  TestPrhPciDuplicate,
  TestPrhPciOutsideBridge,
  TestPrhMemoryAttributesExceedCapabilities
} TEST_PRH_FIXTURE;

static void
PackCbUint64 (
  struct cbuint64 *Value,
  UINT64           Data
  )
{
  Value->lo = (UINT32)Data;
  Value->hi = (UINT32)(Data >> 32);
}

static void
PackCbUint64At (
  VOID    *Base,
  UINTN    Offset,
  UINT64   Data
  )
{
  PackCbUint64 ((struct cbuint64 *)((UINT8 *)Base + Offset), Data);
}

static void
FinalizePayloadResourceHandoff (
  struct cb_payload_resource_handoff *Handoff
  )
{
  Handoff->crc32 = 0;
  Handoff->crc32 = Cdk2CorebootCalculateCrc32 (Handoff, Handoff->size);
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
  struct lb_boot_mode     *BootMode;

  memset (Storage, 0, StorageSize);
  Memory = (struct cb_memory *)(VOID *)(Storage + sizeof (struct cb_header));
  Memory->tag  = CB_TAG_MEMORY;
  Memory->size = sizeof (*Memory) + 3 * sizeof (struct cb_memory_range);

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

  Range = &Memory->map[2];
  Range->start.lo = 0x00400000;
  Range->start.hi = 0;
  Range->size.lo  = 0x00001000;
  Range->size.hi  = 0;
  Range->type     = CB_MEM_TABLE;

  BootMode = (struct lb_boot_mode *)(VOID *)((UINT8 *)Memory + Memory->size);
  BootMode->tag       = CB_TAG_BOOT_MODE;
  BootMode->size      = sizeof (*BootMode);
  BootMode->boot_mode = LB_BOOT_MODE_FLASH_UPDATE;

  return FinalizeTable (Storage, StorageSize, Memory->size + BootMode->size, 2);
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

static UINTN
BuildPayloadResourceHandoffTable (
  UINT8             *Storage,
  UINTN              StorageSize,
  TEST_PRH_FIXTURE   Fixture
  )
{
  struct cb_payload_resource_handoff   *Prh;
  struct cb_payload_resource_section   *Sections;
  struct cb_prh_memory_policy_entry    *MemoryPolicy;
  struct cb_prh_x86_cache_state        *CacheState;
  struct cb_prh_x86_variable_mtrr      *VariableMtrr;
  struct cb_prh_pci_root_bridge_entry  *RootBridge;
  struct cb_prh_pci_assignment_entry   *PciAssignment;
  struct cb_prh_framebuffer_entry      *Framebuffer;
  UINT8                                *Payload;
  UINTN                                 PayloadOffset;
  UINT32                                MemoryEntryCount;
  UINT32                                PciAssignmentCount;
  UINTN                                 SectionCount;

  memset (Storage, 0, StorageSize);
  Prh = (struct cb_payload_resource_handoff *)(VOID *)(Storage + sizeof (struct cb_header));
  Prh->tag                   = CB_TAG_PAYLOAD_RESOURCE_HANDOFF;
  Prh->revision              = CB_PAYLOAD_RESOURCE_HANDOFF_REVISION;
  Prh->header_length         = sizeof (*Prh);
  Prh->section_header_length = sizeof (struct cb_payload_resource_section);
  Prh->producer_stage        = 1;
  PackCbUint64At (Prh, OFFSET_OF (struct cb_payload_resource_handoff, producer_generation), 1);
  PackCbUint64At (
    Prh,
    OFFSET_OF (struct cb_payload_resource_handoff, lifetime_flags),
    CB_PRH_LIFETIME_COLD_BOOT | CB_PRH_LIFETIME_EXIT_BOOT_SERVICES
    );

  SectionCount       = 6;
  Prh->section_count = (UINT32)SectionCount;
  Sections           = (struct cb_payload_resource_section *)(VOID *)((UINT8 *)Prh + Prh->header_length);
  PayloadOffset      = Prh->header_length + SectionCount * Prh->section_header_length;
  Payload            = (UINT8 *)Prh + PayloadOffset;

  MemoryEntryCount          = (Fixture == TestPrhMemoryOverlap) ? 2U : 1U;
  Sections[0].type          = CB_PRH_SECTION_MEMORY_POLICY;
  Sections[0].flags         = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
  Sections[0].header_length = sizeof (Sections[0]);
  Sections[0].entry_size    = sizeof (*MemoryPolicy);
  Sections[0].entry_count   = MemoryEntryCount;
  Sections[0].offset        = (UINT32)PayloadOffset;
  Sections[0].length        = MemoryEntryCount * sizeof (*MemoryPolicy);
  MemoryPolicy              = (struct cb_prh_memory_policy_entry *)(VOID *)Payload;
  PackCbUint64At (MemoryPolicy, OFFSET_OF (struct cb_prh_memory_policy_entry, base), 0x00100000ULL);
  PackCbUint64At (MemoryPolicy, OFFSET_OF (struct cb_prh_memory_policy_entry, length), 0x00200000ULL);
  PackCbUint64At (MemoryPolicy, OFFSET_OF (struct cb_prh_memory_policy_entry, capabilities), EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB);
  PackCbUint64At (MemoryPolicy, OFFSET_OF (struct cb_prh_memory_policy_entry, attributes), EFI_MEMORY_WB);
  MemoryPolicy[0].gcd_type        = 1;
  MemoryPolicy[0].efi_memory_type = EfiConventionalMemory;
  MemoryPolicy[0].owner_flags     = CB_PRH_MEMORY_CACHE_AUTHORITATIVE |
                                    CB_PRH_MEMORY_GCD_AUTHORITATIVE |
                                    CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE;
  if (Fixture == TestPrhMemoryZeroLength) {
    PackCbUint64At (&MemoryPolicy[0], OFFSET_OF (struct cb_prh_memory_policy_entry, length), 0);
  } else if (Fixture == TestPrhMemoryWrap) {
    PackCbUint64At (&MemoryPolicy[0], OFFSET_OF (struct cb_prh_memory_policy_entry, base), MAX_UINT64 - 0xffULL);
    PackCbUint64At (&MemoryPolicy[0], OFFSET_OF (struct cb_prh_memory_policy_entry, length), 0x200ULL);
  } else if (Fixture == TestPrhMemoryOverlap) {
    PackCbUint64At (&MemoryPolicy[1], OFFSET_OF (struct cb_prh_memory_policy_entry, base), 0x00180000ULL);
    PackCbUint64At (&MemoryPolicy[1], OFFSET_OF (struct cb_prh_memory_policy_entry, length), 0x00100000ULL);
    PackCbUint64At (&MemoryPolicy[1], OFFSET_OF (struct cb_prh_memory_policy_entry, capabilities), EFI_MEMORY_UC | EFI_MEMORY_WC | EFI_MEMORY_WT | EFI_MEMORY_WB);
    PackCbUint64At (&MemoryPolicy[1], OFFSET_OF (struct cb_prh_memory_policy_entry, attributes), EFI_MEMORY_WB);
    MemoryPolicy[1].gcd_type        = 1;
    MemoryPolicy[1].efi_memory_type = EfiConventionalMemory;
    MemoryPolicy[1].owner_flags     = MemoryPolicy[0].owner_flags;
  } else if (Fixture == TestPrhMemoryProtectionNoPaging) {
    MemoryPolicy[0].owner_flags |= CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE;
  } else if (Fixture == TestPrhMemoryAttributesExceedCapabilities) {
    PackCbUint64At (
      &MemoryPolicy[0],
      OFFSET_OF (struct cb_prh_memory_policy_entry, capabilities),
      EFI_MEMORY_UC
      );
  }

  PayloadOffset += Sections[0].length;
  Payload        = (UINT8 *)Prh + PayloadOffset;

  Sections[1].type          = CB_PRH_SECTION_X86_CACHE_STATE;
  Sections[1].flags         = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
  Sections[1].header_length = sizeof (Sections[1]);
  Sections[1].entry_size    = sizeof (*VariableMtrr);
  Sections[1].entry_count   = 1;
  Sections[1].offset        = (UINT32)PayloadOffset;
  Sections[1].length        = sizeof (*CacheState) + sizeof (*VariableMtrr);
  CacheState                = (struct cb_prh_x86_cache_state *)(VOID *)Payload;
  PackCbUint64At (CacheState, OFFSET_OF (struct cb_prh_x86_cache_state, mtrr_default_type_msr), 0x800ULL | 6U);
  PackCbUint64At (CacheState, OFFSET_OF (struct cb_prh_x86_cache_state, pat_msr), 0x0007040600070406ULL);
  PackCbUint64At (CacheState, OFFSET_OF (struct cb_prh_x86_cache_state, fixed_mtrr_crc64), 0x12345678ULL);
  CacheState->variable_count = (Fixture == TestPrhCacheCountMismatch) ? 2U : 1U;
  CacheState->flags          = CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC |
                               CB_PRH_X86_CACHE_FLAG_FIXED_VALID;
  VariableMtrr = (struct cb_prh_x86_variable_mtrr *)(VOID *)(CacheState + 1);
  PackCbUint64At (VariableMtrr, OFFSET_OF (struct cb_prh_x86_variable_mtrr, phys_base_msr), 0x00100000ULL | 6U);
  PackCbUint64At (VariableMtrr, OFFSET_OF (struct cb_prh_x86_variable_mtrr, phys_mask_msr), 0xffe00000ULL | BIT11);

  PayloadOffset += Sections[1].length;
  Payload        = (UINT8 *)Prh + PayloadOffset;

  Sections[2].type          = CB_PRH_SECTION_PCI_ROOT_BRIDGES;
  Sections[2].flags         = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
  Sections[2].header_length = sizeof (Sections[2]);
  Sections[2].entry_size    = sizeof (*RootBridge);
  Sections[2].entry_count   = 1;
  Sections[2].offset        = (UINT32)PayloadOffset;
  Sections[2].length        = sizeof (*RootBridge);
  RootBridge                = (struct cb_prh_pci_root_bridge_entry *)(VOID *)Payload;
  RootBridge->bus_end       = 0xff;
  PackCbUint64At (RootBridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_base), 0x1000);
  PackCbUint64At (RootBridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_length), 0xf000);
  PackCbUint64At (RootBridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_base), 0xe0000000ULL);
  PackCbUint64At (RootBridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_length), 0x10000000ULL);

  PayloadOffset += Sections[2].length;
  Payload        = (UINT8 *)Prh + PayloadOffset;

  Sections[3].type          = CB_PRH_SECTION_PCI_ASSIGNMENTS;
  Sections[3].flags         = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
  Sections[3].header_length = sizeof (Sections[3]);
  Sections[3].entry_size    = sizeof (*PciAssignment);
  PciAssignmentCount        = (Fixture == TestPrhPciDuplicate) ? 2U : 1U;
  Sections[3].entry_count   = PciAssignmentCount;
  Sections[3].offset        = (UINT32)PayloadOffset;
  Sections[3].length        = PciAssignmentCount * sizeof (*PciAssignment);
  PciAssignment             = (struct cb_prh_pci_assignment_entry *)(VOID *)Payload;
  PciAssignment->device     = 2;
  PciAssignment->bar        = 0;
  PciAssignment->resource_type = CB_PRH_PCI_RESOURCE_MMIO32;
  PackCbUint64At (PciAssignment, OFFSET_OF (struct cb_prh_pci_assignment_entry, base), 0xe0000000ULL);
  PackCbUint64At (PciAssignment, OFFSET_OF (struct cb_prh_pci_assignment_entry, length), 0x100000ULL);
  PackCbUint64At (PciAssignment, OFFSET_OF (struct cb_prh_pci_assignment_entry, attributes), EFI_MEMORY_UC);
  if (Fixture == TestPrhPciBadBar) {
    PciAssignment->bar = 6;
  } else if (Fixture == TestPrhPciOutsideBridge) {
    PackCbUint64At (PciAssignment, OFFSET_OF (struct cb_prh_pci_assignment_entry, base), 0xd0000000ULL);
  } else if (Fixture == TestPrhPciDuplicate) {
    PciAssignment[1] = PciAssignment[0];
  }

  PayloadOffset += Sections[3].length;
  Payload        = (UINT8 *)Prh + PayloadOffset;

  Sections[4].type          = CB_PRH_SECTION_FRAMEBUFFER;
  Sections[4].flags         = CB_PRH_SECTION_FLAG_AUTHORITATIVE;
  Sections[4].header_length = sizeof (Sections[4]);
  Sections[4].entry_size    = sizeof (*Framebuffer);
  Sections[4].entry_count   = 1;
  Sections[4].offset        = (UINT32)PayloadOffset;
  Sections[4].length        = sizeof (*Framebuffer);
  Framebuffer               = (struct cb_prh_framebuffer_entry *)(VOID *)Payload;
  PackCbUint64At (Framebuffer, OFFSET_OF (struct cb_prh_framebuffer_entry, physical_address), 0xfd000000ULL);
  PackCbUint64At (Framebuffer, OFFSET_OF (struct cb_prh_framebuffer_entry, size), 4096ULL * 768U);
  Framebuffer->x_resolution       = 1024;
  Framebuffer->y_resolution       = 768;
  Framebuffer->bytes_per_line     = 4096;
  Framebuffer->bits_per_pixel     = 32;
  Framebuffer->red_mask_pos       = (Fixture == TestPrhFramebufferBadMask) ? 31 : 16;
  Framebuffer->red_mask_size      = 8;
  Framebuffer->green_mask_pos     = 8;
  Framebuffer->green_mask_size    = 8;
  Framebuffer->blue_mask_pos      = 0;
  Framebuffer->blue_mask_size     = 8;
  Framebuffer->reserved_mask_pos  = 24;
  Framebuffer->reserved_mask_size = 8;
  Framebuffer->owner_flags        = CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE |
                                    CB_PRH_FRAMEBUFFER_MEMORY_DELEGATED;

  PayloadOffset += Sections[4].length;
  Payload        = (UINT8 *)Prh + PayloadOffset;

  Sections[5].type          = TEST_PRH_UNKNOWN_SECTION;
  Sections[5].flags         = (Fixture == TestPrhUnknownMandatory) ? CB_PRH_SECTION_FLAG_MANDATORY : 0;
  Sections[5].header_length = sizeof (Sections[5]);
  Sections[5].entry_size    = sizeof (UINT32);
  Sections[5].entry_count   = 1;
  Sections[5].offset        = (UINT32)PayloadOffset;
  Sections[5].length        = sizeof (UINT32);
  *(UINT32 *)(VOID *)Payload = 0xa5a5a5a5U;

  PayloadOffset += Sections[5].length;
  Prh->size      = (UINT32)PayloadOffset;

  if (Fixture == TestPrhShortHeader) {
    Prh->header_length = sizeof (struct cb_record);
  } else if (Fixture == TestPrhSectionOverflow) {
    Sections[0].offset = Prh->size - 4U;
    Sections[0].length = 8U;
  } else if (Fixture == TestPrhSectionOverlap) {
    Sections[5].offset = Sections[3].offset;
    Sections[5].length = sizeof (UINT32);
  } else if (Fixture == TestPrhDuplicateType) {
    Sections[1].type = Sections[0].type;
  } else if (Fixture == TestPrhKnownMandatory) {
    Sections[5].type  = CB_PRH_SECTION_BOOT_INTENT;
    Sections[5].flags = CB_PRH_SECTION_FLAG_MANDATORY;
  } else if (Fixture == TestPrhMissingLifetime) {
    PackCbUint64At (Prh, OFFSET_OF (struct cb_payload_resource_handoff, lifetime_flags), 0);
  }

  FinalizePayloadResourceHandoff (Prh);
  if (Fixture == TestPrhBadCrc) {
    Prh->crc32 ^= 1U;
  }

  return FinalizeTable (Storage, StorageSize, Prh->size, 1);
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
  UINT8                       TransactionHobStorage[512];
  CDK2_COREBOOT_HANDOFF       Handoff;
  CDK2_COREBOOT_HANDOFF       TransactionHandoff;
  EFI_HOB_HANDOFF_INFO_TABLE *HobInfo;
  EFI_HOB_HANDOFF_INFO_TABLE *TransactionHob;
  EFI_HOB_GENERIC_HEADER     *Hob;
  EFI_HOB_GENERIC_HEADER      PreviousEndMarker;
  EFI_HOB_GENERIC_HEADER      TransactionEndMarker;
  EFI_PEI_HOB_POINTERS        HobWalker;
  UINTN                       HobCursor;
  UINTN                       ResourceCount;
  UINTN                       AllocationCount;
  UINTN                       StackCount;
  UINTN                       CpuCount;
  UINTN                       GuidCount;
  UINTN                       ApiGuidCount;
  UINTN                       PayloadResourceGuidCount;
  UINTN                       WalkerCount;
  UINTN                       CodeAllocationCount;
  UINTN                       ModuleCount;
  EFI_PHYSICAL_ADDRESS        PreviousEndOfHobList;
  EFI_PHYSICAL_ADDRESS        PreviousFreeMemoryBottom;
  EFI_PHYSICAL_ADDRESS        BadFreeMemoryBottom;
  EFI_PHYSICAL_ADDRESS        TransactionEndOfHobList;
  EFI_PHYSICAL_ADDRESS        TransactionFreeMemoryBottom;
  EFI_PHYSICAL_ADDRESS        TransactionFreeMemoryTop;
  UINTN                       TableSize;
  UINTN                       HobMemBase;
  UINTN                       TransactionFreeTopOffset;
  CONST VOID                 *Record;
  CONST struct cb_payload_resource_section *PrhSection;
  CONST struct cb_serial      *Serial;
  CONST struct cb_framebuffer *Framebuffer;
  EFI_HOB_RESOURCE_DESCRIPTOR *Resource;
  EFI_GUID                    TestGuid;
  EFI_GUID                    PayloadResourceGuid;
  EFI_GUID                    StackGuid;
  EFI_GUID                    ModuleGuid;
  EFI_GUID                    DxeCoreGuid;
  EFI_GUID                    ZeroGuid;
  UINT8                       TestData[4];
  CDK2_NATIVE_CONTEXT         TransferContext;
  EFI_HOB_HANDOFF_INFO_TABLE *TransferHob;
  EFI_HOB_GENERIC_HEADER     *TransferEnd;
  EFI_PHYSICAL_ADDRESS        TransferFreeBottom;
  EFI_PHYSICAL_ADDRESS        TransferFreeTop;
  EFI_STATUS                  Status;
  int                         Failures;

  Failures = 0;
  PayloadResourceGuid = (EFI_GUID){ 0xc263a6a9, 0x6938, 0x495e, { 0x95, 0xb6, 0x6a, 0x1a, 0x0b, 0x6b, 0xa8, 0x8e } };
  TableSize = BuildMemoryTable (Storage, sizeof (Storage));
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "valid table rejected");
  Failures += Expect (Handoff.RecordCount == 2, "record count is wrong");
  Failures += Expect (Handoff.MemoryRangeCount == 3, "memory range count is wrong");
  Failures += Expect (Handoff.UsableRamCount == 1, "usable RAM count is wrong");
  Failures += Expect (Handoff.LargestUsableRamBase == 0x00100000, "usable RAM base is wrong");
  Failures += Expect (Handoff.LargestUsableRamSize == 0x00300000, "usable RAM size is wrong");
  Failures += Expect (Handoff.PayloadResourceHandoffStatus == EFI_NOT_FOUND, "absent payload-resource record status is wrong");
  Status = Cdk2CorebootFindPayloadResourceSection (
             &Handoff,
             CB_PRH_SECTION_MEMORY_POLICY,
             &PrhSection
             );
  Failures += Expect (Status == EFI_NOT_FOUND, "absent payload-resource section did not fall back");

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
             sizeof (struct cb_memory) + 4 * sizeof (struct cb_memory_range),
             &Record
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "short record was accepted");

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhValid);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "valid payload-resource table rejected");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_SUCCESS &&
                Handoff.PayloadResourceHandoff != NULL,
                "valid payload-resource record was not accepted"
                );
  Status = Cdk2CorebootFindPayloadResourceSection (
             &Handoff,
             CB_PRH_SECTION_MEMORY_POLICY,
             &PrhSection
             );
  Failures += Expect (
                Status == EFI_SUCCESS &&
                PrhSection != NULL &&
                PrhSection->entry_count == 1,
                "payload-resource memory policy section lookup failed"
                );
  Status = Cdk2CorebootFindPayloadResourceSection (
             &Handoff,
             CB_PRH_SECTION_FRAMEBUFFER,
             &PrhSection
             );
  Failures += Expect (
                Status == EFI_SUCCESS &&
                PrhSection != NULL &&
                PrhSection->entry_count == 1,
                "payload-resource framebuffer section lookup failed"
                );
  Status = Cdk2CorebootFindPayloadResourceSection (
             &Handoff,
             TEST_PRH_UNKNOWN_SECTION,
             &PrhSection
             );
  Failures += Expect (Status == EFI_SUCCESS && PrhSection != NULL, "skippable unknown payload-resource section rejected");
  Status = Cdk2CorebootFindPayloadResourceSection (
             &Handoff,
             CB_PRH_SECTION_RUNTIME_POLICY,
             &PrhSection
             );
  Failures += Expect (Status == EFI_NOT_FOUND, "missing payload-resource section was found");

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             HobStorage,
             HobStorage + sizeof (HobStorage),
             HobStorage,
             HobStorage + sizeof (HobStorage),
             FALSE,
             &HobInfo
             );
  Failures += Expect (Status == EFI_SUCCESS, "payload-resource HOB construction failed");
  PayloadResourceGuidCount = 0;
  HobCursor = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    if (Hob->HobType == EFI_HOB_TYPE_GUID_EXTENSION) {
      EFI_HOB_GUID_TYPE  *GuidHob;
      UINTN               DataLength;

      GuidHob    = (EFI_HOB_GUID_TYPE *)(VOID *)Hob;
      DataLength = Hob->HobLength - sizeof (*GuidHob);
      if (memcmp (&GuidHob->Name, &PayloadResourceGuid, sizeof (PayloadResourceGuid)) == 0) {
        Failures += Expect (
                      DataLength >= Handoff.PayloadResourceHandoff->size &&
                      memcmp (
                        GuidHob + 1,
                        Handoff.PayloadResourceHandoff,
                        Handoff.PayloadResourceHandoff->size
                        ) == 0,
                      "payload-resource GUID HOB data is wrong"
                      );
        PayloadResourceGuidCount++;
      }
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }

  Failures += Expect (PayloadResourceGuidCount == 1, "payload-resource GUID HOB count is wrong");

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhBadCrc);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "bad payload-resource CRC rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_CRC_ERROR &&
                Handoff.PayloadResourceHandoff == NULL,
                "bad payload-resource CRC did not disable only the new ABI"
                );
  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             HobStorage,
             HobStorage + sizeof (HobStorage),
             HobStorage,
             HobStorage + sizeof (HobStorage),
             FALSE,
             &HobInfo
             );
  Failures += Expect (Status == EFI_SUCCESS, "bad payload-resource HOB fallback failed");
  PayloadResourceGuidCount = 0;
  HobCursor = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    if (Hob->HobType == EFI_HOB_TYPE_GUID_EXTENSION) {
      EFI_HOB_GUID_TYPE  *GuidHob;

      GuidHob = (EFI_HOB_GUID_TYPE *)(VOID *)Hob;
      if (memcmp (&GuidHob->Name, &PayloadResourceGuid, sizeof (PayloadResourceGuid)) == 0) {
        PayloadResourceGuidCount++;
      }
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }

  Failures += Expect (PayloadResourceGuidCount == 0, "bad payload-resource record published a HOB");


  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhShortHeader);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "short payload-resource header rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "short payload-resource header was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhSectionOverflow);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "overflowing payload-resource section rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "overflowing payload-resource section was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhUnknownMandatory);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "mandatory unknown payload-resource section rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_UNSUPPORTED &&
                Handoff.PayloadResourceHandoff == NULL,
                "mandatory unknown payload-resource section was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhKnownMandatory);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "deferred payload-resource section rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_UNSUPPORTED &&
                Handoff.PayloadResourceHandoff == NULL,
                "deferred mandatory payload-resource section was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhSectionOverlap);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "overlapping payload-resource sections rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "overlapping payload-resource sections were accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhDuplicateType);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "duplicate payload-resource section types rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "duplicate payload-resource section types were accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhMemoryZeroLength);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "zero-length payload-resource memory range rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "zero-length payload-resource memory range was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhMemoryWrap);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "wrapping payload-resource memory range rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "wrapping payload-resource memory range was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhMemoryOverlap);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "overlapping payload-resource memory ranges rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "overlapping payload-resource memory ranges were accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhCacheCountMismatch);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "bad x86 cache payload rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "bad x86 cache payload was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhMissingLifetime);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "missing payload-resource lifetime rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "missing payload-resource lifetime was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhMemoryProtectionNoPaging);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "payload-resource paging contract gap rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_UNSUPPORTED &&
                Handoff.PayloadResourceHandoff == NULL,
                "payload-resource protection ownership was accepted without paging proof"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhFramebufferBadMask);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "bad payload-resource framebuffer rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "bad payload-resource framebuffer was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhPciBadBar);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "bad payload-resource PCI BAR rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "bad payload-resource PCI BAR was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhPciDuplicate);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "duplicate payload-resource PCI BAR rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "duplicate payload-resource PCI BAR was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (Storage, sizeof (Storage), TestPrhPciOutsideBridge);
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "out-of-window payload-resource PCI assignment rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "out-of-window payload-resource PCI assignment was accepted"
                );

  TableSize = BuildPayloadResourceHandoffTable (
                Storage,
                sizeof (Storage),
                TestPrhMemoryAttributesExceedCapabilities
                );
  Status = Cdk2CorebootParseTable (Storage, TableSize, &Handoff);
  Failures += Expect (Status == EFI_SUCCESS, "impossible payload-resource memory attributes rejected the whole table");
  Failures += Expect (
                Handoff.PayloadResourceHandoffStatus == EFI_COMPROMISED_DATA &&
                Handoff.PayloadResourceHandoff == NULL,
                "impossible payload-resource memory attributes were accepted"
                );

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
  Failures += Expect (Handoff.MemoryRangeCount == 3, "forward target was not parsed");

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             HobStorage,
             HobStorage + sizeof (HobStorage),
             HobStorage,
             HobStorage + sizeof (HobStorage),
             TRUE,
             &HobInfo
             );
  Failures += Expect (Status == EFI_SUCCESS, "HOB construction failed");
  Failures += Expect (HobInfo != NULL && HobInfo->Header.HobType == EFI_HOB_TYPE_HANDOFF, "PHIT is missing");
  Failures += Expect (HobInfo->BootMode == BOOT_ON_FLASH_UPDATE, "coreboot boot mode not applied");
  ResourceCount = 0;
  Resource      = NULL;
  HobCursor = (UINTN)(VOID *)HobInfo;
  while (HobCursor < (UINTN)HobInfo->EfiEndOfHobList) {
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobCursor;
    Failures += Expect (Hob->HobLength >= sizeof (*Hob), "HOB length is invalid");
    if (Hob->HobType == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) {
      ResourceCount++;
      Resource = (EFI_HOB_RESOURCE_DESCRIPTOR *)(VOID *)Hob;
      if (ResourceCount == 1) {
        Failures += Expect (
                      Resource->ResourceType == EFI_RESOURCE_SYSTEM_MEMORY,
                      "RAM resource type is wrong"
                      );
      } else if (ResourceCount == 2) {
        Failures += Expect (
                      Resource->ResourceType == EFI_RESOURCE_MEMORY_RESERVED,
                      "reserved resource type is wrong"
                      );
      } else if (ResourceCount == 3) {
        Failures += Expect (
                      Resource->ResourceType == EFI_RESOURCE_MEMORY_RESERVED,
                      "coreboot table resource type is wrong"
                      );
      }
    }

    HobCursor += (Hob->HobLength + 7U) & ~(UINTN)7U;
  }

  Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)HobInfo->EfiEndOfHobList;
  Failures += Expect (Hob->HobType == EFI_HOB_TYPE_END_OF_HOB_LIST, "HOB list has no end marker");
  Failures += Expect (ResourceCount == 3, "resource HOB count is wrong");
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

  PreviousEndOfHobList    = HobInfo->EfiEndOfHobList;
  PreviousFreeMemoryBottom = HobInfo->EfiFreeMemoryBottom;
  Status = Cdk2CorebootAppendMemoryAllocationHob (
             HobInfo,
             MAX_UINT64 - EFI_PAGE_SIZE + 1,
             EFI_PAGE_SIZE,
             EfiBootServicesData
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "wrapping allocation HOB accepted");
  Status = Cdk2CorebootAppendStackHob (
             HobInfo,
             MAX_UINT64 - EFI_PAGE_SIZE + 1,
             EFI_PAGE_SIZE
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "wrapping stack HOB accepted");
  Status = Cdk2CorebootAppendModuleHob (
             HobInfo,
             &DxeCoreGuid,
             MAX_UINT64 - EFI_PAGE_SIZE + 1,
             EFI_PAGE_SIZE,
             MAX_UINT64
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "wrapping module HOB accepted");
  Status = Cdk2CorebootAppendFvHob (
             HobInfo,
             MAX_UINT64 - EFI_PAGE_SIZE + 1,
             EFI_PAGE_SIZE
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "wrapping FV HOB accepted");
  Failures += Expect (
                HobInfo->EfiEndOfHobList == PreviousEndOfHobList,
                "rejected descriptor append moved the end marker"
                );
  Failures += Expect (
                HobInfo->EfiFreeMemoryBottom == PreviousFreeMemoryBottom,
                "rejected descriptor append moved free bottom"
                );

  PreviousEndOfHobList     = HobInfo->EfiEndOfHobList;
  PreviousFreeMemoryBottom = HobInfo->EfiFreeMemoryBottom;
  PreviousEndMarker        = *(EFI_HOB_GENERIC_HEADER *)(UINTN)PreviousEndOfHobList;
  BadFreeMemoryBottom      = PreviousFreeMemoryBottom + sizeof (EFI_HOB_GENERIC_HEADER);
  HobInfo->EfiFreeMemoryBottom = BadFreeMemoryBottom;
  Status = Cdk2CorebootAppendCpuHob (HobInfo, 36, 16);
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "desynchronized PHIT append accepted");
  Failures += Expect (
                HobInfo->EfiEndOfHobList == PreviousEndOfHobList,
                "desynchronized PHIT append moved the end marker"
                );
  Failures += Expect (
                HobInfo->EfiFreeMemoryBottom == BadFreeMemoryBottom,
                "desynchronized PHIT append rewrote free bottom"
                );
  Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)PreviousEndOfHobList;
  Failures += Expect (
                Hob->HobType == PreviousEndMarker.HobType &&
                Hob->HobLength == PreviousEndMarker.HobLength,
                "desynchronized PHIT append overwrote the end marker"
                );
  HobInfo->EfiEndOfHobList     = PreviousEndOfHobList;
  HobInfo->EfiFreeMemoryBottom = PreviousFreeMemoryBottom;
  *(EFI_HOB_GENERIC_HEADER *)(UINTN)PreviousEndOfHobList = PreviousEndMarker;

  TransactionHandoff       = (CDK2_COREBOOT_HANDOFF){ 0 };
  TransactionFreeTopOffset = TEST_HOB_ALIGN8 (sizeof (EFI_HOB_HANDOFF_INFO_TABLE)) +
                             TEST_HOB_ALIGN8 (sizeof (EFI_HOB_FIRMWARE_VOLUME)) +
                             TEST_HOB_ALIGN8 (sizeof (EFI_HOB_MEMORY_ALLOCATION)) +
                             TEST_HOB_ALIGN8 (sizeof (EFI_HOB_GENERIC_HEADER));
  Status = Cdk2CorebootBuildHobs (
             &TransactionHandoff,
             TransactionHobStorage,
             TransactionHobStorage + sizeof (TransactionHobStorage),
             TransactionHobStorage,
             TransactionHobStorage + TransactionFreeTopOffset,
             FALSE,
             &TransactionHob
             );
  Failures += Expect (Status == EFI_SUCCESS, "transactional HOB construction failed");
  if (!EFI_ERROR (Status)) {
    TransactionEndOfHobList     = TransactionHob->EfiEndOfHobList;
    TransactionFreeMemoryBottom = TransactionHob->EfiFreeMemoryBottom;
    TransactionFreeMemoryTop    = TransactionHob->EfiFreeMemoryTop;
    TransactionEndMarker        = *(EFI_HOB_GENERIC_HEADER *)(UINTN)TransactionEndOfHobList;
    Status = Cdk2CorebootTestAppendLoadedDxeCoreHobs (
               TransactionHob,
               0x00100000,
               EFI_PAGE_SIZE,
               &DxeCoreGuid,
               0x00400000,
               EFI_PAGE_SIZE,
               0x00400100
               );
    Failures += Expect (Status == EFI_OUT_OF_RESOURCES, "partial DXE HOB append status");
    Failures += Expect (
                  TransactionHob->EfiEndOfHobList == TransactionEndOfHobList,
                  "partial DXE HOB append moved the end marker"
                  );
    Failures += Expect (
                  TransactionHob->EfiFreeMemoryBottom == TransactionFreeMemoryBottom,
                  "partial DXE HOB append moved free bottom"
                  );
    Failures += Expect (
                  TransactionHob->EfiFreeMemoryTop == TransactionFreeMemoryTop,
                  "partial DXE HOB append moved free top"
                  );
    Hob = (EFI_HOB_GENERIC_HEADER *)(UINTN)TransactionEndOfHobList;
    Failures += Expect (
                  Hob->HobType == TransactionEndMarker.HobType &&
                  Hob->HobLength == TransactionEndMarker.HobLength,
                  "partial DXE HOB append overwrote the end marker"
                  );
  }

  memset (mTransferHobStorage, 0, sizeof (mTransferHobStorage));
  TransferHob = (EFI_HOB_HANDOFF_INFO_TABLE *)(VOID *)mTransferHobStorage;
  TransferEnd = (EFI_HOB_GENERIC_HEADER *)(VOID *)(TransferHob + 1);
  TransferFreeBottom = (EFI_PHYSICAL_ADDRESS)(UINTN)(TransferEnd + 1);
  TransferFreeTop    = TransferFreeBottom + 0x20 * EFI_PAGE_SIZE;
  TransferHob->Header.HobType      = EFI_HOB_TYPE_HANDOFF;
  TransferHob->Header.HobLength    = sizeof (*TransferHob);
  TransferHob->Version             = EFI_HOB_HANDOFF_TABLE_VERSION;
  TransferHob->BootMode            = BOOT_WITH_FULL_CONFIGURATION;
  TransferHob->EfiMemoryBottom     = (EFI_PHYSICAL_ADDRESS)(UINTN)mTransferHobStorage;
  TransferHob->EfiMemoryTop        = TransferFreeTop;
  TransferHob->EfiEndOfHobList     = (EFI_PHYSICAL_ADDRESS)(UINTN)TransferEnd;
  TransferHob->EfiFreeMemoryBottom = TransferFreeBottom;
  TransferHob->EfiFreeMemoryTop    = TransferFreeTop;
  TransferEnd->HobType             = EFI_HOB_TYPE_END_OF_HOB_LIST;
  TransferEnd->HobLength           = sizeof (*TransferEnd);
  TransferContext = (CDK2_NATIVE_CONTEXT){ 0 };
  TransferContext.HobList          = TransferHob;
  TransferContext.HobListSize      = sizeof (*TransferHob) + sizeof (*TransferEnd);
  TransferContext.ImageBase        = 0x00400000;
  TransferContext.ImageSize        = 0x00020000;
  TransferContext.ImageEntryPoint  = 0x00401000;
  TransferContext.AllocationBottom = TransferFreeBottom;
  TransferContext.AllocationTop    = TransferFreeTop;
  TransferContext.ImageSize        = 0;
  Status = Cdk2CorebootTestTransfer (&TransferContext);
  Failures += Expect (Status == EFI_NOT_READY, "transfer accepted invalid handoff image");
  TransferContext.ImageSize        = 0x00020000;
  Status = Cdk2CorebootTestTransfer (&TransferContext);
  Failures += Expect (Status == EFI_OUT_OF_RESOURCES, "transfer stack HOB exhaustion status");
  Failures += Expect (
                TransferContext.AllocationBottom == TransferFreeBottom,
                "failed transfer moved allocation bottom"
                );
  Failures += Expect (
                TransferContext.AllocationTop == TransferFreeTop,
                "failed transfer moved allocation top"
                );
  Failures += Expect (
                TransferHob->EfiFreeMemoryTop == TransferFreeTop,
                "failed transfer moved PHIT free top"
                );
  Failures += Expect (
                TransferHob->EfiEndOfHobList == (EFI_PHYSICAL_ADDRESS)(UINTN)TransferEnd,
                "failed transfer moved HOB end marker"
                );

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             TinyHobStorage,
             TinyHobStorage + sizeof (TinyHobStorage),
             TinyHobStorage,
             TinyHobStorage + sizeof (TinyHobStorage),
             FALSE,
             &HobInfo
             );
  Failures += Expect (Status == EFI_OUT_OF_RESOURCES, "HOB exhaustion was not rejected");

  Status = Cdk2CorebootBuildHobs (
             &Handoff,
             (VOID *)(UINTN)0x1000,
             (VOID *)(UINTN)MAX_UINTN,
             (VOID *)(UINTN)(MAX_UINTN - 3U),
             (VOID *)(UINTN)MAX_UINTN,
             FALSE,
             &HobInfo
             );
  Failures += Expect (Status == EFI_INVALID_PARAMETER, "wrapped HOB free bottom accepted");

  Handoff = (CDK2_COREBOOT_HANDOFF){ 0 };
  Handoff.MemoryRangeCount     = 1;
  Handoff.MemoryRanges[0].Base = TEST_TEMP_MAP_LIMIT - TEST_HOB_REGION_SIZE;
  Handoff.MemoryRanges[0].Size = TEST_HOB_REGION_SIZE;
  Handoff.MemoryRanges[0].Type = CB_MEM_RAM;
  HobMemBase = 0;
  Status = Cdk2CorebootFindHobMemoryBase (
             &Handoff,
             0x00100000,
             0x00100000,
             TEST_HOB_REGION_SIZE,
             TEST_TEMP_MAP_LIMIT,
             &HobMemBase
             );
  Failures += Expect (Status == EFI_SUCCESS, "temp-map edge HOB memory rejected");
  Failures += Expect (
                HobMemBase == (UINTN)(TEST_TEMP_MAP_LIMIT - TEST_HOB_REGION_SIZE),
                "temp-map edge HOB memory base is wrong"
                );

  Handoff = (CDK2_COREBOOT_HANDOFF){ 0 };
  Handoff.MemoryRangeCount     = 1;
  Handoff.MemoryRanges[0].Base = MAX_UINT64 - 0xfffULL;
  Handoff.MemoryRanges[0].Size = 0x800;
  Handoff.MemoryRanges[0].Type = CB_MEM_RAM;
  Status = Cdk2CorebootFindHobMemoryBase (
             &Handoff,
             0x00100000,
             0x00100000,
             TEST_HOB_REGION_SIZE,
             TEST_TEMP_MAP_LIMIT,
             &HobMemBase
             );
  Failures += Expect (Status == EFI_OUT_OF_RESOURCES, "high aligned RAM range selected HOB memory");

  Handoff.MemoryRanges[0].Base = MAX_UINT64 - 0x7ffULL;
  Handoff.MemoryRanges[0].Size = 0x1000;
  Status = Cdk2CorebootFindHobMemoryBase (
             &Handoff,
             0x00100000,
             0x00100000,
             TEST_HOB_REGION_SIZE,
             TEST_TEMP_MAP_LIMIT,
             &HobMemBase
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "wrapping RAM range accepted for HOB memory");

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
             FALSE,
             &HobInfo
             );
  Failures += Expect (Status == EFI_COMPROMISED_DATA, "overlapping memory ranges accepted");

  if (Failures != 0) {
    return 1;
  }

  puts ("cdk2 coreboot test: PASS");
  return 0;
}
