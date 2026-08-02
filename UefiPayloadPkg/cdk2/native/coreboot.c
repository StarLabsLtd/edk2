/** @file

  Freestanding coreboot table validation for the native cdk2 stage.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot.h"

#define CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK \
  (EFI_CACHE_ATTRIBUTE_MASK | EFI_MEMORY_ACCESS_MASK | EFI_MEMORY_NV | \
   EFI_MEMORY_MORE_RELIABLE | EFI_MEMORY_SP | EFI_MEMORY_CPU_CRYPTO | \
   EFI_MEMORY_HOT_PLUGGABLE | EFI_MEMORY_RUNTIME)

STATIC
UINT64
Cdk2CorebootUnpack64 (
  IN CONST struct cbuint64  *Value
  )
{
  return (UINT64)Value->lo | ((UINT64)Value->hi << 32);
}

STATIC
UINT64
Cdk2CorebootUnpack64At (
  IN CONST VOID  *Base,
  IN UINTN        Offset
  )
{
  return Cdk2CorebootUnpack64 (
           (CONST struct cbuint64 *)(CONST VOID *)((CONST UINT8 *)Base + Offset)
           );
}

UINT16
Cdk2CorebootChecksum16 (
  IN CONST VOID  *Buffer,
  IN UINTN        Length
  )
{
  CONST UINT8  *Bytes;
  UINT32        Sum;
  UINTN         Index;

  if (Buffer == NULL) {
    return 0;
  }

  Bytes = (CONST UINT8 *)Buffer;
  Sum   = 0;
  for (Index = 0; Index < Length; Index++) {
    Sum += (Index & 1) ? ((UINT32)Bytes[Index] << 8) : Bytes[Index];
    if (Sum >= 0x10000U) {
      Sum = (Sum + (Sum >> 16)) & 0xffffU;
    }
  }

  return (UINT16)(~Sum & 0xffffU);
}

STATIC
UINT32
Cdk2CorebootCrc32Update (
  IN UINT32  Crc,
  IN UINT8   Byte
  )
{
  UINTN  BitIndex;

  Crc ^= (UINT32)Byte << 24;
  for (BitIndex = 0; BitIndex < 8; BitIndex++) {
    if ((Crc & BIT31) != 0) {
      Crc = (Crc << 1) ^ 0x04C11DB7U;
    } else {
      Crc <<= 1;
    }
  }

  return Crc;
}

UINT32
Cdk2CorebootCalculateCrc32 (
  IN CONST VOID  *Buffer,
  IN UINTN        Length
  )
{
  CONST UINT8  *Bytes;
  UINT32        Crc;
  UINTN         Index;

  if (Buffer == NULL) {
    return 0;
  }

  Bytes = (CONST UINT8 *)Buffer;
  Crc   = 0;
  for (Index = 0; Index < Length; Index++) {
    Crc = Cdk2CorebootCrc32Update (Crc, Bytes[Index]);
  }

  return Crc;
}

STATIC
BOOLEAN
Cdk2CorebootAligned4 (
  IN UINTN  Value
  )
{
  return (Value & 3U) == 0;
}

STATIC
BOOLEAN
Cdk2CorebootU32RangeWithin (
  IN  UINT32  Offset,
  IN  UINT32  Length,
  IN  UINT32  Limit,
  OUT UINT32  *End OPTIONAL
  )
{
  if (Offset > Limit || Length > Limit - Offset) {
    return FALSE;
  }

  if (End != NULL) {
    *End = Offset + Length;
  }

  return TRUE;
}

STATIC
UINTN
Cdk2CorebootBitCount64 (
  IN UINT64  Value
  )
{
  UINTN  Count;

  Count = 0;
  while (Value != 0) {
    Count += (UINTN)(Value & 1U);
    Value >>= 1;
  }

  return Count;
}

STATIC
BOOLEAN
Cdk2CorebootU64RangeEnd (
  IN  UINT64  Base,
  IN  UINT64  Length,
  OUT UINT64  *End
  )
{
  if (End == NULL || Length == 0 || Base > MAX_UINT64 - Length) {
    return FALSE;
  }

  *End = Base + Length;
  return TRUE;
}

STATIC
UINT64
Cdk2CorebootPayloadResourceLifetime (
  IN CONST struct cb_payload_resource_handoff *Record
  )
{
  return Cdk2CorebootUnpack64At (
           Record,
           OFFSET_OF (struct cb_payload_resource_handoff, lifetime_flags)
           );
}

STATIC
UINT64
Cdk2CorebootPayloadResourceProducerGeneration (
  IN CONST struct cb_payload_resource_handoff *Record
  )
{
  return Cdk2CorebootUnpack64At (
           Record,
           OFFSET_OF (struct cb_payload_resource_handoff, producer_generation)
           );
}

STATIC
CONST struct cb_payload_resource_section *
Cdk2CorebootPayloadResourceFindSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN UINT16                                    Type
  )
{
  CONST struct cb_payload_resource_section  *Section;
  UINTN                                      Index;

  for (Index = 0; Index < Record->section_count; Index++) {
    Section = (CONST struct cb_payload_resource_section *)(CONST VOID *)(
                                                             (CONST UINT8 *)Record +
                                                             Record->header_length +
                                                             Index * Record->section_header_length
                                                             );
    if (Section->type == Type) {
      return Section;
    }
  }

  return NULL;
}

STATIC
UINT32
Cdk2CorebootPayloadResourceCrc32 (
  IN CONST struct cb_payload_resource_handoff  *Record
  )
{
  CONST UINT8  *Bytes;
  UINT32        Crc;
  UINTN         CrcOffset;
  UINTN         Index;
  UINT8         Byte;

  if (Record == NULL) {
    return 0;
  }

  Bytes     = (CONST UINT8 *)Record;
  Crc       = 0;
  CrcOffset = OFFSET_OF (struct cb_payload_resource_handoff, crc32);
  for (Index = 0; Index < Record->size; Index++) {
    Byte = ((Index >= CrcOffset) && (Index < CrcOffset + sizeof (Record->crc32))) ?
           0 :
           Bytes[Index];
    Crc = Cdk2CorebootCrc32Update (Crc, Byte);
  }

  return Crc;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePayloadResourceSectionBounds (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section,
  IN UINT32                                    SectionTableEnd
  )
{
  UINT32  PayloadEnd;
  UINT64  EntryBytes;

  if (Section->header_length < CDK2_COREBOOT_PAYLOAD_RESOURCE_SECTION_MIN_SIZE ||
      Section->header_length > Record->section_header_length ||
      (Section->flags & ~CB_PRH_SECTION_FLAG_VALID_MASK) != 0 ||
      !Cdk2CorebootAligned4 (Section->header_length) ||
      !Cdk2CorebootAligned4 (Section->offset) ||
      !Cdk2CorebootAligned4 (Section->length))
  {
    return ((Section->flags & ~CB_PRH_SECTION_FLAG_VALID_MASK) != 0) ?
           EFI_UNSUPPORTED :
           EFI_COMPROMISED_DATA;
  }

  if (!Cdk2CorebootU32RangeWithin (Section->offset, Section->length, Record->size, &PayloadEnd)) {
    return EFI_COMPROMISED_DATA;
  }

  if (Section->length != 0 && Section->offset < SectionTableEnd) {
    return EFI_COMPROMISED_DATA;
  }

  if (Section->entry_size == 0) {
    return (Section->entry_count == 0) ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
  }

  if (!Cdk2CorebootAligned4 (Section->entry_size)) {
    return EFI_COMPROMISED_DATA;
  }

  EntryBytes = (UINT64)Section->entry_size * Section->entry_count;
  if (EntryBytes > Section->length) {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePayloadResourceFixedEntries (
  IN CONST struct cb_payload_resource_section *Section,
  IN UINT32                                    MinimumEntrySize,
  IN BOOLEAN                                   RequireEntries
  )
{
  UINT64  EntryBytes;

  if (Section->entry_size < MinimumEntrySize ||
      !Cdk2CorebootAligned4 (Section->entry_size))
  {
    return EFI_COMPROMISED_DATA;
  }

  if (RequireEntries && Section->entry_count == 0) {
    return EFI_COMPROMISED_DATA;
  }

  EntryBytes = (UINT64)Section->entry_size * Section->entry_count;
  if (EntryBytes != Section->length) {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidateMemoryPolicySection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST UINT8                         *Base;
  CONST struct cb_prh_memory_policy_entry *Entry;
  UINT64                               PreviousEnd;
  UINT64                               RangeBase;
  UINT64                               RangeLength;
  UINT64                               RangeEnd;
  UINT64                               Capabilities;
  UINT64                               Attributes;
  UINT64                               UnsupportedAttributes;
  UINTN                                Index;
  EFI_STATUS                           Status;

  Status = Cdk2CorebootValidatePayloadResourceFixedEntries (
             Section,
             sizeof (struct cb_prh_memory_policy_entry),
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Base        = (CONST UINT8 *)Record + Section->offset;
  PreviousEnd = 0;
  for (Index = 0; Index < Section->entry_count; Index++) {
    Entry       = (CONST struct cb_prh_memory_policy_entry *)(CONST VOID *)(Base + Index * Section->entry_size);
    RangeBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_memory_policy_entry, base));
    RangeLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_memory_policy_entry, length));
    if (!Cdk2CorebootU64RangeEnd (RangeBase, RangeLength, &RangeEnd) ||
        (Index != 0 && RangeBase < PreviousEnd))
    {
      return EFI_COMPROMISED_DATA;
    }

    Capabilities         = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_memory_policy_entry, capabilities));
    Attributes           = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_memory_policy_entry, attributes));
    UnsupportedAttributes = (Capabilities | Attributes) & ~CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK;
    if (UnsupportedAttributes != 0) {
      return EFI_UNSUPPORTED;
    }

    if ((Entry->owner_flags & ~CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK) != 0 ||
        Entry->reserved != 0)
    {
      return ((Entry->owner_flags & ~CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK) != 0) ?
             EFI_UNSUPPORTED :
             EFI_COMPROMISED_DATA;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_GCD_AUTHORITATIVE) != 0 &&
        Entry->gcd_type > CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED)
    {
      return EFI_UNSUPPORTED;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE) != 0 &&
        Entry->efi_memory_type >= EfiMaxMemoryType)
    {
      return EFI_UNSUPPORTED;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) != 0 &&
        Cdk2CorebootBitCount64 (Attributes & EFI_CACHE_ATTRIBUTE_MASK) != 1)
    {
      return EFI_COMPROMISED_DATA;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE) != 0 &&
        (((RangeBase | RangeLength) & EFI_PAGE_MASK) != 0))
    {
      return EFI_COMPROMISED_DATA;
    }

    PreviousEnd = RangeEnd;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidateX86CacheSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST struct cb_prh_x86_cache_state *CacheState;
  UINT64                               VariableBytes;
  UINT64                               LifetimeFlags;

  if (Section->length < sizeof (struct cb_prh_x86_cache_state) ||
      Section->entry_size < sizeof (struct cb_prh_x86_variable_mtrr) ||
      !Cdk2CorebootAligned4 (Section->entry_size))
  {
    return EFI_COMPROMISED_DATA;
  }

  CacheState = (CONST struct cb_prh_x86_cache_state *)(CONST VOID *)((CONST UINT8 *)Record + Section->offset);
  if (CacheState->variable_count != Section->entry_count) {
    return EFI_COMPROMISED_DATA;
  }

  if ((CacheState->flags & ~CB_PRH_X86_CACHE_FLAG_VALID_MASK) != 0) {
    return EFI_UNSUPPORTED;
  }

  LifetimeFlags = Cdk2CorebootPayloadResourceLifetime (Record);
  if (((CacheState->flags & CB_PRH_X86_CACHE_FLAG_S3_VALID) != 0) &&
      ((LifetimeFlags & CB_PRH_LIFETIME_S3_RESUME) == 0))
  {
    return EFI_COMPROMISED_DATA;
  }

  VariableBytes = (UINT64)Section->entry_size * Section->entry_count;
  if (VariableBytes != Section->length - sizeof (*CacheState)) {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePciRootBridgesSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST UINT8                          *Base;
  CONST struct cb_prh_pci_root_bridge_entry *Entry;
  UINT64                                WindowBase;
  UINT64                                WindowLength;
  UINT64                                WindowEnd;
  UINTN                                 Index;
  EFI_STATUS                            Status;

  Status = Cdk2CorebootValidatePayloadResourceFixedEntries (
             Section,
             sizeof (struct cb_prh_pci_root_bridge_entry),
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Base = (CONST UINT8 *)Record + Section->offset;
  for (Index = 0; Index < Section->entry_count; Index++) {
    Entry = (CONST struct cb_prh_pci_root_bridge_entry *)(CONST VOID *)(Base + Index * Section->entry_size);
    if (Entry->bus_start > Entry->bus_end || Entry->flags != 0) {
      return (Entry->flags != 0) ? EFI_UNSUPPORTED : EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem64_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem64_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem32_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem32_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem64_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem64_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePciAssignmentsSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST UINT8                         *Base;
  CONST struct cb_prh_pci_assignment_entry *Entry;
  UINT64                               ResourceBase;
  UINT64                               ResourceLength;
  UINT64                               ResourceEnd;
  UINTN                                Index;
  EFI_STATUS                           Status;

  Status = Cdk2CorebootValidatePayloadResourceFixedEntries (
             Section,
             sizeof (struct cb_prh_pci_assignment_entry),
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Base = (CONST UINT8 *)Record + Section->offset;
  for (Index = 0; Index < Section->entry_count; Index++) {
    Entry = (CONST struct cb_prh_pci_assignment_entry *)(CONST VOID *)(Base + Index * Section->entry_size);
    if (Entry->device > 31 || Entry->function > 7 ||
        Entry->resource_type < CB_PRH_PCI_RESOURCE_IO ||
        Entry->resource_type > CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64)
    {
      return EFI_COMPROMISED_DATA;
    }

    if (Entry->flags != 0) {
      return EFI_UNSUPPORTED;
    }

    ResourceBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_assignment_entry, base));
    ResourceLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_assignment_entry, length));
    if (!Cdk2CorebootU64RangeEnd (ResourceBase, ResourceLength, &ResourceEnd)) {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
Cdk2CorebootPixelMaskValid (
  IN UINT8  Position,
  IN UINT8  Size
  )
{
  if (Size == 0) {
    return Position == 0;
  }

  return Position < 32 && Size <= 32 && Size <= 32 - Position;
}

STATIC
EFI_STATUS
Cdk2CorebootValidateFramebufferSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST UINT8                           *Base;
  CONST struct cb_prh_framebuffer_entry *Entry;
  UINT64                                FramebufferBase;
  UINT64                                FramebufferSize;
  UINT64                                FramebufferEnd;
  UINT64                                MinimumLineBits;
  UINT64                                MinimumLineBytes;
  UINT64                                MinimumSize;
  UINTN                                 Index;
  EFI_STATUS                            Status;

  Status = Cdk2CorebootValidatePayloadResourceFixedEntries (
             Section,
             CDK2_COREBOOT_PRH_FRAMEBUFFER_MIN_SIZE,
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Base = (CONST UINT8 *)Record + Section->offset;
  for (Index = 0; Index < Section->entry_count; Index++) {
    Entry = (CONST struct cb_prh_framebuffer_entry *)(CONST VOID *)(Base + Index * Section->entry_size);
    if ((Entry->owner_flags & ~CB_PRH_FRAMEBUFFER_OWNER_FLAG_VALID_MASK) != 0) {
      return EFI_UNSUPPORTED;
    }

    if ((Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0 &&
        (Entry->owner_flags & CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE) == 0)
    {
      return EFI_COMPROMISED_DATA;
    }

    if (Entry->reserved[0] != 0 || Entry->reserved[1] != 0 || Entry->reserved[2] != 0 ||
        Entry->bits_per_pixel == 0 || Entry->bits_per_pixel > 32 ||
        Entry->x_resolution == 0 || Entry->y_resolution == 0 ||
        Entry->bytes_per_line == 0)
    {
      return EFI_COMPROMISED_DATA;
    }

    MinimumLineBits  = (UINT64)Entry->x_resolution * Entry->bits_per_pixel;
    MinimumLineBytes = (MinimumLineBits + 7U) / 8U;
    MinimumSize      = (UINT64)Entry->bytes_per_line * Entry->y_resolution;
    if (MinimumLineBytes > Entry->bytes_per_line) {
      return EFI_COMPROMISED_DATA;
    }

    if (!Cdk2CorebootPixelMaskValid (Entry->red_mask_pos, Entry->red_mask_size) ||
        !Cdk2CorebootPixelMaskValid (Entry->green_mask_pos, Entry->green_mask_size) ||
        !Cdk2CorebootPixelMaskValid (Entry->blue_mask_pos, Entry->blue_mask_size) ||
        !Cdk2CorebootPixelMaskValid (Entry->reserved_mask_pos, Entry->reserved_mask_size))
    {
      return EFI_COMPROMISED_DATA;
    }

    FramebufferBase = Cdk2CorebootUnpack64At (
                        Entry,
                        OFFSET_OF (struct cb_prh_framebuffer_entry, physical_address)
                        );
    FramebufferSize = Cdk2CorebootUnpack64At (
                        Entry,
                        OFFSET_OF (struct cb_prh_framebuffer_entry, size)
                        );
    if (!Cdk2CorebootU64RangeEnd (FramebufferBase, FramebufferSize, &FramebufferEnd) ||
        FramebufferSize < MinimumSize)
    {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePayloadResourceCrossSectionRules (
  IN CONST struct cb_payload_resource_handoff *Record
  )
{
  CONST struct cb_payload_resource_section *Section;
  CONST struct cb_payload_resource_section *X86CacheSection;
  CONST struct cb_prh_memory_policy_entry  *MemoryEntry;
  CONST struct cb_prh_x86_cache_state      *CacheState;
  CONST UINT8                              *SectionBase;
  UINT64                                    LifetimeFlags;
  BOOLEAN                                   AuthoritativeSection;
  BOOLEAN                                   CacheAuthoritativeMemory;
  BOOLEAN                                   ProtectionAuthoritativeMemory;
  BOOLEAN                                   PciAssignmentAuthoritative;
  BOOLEAN                                   PciRootBridgeAuthoritative;
  UINTN                                     Index;
  UINTN                                     EntryIndex;

  LifetimeFlags = Cdk2CorebootPayloadResourceLifetime (Record);
  if ((LifetimeFlags & ~CB_PRH_LIFETIME_VALID_MASK) != 0) {
    return EFI_UNSUPPORTED;
  }

  AuthoritativeSection          = FALSE;
  CacheAuthoritativeMemory      = FALSE;
  ProtectionAuthoritativeMemory = FALSE;
  PciAssignmentAuthoritative    = FALSE;
  PciRootBridgeAuthoritative    = FALSE;
  for (Index = 0; Index < Record->section_count; Index++) {
    Section = (CONST struct cb_payload_resource_section *)(CONST VOID *)(
                                                            (CONST UINT8 *)Record +
                                                            Record->header_length +
                                                            Index * Record->section_header_length
                                                            );
    if ((Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0) {
      AuthoritativeSection = TRUE;
    }

    if (Section->type == CB_PRH_SECTION_MEMORY_POLICY) {
      SectionBase = (CONST UINT8 *)Record + Section->offset;
      for (EntryIndex = 0; EntryIndex < Section->entry_count; EntryIndex++) {
        MemoryEntry = (CONST struct cb_prh_memory_policy_entry *)(CONST VOID *)(
                                                                      SectionBase +
                                                                      EntryIndex * Section->entry_size
                                                                      );
        if ((MemoryEntry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) != 0) {
          CacheAuthoritativeMemory = TRUE;
        }

        if ((MemoryEntry->owner_flags & CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE) != 0) {
          ProtectionAuthoritativeMemory = TRUE;
        }
      }
    } else if (Section->type == CB_PRH_SECTION_PCI_ROOT_BRIDGES &&
               (Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0)
    {
      PciRootBridgeAuthoritative = TRUE;
    } else if (Section->type == CB_PRH_SECTION_PCI_ASSIGNMENTS &&
               (Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0)
    {
      PciAssignmentAuthoritative = TRUE;
    }
  }

  if (AuthoritativeSection &&
      (((LifetimeFlags & CB_PRH_LIFETIME_COLD_BOOT) == 0) ||
       ((LifetimeFlags & CB_PRH_LIFETIME_VALID_UNTIL_MASK) == 0)))
  {
    return EFI_COMPROMISED_DATA;
  }

  if (((LifetimeFlags & CB_PRH_LIFETIME_S3_RESUME) != 0) &&
      Cdk2CorebootPayloadResourceProducerGeneration (Record) == 0)
  {
    return EFI_COMPROMISED_DATA;
  }

  if (CacheAuthoritativeMemory) {
    X86CacheSection = Cdk2CorebootPayloadResourceFindSection (
                        Record,
                        CB_PRH_SECTION_X86_CACHE_STATE
                        );
    if (X86CacheSection == NULL ||
        (X86CacheSection->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0)
    {
      return EFI_UNSUPPORTED;
    }

    CacheState = (CONST struct cb_prh_x86_cache_state *)(CONST VOID *)(
                                                          (CONST UINT8 *)Record +
                                                          X86CacheSection->offset
                                                          );
    if ((CacheState->flags & CB_PRH_X86_CACHE_FLAG_BSP_AP_SYNC) == 0) {
      return EFI_UNSUPPORTED;
    }

    if (((LifetimeFlags & CB_PRH_LIFETIME_S3_RESUME) != 0) &&
        ((CacheState->flags & CB_PRH_X86_CACHE_FLAG_S3_VALID) == 0))
    {
      return EFI_UNSUPPORTED;
    }
  }

  if (ProtectionAuthoritativeMemory) {
    return EFI_UNSUPPORTED;
  }

  if (PciAssignmentAuthoritative && !PciRootBridgeAuthoritative) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePayloadResourceHandoff (
  IN CONST struct cb_payload_resource_handoff  *Record
  )
{
  CONST struct cb_payload_resource_section *Section;
  CONST struct cb_payload_resource_section *OtherSection;
  UINT64                                    SectionBytes;
  UINT32                                    SectionTableEnd;
  UINTN                                     Index;
  UINTN                                     OtherIndex;
  EFI_STATUS                                Status;

  if (Record->tag != CB_TAG_PAYLOAD_RESOURCE_HANDOFF ||
      Record->size < CDK2_COREBOOT_PAYLOAD_RESOURCE_HANDOFF_MIN_SIZE ||
      !Cdk2CorebootAligned4 (Record->size) ||
      Record->header_length < CDK2_COREBOOT_PAYLOAD_RESOURCE_HANDOFF_MIN_SIZE ||
      Record->header_length > Record->size ||
      !Cdk2CorebootAligned4 (Record->header_length) ||
      Record->section_header_length < CDK2_COREBOOT_PAYLOAD_RESOURCE_SECTION_MIN_SIZE ||
      !Cdk2CorebootAligned4 (Record->section_header_length) ||
      Record->section_count > CDK2_COREBOOT_PAYLOAD_RESOURCE_MAX_SECTIONS)
  {
    return EFI_COMPROMISED_DATA;
  }

  if (Record->revision != CB_PAYLOAD_RESOURCE_HANDOFF_REVISION) {
    return EFI_UNSUPPORTED;
  }

  if (Record->flags != 0) {
    return EFI_UNSUPPORTED;
  }

  if ((Cdk2CorebootPayloadResourceLifetime (Record) & ~CB_PRH_LIFETIME_VALID_MASK) != 0) {
    return EFI_UNSUPPORTED;
  }

  SectionBytes = (UINT64)Record->section_header_length * Record->section_count;
  if (SectionBytes > MAX_UINT32 ||
      !Cdk2CorebootU32RangeWithin (Record->header_length, (UINT32)SectionBytes, Record->size, &SectionTableEnd))
  {
    return EFI_COMPROMISED_DATA;
  }

  if (Cdk2CorebootPayloadResourceCrc32 (Record) != Record->crc32) {
    return EFI_CRC_ERROR;
  }

  for (Index = 0; Index < Record->section_count; Index++) {
    Section = (CONST struct cb_payload_resource_section *)(CONST VOID *)(
                                                            (CONST UINT8 *)Record +
                                                            Record->header_length +
                                                            Index * Record->section_header_length
                                                            );
    Status = Cdk2CorebootValidatePayloadResourceSectionBounds (
               Record,
               Section,
               SectionTableEnd
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    for (OtherIndex = 0; OtherIndex < Index; OtherIndex++) {
      OtherSection = (CONST struct cb_payload_resource_section *)(CONST VOID *)(
                                                               (CONST UINT8 *)Record +
                                                               Record->header_length +
                                                               OtherIndex * Record->section_header_length
                                                               );
      if (Section->type == OtherSection->type) {
        return EFI_COMPROMISED_DATA;
      }

      if ((Section->length != 0) && (OtherSection->length != 0) &&
          ((Section->offset < OtherSection->offset + OtherSection->length) &&
           (OtherSection->offset < Section->offset + Section->length)))
      {
        return EFI_COMPROMISED_DATA;
      }
    }

    switch (Section->type) {
      case CB_PRH_SECTION_MEMORY_POLICY:
        Status = Cdk2CorebootValidateMemoryPolicySection (Record, Section);
        break;

      case CB_PRH_SECTION_X86_CACHE_STATE:
        Status = Cdk2CorebootValidateX86CacheSection (Record, Section);
        break;

      case CB_PRH_SECTION_PCI_ROOT_BRIDGES:
        Status = Cdk2CorebootValidatePciRootBridgesSection (Record, Section);
        break;

      case CB_PRH_SECTION_PCI_ASSIGNMENTS:
        Status = Cdk2CorebootValidatePciAssignmentsSection (Record, Section);
        break;

      case CB_PRH_SECTION_FRAMEBUFFER:
        Status = Cdk2CorebootValidateFramebufferSection (Record, Section);
        break;

      case CB_PRH_SECTION_BOOT_INTENT:
      case CB_PRH_SECTION_RUNTIME_POLICY:
        // These sections are reserved until their semantic contracts exist.
        Status = EFI_UNSUPPORTED;
        break;

      default:
        Status = ((Section->flags & CB_PRH_SECTION_FLAG_MANDATORY) != 0) ?
                 EFI_UNSUPPORTED :
                 EFI_SUCCESS;
        break;
    }

    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return Cdk2CorebootValidatePayloadResourceCrossSectionRules (Record);
}

STATIC
EFI_STATUS
Cdk2CorebootParseOneTable (
  IN  CONST VOID             *Table,
  IN  UINTN                   TableSize,
  OUT CDK2_COREBOOT_HANDOFF  *Handoff
  )
{
  CONST struct cb_header        *Header;
  CONST UINT8                   *RecordBytes;
  CONST struct cb_record        *Record;
  CONST struct cb_memory        *Memory;
  CONST struct cb_memory_range  *Range;
  CONST struct cb_forward       *Forward;
  UINTN                          HeaderBytes;
  UINTN                          RecordsRemaining;
  UINTN                          RecordIndex;
  UINTN                          RangeCount;
  UINTN                          RangeIndex;
  UINT64                         Base;
  UINT64                         Size;
  UINT64                         End;

  if (Table == NULL || Handoff == NULL || TableSize < sizeof (struct cb_header)) {
    return EFI_INVALID_PARAMETER;
  }

  Header      = (CONST struct cb_header *)Table;
  HeaderBytes = Header->header_bytes;
  if (Header->signature != CB_HEADER_SIGNATURE ||
      HeaderBytes < sizeof (struct cb_header) ||
      HeaderBytes > TableSize ||
      Header->table_bytes == 0 ||
      Header->table_bytes > CDK2_COREBOOT_MAX_TABLE_BYTES ||
      Header->table_bytes > TableSize - HeaderBytes ||
      Header->table_entries == 0 ||
      Header->table_entries > CDK2_COREBOOT_MAX_RECORDS)
  {
    return EFI_COMPROMISED_DATA;
  }

  if (Cdk2CorebootChecksum16 (Header, sizeof (struct cb_header)) != 0 ||
      Cdk2CorebootChecksum16 (
        (CONST UINT8 *)Header + HeaderBytes,
        Header->table_bytes
        ) != (UINT16)Header->table_checksum)
  {
    return EFI_COMPROMISED_DATA;
  }

  *Handoff = (CDK2_COREBOOT_HANDOFF){ 0 };
  Handoff->Header                       = Header;
  Handoff->TableSize                    = HeaderBytes + Header->table_bytes;
  Handoff->PayloadResourceHandoffStatus = EFI_NOT_FOUND;

  RecordBytes      = (CONST UINT8 *)Header + HeaderBytes;
  RecordsRemaining = Header->table_bytes;
  RecordIndex      = 0;
  while (RecordIndex < Header->table_entries) {
    if (RecordsRemaining < sizeof (struct cb_record)) {
      return EFI_COMPROMISED_DATA;
    }

    Record = (CONST struct cb_record *)(RecordBytes + (Header->table_bytes - RecordsRemaining));
    if (Record->size < sizeof (struct cb_record) || Record->size > RecordsRemaining) {
      return EFI_COMPROMISED_DATA;
    }

    Handoff->RecordCount++;
    switch (Record->tag) {
      case CB_TAG_MEMORY:
        if (Record->size < sizeof (struct cb_memory)) {
          return EFI_COMPROMISED_DATA;
        }

        RangeCount = (Record->size - sizeof (struct cb_memory)) /
                     sizeof (struct cb_memory_range);
        if ((Record->size - sizeof (struct cb_memory)) % sizeof (struct cb_memory_range) != 0 ||
            RangeCount > CDK2_COREBOOT_MAX_MEMORY_RANGES - Handoff->MemoryRangeCount)
        {
          return EFI_COMPROMISED_DATA;
        }

        Memory = (CONST struct cb_memory *)Record;
        for (RangeIndex = 0; RangeIndex < RangeCount; RangeIndex++) {
          Range = &Memory->map[RangeIndex];
          Base  = Cdk2CorebootUnpack64 (&Range->start);
          Size  = Cdk2CorebootUnpack64 (&Range->size);
          End   = Base + Size;
          if (Size == 0 || End < Base) {
            return EFI_COMPROMISED_DATA;
          }

          Handoff->MemoryRanges[Handoff->MemoryRangeCount].Base = Base;
          Handoff->MemoryRanges[Handoff->MemoryRangeCount].Size = Size;
          Handoff->MemoryRanges[Handoff->MemoryRangeCount].Type = Range->type;
          Handoff->MemoryRangeCount++;

          if (Range->type == CB_MEM_RAM) {
            Handoff->UsableRamCount++;
            if (Size > Handoff->LargestUsableRamSize) {
              Handoff->LargestUsableRamBase = Base;
              Handoff->LargestUsableRamSize = Size;
            }
          }
        }

        break;

      case CB_TAG_FORWARD:
        if (Record->size != sizeof (struct cb_forward) ||
            Handoff->ForwardAddress != 0)
        {
          return EFI_COMPROMISED_DATA;
        }

        Forward = (CONST struct cb_forward *)Record;
        if (Forward->forward == 0) {
          return EFI_COMPROMISED_DATA;
        }

        Handoff->ForwardAddress = Forward->forward;
        break;

      case CB_TAG_PAYLOAD_RESOURCE_HANDOFF:
        if (Handoff->PayloadResourceHandoffStatus != EFI_NOT_FOUND) {
          Handoff->PayloadResourceHandoffStatus = EFI_COMPROMISED_DATA;
          Handoff->PayloadResourceHandoff       = NULL;
          break;
        }

        Handoff->PayloadResourceHandoffStatus = Cdk2CorebootValidatePayloadResourceHandoff (
                                                  (CONST struct cb_payload_resource_handoff *)Record
                                                  );
        if (!EFI_ERROR (Handoff->PayloadResourceHandoffStatus)) {
          Handoff->PayloadResourceHandoff = (CONST struct cb_payload_resource_handoff *)Record;
        }

        break;

      default:
        break;
    }

    RecordsRemaining -= Record->size;
    RecordIndex++;
  }

  if (RecordsRemaining != 0) {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
Cdk2CorebootParseTable (
  IN  CONST VOID             *Table,
  IN  UINTN                   TableSize,
  OUT CDK2_COREBOOT_HANDOFF  *Handoff
  )
{
  return Cdk2CorebootParseOneTable (Table, TableSize, Handoff);
}

EFI_STATUS
Cdk2CorebootParse (
  IN  UINTN                   BootloaderParameter,
  OUT CDK2_COREBOOT_HANDOFF  *Handoff
  )
{
  CONST VOID  *Table;
  UINTN        Depth;
  EFI_STATUS   Status;

  if (BootloaderParameter == 0 || Handoff == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Table = (CONST VOID *)(UINTN)BootloaderParameter;
  for (Depth = 0; Depth < CDK2_COREBOOT_MAX_FORWARD_DEPTH; Depth++) {
    Status = Cdk2CorebootParseOneTable (
               Table,
               sizeof (struct cb_header) + CDK2_COREBOOT_MAX_TABLE_BYTES,
               Handoff
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (Handoff->ForwardAddress == 0) {
      return EFI_SUCCESS;
    }

    if (Handoff->ForwardAddress > MAX_UINTN ||
        Handoff->ForwardAddress == (UINT64)(UINTN)Table)
    {
      return EFI_COMPROMISED_DATA;
    }

    Table = (CONST VOID *)(UINTN)Handoff->ForwardAddress;
  }

  return EFI_COMPROMISED_DATA;
}

EFI_STATUS
Cdk2CorebootFindRecord (
  IN  CONST CDK2_COREBOOT_HANDOFF  *Handoff,
  IN  UINT32                        Tag,
  IN  UINT32                        MinimumSize,
  OUT CONST VOID                  **Record
  )
{
  CONST struct cb_record  *Current;
  CONST UINT8              *Cursor;
  UINTN                     Remaining;
  UINTN                     Index;

  if (Handoff == NULL || Handoff->Header == NULL || Record == NULL ||
      MinimumSize < sizeof (struct cb_record) ||
      Handoff->Header->header_bytes > Handoff->TableSize)
  {
    return EFI_INVALID_PARAMETER;
  }

  *Record   = NULL;
  Cursor    = (CONST UINT8 *)Handoff->Header + Handoff->Header->header_bytes;
  Remaining = Handoff->TableSize - Handoff->Header->header_bytes;
  for (Index = 0; Index < Handoff->RecordCount; Index++) {
    if (Remaining < sizeof (struct cb_record)) {
      return EFI_COMPROMISED_DATA;
    }

    Current = (CONST struct cb_record *)(CONST VOID *)Cursor;
    if (Current->size < sizeof (struct cb_record) || Current->size > Remaining) {
      return EFI_COMPROMISED_DATA;
    }

    if (Current->tag == Tag) {
      if (Current->size < MinimumSize) {
        return EFI_COMPROMISED_DATA;
      }

      *Record = Current;
      return EFI_SUCCESS;
    }

    Cursor    += Current->size;
    Remaining -= Current->size;
  }

  return EFI_NOT_FOUND;
}

EFI_STATUS
Cdk2CorebootFindPayloadResourceSection (
  IN  CONST CDK2_COREBOOT_HANDOFF             *Handoff,
  IN  UINT16                                   Type,
  OUT CONST struct cb_payload_resource_section **Section
  )
{
  CONST struct cb_payload_resource_handoff *Record;
  CONST struct cb_payload_resource_section *Current;
  UINTN                                     Index;

  if (Handoff == NULL || Section == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Section = NULL;
  if (Handoff->PayloadResourceHandoffStatus != EFI_SUCCESS) {
    return Handoff->PayloadResourceHandoffStatus;
  }

  Record = Handoff->PayloadResourceHandoff;
  if (Record == NULL) {
    return EFI_COMPROMISED_DATA;
  }

  for (Index = 0; Index < Record->section_count; Index++) {
    Current = (CONST struct cb_payload_resource_section *)(CONST VOID *)(
                                                          (CONST UINT8 *)Record +
                                                          Record->header_length +
                                                          Index * Record->section_header_length
                                                          );
    if (Current->type == Type) {
      *Section = Current;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}
