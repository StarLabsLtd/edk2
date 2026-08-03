/** @file

  Freestanding coreboot table validation for the native cdk2 stage.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot.h"

#define CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK \
  (EFI_CACHE_ATTRIBUTE_MASK | EFI_MEMORY_ACCESS_MASK | EFI_MEMORY_NV | \
   EFI_MEMORY_MORE_RELIABLE | EFI_MEMORY_SP | EFI_MEMORY_CPU_CRYPTO | \
   EFI_MEMORY_HOT_PLUGGABLE | EFI_MEMORY_RUNTIME)

#define CDK2_COREBOOT_4GB  0x100000000ULL

#define CDK2_COREBOOT_PCI_MAX_BAR                     6U
#define CDK2_COREBOOT_PRH_MEMORY_POLICY_MAX_COUNT     1024U
#define CDK2_COREBOOT_PRH_PCI_ASSIGNMENT_MAX_COUNT    256U
#define CDK2_COREBOOT_PRH_MEMORY_AUTHORITATIVE_FLAGS  \
  (CB_PRH_MEMORY_CACHE_AUTHORITATIVE |                \
   CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE |           \
   CB_PRH_MEMORY_GCD_AUTHORITATIVE |                  \
   CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE)
#define CDK2_COREBOOT_PRH_MEMORY_COVERAGE_FLAGS  \
  (CDK2_COREBOOT_PRH_MEMORY_AUTHORITATIVE_FLAGS | \
   CB_PRH_MEMORY_DELEGATED_TO_PAYLOAD)

#define CDK2_COREBOOT_MTRR_TYPE_UC     0U
#define CDK2_COREBOOT_MTRR_TYPE_WC     1U
#define CDK2_COREBOOT_MTRR_TYPE_WT     4U
#define CDK2_COREBOOT_MTRR_TYPE_WP     5U
#define CDK2_COREBOOT_MTRR_TYPE_WB     6U
#define CDK2_COREBOOT_MTRR_TYPE_UC_MINUS  7U
#define CDK2_COREBOOT_MTRR_FIXED_ENABLE             BIT10
#define CDK2_COREBOOT_MTRR_ENABLE                   BIT11
#define CDK2_COREBOOT_MTRR_VALID                    BIT11
#define CDK2_COREBOOT_MTRR_MIN_PHYSICAL_ADDRESS_BITS  32U
#define CDK2_COREBOOT_MTRR_MAX_PHYSICAL_ADDRESS_BITS  52U
#define CDK2_COREBOOT_MTRR_DEFAULT_TYPE_VALID_MASK  0x0000000000000CFFULL

#define CDK2_COREBOOT_1MB  0x100000ULL

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
BOOLEAN
Cdk2CorebootIsPowerOfTwo64 (
  IN UINT64  Value
  )
{
  return (Value != 0) && ((Value & (Value - 1U)) == 0);
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
Cdk2CorebootMtrrTypeValid (
  IN UINT8  Type
  )
{
  return (Type == CDK2_COREBOOT_MTRR_TYPE_UC) ||
         (Type == CDK2_COREBOOT_MTRR_TYPE_WC) ||
         (Type == CDK2_COREBOOT_MTRR_TYPE_WT) ||
         (Type == CDK2_COREBOOT_MTRR_TYPE_WP) ||
         (Type == CDK2_COREBOOT_MTRR_TYPE_WB);
}

STATIC
BOOLEAN
Cdk2CorebootPatTypeValid (
  IN UINT8  Type
  )
{
  return Cdk2CorebootMtrrTypeValid (Type) ||
         (Type == CDK2_COREBOOT_MTRR_TYPE_UC_MINUS);
}

STATIC
BOOLEAN
Cdk2CorebootPatMsrValid (
  IN UINT64  PatMsr
  )
{
  UINTN  Index;
  UINT8  EntryType;

  for (Index = 0; Index < 8; Index++) {
    EntryType = (UINT8)((PatMsr >> (Index * 8U)) & 0xffU);
    if (!Cdk2CorebootPatTypeValid (EntryType)) {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootCacheAttributeToMtrrType (
  IN  UINT64  Attributes,
  OUT UINT8   *Type
  )
{
  if (Type == NULL) {
    return FALSE;
  }

  switch (Attributes & EFI_CACHE_ATTRIBUTE_MASK) {
    case EFI_MEMORY_UC:
      *Type = CDK2_COREBOOT_MTRR_TYPE_UC;
      return TRUE;
    case EFI_MEMORY_WC:
      *Type = CDK2_COREBOOT_MTRR_TYPE_WC;
      return TRUE;
    case EFI_MEMORY_WT:
      *Type = CDK2_COREBOOT_MTRR_TYPE_WT;
      return TRUE;
    case EFI_MEMORY_WP:
      *Type = CDK2_COREBOOT_MTRR_TYPE_WP;
      return TRUE;
    case EFI_MEMORY_WB:
      *Type = CDK2_COREBOOT_MTRR_TYPE_WB;
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
BOOLEAN
Cdk2CorebootPatContainsType (
  IN UINT64  PatMsr,
  IN UINT8   Type
  )
{
  BOOLEAN  Found;
  UINTN    Index;
  UINT8    EntryType;

  Found = FALSE;
  for (Index = 0; Index < 8; Index++) {
    EntryType = (UINT8)((PatMsr >> (Index * 8U)) & 0xffU);
    if (!Cdk2CorebootPatTypeValid (EntryType)) {
      return FALSE;
    }

    if (EntryType == Type) {
      Found = TRUE;
    }
  }

  return Found;
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
BOOLEAN
Cdk2CorebootU64RangeWithin (
  IN UINT64  Base,
  IN UINT64  Length,
  IN UINT64  ContainerBase,
  IN UINT64  ContainerLength
  )
{
  UINT64  End;
  UINT64  ContainerEnd;

  if (!Cdk2CorebootU64RangeEnd (Base, Length, &End) ||
      !Cdk2CorebootU64RangeEnd (ContainerBase, ContainerLength, &ContainerEnd))
  {
    return FALSE;
  }

  return (Base >= ContainerBase) && (End <= ContainerEnd);
}

STATIC
BOOLEAN
Cdk2CorebootU64RangesOverlap (
  IN UINT64  FirstBase,
  IN UINT64  FirstLength,
  IN UINT64  SecondBase,
  IN UINT64  SecondLength
  )
{
  UINT64  FirstEnd;
  UINT64  SecondEnd;

  if (!Cdk2CorebootU64RangeEnd (FirstBase, FirstLength, &FirstEnd) ||
      !Cdk2CorebootU64RangeEnd (SecondBase, SecondLength, &SecondEnd))
  {
    return FALSE;
  }

  return (FirstBase < SecondEnd) && (SecondBase < FirstEnd);
}

STATIC
BOOLEAN
Cdk2CorebootEfiMemoryTypeVendorReserved (
  IN UINT32  EfiMemoryType
  )
{
  return ((EfiMemoryType >= MEMORY_TYPE_OEM_RESERVED_MIN) &&
          (EfiMemoryType <= MEMORY_TYPE_OEM_RESERVED_MAX)) ||
         ((EfiMemoryType >= MEMORY_TYPE_OS_RESERVED_MIN) &&
          (EfiMemoryType <= MEMORY_TYPE_OS_RESERVED_MAX));
}

STATIC
BOOLEAN
Cdk2CorebootEfiMemoryTypeValid (
  IN UINT32  EfiMemoryType
  )
{
  return (EfiMemoryType < EfiMaxMemoryType) ||
         Cdk2CorebootEfiMemoryTypeVendorReserved (EfiMemoryType);
}

STATIC
BOOLEAN
Cdk2CorebootEfiTypeMatchesGcdType (
  IN UINT32  GcdType,
  IN UINT32  EfiMemoryType
  )
{
  switch (GcdType) {
    case CB_PRH_GCD_MEMORY_TYPE_NON_EXISTENT:
      return EfiMemoryType == EfiReservedMemoryType;

    case CB_PRH_GCD_MEMORY_TYPE_RESERVED:
      return (EfiMemoryType == EfiReservedMemoryType) ||
             (EfiMemoryType == EfiUnusableMemory) ||
             (EfiMemoryType == EfiACPIReclaimMemory) ||
             (EfiMemoryType == EfiACPIMemoryNVS) ||
             (EfiMemoryType == EfiPalCode);

    case CB_PRH_GCD_MEMORY_TYPE_SYSTEM:
    case CB_PRH_GCD_MEMORY_TYPE_RELIABLE:
      if (Cdk2CorebootEfiMemoryTypeVendorReserved (EfiMemoryType)) {
        return TRUE;
      }

      return (EfiMemoryType == EfiLoaderCode) ||
             (EfiMemoryType == EfiLoaderData) ||
             (EfiMemoryType == EfiBootServicesCode) ||
             (EfiMemoryType == EfiBootServicesData) ||
             (EfiMemoryType == EfiRuntimeServicesCode) ||
             (EfiMemoryType == EfiRuntimeServicesData) ||
             (EfiMemoryType == EfiConventionalMemory) ||
             (EfiMemoryType == EfiACPIReclaimMemory) ||
             (EfiMemoryType == EfiACPIMemoryNVS);

    case CB_PRH_GCD_MEMORY_TYPE_MMIO:
      return (EfiMemoryType == EfiMemoryMappedIO) ||
             (EfiMemoryType == EfiMemoryMappedIOPortSpace);

    case CB_PRH_GCD_MEMORY_TYPE_PERSISTENT:
      return EfiMemoryType == EfiPersistentMemory;

    case CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED:
      return EfiMemoryType == EfiUnacceptedMemoryType;

    default:
      return FALSE;
  }
}

STATIC
BOOLEAN
Cdk2CorebootMemoryPolicyCoversRangeByOwnerFlags (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section,
  IN UINT32                                    RequiredOwnerFlags,
  IN BOOLEAN                                   RequireAllOwnerFlags,
  IN BOOLEAN                                   RequireGcdType,
  IN UINT32                                    GcdType,
  IN UINT64                                    Base,
  IN UINT64                                    Length
  )
{
  CONST UINT8                         *SectionBase;
  CONST struct cb_prh_memory_policy_entry *Entry;
  UINT64                               RangeEnd;
  UINT64                               Covered;
  UINT64                               EntryBase;
  UINT64                               EntryLength;
  UINT64                               EntryEnd;
  UINTN                                Index;

  if ((Record == NULL) || (Section == NULL) ||
      ((Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0))
  {
    return FALSE;
  }

  if (!Cdk2CorebootU64RangeEnd (Base, Length, &RangeEnd)) {
    return FALSE;
  }

  SectionBase = (CONST UINT8 *)Record + Section->offset;
  Covered     = Base;
  Index       = 0;
  while (Covered < RangeEnd) {
    for (; Index < Section->entry_count; Index++) {
      Entry = (CONST struct cb_prh_memory_policy_entry *)(CONST VOID *)(
                                                              SectionBase +
                                                              Index * Section->entry_size
                                                              );
      EntryBase = Cdk2CorebootUnpack64At (
                    Entry,
                    OFFSET_OF (struct cb_prh_memory_policy_entry, base)
                    );
      EntryLength = Cdk2CorebootUnpack64At (
                      Entry,
                      OFFSET_OF (struct cb_prh_memory_policy_entry, length)
                      );
      if (!Cdk2CorebootU64RangeEnd (EntryBase, EntryLength, &EntryEnd)) {
        return FALSE;
      }

      if (EntryEnd <= Covered) {
        continue;
      }

      if (EntryBase > Covered) {
        return FALSE;
      }

      if (RequireAllOwnerFlags) {
        if ((Entry->owner_flags & RequiredOwnerFlags) != RequiredOwnerFlags) {
          return FALSE;
        }
      } else if ((Entry->owner_flags & RequiredOwnerFlags) == 0) {
        return FALSE;
      }

      if (RequireGcdType && (Entry->gcd_type != GcdType)) {
        return FALSE;
      }

      Covered = (EntryEnd < RangeEnd) ? EntryEnd : RangeEnd;
      Index++;
      break;
    }

    if ((Index == Section->entry_count) && (Covered < RangeEnd)) {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootMemoryPolicyCoversRangeWithAnyOwner (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section,
  IN UINT32                                    OwnerFlags,
  IN UINT64                                    Base,
  IN UINT64                                    Length
  )
{
  return Cdk2CorebootMemoryPolicyCoversRangeByOwnerFlags (
           Record,
           Section,
           OwnerFlags,
           FALSE,
           FALSE,
           0,
           Base,
           Length
           );
}

STATIC
BOOLEAN
Cdk2CorebootMemoryPolicyCoversRangeWithGcdType (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section,
  IN UINT32                                    RequiredOwnerFlags,
  IN UINT32                                    GcdType,
  IN UINT64                                    Base,
  IN UINT64                                    Length
  )
{
  return Cdk2CorebootMemoryPolicyCoversRangeByOwnerFlags (
           Record,
           Section,
           RequiredOwnerFlags,
           TRUE,
           TRUE,
           GcdType,
           Base,
           Length
           );
}

STATIC
BOOLEAN
Cdk2CorebootU64RangeBelow4GB (
  IN UINT64  Base,
  IN UINT64  Length
  )
{
  UINT64  End;

  if (Length == 0) {
    return TRUE;
  }

  if (!Cdk2CorebootU64RangeEnd (Base, Length, &End)) {
    return FALSE;
  }

  return (Base < CDK2_COREBOOT_4GB) && (End <= CDK2_COREBOOT_4GB);
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

  if (Section->entry_count > CDK2_COREBOOT_PRH_MEMORY_POLICY_MAX_COUNT) {
    return EFI_COMPROMISED_DATA;
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

    if ((Attributes & ~Capabilities) != 0) {
      return EFI_COMPROMISED_DATA;
    }

    if ((Entry->owner_flags & ~CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK) != 0 ||
        Entry->reserved != 0)
    {
      return ((Entry->owner_flags & ~CB_PRH_MEMORY_OWNER_FLAG_VALID_MASK) != 0) ?
             EFI_UNSUPPORTED :
             EFI_COMPROMISED_DATA;
    }

    if (((Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0) &&
        ((Entry->owner_flags & CDK2_COREBOOT_PRH_MEMORY_AUTHORITATIVE_FLAGS) != 0))
    {
      return EFI_COMPROMISED_DATA;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_GCD_AUTHORITATIVE) != 0 &&
        Entry->gcd_type > CB_PRH_GCD_MEMORY_TYPE_UNACCEPTED)
    {
      return EFI_UNSUPPORTED;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE) != 0 &&
        !Cdk2CorebootEfiMemoryTypeValid (Entry->efi_memory_type))
    {
      return EFI_UNSUPPORTED;
    }

    if (((Entry->owner_flags & CB_PRH_MEMORY_GCD_AUTHORITATIVE) != 0) &&
        ((Entry->owner_flags & CB_PRH_MEMORY_EFI_TYPE_AUTHORITATIVE) != 0) &&
        !Cdk2CorebootEfiTypeMatchesGcdType (Entry->gcd_type, Entry->efi_memory_type))
    {
      return EFI_COMPROMISED_DATA;
    }

    if ((Entry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) != 0 &&
        Cdk2CorebootBitCount64 (Attributes & EFI_CACHE_ATTRIBUTE_MASK) != 1)
    {
      return EFI_COMPROMISED_DATA;
    }

    if ((((Attributes & EFI_MEMORY_RUNTIME) != 0) ||
         ((Entry->owner_flags & CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE) != 0)) &&
        (((RangeBase | RangeLength) & EFI_PAGE_MASK) != 0))
    {
      return EFI_COMPROMISED_DATA;
    }

    PreviousEnd = RangeEnd;
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
Cdk2CorebootMtrrAddressMask (
  IN  CONST struct cb_prh_x86_cache_state  *CacheState,
  OUT UINT64                               *AddressMask
  )
{
  UINT32  PhysicalAddressBits;

  if ((CacheState == NULL) || (AddressMask == NULL)) {
    return FALSE;
  }

  PhysicalAddressBits = CacheState->physical_address_bits;
  if ((PhysicalAddressBits < CDK2_COREBOOT_MTRR_MIN_PHYSICAL_ADDRESS_BITS) ||
      (PhysicalAddressBits > CDK2_COREBOOT_MTRR_MAX_PHYSICAL_ADDRESS_BITS))
  {
    return FALSE;
  }

  *AddressMask = ((1ULL << PhysicalAddressBits) - 1U) & ~(UINT64)EFI_PAGE_MASK;
  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootDefaultMtrrValid (
  IN  UINT64  DefaultTypeMsr,
  OUT UINT8   *DefaultType OPTIONAL
  )
{
  UINT8  Type;

  Type = (UINT8)(DefaultTypeMsr & 0xffU);
  if (((DefaultTypeMsr & ~CDK2_COREBOOT_MTRR_DEFAULT_TYPE_VALID_MASK) != 0) ||
      ((DefaultTypeMsr & CDK2_COREBOOT_MTRR_ENABLE) == 0) ||
      !Cdk2CorebootMtrrTypeValid (Type))
  {
    return FALSE;
  }

  if (DefaultType != NULL) {
    *DefaultType = Type;
  }

  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootVariableMtrrDecode (
  IN CONST struct cb_prh_x86_variable_mtrr *VariableMtrr,
  IN UINT64                                 MtrrAddressMask,
  OUT BOOLEAN                              *Active,
  OUT UINT8                                *Type OPTIONAL,
  OUT UINT64                               *Base OPTIONAL,
  OUT UINT64                               *Length OPTIONAL
  );

STATIC
EFI_STATUS
Cdk2CorebootValidateX86CacheSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST struct cb_prh_x86_cache_state *CacheState;
  CONST struct cb_prh_x86_variable_mtrr *VariableMtrr;
  CONST UINT8                         *VariableBase;
  UINT64                               DefaultTypeMsr;
  UINT64                               PatMsr;
  UINT64                               VariableBytes;
  UINT64                               LifetimeFlags;
  UINT64                               MtrrAddressMask;
  BOOLEAN                              Active;
  UINTN                                Index;

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

  if (CacheState->reserved != 0) {
    return EFI_COMPROMISED_DATA;
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

  if (!Cdk2CorebootMtrrAddressMask (CacheState, &MtrrAddressMask)) {
    return EFI_COMPROMISED_DATA;
  }

  DefaultTypeMsr = Cdk2CorebootUnpack64At (
                     CacheState,
                     OFFSET_OF (struct cb_prh_x86_cache_state, mtrr_default_type_msr)
                     );
  if (!Cdk2CorebootDefaultMtrrValid (DefaultTypeMsr, NULL)) {
    return EFI_COMPROMISED_DATA;
  }

  PatMsr = Cdk2CorebootUnpack64At (CacheState, OFFSET_OF (struct cb_prh_x86_cache_state, pat_msr));
  if (!Cdk2CorebootPatMsrValid (PatMsr)) {
    return EFI_COMPROMISED_DATA;
  }

  VariableBase = (CONST UINT8 *)(CacheState + 1);
  for (Index = 0; Index < Section->entry_count; Index++) {
    VariableMtrr = (CONST struct cb_prh_x86_variable_mtrr *)(CONST VOID *)(
                                                                     VariableBase +
                                                                     Index * Section->entry_size
                                                                     );
    if (!Cdk2CorebootVariableMtrrDecode (
           VariableMtrr,
           MtrrAddressMask,
           &Active,
           NULL,
           NULL,
           NULL
           ))
    {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
Cdk2CorebootVariableMtrrDecode (
  IN CONST struct cb_prh_x86_variable_mtrr *VariableMtrr,
  IN UINT64                                 MtrrAddressMask,
  OUT BOOLEAN                              *Active,
  OUT UINT8                                *Type OPTIONAL,
  OUT UINT64                               *Base OPTIONAL,
  OUT UINT64                               *Length OPTIONAL
  )
{
  UINT64  PhysBaseMsr;
  UINT64  PhysMaskMsr;
  UINT64  Mask;
  UINT64  RangeMask;
  UINT64  MtrrBase;
  UINT64  MtrrLength;
  UINT64  PhysBaseValidMask;
  UINT64  PhysMaskValidMask;
  UINT8   MtrrType;

  PhysBaseValidMask = MtrrAddressMask | 0xffULL;
  PhysMaskValidMask = MtrrAddressMask | CDK2_COREBOOT_MTRR_VALID;
  PhysMaskMsr = Cdk2CorebootUnpack64At (
                  VariableMtrr,
                  OFFSET_OF (struct cb_prh_x86_variable_mtrr, phys_mask_msr)
                  );
  if ((Active == NULL) ||
      (MtrrAddressMask == 0) ||
      ((PhysMaskMsr & ~PhysMaskValidMask) != 0))
  {
    return FALSE;
  }

  PhysBaseMsr = Cdk2CorebootUnpack64At (
                  VariableMtrr,
                  OFFSET_OF (struct cb_prh_x86_variable_mtrr, phys_base_msr)
                  );
  MtrrType = (UINT8)(PhysBaseMsr & 0xffU);
  MtrrBase = PhysBaseMsr & MtrrAddressMask;
  if (((PhysBaseMsr & ~PhysBaseValidMask) != 0) ||
      !Cdk2CorebootMtrrTypeValid (MtrrType))
  {
    return FALSE;
  }

  if ((PhysMaskMsr & CDK2_COREBOOT_MTRR_VALID) == 0) {
    *Active = FALSE;
    return TRUE;
  }

  Mask = PhysMaskMsr & MtrrAddressMask;
  RangeMask = ~Mask & MtrrAddressMask;
  if (RangeMask > MAX_UINT64 - SIZE_4KB) {
    return FALSE;
  }

  MtrrLength = RangeMask + SIZE_4KB;
  if (!Cdk2CorebootIsPowerOfTwo64 (MtrrLength) ||
      ((MtrrBase & (MtrrLength - 1U)) != 0))
  {
    return FALSE;
  }

  *Active = TRUE;
  if (Type != NULL) {
    *Type = MtrrType;
  }

  if (Base != NULL) {
    *Base = MtrrBase;
  }

  if (Length != NULL) {
    *Length = MtrrLength;
  }

  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootMergeVariableMtrrTypes (
  IN  UINT8  First,
  IN  UINT8  Second,
  OUT UINT8  *Merged
  )
{
  if (Merged == NULL) {
    return FALSE;
  }

  if (First == Second) {
    *Merged = First;
    return TRUE;
  }

  if ((First == CDK2_COREBOOT_MTRR_TYPE_UC) ||
      (Second == CDK2_COREBOOT_MTRR_TYPE_UC))
  {
    *Merged = CDK2_COREBOOT_MTRR_TYPE_UC;
    return TRUE;
  }

  if (((First == CDK2_COREBOOT_MTRR_TYPE_WB) &&
       (Second == CDK2_COREBOOT_MTRR_TYPE_WT)) ||
      ((First == CDK2_COREBOOT_MTRR_TYPE_WT) &&
       (Second == CDK2_COREBOOT_MTRR_TYPE_WB)))
  {
    *Merged = CDK2_COREBOOT_MTRR_TYPE_WT;
    return TRUE;
  }

  return FALSE;
}

STATIC
BOOLEAN
Cdk2CorebootEffectiveMtrrTypeAt (
  IN CONST struct cb_prh_x86_cache_state       *CacheState,
  IN CONST struct cb_payload_resource_section  *CacheSection,
  IN UINT64                                     MtrrAddressMask,
  IN UINT8                                      DefaultType,
  IN UINT64                                     Address,
  IN UINT64                                     Limit,
  OUT UINT8                                    *EffectiveType,
  OUT UINT64                                   *NextAddress
  )
{
  CONST struct cb_prh_x86_variable_mtrr  *VariableMtrr;
  CONST UINT8                            *VariableBase;
  UINT64                                  VariableBaseAddress;
  UINT64                                  VariableLength;
  UINT64                                  VariableEnd;
  UINT64                                  Next;
  UINT8                                   CurrentType;
  UINT8                                   VariableType;
  BOOLEAN                                 Active;
  BOOLEAN                                 Matched;
  UINTN                                   Index;

  if ((CacheState == NULL) || (CacheSection == NULL) ||
      (EffectiveType == NULL) || (NextAddress == NULL) ||
      (Address >= Limit))
  {
    return FALSE;
  }

  CurrentType  = DefaultType;
  Matched      = FALSE;
  Next         = Limit;
  VariableBase = (CONST UINT8 *)(CacheState + 1);
  for (Index = 0; Index < CacheSection->entry_count; Index++) {
    VariableMtrr = (CONST struct cb_prh_x86_variable_mtrr *)(CONST VOID *)(
                                                                    VariableBase +
                                                                    Index * CacheSection->entry_size
                                                                    );
    if (!Cdk2CorebootVariableMtrrDecode (
           VariableMtrr,
           MtrrAddressMask,
           &Active,
           &VariableType,
           &VariableBaseAddress,
           &VariableLength
           ))
    {
      return FALSE;
    }

    if (!Active) {
      continue;
    }

    if (!Cdk2CorebootU64RangeEnd (VariableBaseAddress, VariableLength, &VariableEnd)) {
      return FALSE;
    }

    if (Address < VariableBaseAddress) {
      if (VariableBaseAddress < Next) {
        Next = VariableBaseAddress;
      }

      continue;
    }

    if (Address >= VariableEnd) {
      continue;
    }

    if (VariableEnd < Next) {
      Next = VariableEnd;
    }

    if (!Matched) {
      CurrentType = VariableType;
      Matched     = TRUE;
    } else if (!Cdk2CorebootMergeVariableMtrrTypes (CurrentType, VariableType, &CurrentType)) {
      return FALSE;
    }
  }

  if (Next <= Address) {
    return FALSE;
  }

  *EffectiveType = CurrentType;
  *NextAddress   = Next;
  return TRUE;
}

STATIC
BOOLEAN
Cdk2CorebootCacheRangeCoveredByMtrr (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *CacheSection,
  IN UINT8                                     DefaultType,
  IN UINT8                                     Type,
  IN UINT64                                    Base,
  IN UINT64                                    Length
  )
{
  CONST struct cb_prh_x86_cache_state    *CacheState;
  UINT64                                  DefaultTypeMsr;
  UINT64                                  MtrrAddressMask;
  UINT64                                  RangeEnd;
  UINT64                                  Covered;
  UINT64                                  Next;
  UINT8                                   EffectiveType;

  if (!Cdk2CorebootU64RangeEnd (Base, Length, &RangeEnd)) {
    return FALSE;
  }

  CacheState = (CONST struct cb_prh_x86_cache_state *)(CONST VOID *)(
                                                        (CONST UINT8 *)Record +
                                                        CacheSection->offset
                                                        );
  if (!Cdk2CorebootMtrrAddressMask (CacheState, &MtrrAddressMask)) {
    return FALSE;
  }

  if (RangeEnd > MtrrAddressMask + SIZE_4KB) {
    return FALSE;
  }

  DefaultTypeMsr = Cdk2CorebootUnpack64At (
                     CacheState,
                     OFFSET_OF (struct cb_prh_x86_cache_state, mtrr_default_type_msr)
                     );
  if ((Base < CDK2_COREBOOT_1MB) &&
      (((CacheState->flags & CB_PRH_X86_CACHE_FLAG_FIXED_VALID) != 0) ||
       ((DefaultTypeMsr & CDK2_COREBOOT_MTRR_FIXED_ENABLE) != 0)))
  {
    return FALSE;
  }

  Covered = Base;
  while (Covered < RangeEnd) {
    if (!Cdk2CorebootEffectiveMtrrTypeAt (
           CacheState,
           CacheSection,
           MtrrAddressMask,
           DefaultType,
           Covered,
           RangeEnd,
           &EffectiveType,
           &Next
           ))
    {
      return FALSE;
    }

    if (EffectiveType != Type) {
      return FALSE;
    }

    Covered = Next;
  }

  return TRUE;
}

STATIC
EFI_STATUS
Cdk2CorebootValidateMemoryPolicyAgainstCacheState (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *MemorySection,
  IN CONST struct cb_payload_resource_section *CacheSection
  )
{
  CONST UINT8                         *SectionBase;
  CONST struct cb_prh_memory_policy_entry *Entry;
  CONST struct cb_prh_x86_cache_state *CacheState;
  UINT64                               Attributes;
  UINT64                               Base;
  UINT64                               Length;
  UINT64                               DefaultTypeMsr;
  UINT64                               PatMsr;
  UINT8                                DefaultType;
  UINT8                                Type;
  UINTN                                Index;

  CacheState = (CONST struct cb_prh_x86_cache_state *)(CONST VOID *)(
                                                        (CONST UINT8 *)Record +
                                                        CacheSection->offset
                                                        );
  DefaultTypeMsr = Cdk2CorebootUnpack64At (
                     CacheState,
                     OFFSET_OF (struct cb_prh_x86_cache_state, mtrr_default_type_msr)
                     );
  if (!Cdk2CorebootDefaultMtrrValid (DefaultTypeMsr, &DefaultType)) {
    return EFI_COMPROMISED_DATA;
  }

  PatMsr      = Cdk2CorebootUnpack64At (CacheState, OFFSET_OF (struct cb_prh_x86_cache_state, pat_msr));
  SectionBase = (CONST UINT8 *)Record + MemorySection->offset;
  for (Index = 0; Index < MemorySection->entry_count; Index++) {
    Entry = (CONST struct cb_prh_memory_policy_entry *)(CONST VOID *)(
                                                            SectionBase +
                                                            Index * MemorySection->entry_size
                                                            );
    if ((Entry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) == 0) {
      continue;
    }

    Attributes = Cdk2CorebootUnpack64At (
                   Entry,
                   OFFSET_OF (struct cb_prh_memory_policy_entry, attributes)
                   );
    if (!Cdk2CorebootCacheAttributeToMtrrType (Attributes, &Type)) {
      return EFI_UNSUPPORTED;
    }

    if (!Cdk2CorebootPatContainsType (PatMsr, Type)) {
      return EFI_COMPROMISED_DATA;
    }

    Base = Cdk2CorebootUnpack64At (
             Entry,
             OFFSET_OF (struct cb_prh_memory_policy_entry, base)
             );
    Length = Cdk2CorebootUnpack64At (
               Entry,
               OFFSET_OF (struct cb_prh_memory_policy_entry, length)
               );
    if (!Cdk2CorebootCacheRangeCoveredByMtrr (
           Record,
           CacheSection,
           DefaultType,
           Type,
           Base,
           Length
           ))
    {
      return EFI_COMPROMISED_DATA;
    }
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
  CONST struct cb_prh_pci_root_bridge_entry *OtherEntry;
  UINT64                                WindowBase;
  UINT64                                WindowLength;
  UINT64                                WindowEnd;
  UINTN                                 Index;
  UINTN                                 OtherIndex;
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

    for (OtherIndex = 0; OtherIndex < Index; OtherIndex++) {
      OtherEntry = (CONST struct cb_prh_pci_root_bridge_entry *)(CONST VOID *)(
                                                                       Base + OtherIndex * Section->entry_size
                                                                       );
      if ((Entry->segment == OtherEntry->segment) &&
          (Entry->bus_start <= OtherEntry->bus_end) &&
          (OtherEntry->bus_start <= Entry->bus_end))
      {
        return EFI_COMPROMISED_DATA;
      }
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_length));
    if (!Cdk2CorebootU64RangeBelow4GB (WindowBase, WindowLength)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem64_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem64_length));
    if (WindowLength != 0 && !Cdk2CorebootU64RangeEnd (WindowBase, WindowLength, &WindowEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    WindowBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem32_base));
    WindowLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem32_length));
    if (!Cdk2CorebootU64RangeBelow4GB (WindowBase, WindowLength)) {
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
BOOLEAN
Cdk2CorebootPciResourceMmio32 (
  IN UINT8  ResourceType
  )
{
  return (ResourceType == CB_PRH_PCI_RESOURCE_MMIO32) ||
         (ResourceType == CB_PRH_PCI_RESOURCE_PREFETCH_MMIO32);
}

STATIC
BOOLEAN
Cdk2CorebootPciResourceMmio64 (
  IN UINT8  ResourceType
  )
{
  return (ResourceType == CB_PRH_PCI_RESOURCE_MMIO64) ||
         (ResourceType == CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64);
}

STATIC
BOOLEAN
Cdk2CorebootPciResourceMemory (
  IN UINT8  ResourceType
  )
{
  return ResourceType != CB_PRH_PCI_RESOURCE_IO;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePciAssignmentsSection (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *Section
  )
{
  CONST UINT8                              *Base;
  CONST struct cb_prh_pci_assignment_entry *Entry;
  CONST struct cb_prh_pci_assignment_entry *OtherEntry;
  UINT64                                    ResourceBase;
  UINT64                                    ResourceLength;
  UINT64                                    ResourceEnd;
  UINT64                                    ResourceAttributes;
  UINT64                                    OtherResourceBase;
  UINT64                                    OtherResourceLength;
  UINTN                                     Index;
  UINTN                                     OtherIndex;
  EFI_STATUS                                Status;

  Status = Cdk2CorebootValidatePayloadResourceFixedEntries (
             Section,
             sizeof (struct cb_prh_pci_assignment_entry),
             TRUE
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Section->entry_count > CDK2_COREBOOT_PRH_PCI_ASSIGNMENT_MAX_COUNT) {
    return EFI_COMPROMISED_DATA;
  }

  Base = (CONST UINT8 *)Record + Section->offset;
  for (Index = 0; Index < Section->entry_count; Index++) {
    Entry = (CONST struct cb_prh_pci_assignment_entry *)(CONST VOID *)(Base + Index * Section->entry_size);
    if (Entry->device > 31 || Entry->function > 7 ||
        Entry->bar >= CDK2_COREBOOT_PCI_MAX_BAR ||
        Entry->resource_type < CB_PRH_PCI_RESOURCE_IO ||
        Entry->resource_type > CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64)
    {
      return EFI_COMPROMISED_DATA;
    }

    if (Entry->flags != 0) {
      return EFI_UNSUPPORTED;
    }

    if (Cdk2CorebootPciResourceMmio64 (Entry->resource_type) &&
        (Entry->bar >= CDK2_COREBOOT_PCI_MAX_BAR - 1U))
    {
      return EFI_COMPROMISED_DATA;
    }

    for (OtherIndex = 0; OtherIndex < Index; OtherIndex++) {
      UINT8  EntryBarEnd;
      UINT8  OtherBarEnd;

      OtherEntry = (CONST struct cb_prh_pci_assignment_entry *)(CONST VOID *)(
                                                                      Base + OtherIndex * Section->entry_size
                                                                      );
      if ((Entry->segment == OtherEntry->segment) &&
          (Entry->bus == OtherEntry->bus) &&
          (Entry->device == OtherEntry->device) &&
          (Entry->function == OtherEntry->function))
      {
        EntryBarEnd = Entry->bar;
        if (Cdk2CorebootPciResourceMmio64 (Entry->resource_type)) {
          EntryBarEnd++;
        }

        OtherBarEnd = OtherEntry->bar;
        if (Cdk2CorebootPciResourceMmio64 (OtherEntry->resource_type)) {
          OtherBarEnd++;
        }

        if ((Entry->bar <= OtherBarEnd) && (OtherEntry->bar <= EntryBarEnd)) {
          return EFI_COMPROMISED_DATA;
        }
      }
    }

    ResourceBase   = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_assignment_entry, base));
    ResourceLength = Cdk2CorebootUnpack64At (Entry, OFFSET_OF (struct cb_prh_pci_assignment_entry, length));
    if (!Cdk2CorebootU64RangeEnd (ResourceBase, ResourceLength, &ResourceEnd)) {
      return EFI_COMPROMISED_DATA;
    }

    if (ResourceBase == 0) {
      return EFI_COMPROMISED_DATA;
    }

    if (!Cdk2CorebootIsPowerOfTwo64 (ResourceLength) ||
        ((ResourceBase & (ResourceLength - 1U)) != 0))
    {
      return EFI_COMPROMISED_DATA;
    }

    for (OtherIndex = 0; OtherIndex < Index; OtherIndex++) {
      OtherEntry = (CONST struct cb_prh_pci_assignment_entry *)(CONST VOID *)(
                                                                      Base + OtherIndex * Section->entry_size
                                                                      );
      if (Cdk2CorebootPciResourceMemory (Entry->resource_type) !=
          Cdk2CorebootPciResourceMemory (OtherEntry->resource_type))
      {
        continue;
      }

      OtherResourceBase = Cdk2CorebootUnpack64At (
                            OtherEntry,
                            OFFSET_OF (struct cb_prh_pci_assignment_entry, base)
                            );
      OtherResourceLength = Cdk2CorebootUnpack64At (
                              OtherEntry,
                              OFFSET_OF (struct cb_prh_pci_assignment_entry, length)
                              );
      if (Cdk2CorebootU64RangesOverlap (
            ResourceBase,
            ResourceLength,
            OtherResourceBase,
            OtherResourceLength
            ))
      {
        return EFI_COMPROMISED_DATA;
      }
    }

    if (Cdk2CorebootPciResourceMmio32 (Entry->resource_type) &&
        !Cdk2CorebootU64RangeBelow4GB (ResourceBase, ResourceLength))
    {
      return EFI_COMPROMISED_DATA;
    }

    ResourceAttributes = Cdk2CorebootUnpack64At (
                           Entry,
                           OFFSET_OF (struct cb_prh_pci_assignment_entry, attributes)
                           );
    if (Cdk2CorebootPciResourceMemory (Entry->resource_type)) {
      if ((ResourceAttributes & ~CDK2_COREBOOT_PRH_MEMORY_ATTRIBUTE_MASK) != 0) {
        return EFI_UNSUPPORTED;
      }
    } else if (ResourceAttributes != 0) {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
Cdk2CorebootPixelMaskValid (
  IN  UINT8   Position,
  IN  UINT8   Size,
  IN  UINT8   BitsPerPixel,
  OUT UINT64  *Mask
  )
{
  UINT64  LocalMask;

  if (Mask == NULL || BitsPerPixel == 0 || BitsPerPixel > 32) {
    return FALSE;
  }

  if (Size == 0) {
    if (Position != 0) {
      return FALSE;
    }

    *Mask = 0;
    return TRUE;
  }

  if ((Position >= BitsPerPixel) ||
      (Size > BitsPerPixel) ||
      (Size > BitsPerPixel - Position))
  {
    return FALSE;
  }

  if (Size == 64) {
    LocalMask = MAX_UINT64;
  } else {
    LocalMask = (1ULL << Size) - 1U;
  }

  *Mask = LocalMask << Position;
  return TRUE;
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
  UINT64                                RedMask;
  UINT64                                GreenMask;
  UINT64                                BlueMask;
  UINT64                                ReservedMask;
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

    if (!Cdk2CorebootPixelMaskValid (
           Entry->red_mask_pos,
           Entry->red_mask_size,
           Entry->bits_per_pixel,
           &RedMask
           ) ||
        !Cdk2CorebootPixelMaskValid (
           Entry->green_mask_pos,
           Entry->green_mask_size,
           Entry->bits_per_pixel,
           &GreenMask
           ) ||
        !Cdk2CorebootPixelMaskValid (
           Entry->blue_mask_pos,
           Entry->blue_mask_size,
           Entry->bits_per_pixel,
           &BlueMask
           ) ||
        !Cdk2CorebootPixelMaskValid (
           Entry->reserved_mask_pos,
           Entry->reserved_mask_size,
           Entry->bits_per_pixel,
           &ReservedMask
           ))
    {
      return EFI_COMPROMISED_DATA;
    }

    if (((RedMask & GreenMask) != 0) ||
        ((RedMask & BlueMask) != 0) ||
        ((RedMask & ReservedMask) != 0) ||
        ((GreenMask & BlueMask) != 0) ||
        ((GreenMask & ReservedMask) != 0) ||
        ((BlueMask & ReservedMask) != 0))
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
BOOLEAN
Cdk2CorebootPciAssignmentFitsBridgeWindow (
  IN CONST struct cb_prh_pci_root_bridge_entry *Bridge,
  IN UINT8                                      ResourceType,
  IN UINT64                                     ResourceBase,
  IN UINT64                                     ResourceLength
  )
{
  UINT64  WindowBase;
  UINT64  WindowLength;

  switch (ResourceType) {
    case CB_PRH_PCI_RESOURCE_IO:
      WindowBase   = Cdk2CorebootUnpack64At (Bridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_base));
      WindowLength = Cdk2CorebootUnpack64At (Bridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, io_length));
      break;

    case CB_PRH_PCI_RESOURCE_MMIO32:
      WindowBase   = Cdk2CorebootUnpack64At (Bridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_base));
      WindowLength = Cdk2CorebootUnpack64At (Bridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem32_length));
      break;

    case CB_PRH_PCI_RESOURCE_MMIO64:
      WindowBase   = Cdk2CorebootUnpack64At (Bridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem64_base));
      WindowLength = Cdk2CorebootUnpack64At (Bridge, OFFSET_OF (struct cb_prh_pci_root_bridge_entry, mem64_length));
      break;

    case CB_PRH_PCI_RESOURCE_PREFETCH_MMIO32:
      WindowBase = Cdk2CorebootUnpack64At (
                     Bridge,
                     OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem32_base)
                     );
      WindowLength = Cdk2CorebootUnpack64At (
                       Bridge,
                       OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem32_length)
                       );
      break;

    case CB_PRH_PCI_RESOURCE_PREFETCH_MMIO64:
      WindowBase = Cdk2CorebootUnpack64At (
                     Bridge,
                     OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem64_base)
                     );
      WindowLength = Cdk2CorebootUnpack64At (
                       Bridge,
                       OFFSET_OF (struct cb_prh_pci_root_bridge_entry, pref_mem64_length)
                       );
      break;

    default:
      return FALSE;
  }

  return Cdk2CorebootU64RangeWithin (
           ResourceBase,
           ResourceLength,
           WindowBase,
           WindowLength
           );
}

STATIC
BOOLEAN
Cdk2CorebootPciAssignmentHasOwningBridge (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *RootBridgeSection,
  IN CONST struct cb_prh_pci_assignment_entry *Assignment
  )
{
  CONST UINT8                              *Base;
  CONST struct cb_prh_pci_root_bridge_entry *Bridge;
  UINT64                                    ResourceBase;
  UINT64                                    ResourceLength;
  UINTN                                     Index;

  ResourceBase = Cdk2CorebootUnpack64At (
                   Assignment,
                   OFFSET_OF (struct cb_prh_pci_assignment_entry, base)
                   );
  ResourceLength = Cdk2CorebootUnpack64At (
                     Assignment,
                     OFFSET_OF (struct cb_prh_pci_assignment_entry, length)
                     );

  Base = (CONST UINT8 *)Record + RootBridgeSection->offset;
  for (Index = 0; Index < RootBridgeSection->entry_count; Index++) {
    Bridge = (CONST struct cb_prh_pci_root_bridge_entry *)(CONST VOID *)(
                                                               Base + Index * RootBridgeSection->entry_size
                                                               );
    if ((Assignment->segment == Bridge->segment) &&
        (Assignment->bus >= Bridge->bus_start) &&
        (Assignment->bus <= Bridge->bus_end) &&
        Cdk2CorebootPciAssignmentFitsBridgeWindow (
          Bridge,
          Assignment->resource_type,
          ResourceBase,
          ResourceLength
          ))
    {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePciAssignmentsAgainstRootBridges (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *RootBridgeSection,
  IN CONST struct cb_payload_resource_section *AssignmentSection
  )
{
  CONST UINT8                              *Base;
  CONST struct cb_prh_pci_assignment_entry *Assignment;
  UINTN                                     Index;

  if ((AssignmentSection->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0) {
    return EFI_SUCCESS;
  }

  if ((RootBridgeSection == NULL) ||
      ((RootBridgeSection->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0))
  {
    return EFI_UNSUPPORTED;
  }

  Base = (CONST UINT8 *)Record + AssignmentSection->offset;
  for (Index = 0; Index < AssignmentSection->entry_count; Index++) {
    Assignment = (CONST struct cb_prh_pci_assignment_entry *)(CONST VOID *)(
                                                           Base + Index * AssignmentSection->entry_size
                                                           );
    if (!Cdk2CorebootPciAssignmentHasOwningBridge (Record, RootBridgeSection, Assignment)) {
      return EFI_COMPROMISED_DATA;
    }
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
Cdk2CorebootPciAssignmentCoversRange (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *AssignmentSection,
  IN UINT64                                    Base,
  IN UINT64                                    Length
  )
{
  CONST UINT8                              *SectionBase;
  CONST struct cb_prh_pci_assignment_entry *Assignment;
  UINT64                                    AssignmentBase;
  UINT64                                    AssignmentLength;
  UINTN                                     Index;

  if ((Record == NULL) || (AssignmentSection == NULL) ||
      ((AssignmentSection->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) == 0))
  {
    return FALSE;
  }

  SectionBase = (CONST UINT8 *)Record + AssignmentSection->offset;
  for (Index = 0; Index < AssignmentSection->entry_count; Index++) {
    Assignment = (CONST struct cb_prh_pci_assignment_entry *)(CONST VOID *)(
                                                                SectionBase +
                                                                Index * AssignmentSection->entry_size
                                                                );
    if (!Cdk2CorebootPciResourceMemory (Assignment->resource_type)) {
      continue;
    }

    AssignmentBase = Cdk2CorebootUnpack64At (
                       Assignment,
                       OFFSET_OF (struct cb_prh_pci_assignment_entry, base)
                       );
    AssignmentLength = Cdk2CorebootUnpack64At (
                         Assignment,
                         OFFSET_OF (struct cb_prh_pci_assignment_entry, length)
                         );
    if (Cdk2CorebootU64RangeWithin (Base, Length, AssignmentBase, AssignmentLength)) {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
EFI_STATUS
Cdk2CorebootValidateFramebufferOwnership (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST struct cb_payload_resource_section *FramebufferSection,
  IN CONST struct cb_payload_resource_section *MemorySection,
  IN CONST struct cb_payload_resource_section *PciAssignmentSection
  )
{
  CONST UINT8                           *SectionBase;
  CONST struct cb_prh_framebuffer_entry *Framebuffer;
  UINT64                                FramebufferBase;
  UINT64                                FramebufferSize;
  UINTN                                 Index;

  if (FramebufferSection == NULL) {
    return EFI_SUCCESS;
  }

  SectionBase = (CONST UINT8 *)Record + FramebufferSection->offset;
  for (Index = 0; Index < FramebufferSection->entry_count; Index++) {
    Framebuffer = (CONST struct cb_prh_framebuffer_entry *)(CONST VOID *)(
                                                              SectionBase +
                                                              Index * FramebufferSection->entry_size
                                                              );
    if ((Framebuffer->owner_flags & CB_PRH_FRAMEBUFFER_GEOMETRY_AUTHORITATIVE) == 0) {
      continue;
    }

    FramebufferBase = Cdk2CorebootUnpack64At (
                        Framebuffer,
                        OFFSET_OF (struct cb_prh_framebuffer_entry, physical_address)
                        );
    FramebufferSize = Cdk2CorebootUnpack64At (
                        Framebuffer,
                        OFFSET_OF (struct cb_prh_framebuffer_entry, size)
                        );
    if (!Cdk2CorebootMemoryPolicyCoversRangeWithGcdType (
           Record,
           MemorySection,
           CB_PRH_MEMORY_CACHE_AUTHORITATIVE | CB_PRH_MEMORY_GCD_AUTHORITATIVE,
           CB_PRH_GCD_MEMORY_TYPE_MMIO,
           FramebufferBase,
           FramebufferSize
           ) ||
        !Cdk2CorebootPciAssignmentCoversRange (
           Record,
           PciAssignmentSection,
           FramebufferBase,
           FramebufferSize
           ))
    {
      return EFI_UNSUPPORTED;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePayloadResourceCrossSectionRules (
  IN CONST struct cb_payload_resource_handoff *Record,
  IN CONST CDK2_COREBOOT_HANDOFF             *Handoff
  )
{
  CONST struct cb_payload_resource_section *Section;
  CONST struct cb_payload_resource_section *MemoryPolicySection;
  CONST struct cb_payload_resource_section *X86CacheSection;
  CONST struct cb_payload_resource_section *PciRootBridgeSection;
  CONST struct cb_payload_resource_section *PciAssignmentSection;
  CONST struct cb_payload_resource_section *FramebufferSection;
  CONST struct cb_prh_memory_policy_entry  *MemoryEntry;
  CONST struct cb_prh_x86_cache_state      *CacheState;
  CONST UINT8                              *SectionBase;
  UINT64                                    LifetimeFlags;
  BOOLEAN                                   AuthoritativeSection;
  BOOLEAN                                   MemoryOwnershipPolicy;
  BOOLEAN                                   CacheAuthoritativeMemory;
  BOOLEAN                                   ProtectionAuthoritativeMemory;
  BOOLEAN                                   PciAssignmentAuthoritative;
  UINTN                                     Index;
  UINTN                                     EntryIndex;
  EFI_STATUS                                Status;

  LifetimeFlags = Cdk2CorebootPayloadResourceLifetime (Record);
  if ((LifetimeFlags & ~CB_PRH_LIFETIME_VALID_MASK) != 0) {
    return EFI_UNSUPPORTED;
  }

  MemoryPolicySection          = NULL;
  X86CacheSection              = NULL;
  PciRootBridgeSection         = NULL;
  PciAssignmentSection         = NULL;
  FramebufferSection           = NULL;
  AuthoritativeSection          = FALSE;
  MemoryOwnershipPolicy         = FALSE;
  CacheAuthoritativeMemory      = FALSE;
  ProtectionAuthoritativeMemory = FALSE;
  PciAssignmentAuthoritative    = FALSE;
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
      MemoryPolicySection = Section;
      SectionBase = (CONST UINT8 *)Record + Section->offset;
      for (EntryIndex = 0; EntryIndex < Section->entry_count; EntryIndex++) {
        MemoryEntry = (CONST struct cb_prh_memory_policy_entry *)(CONST VOID *)(
                                                                      SectionBase +
                                                                      EntryIndex * Section->entry_size
                                                                      );
        if ((MemoryEntry->owner_flags & CDK2_COREBOOT_PRH_MEMORY_COVERAGE_FLAGS) != 0) {
          MemoryOwnershipPolicy = TRUE;
        }

        if ((MemoryEntry->owner_flags & CB_PRH_MEMORY_CACHE_AUTHORITATIVE) != 0) {
          CacheAuthoritativeMemory = TRUE;
        }

        if ((MemoryEntry->owner_flags & CB_PRH_MEMORY_PROTECTION_AUTHORITATIVE) != 0) {
          ProtectionAuthoritativeMemory = TRUE;
        }
      }
    } else if (Section->type == CB_PRH_SECTION_X86_CACHE_STATE) {
      X86CacheSection = Section;
    } else if (Section->type == CB_PRH_SECTION_PCI_ROOT_BRIDGES) {
      PciRootBridgeSection = Section;
    } else if (Section->type == CB_PRH_SECTION_PCI_ASSIGNMENTS) {
      PciAssignmentSection = Section;
      if ((Section->flags & CB_PRH_SECTION_FLAG_AUTHORITATIVE) != 0) {
        PciAssignmentAuthoritative = TRUE;
      }
    } else if (Section->type == CB_PRH_SECTION_FRAMEBUFFER) {
      FramebufferSection = Section;
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

    Status = Cdk2CorebootValidateMemoryPolicyAgainstCacheState (
               Record,
               MemoryPolicySection,
               X86CacheSection
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }

  }

  if (MemoryOwnershipPolicy && (Handoff != NULL) && (Handoff->MemoryRangeCount != 0)) {
    for (Index = 0; Index < Handoff->MemoryRangeCount; Index++) {
      if (!Cdk2CorebootMemoryPolicyCoversRangeWithAnyOwner (
             Record,
             MemoryPolicySection,
             CDK2_COREBOOT_PRH_MEMORY_COVERAGE_FLAGS,
             Handoff->MemoryRanges[Index].Base,
             Handoff->MemoryRanges[Index].Size
             ))
      {
        return EFI_COMPROMISED_DATA;
      }
    }
  }

  if ((LifetimeFlags & CB_PRH_LIFETIME_S3_RESUME) != 0) {
    return EFI_UNSUPPORTED;
  }

  if (ProtectionAuthoritativeMemory) {
    return EFI_UNSUPPORTED;
  }

  if (PciAssignmentAuthoritative) {
    Status = Cdk2CorebootValidatePciAssignmentsAgainstRootBridges (
               Record,
               PciRootBridgeSection,
               PciAssignmentSection
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  Status = Cdk2CorebootValidateFramebufferOwnership (
             Record,
             FramebufferSection,
             MemoryPolicySection,
             PciAssignmentSection
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
Cdk2CorebootPayloadResourceSectionTypeKnown (
  IN UINT16  Type
  )
{
  switch (Type) {
    case CB_PRH_SECTION_MEMORY_POLICY:
    case CB_PRH_SECTION_X86_CACHE_STATE:
    case CB_PRH_SECTION_PCI_ROOT_BRIDGES:
    case CB_PRH_SECTION_PCI_ASSIGNMENTS:
    case CB_PRH_SECTION_BOOT_INTENT:
    case CB_PRH_SECTION_RUNTIME_POLICY:
    case CB_PRH_SECTION_FRAMEBUFFER:
      return TRUE;

    default:
      return FALSE;
  }
}

STATIC
EFI_STATUS
Cdk2CorebootValidatePayloadResourceHandoff (
  IN CONST struct cb_payload_resource_handoff  *Record,
  IN CONST CDK2_COREBOOT_HANDOFF              *Handoff
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
      if ((Section->type == OtherSection->type) &&
          Cdk2CorebootPayloadResourceSectionTypeKnown (Section->type))
      {
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

  return Cdk2CorebootValidatePayloadResourceCrossSectionRules (Record, Handoff);
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

        Handoff->PayloadResourceHandoffStatus = EFI_SUCCESS;
        Handoff->PayloadResourceHandoff       = (CONST struct cb_payload_resource_handoff *)Record;

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

  if ((Handoff->PayloadResourceHandoffStatus == EFI_SUCCESS) &&
      (Handoff->PayloadResourceHandoff != NULL))
  {
    Handoff->PayloadResourceHandoffStatus = Cdk2CorebootValidatePayloadResourceHandoff (
                                              Handoff->PayloadResourceHandoff,
                                              Handoff
                                              );
    if (EFI_ERROR (Handoff->PayloadResourceHandoffStatus)) {
      Handoff->PayloadResourceHandoff = NULL;
    }
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
