/** @file

  Freestanding coreboot table validation for the native cdk2 stage.

  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "coreboot.h"

STATIC
UINT64
Cdk2CorebootUnpack64 (
  IN CONST struct cbuint64  *Value
  )
{
  return (UINT64)Value->lo | ((UINT64)Value->hi << 32);
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
  Handoff->Header    = Header;
  Handoff->TableSize = HeaderBytes + Header->table_bytes;

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
