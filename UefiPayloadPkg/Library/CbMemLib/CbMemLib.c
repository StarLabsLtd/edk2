/** @file
  Coreboot CBMEM access and payload timestamp support.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Base.h>
#include <Coreboot.h>
#include <Guid/CbMemTableHob.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BlParseLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>

#include <Library/CbMemLib.h>

STATIC
UINT64
CbMemUnpack64 (
  IN struct cbuint64  Value
  )
{
  return LShiftU64 (Value.hi, 32) | Value.lo;
}

STATIC
UINT64
CbMemUnpackReferenceAddress (
  IN UINT64  Value
  )
{
  struct cbuint64  Packed;

  CopyMem (&Packed, &Value, sizeof (Packed));
  return CbMemUnpack64 (Packed);
}

STATIC
RETURN_STATUS
GetCorebootTable (
  OUT struct cb_header  **Header
  )
{
  struct cb_header     *Candidate;
  COREBOOT_TABLE_HOB   *TableHob;
  VOID                 *GuidHob;
  VOID                 *HobList;

  if (Header == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  *Header   = NULL;
  HobList = GetHobList ();
  GuidHob = NULL;
  if (HobList != NULL) {
    GuidHob = GetFirstGuidHob (&gUefiPayloadCorebootTableGuid);
  }
  if ((GuidHob != NULL) &&
      (GET_GUID_HOB_DATA_SIZE (GuidHob) >= sizeof (*TableHob)))
  {
    TableHob  = (COREBOOT_TABLE_HOB *)GET_GUID_HOB_DATA (GuidHob);
    if (TableHob->Address > MAX_UINTN) {
      return RETURN_UNSUPPORTED;
    }

    Candidate = (struct cb_header *)(UINTN)TableHob->Address;
    if ((Candidate != NULL) && (Candidate->signature == CB_HEADER_SIGNATURE) &&
        (Candidate->header_bytes >= sizeof (*Candidate)) &&
        (Candidate->table_bytes >= sizeof (struct cb_record)) &&
        (TableHob->Size >= Candidate->header_bytes + Candidate->table_bytes))
    {
      *Header = Candidate;
      return RETURN_SUCCESS;
    }
  }

  // Legacy coreboot handoff: retain the low-memory scan for payloads that do
  // not publish the table HOB.
  Candidate = (struct cb_header *)GetParameterBase ();
  if ((Candidate != NULL) && (Candidate->signature == CB_HEADER_SIGNATURE) &&
      (Candidate->header_bytes >= sizeof (*Candidate)) &&
      (Candidate->table_bytes >= sizeof (struct cb_record)))
  {
    *Header = Candidate;
    return RETURN_SUCCESS;
  }

  return (GuidHob == NULL) ? RETURN_NOT_FOUND : RETURN_COMPROMISED_DATA;
}

STATIC
RETURN_STATUS
FindCorebootRecord (
  IN  UINT32         Tag,
  OUT struct cb_record **Record,
  OUT UINT32         *RecordSize
  )
{
  struct cb_header  *Header;
  struct cb_record  *Current;
  UINT8             *Cursor;
  UINT8             *End;
  UINTN             Index;
  RETURN_STATUS     Status;

  if (Record == NULL) {
    return RETURN_INVALID_PARAMETER;
  }

  *Record = NULL;
  if (RecordSize != NULL) {
    *RecordSize = 0;
  }

  Status = GetCorebootTable (&Header);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  Cursor = (UINT8 *)Header + Header->header_bytes;
  End    = Cursor + Header->table_bytes;
  if (End < Cursor) {
    return RETURN_COMPROMISED_DATA;
  }

  for (Index = 0; Index < Header->table_entries; Index++) {
    if ((UINTN)(End - Cursor) < sizeof (struct cb_record)) {
      return RETURN_COMPROMISED_DATA;
    }

    Current = (struct cb_record *)Cursor;
    if ((Current->size < sizeof (*Current)) ||
        (Current->size > (UINTN)(End - Cursor)))
    {
      return RETURN_COMPROMISED_DATA;
    }

    if (Current->tag == Tag) {
      *Record = Current;
      if (RecordSize != NULL) {
        *RecordSize = Current->size;
      }
      return RETURN_SUCCESS;
    }

    Cursor += Current->size;
  }

  return RETURN_NOT_FOUND;
}

STATIC
RETURN_STATUS
GetLegacyCbmemPointer (
  IN  UINT32  Id,
  OUT VOID    **Address,
  OUT UINT32  *Size
  )
{
  struct cb_record     *Record;
  struct cb_cbmem_ref  *Reference;
  UINT64               ReferenceAddress;
  UINT32               Tag;
  RETURN_STATUS        Status;

  switch (Id) {
    case CBMEM_ID_CONSOLE:
      Tag = CB_TAG_CBMEM_CONSOLE;
      break;
    case CBMEM_ID_TIMESTAMP:
      Tag = CB_TAG_TIMESTAMPS;
      break;
    default:
      return RETURN_NOT_FOUND;
  }

  Status = FindCorebootRecord (Tag, &Record, NULL);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  if ((Record->size < sizeof (*Reference)) || (Address == NULL)) {
    return RETURN_COMPROMISED_DATA;
  }

  Reference = (struct cb_cbmem_ref *)Record;
  ReferenceAddress = CbMemUnpackReferenceAddress (Reference->cbmem_addr);
  if (ReferenceAddress > MAX_UINTN) {
    return RETURN_UNSUPPORTED;
  }

  *Address = (VOID *)(UINTN)ReferenceAddress;
  if (Size != NULL) {
    *Size = 0;
  }

  return (*Address == NULL) ? RETURN_COMPROMISED_DATA : RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
CbMemFind (
  IN  UINT32  Id,
  OUT VOID    **Address,
  OUT UINT32  *Size
  )
{
  struct cb_record       *Record;
  struct cb_cbmem_entry  *Entry;
  struct cb_header       *Header;
  UINT8                  *Cursor;
  UINT8                  *End;
  UINT64                 EntryAddress;
  UINTN                  Index;
  RETURN_STATUS          Status;

  if ((Address == NULL) || (Size == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  *Address = NULL;
  *Size    = 0;

  Status = GetCorebootTable (&Header);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  Cursor = (UINT8 *)Header + Header->header_bytes;
  End    = Cursor + Header->table_bytes;
  if (End < Cursor) {
    return RETURN_COMPROMISED_DATA;
  }

  for (Index = 0; Index < Header->table_entries; Index++) {
    if ((UINTN)(End - Cursor) < sizeof (*Record)) {
      return RETURN_COMPROMISED_DATA;
    }

    Record = (struct cb_record *)Cursor;
    if ((Record->size < sizeof (*Record)) ||
        (Record->size > (UINTN)(End - Cursor)))
    {
      return RETURN_COMPROMISED_DATA;
    }

    if ((Record->tag == CB_TAG_CBMEM_ENTRY) &&
        (Record->size >= sizeof (*Entry)))
    {
      Entry = (struct cb_cbmem_entry *)Record;
      if (Entry->id == Id) {
        EntryAddress = CbMemUnpack64 (Entry->address);
        if (EntryAddress > MAX_UINTN) {
          return RETURN_UNSUPPORTED;
        }

        *Address = (VOID *)(UINTN)EntryAddress;
        *Size    = Entry->entry_size;
        return (*Address == NULL) ? RETURN_COMPROMISED_DATA : RETURN_SUCCESS;
      }
    }

    Cursor += Record->size;
  }

  return GetLegacyCbmemPointer (Id, Address, Size);
}

RETURN_STATUS
EFIAPI
CbMemFindDmaRange (
  OUT PHYSICAL_ADDRESS  *Address,
  OUT UINT32            *Size
  )
{
  struct cb_record  *Record;
  struct cb_range   *Range;
  UINT64            RangeAddress;
  RETURN_STATUS     Status;

  if ((Address == NULL) || (Size == NULL)) {
    return RETURN_INVALID_PARAMETER;
  }

  *Address = 0;
  *Size    = 0;
  Status   = FindCorebootRecord (CB_TAG_DMA, &Record, NULL);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  if (Record->size != sizeof (*Range)) {
    return RETURN_COMPROMISED_DATA;
  }

  Range        = (struct cb_range *)Record;
  RangeAddress = CbMemUnpackReferenceAddress (Range->range_start);
  if ((RangeAddress == 0) || (Range->range_size == 0) ||
      (RangeAddress > MAX_UINTN) ||
      (RangeAddress + Range->range_size < RangeAddress))
  {
    return RETURN_COMPROMISED_DATA;
  }

  *Address = RangeAddress;
  *Size    = Range->range_size;
  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
CbMemPublishTableHob (
  VOID
  )
{
  struct cb_header      *Header;
  COREBOOT_TABLE_HOB    TableHob;
  RETURN_STATUS         Status;

  Status = GetCorebootTable (&Header);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  TableHob.Address  = (UINT64)(UINTN)Header;
  TableHob.Size     = Header->header_bytes + Header->table_bytes;
  TableHob.Reserved = 0;
  return (BuildGuidDataHob (
            &gUefiPayloadCorebootTableGuid,
            &TableHob,
            sizeof (TableHob)
            ) == NULL) ? RETURN_OUT_OF_RESOURCES : RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
CbMemLogSummary (
  VOID
  )
{
  struct cb_timestamp_table  *Table;
  UINT32                     Size;
  RETURN_STATUS              Status;

  if (!FeaturePcdGet (PcdCbmemTimestamps)) {
    return RETURN_UNSUPPORTED;
  }

  Status = CbMemFind (CBMEM_ID_TIMESTAMP, (VOID **)&Table, &Size);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  if ((Size != 0) && (Size < sizeof (*Table))) {
    return RETURN_COMPROMISED_DATA;
  }

  if ((Table->max_entries == 0) ||
      (Table->num_entries > Table->max_entries) ||
      ((Size != 0) &&
       (Table->max_entries > ((Size - sizeof (*Table)) / sizeof (Table->entries[0])))))
  {
    return RETURN_COMPROMISED_DATA;
  }

  DEBUG ((
    DEBUG_INFO,
    "CBMEM: timestamp table=%p size=0x%x base=0x%lx entries=%u/%u freq=%uMHz\n",
    Table,
    Size,
    Table->base_time,
    Table->num_entries,
    Table->max_entries,
    Table->tick_freq_mhz
    ));

  return RETURN_SUCCESS;
}

RETURN_STATUS
EFIAPI
CbMemTimestampAdd (
  IN UINT32  Id
  )
{
#if defined (MDE_CPU_X64) || defined (MDE_CPU_IA32)
  struct cb_timestamp_table  *Table;
  UINT32                     Size;
  UINT64                     Timestamp;
  RETURN_STATUS              Status;

  if (!FeaturePcdGet (PcdCbmemTimestamps)) {
    return RETURN_UNSUPPORTED;
  }

  Status = CbMemFind (CBMEM_ID_TIMESTAMP, (VOID **)&Table, &Size);
  if (RETURN_ERROR (Status)) {
    return Status;
  }

  if ((Size != 0) &&
      ((Size < sizeof (*Table)) ||
       (Table->max_entries > ((Size - sizeof (*Table)) / sizeof (Table->entries[0])))))
  {
    return RETURN_COMPROMISED_DATA;
  }

  if ((Table->max_entries == 0) || (Table->num_entries >= Table->max_entries)) {
    return RETURN_COMPROMISED_DATA;
  }

  Timestamp = AsmReadTsc ();
  if (Timestamp < Table->base_time) {
    return RETURN_UNSUPPORTED;
  }

  Table->entries[Table->num_entries].entry_id    = Id;
  Table->entries[Table->num_entries].entry_stamp = (INT64)(Timestamp - Table->base_time);
  Table->num_entries++;
  return RETURN_SUCCESS;
#else
  (VOID)Id;
  return RETURN_UNSUPPORTED;
#endif
}
