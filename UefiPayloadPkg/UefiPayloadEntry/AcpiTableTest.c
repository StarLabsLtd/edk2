/** @file
  Exercise the production native TPM log importer with bounded HOB allocation.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
static int Required = 1;
#define _PCD_VALUE_PcdTpm2MeasurementRequired Required
#include "AcpiTable.c"

static UINT8 Log[256], Table[256], Copied[256];
static unsigned Hobs;
static BOOLEAN FailAllocation;
VOID *EFIAPI CopyMem(VOID *Dest, CONST VOID *Source, UINTN Size) { return memcpy(Dest, Source, Size); }
INTN EFIAPI CompareMem(CONST VOID *Left, CONST VOID *Right, UINTN Size) { return memcmp(Left, Right, Size); }
BOOLEAN EFIAPI IsZeroBuffer(CONST VOID *Buffer, UINTN Size)
{ CONST UINT8 *Bytes = Buffer; while (Size--) { if (*Bytes++) { return FALSE; } } return TRUE; }
UINT16 EFIAPI ReadUnaligned16(CONST VOID *Source) { UINT16 Value; memcpy(&Value, Source, 2); return Value; }
UINT32 EFIAPI ReadUnaligned32(CONST VOID *Source) { UINT32 Value; memcpy(&Value, Source, 4); return Value; }
UINT64 EFIAPI ReadUnaligned64(CONST VOID *Source) { UINT64 Value; memcpy(&Value, Source, 8); return Value; }
BOOLEAN EFIAPI DebugPrintEnabled(VOID) { return TRUE; }
BOOLEAN EFIAPI DebugPrintLevelEnabled(CONST UINTN Level) { return TRUE; }
VOID EFIAPI DebugPrint(UINTN Level, CONST CHAR8 *Format, ...) { }
VOID *EFIAPI BuildGuidHob(CONST EFI_GUID *Guid, UINTN Size)
{ Hobs++; return FailAllocation || Size > sizeof(Copied) ? NULL : Copied; }
EFI_GUID gTcgEvent2EntryHobGuid;

static void Put32(UINT8 *Dest, UINT32 Value) { memcpy(Dest, &Value, 4); }
static void Put16(UINT8 *Dest, UINT16 Value) { memcpy(Dest, &Value, 2); }
static UINTN Prepare(void)
{
  EFI_ACPI_DESCRIPTION_HEADER *Header = (VOID *)Table;
  UINTN Offset = sizeof(EFI_TPM2_ACPI_TABLE) +
    EFI_TPM2_ACPI_TABLE_START_METHOD_SPECIFIC_PARAMETERS_MAX_SIZE_REVISION_4;
  UINT64 Address = (UINTN)Log;
  memset(Log, 0, sizeof(Log));
  memset(Table, 0, sizeof(Table));
  Hobs = 0;
  FailAllocation = FALSE;
  Header->Signature = EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE;
  Header->Revision = EFI_TPM2_ACPI_TABLE_REVISION_4;
  Header->Length = Offset + 12;
  Put32(Table + Offset, 118);
  memcpy(Table + Offset + 4, &Address, 8);
  Put32(Log + 4, EV_NO_ACTION);
  Put32(Log + 28, 33);
  memcpy(Log + 32, "Spec ID Event03", 16);
  Log[32 + 21] = 2;
  Log[32 + 23] = 2;
  Put32(Log + 32 + 24, 1);
  Put16(Log + 32 + 28, TPM_ALG_SHA256);
  Put16(Log + 32 + 30, 32);
  Put32(Log + 65, 2);
  Put32(Log + 69, EV_POST_CODE);
  Put32(Log + 73, 1);
  Put16(Log + 77, TPM_ALG_SHA256);
  Put32(Log + 111, 3);
  memcpy(Log + 115, "abc", 3);
  return Offset;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "import %u: %s\n", __LINE__, #x); return 1; } } while (0)
#define IMPORT() BuildTpmEventHobsFromAcpi((VOID *)Table)
int main(void)
{
  UINTN Offset = Prepare(), Size, DataOffset;
  UINT32 DataSize;
  CHECK(IMPORT() == RETURN_SUCCESS && Hobs == 1 && memcmp(Copied, Log + 65, 53) == 0);
  Put32(Table + Offset, sizeof(Log));
  CHECK(IMPORT() == RETURN_SUCCESS);
  Log[255] = 1;
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare(); FailAllocation = TRUE;
  CHECK(IMPORT() == RETURN_OUT_OF_RESOURCES);
  Prepare(); Put32(Table + Offset, 117);
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare(); Put32(Log, 1);
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare(); Log[8] = 1;
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare(); Put32(Log + 28, MAX_UINT32);
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare(); Put32(Log + 56, MAX_UINT32);
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare(); Put32(Log + 111, MAX_UINT32);
  CHECK(IMPORT() == RETURN_COMPROMISED_DATA);
  Prepare();
  { UINT64 Address = MAX_UINT64 - 10; memcpy(Table + Offset + 4, &Address, 8); }
  CHECK(IMPORT() == RETURN_BAD_BUFFER_SIZE);
  Prepare(); Put32(Log + 73, 2); Put16(Log + 111, TPM_ALG_SHA256);
  memset(Log + 113, 0, 32); Put32(Log + 145, 3); memcpy(Log + 149, "abc", 3);
  CHECK(!GetTcgPcrEvent2Size(Log + 65, 87, &Size, &DataOffset, &DataSize, 1U << TPM_ALG_SHA256));
  Prepare(); Put16(Log + 77, TPM_ALG_SHA1);
  CHECK(!GetTcgPcrEvent2Size(Log + 65, 53, &Size, &DataOffset, &DataSize, 1U << TPM_ALG_SHA256));
  Put32(Log + 99, 3); memcpy(Log + 103, "abc", 3);
  CHECK(!GetTcgPcrEvent2Size(Log + 65, 41, &Size, &DataOffset, &DataSize,
    (1U << TPM_ALG_SHA1) | (1U << TPM_ALG_SHA256)));
  Required = FALSE;
  CHECK(GetTcgPcrEvent2Size(Log + 65, 41, &Size, &DataOffset, &DataSize, MAX_UINT32));
  puts("Production native log import: valid, padding, malformed, allocation and default policy passed");
  return 0;
}
