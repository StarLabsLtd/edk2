/** @file
  Exercise the production fixed ACPI log with a growing loader event stream.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include <PiDxe.h>
#include <Library/PcdLib.h>
EFI_GUID gEfiCallerIdGuid;
static BOOLEAN Required;
static UINT32 Minimum = 0x10000;
static UINT8 Revision = 4;
static UINT32 PublishedSize;
static UINTN AllocatedPages;
static UINT64 PublishedAddress;
#undef FixedPcdGetBool
#define FixedPcdGetBool(Token) Required
#undef PcdGet32
#define PcdGet32(Token) Minimum
#undef PcdGet8
#define PcdGet8(Token) Revision
#undef PcdGetBool
#define PcdGetBool(Token) FALSE
#undef PcdGetPtr
#define PcdGetPtr(Token) ((VOID *)0)
#undef PcdSet32S
#define PcdSet32S(Token, Value) (PublishedSize = (Value), EFI_SUCCESS)
#undef PcdSet64S
#define PcdSet64S(Token, Value) (PublishedAddress = (Value), EFI_SUCCESS)
#include "Tcg2Dxe.c"

VOID *EFIAPI CopyMem(VOID *To, CONST VOID *From, UINTN Size) { return memmove(To, From, Size); }
VOID *EFIAPI ZeroMem(VOID *To, UINTN Size) { return memset(To, 0, Size); }
UINT16 EFIAPI ReadUnaligned16(CONST VOID *P) { UINT16 V; memcpy(&V, P, 2); return V; }
UINT32 EFIAPI ReadUnaligned32(CONST VOID *P) { UINT32 V; memcpy(&V, P, 4); return V; }
UINT64 EFIAPI LShiftU64(UINT64 V, UINTN N) { return V << N; }
UINT16 EFIAPI Tpm2GetHashSizeFromAlgo(TPMI_ALG_HASH Algo) { return SHA256_DIGEST_SIZE; }
UINT16 EFIAPI GetHashSizeFromAlgo(TPMI_ALG_HASH Algo) { return SHA256_DIGEST_SIZE; }
INTN EFIAPI CompareMem(CONST VOID *A, CONST VOID *B, UINTN Size) { return memcmp(A, B, Size); }

BOOLEAN EFIAPI DebugAssertEnabled(VOID) { return TRUE; }
BOOLEAN EFIAPI DebugPrintEnabled(VOID) { return FALSE; }
BOOLEAN EFIAPI DebugCodeEnabled(VOID) { return TRUE; }
VOID EFIAPI DebugAssert(CONST CHAR8 *File, UINTN Line, CONST CHAR8 *Text)
{ fprintf(stderr, "%s:%lu: %s\n", File, (unsigned long)Line, Text); abort(); }
VOID EFIAPI DebugPrint(UINTN Level, CONST CHAR8 *Format, ...) { }

#define CHECK(Condition) do { if (!(Condition)) { fprintf(stderr, "%d: %s\n", __LINE__, #Condition); exit(1); } } while (0)
UINT32 EFIAPI WriteUnaligned32(VOID *P, UINT32 V) { memcpy(P, &V, 4); return V; }
EFI_GUID gTcgEventEntryHobGuid, gTcgEvent2EntryHobGuid;
static UINT8 Main[0x200000], Acpi[0x200000], Data[35675];
static _Alignas(8) UINT8 Final[256];
static EFI_STATUS EFIAPI AllocateLogPages(EFI_ALLOCATE_TYPE Type, EFI_MEMORY_TYPE Memory,
  UINTN Pages, EFI_PHYSICAL_ADDRESS *Address)
{
  if (Memory != EfiACPIMemoryNVS) return EFI_ABORTED;
  CHECK(Pages <= sizeof(Acpi) / EFI_PAGE_SIZE);
  AllocatedPages = Pages;
  *Address = (UINTN)Acpi;
  return EFI_SUCCESS;
}
static EFI_BOOT_SERVICES Services = { .AllocatePages = AllocateLogPages };
EFI_BOOT_SERVICES *gBS = &Services;
VOID *EFIAPI SetMem(VOID *P, UINTN Size, UINT8 Value) { return memset(P, Value, Size); }
VOID *EFIAPI AllocatePool(UINTN Size) { abort(); }
VOID *EFIAPI AllocateCopyPool(UINTN Size, CONST VOID *Data) { abort(); }
VOID EFIAPI FreePool(VOID *P) { abort(); }
VOID *EFIAPI GetHobList(VOID) { abort(); }
VOID EFIAPI CpuDeadLoop(VOID) { abort(); }
VOID *EFIAPI GetFirstGuidHob(CONST EFI_GUID *Guid) { abort(); }
VOID *EFIAPI GetNextGuidHob(CONST EFI_GUID *Guid, CONST VOID *Hob) { abort(); }
EFI_GUID gTcg800155PlatformIdEventHobGuid, gTcgEfiStartupLocalityEventHobGuid;
EFI_GUID gEfiTcg2FinalEventsTableGuid;

#pragma pack(1)
static struct { UINT32 Pcr, Type, Count; UINT16 Alg; UINT8 Digest[32]; UINT32 Size; } Header;
#pragma pack()
static void Reset(void)
{
  memset(&mTcgDxeData, 0, sizeof(mTcgDxeData));
  mTcgDxeData.BsCap.ActivePcrBanks = EFI_TCG2_BOOT_HASH_ALG_SHA256;
  UINT32 Size;
  CHECK(GetAcpiLogAreaSize(&Size) == EFI_SUCCESS);
  mTcgDxeData.EventLogAreaStruct[1].Lasa = (UINTN)Main;
  mTcgDxeData.EventLogAreaStruct[1].Laml = sizeof(Main);
  mTcgDxeData.AcpiEventLogAreaStruct[1].Lasa = (UINTN)Acpi;
  mTcgDxeData.AcpiEventLogAreaStruct[1].Laml = Size - GetTruncationEventSize();
  memset(&Header, 0, sizeof(Header));
  Header.Pcr = 8; Header.Type = 0x0d /* EV_IPL */; Header.Count = 1; Header.Alg = TPM_ALG_SHA256;
}
static EFI_STATUS Append(UINT32 Size)
{
  Header.Size = Size;
  return TcgDxeLogEvent(EFI_TCG2_EVENT_LOG_FORMAT_TCG_2, &Header, sizeof(Header), Data, Size);
}
int main(void)
{
  for (Required = FALSE; Required <= TRUE; Required++) {
    Reset();
    UINT32 Capacity;
    CHECK(GetAcpiLogAreaSize(&Capacity) == EFI_SUCCESS);
    /* Match the observed prefix before GRUB's 35,675-byte submenu event. */
    mTcgDxeData.EventLogAreaStruct[1].EventLogSize = 42326;
    mTcgDxeData.AcpiEventLogAreaStruct[1].EventLogSize = 42326;
    CHECK(Append(sizeof(Data)) == EFI_SUCCESS);
    CHECK(mTcgDxeData.AcpiEventLogAreaStruct[1].EventLogTruncated == !Required);
    CHECK(Capacity == (Required ? 0x100000 + GetTruncationEventSize() : 0x10000));
    if (Required) CHECK(mTcgDxeData.AcpiEventLogAreaStruct[1].EventLogSize == 42326 + sizeof(Header) + sizeof(Data));
    Reset();
    TCG_EVENT_LOG_AREA_STRUCT *Log = &mTcgDxeData.AcpiEventLogAreaStruct[1];
    Log->EventLogSize = Log->Laml - sizeof(Header) - 1;
    CHECK(Append(1) == EFI_SUCCESS);
    CHECK(Append(0) == (Required ? EFI_VOLUME_FULL : EFI_SUCCESS));
    CHECK(Log->EventLogTruncated);
    CHECK(Append(1) == (Required ? EFI_VOLUME_FULL : EFI_SUCCESS));
  }
  for (Required = FALSE; Required <= TRUE; Required++) {
    UINT32 Size = 123;
    Minimum = 73;
    CHECK(GetTruncationEventSize() == 74);
    CHECK(GetAcpiLogAreaSize(&Size) == EFI_INVALID_PARAMETER);
    Minimum = 0;
    CHECK(GetAcpiLogAreaSize(&Size) == EFI_INVALID_PARAMETER);
    CHECK(Size == 123);
    Minimum = MAX_UINT32;
    CHECK(GetAcpiLogAreaSize(&Size) ==
      ((Required || sizeof(UINTN) == 4) ? EFI_INVALID_PARAMETER : EFI_SUCCESS));
  }
  Minimum = 0x10000;
  Required = TRUE;
  Reset();
  TCG_EVENT_LOG_AREA_STRUCT *Log = &mTcgDxeData.AcpiEventLogAreaStruct[1];
  Log->EventLogSize = Log->Laml - sizeof(Header);
  CHECK(Append(1) == EFI_VOLUME_FULL); /* One byte beyond usable capacity. */
  CHECK(Log->EventLogTruncated);
  /* The observed EFI log plus both EBS events must fit the fixed mirror. */
  Reset();
  mTcgDxeData.EventLogAreaStruct[1].EventLogSize = 127834;
  mTcgDxeData.AcpiEventLogAreaStruct[1].EventLogSize = 127834;
  memset(Final, 0, sizeof(Final));
  mTcgDxeData.GetEventLogCalled[1] = TRUE;
  mTcgDxeData.FinalEventsTable[1] = (VOID *)Final;
  mTcgDxeData.FinalEventLogAreaStruct[1].Lasa =
    (UINTN)(Final + sizeof(EFI_TCG2_FINAL_EVENTS_TABLE));
  mTcgDxeData.FinalEventLogAreaStruct[1].Laml =
    sizeof(Final) - sizeof(EFI_TCG2_FINAL_EVENTS_TABLE);
  Header.Pcr = 5;
  Header.Type = EV_EFI_ACTION;
  memcpy(Data, EFI_EXIT_BOOT_SERVICES_INVOCATION, 29);
  CHECK(Append(29) == EFI_SUCCESS);
  CHECK(mTcgDxeData.FinalEventsTable[1]->NumberOfEvents == 1);
  memcpy(Data, EFI_EXIT_BOOT_SERVICES_SUCCEEDED, 40);
  CHECK(Append(40) == EFI_SUCCESS);
  CHECK(mTcgDxeData.FinalEventsTable[1]->NumberOfEvents == 2);
  CHECK(mTcgDxeData.AcpiEventLogAreaStruct[1].EventLogSize == 128003);
  CHECK(memcmp(Main + 127834, Acpi + 127834, 169) == 0);
  CHECK(!mTcgDxeData.AcpiEventLogAreaStruct[1].EventLogTruncated);
  Minimum = 0x0fffff00;
  UINT32 Size;
  CHECK(GetAcpiLogAreaSize(&Size) ==
    (sizeof(UINTN) == 4 ? EFI_INVALID_PARAMETER : EFI_SUCCESS));
  UINT64 Limit = MAX_UINT32;
  if (sizeof(UINTN) == 4) Limit -= EFI_PAGE_MASK;
  Minimum = (UINT32)((Limit - 74) >> 4);
  CHECK(GetAcpiLogAreaSize(&Size) == EFI_SUCCESS);
  CHECK(Size == (UINT64)Minimum * 16 + 74);
  Minimum++;
  CHECK(GetAcpiLogAreaSize(&Size) == EFI_INVALID_PARAMETER);
  Minimum = 0x10000;
  for (Required = FALSE; Required <= TRUE; Required++) {
    for (Revision = 3; Revision <= 4; Revision++) {
      Reset();
      PublishedSize = 0;
      AllocatedPages = 0;
      PublishedAddress = 0;
      mTcgDxeData.BsCap.SupportedEventLogs = EFI_TCG2_EVENT_LOG_FORMAT_TCG_2;
      CHECK(SetupEventLog() == EFI_ABORTED); /* Stop after fixed-log setup. */
      if (Required || Revision >= 4) {
        CHECK(PublishedSize == (Required ? 0x10004a : 0x10000));
        CHECK(PublishedAddress == (UINTN)Acpi);
        CHECK(AllocatedPages == EFI_SIZE_TO_PAGES(PublishedSize));
        CHECK(mTcgDxeData.AcpiEventLogAreaStruct[1].Laml == PublishedSize - 74);
      } else {
        CHECK(PublishedSize == 0);
        CHECK(AllocatedPages == 0);
        CHECK(mTcgDxeData.AcpiEventLogAreaStruct[1].Lasa == 0);
      }
    }
  }
  puts("Production fixed event log: loader growth, exact capacity and repeated truncation passed");
  return 0;
}
