/** @file
  Exercise the production MM wire dispatcher with a mocked verification engine.
  The real signature/region engine is exercised separately by OwnerTest.
  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
static unsigned char KeyData[] = {0, 0, 0, 1, 0x5a, 0, 0, 0};
#define _PCD_GET_MODE_PTR_PcdFmpDevicePkcs7CertBufferXdr KeyData
static unsigned KeySize = sizeof(KeyData);
#define _PCD_GET_MODE_SIZE_PcdFmpDevicePkcs7CertBufferXdr KeySize
#include "OwnerMm.c"
EFI_GUID gEfiEventExitBootServicesGuid;
EFI_GUID gCorebootCapsuleUpdateGuid;
EFI_GUID gEfiSmmVariableProtocolGuid;
static EFI_SMM_VARIABLE_PROTOCOL Variables;
static unsigned FloorMode;
static UINT32 StoredFloor;
static EFI_MM_SYSTEM_TABLE SystemTable;
EFI_MM_SYSTEM_TABLE *gMmst = &SystemTable;
static BOOLEAN Exited, SourceAllowed = TRUE;
static unsigned Begins, Programs;
static EFI_STATUS VerifyStatus;
static BOOLEAN Activate = TRUE;
static VOID *PacketAddress;
VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { return memcpy(d, s, n); }
VOID *EFIAPI ZeroMem(VOID *d, UINTN n) { return memset(d, 0, n); }
INTN EFIAPI CompareMem(CONST VOID *a, CONST VOID *b, UINTN n) { return memcmp(a, b, n); }
UINT32 EFIAPI ReadUnaligned32(CONST VOID *p) { UINT32 v; memcpy(&v, p, sizeof(v)); return v; }
UINT32 EFIAPI SwapBytes32(UINT32 v) { return __builtin_bswap32(v); }
BOOLEAN CapsuleTrustValid(CONST UINT8 *Root, UINTN Size)
{ return Size == 1 && *Root == 0x5a; }
BOOLEAN CapsuleSourceInit(CAPSULE_SOURCE *s, EFI_PHYSICAL_ADDRESS a, UINTN n)
{ s->Address = a; s->Size = n; return SourceAllowed; }
BOOLEAN CapsuleSourceRead(VOID *c, UINTN o, VOID *b, UINTN n)
{ (void)c; (void)o; (void)b; (void)n; return TRUE; }
VOID CapsuleOwnerClose(CAPSULE_OWNER *o) { o->Active = FALSE; }
EFI_STATUS CapsuleOwnerBegin(CAPSULE_OWNER *o, CONST UINT8 *s, UINTN n)
{
  Begins++;
  /* Dispatch receives the MM core's private shadow, including its signature. */
  if ((CONST VOID *)s != PacketAddress || n != 1 || *s != 0xa5) abort();
  o->Active = Activate && !EFI_ERROR(VerifyStatus);
  return VerifyStatus;
}
EFI_STATUS CapsuleOwnerProgram(CAPSULE_OWNER *o, UINTN b)
{ (void)o; (void)b; Programs++; return EFI_SUCCESS; }
static EFI_STATUS EFIAPI GetVariable(CHAR16 *Name, EFI_GUID *Guid, UINT32 *Attributes,
                                      UINTN *Size, VOID *Data)
{
  if (FloorMode == 3) return EFI_DEVICE_ERROR;
  if (FloorMode == 1 && Name[3] == 'S') {
    FMP_CONTROLLER_STATE State = {.LsvValid = TRUE, .Lsv = StoredFloor};
    memcpy(Data, &State, sizeof(State)); *Size = sizeof(State); return EFI_SUCCESS;
  }
  if (FloorMode == 2 && Name[3] == 'L') {
    memcpy(Data, &StoredFloor, sizeof(StoredFloor)); *Size = sizeof(StoredFloor); return EFI_SUCCESS;
  }
  return EFI_NOT_FOUND;
}
static EFI_STATUS EFIAPI Locate(EFI_GUID *g, VOID *r, VOID **i)
{ (void)g; (void)r; (void)i; return Exited ? EFI_SUCCESS : EFI_NOT_FOUND; }
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "dispatch %u: %s\n", __LINE__, #x); return 1; } } while (0)
static EFI_STATUS Command(VOID *Packet, UINTN *Size)
{
  COREBOOT_CAPSULE_HEADER *Header = Packet;

  /* A delivered rejection must survive MmiManage's transport-status filter. */
  if (Dispatch(NULL, NULL, Packet, Size) != EFI_SUCCESS) abort();
  return Header->Result & BIT31 ? EFIERR(Header->Result & ~BIT31) : Header->Result;
}
int main(void)
{
  static COREBOOT_CAPSULE_PRIVATE_INFO Info = {.FlashSize = CAPSULE_BLOCK_SIZE,
    .BlockSize = CAPSULE_BLOCK_SIZE, .LowestSupportedVersion = 10};
  UINT8 Bytes[sizeof(COREBOOT_CAPSULE_START) + 1] = {0};
  COREBOOT_CAPSULE_START *Start = (VOID *)Bytes;
  COREBOOT_CAPSULE_HEADER Header = {COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_CLOSE, 0};
  COREBOOT_CAPSULE_BLOCK Block;
  COREBOOT_CAPSULE_GEOMETRY Geometry = {{COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_INFO, 0}};
  UINTN Size;
  UINT32 Transaction;
  mInfo = &Info;
  SystemTable.MmLocateProtocol = Locate;
  Variables.SmmGetVariable = GetVariable;
  mPolicy.LowestSupportedVersion = 10;
  Size = sizeof(Geometry);
  CHECK(Command(&Geometry, &Size) == EFI_NOT_READY);
  KeySize = 0;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  KeySize = 3;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  KeySize = sizeof(KeyData);
  KeyData[3] = 0;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  KeyData[3] = 5;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  KeyData[3] = 1;
  KeyData[4] = 0;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  KeyData[4] = 0x5a;
  KeyData[7] = 1;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  KeyData[7] = 0;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_SUCCESS && mFloorReady);
  FloorMode = 1; StoredFloor = 42;
  CHECK(RefreshFloor() == EFI_SUCCESS && mPolicy.LowestSupportedVersion == 42);
  StoredFloor = 11;
  CHECK(RefreshFloor() == EFI_SUCCESS && mPolicy.LowestSupportedVersion == 42);
  FloorMode = 2; StoredFloor = 43;
  CHECK(RefreshFloor() == EFI_SUCCESS && mPolicy.LowestSupportedVersion == 43);
  FloorMode = 0;
  CHECK(RefreshFloor() == EFI_SUCCESS && mPolicy.LowestSupportedVersion == 43);
  FloorMode = 3;
  CHECK(RefreshFloor() == EFI_DEVICE_ERROR);
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_DEVICE_ERROR && !mFloorReady);
  FloorMode = 0;
  CHECK(VariableReady(NULL, &Variables, NULL) == EFI_SUCCESS && mFloorReady);
  Start->Header = (COREBOOT_CAPSULE_HEADER){COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_BEGIN, 0};
  Start->SignedSize = CAPSULE_BLOCK_SIZE + 24;
  Start->ImageOffset = 16;
  Start->SignatureSize = 1;
  Start->Signature[0] = 0xa5;
  PacketAddress = Start->Signature;
  Size = sizeof(Geometry);
  CHECK(Command(&Geometry, &Size) == EFI_SUCCESS && Geometry.FlashSize == Info.FlashSize);
  Size = sizeof(Header);
  CHECK(Command(&Header, &Size) == EFI_ACCESS_DENIED);
  /* The primary packet models the MM core's internal shadow, not external RAM. */
  Size = sizeof(Geometry);
  CHECK(Command(&Geometry, &Size) == EFI_SUCCESS);
  Size = sizeof(Bytes);
  Start->SignatureSize = 2;
  CHECK(Command(Bytes, &Size) == EFI_INVALID_PARAMETER && !Begins);
  Start->SignatureSize = 1;
  SourceAllowed = FALSE;
  CHECK(Command(Bytes, &Size) == EFI_SECURITY_VIOLATION && !Begins);
  SourceAllowed = TRUE;
  Size = sizeof(Bytes);
  VerifyStatus = EFI_SECURITY_VIOLATION;
  CHECK(Command(Bytes, &Size) == EFI_SECURITY_VIOLATION && !mTransaction);
  Size = sizeof(Bytes);
  KeySize = 0;
  VerifyStatus = EFI_SUCCESS;
  CHECK(Command(Bytes, &Size) == EFI_SECURITY_VIOLATION && !mTransaction);
  KeySize = sizeof(KeyData);
  Size = sizeof(Bytes);
  Activate = FALSE;
  CHECK(Command(Bytes, &Size) == EFI_SECURITY_VIOLATION && !mTransaction);
  Activate = TRUE;
  Size = sizeof(Bytes);
  CHECK(Command(Bytes, &Size) == EFI_SUCCESS && Size == sizeof(*Start));
  Transaction = Start->Header.Transaction;
  CHECK(Transaction && mOwner.Active);
  Block = (COREBOOT_CAPSULE_BLOCK){{COREBOOT_CAPSULE_REVISION, COREBOOT_CAPSULE_PROGRAM, Transaction + 1}, 0};
  Size = sizeof(Block);
  CHECK(Command(&Block, &Size) == EFI_ACCESS_DENIED && !Programs);
  Block.Header.Transaction = Transaction;
  Size--;
  CHECK(Command(&Block, &Size) == EFI_INVALID_PARAMETER && !Programs);
  Size = sizeof(Block);
  CHECK(Command(&Block, &Size) == EFI_SUCCESS && Programs == 1);
  CHECK(ExitBootServices(NULL, NULL, NULL) == EFI_SUCCESS && !mTransaction && !mOwner.Active);
  Exited = TRUE;
  Size = sizeof(Bytes);
  CHECK(Command(Bytes, &Size) == EFI_ACCESS_DENIED && !mTransaction);
  Size = sizeof(Block);
  CHECK(Command(&Block, &Size) == EFI_ACCESS_DENIED && Programs == 1);
  Size = sizeof(Geometry);
  CHECK(Command(&Geometry, &Size) == EFI_SUCCESS);
  puts("MM dispatcher: framing, source refusal, signature snapshot, transaction, persistent floor and ExitBootServices passed");
  return 0;
}
