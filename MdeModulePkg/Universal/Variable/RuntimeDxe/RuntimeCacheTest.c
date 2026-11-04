/** @file
  Validate production MM runtime-cache registration boundaries.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef NULL
#define _PCD_GET_MODE_BOOL_PcdEnableVariableRuntimeCache  TRUE
#define _PCD_GET_MODE_BOOL_PcdVariableCollectStatistics  FALSE
#define _PCD_GET_MODE_BOOL_PcdEmuVariableNvModeEnable  FALSE
#define _PCD_GET_MODE_BOOL_PcdReclaimVariableSpaceAtEndOfDxe FALSE
#include <PiMm.h>
#include "VariableSmm.c"
#include "VariableRuntimeCache.c"
#include "VariableStandaloneMm.c"

VARIABLE_STORE_HEADER *mNvVariableCache;
STATIC VARIABLE_MODULE_GLOBAL Global;
STATIC VARIABLE_STORE_HEADER Nv, Vol;
STATIC UINT8 Shared[3 * 4096];
STATIC BOOLEAN Pending, Read, HobDone;
STATIC UINTN Copies;
VARIABLE_MODULE_GLOBAL *mVariableModuleGlobal = &Global;
VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { Copies++; return memcpy(d, s, n); }
STATIC EFI_HOB_RESOURCE_DESCRIPTOR Resources[7];
VOID *EFIAPI GetHobList(VOID) { return Resources; }
VOID *EFIAPI GetNextHob(UINT16 Type, CONST VOID *Start)
{
  CONST UINT8 *Next = Start;
  if (Next < (CONST UINT8 *)Resources || Next >= (CONST UINT8 *)(Resources+ARRAY_SIZE(Resources))) return NULL;
  assert(Type == EFI_HOB_TYPE_RESOURCE_DESCRIPTOR);
  return (VOID *)Next;
}
BOOLEAN EFIAPI MmIsBufferOutsideMmValid(EFI_PHYSICAL_ADDRESS Base, UINT64 Size)
{
  // Hardware/MM memory boundary: the synthetic SMRAM region is inaccessible.
  return Base <= MAX_UINT32 && Size <= MAX_UINT32-Base && Base != 0x60000000;
}
// Unrelated variable-policy/storage operations are dependency boundaries.
VARIABLE_INFO_ENTRY *gVariableInfo;
BOOLEAN mEndOfDxe;
VAR_CHECK_REQUEST_SOURCE mRequestSource;
EFI_STATUS EFIAPI VarCheckRegisterSetVariableCheckHandler(VAR_CHECK_SET_VARIABLE_CHECK_HANDLER h) { assert(0); return EFI_UNSUPPORTED; }
STATIC UINTN LockRequests;
VOID VariableSpeculationBarrier(VOID) {}
VOID ReclaimForOS(VOID) { assert(0); }
VOID InitializeVariableQuota(VOID) { assert(0); }
VOID MorLockInitAtEndOfDxe(VOID) { assert(0); }
VOID ***EFIAPI VarCheckLibInitializeAtEndOfDxe(UINTN *n) { assert(0); return NULL; }
EFI_STATUS EFIAPI LockVariablePolicy(VOID) { assert(0); return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI VariableServiceGetVariable(CHAR16 *n, EFI_GUID *g, UINT32 *a, UINTN *z, VOID *d) { assert(0); return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI VariableServiceGetNextVariableName(UINTN *z, CHAR16 *n, EFI_GUID *g) { assert(0); return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI VariableServiceSetVariable(CHAR16 *n, EFI_GUID *g, UINT32 a, UINTN z, VOID *d) { assert(0); return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI VariableServiceQueryVariableInfo(UINT32 a, UINT64 *m, UINT64 *r, UINT64 *z) { assert(0); return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI VariableLockRequestToLock(CONST EDKII_VARIABLE_LOCK_PROTOCOL *t, CHAR16 *n, EFI_GUID *g) { LockRequests++; return EFI_SUCCESS; }
EFI_STATUS EFIAPI VarCheckVariablePropertySet(CHAR16 *n, EFI_GUID *g, VAR_CHECK_VARIABLE_PROPERTY *p) { assert(0); return EFI_UNSUPPORTED; }
EFI_STATUS EFIAPI VarCheckVariablePropertyGet(CHAR16 *n, EFI_GUID *g, VAR_CHECK_VARIABLE_PROPERTY *p) { assert(0); return EFI_UNSUPPORTED; }
EFI_GUID *EFIAPI CopyGuid(EFI_GUID *d, CONST EFI_GUID *s) { return memcpy(d, s, sizeof(*d)); }
BOOLEAN EFIAPI CompareGuid(CONST EFI_GUID *a, CONST EFI_GUID *b) { return !memcmp(a,b,sizeof(*a)); }
BOOLEAN EFIAPI IsZeroGuid(CONST EFI_GUID *g) { EFI_GUID z = {0}; return CompareGuid(g,&z); }
INTN EFIAPI CompareMem(CONST VOID *a, CONST VOID *b, UINTN n) { return memcmp(a,b,n); }
UINTN EFIAPI StrSize(CONST CHAR16 *s) { UINTN n=0; while(s[n])n++; return (n+1)*sizeof(*s); }
VARIABLE_HEADER *GetEndPointer(VARIABLE_STORE_HEADER *s) { return (VOID *)((UINT8 *)s+s->Size); }

int main(void)
{
  SMM_VARIABLE_COMMUNICATE_RUNTIME_VARIABLE_CACHE_CONTEXT Context = {
    &Read, &Pending, &HobDone, NULL, (VOID *)Shared, (VOID *)(Shared+4096)
  };
  {
    UINTN i;
    UINTN Bases[] = {(UINTN)Shared, (UINTN)&Pending, (UINTN)&Read, (UINTN)&HobDone, 0x40000000, 0x50000000, 0x40000000};
    for(i=0;i<ARRAY_SIZE(Resources);i++) {
      Resources[i].Header.HobType = EFI_HOB_TYPE_RESOURCE_DESCRIPTOR;
      Resources[i].Header.HobLength = sizeof(Resources[i]);
      Resources[i].PhysicalStart = Bases[i];
      Resources[i].ResourceLength = i == 0 ? sizeof(Shared) : i < 4 ? 1 : 4096;
      Resources[i].ResourceType = (i < 4 || i == 6) ? EFI_RESOURCE_SYSTEM_MEMORY :
        i == 4 ? EFI_RESOURCE_MEMORY_RESERVED : EFI_RESOURCE_MEMORY_MAPPED_IO;
    }
    Resources[6].PhysicalStart = 0x3ffff000;
    Resources[6].ResourceLength = 0x3000;
    assert(VariableSmmIsNonPrimaryBufferValid(0x3ffff000,4096));
    assert(VariableSmmIsNonPrimaryBufferValid(0x40001000,4096));
    assert(!VariableSmmIsNonPrimaryBufferValid(0x3ffff000,4097));
    assert(!VariableSmmIsNonPrimaryBufferValid(0x40000fff,2));
    assert(VariableSmmIsNonPrimaryBufferValid((UINTN)Shared, sizeof(Shared)));
    assert(!VariableSmmIsNonPrimaryBufferValid((UINTN)Shared, sizeof(Shared)+1));
    assert(!VariableSmmIsNonPrimaryBufferValid(0x40000000,1));
    {
      EFI_HOB_RESOURCE_DESCRIPTOR Swap = Resources[4];
      Resources[4] = Resources[6];
      Resources[6] = Swap;
      assert(!VariableSmmIsNonPrimaryBufferValid(0x40000000,1));
      Swap = Resources[4]; Resources[4] = Resources[6]; Resources[6] = Swap;
    }
    assert(!VariableSmmIsNonPrimaryBufferValid(0x50000000,1));
    assert(!VariableSmmIsNonPrimaryBufferValid(0x60000000,1));
    assert(!VariableSmmIsNonPrimaryBufferValid(0xffffffff,2));
  }
  Nv.Size = Vol.Size = 4096;
  ((VARIABLE_STORE_HEADER *)Shared)->Size = 4096;
  ((VARIABLE_STORE_HEADER *)(Shared+4096))->Size = 4096;
  mNvVariableCache = &Nv;
  Global.VariableGlobal.VolatileVariableBase = (UINTN)&Vol;
  assert(RuntimeCacheContextValid(&Context));
  Context.RuntimeNvCache = (VOID *)(UINTN)1;
  assert(!RuntimeCacheContextValid(&Context));
  Context.RuntimeNvCache = (VOID *)(Shared+sizeof(Shared)-sizeof(VARIABLE_STORE_HEADER));
  assert(!RuntimeCacheContextValid(&Context));
  Context.RuntimeNvCache = (VOID *)Shared;
  Context.RuntimeVolatileCache = (VOID *)Shared;
  assert(!RuntimeCacheContextValid(&Context));
  Context.RuntimeVolatileCache = (VOID *)(Shared+4096);
  Context.PendingUpdate = Context.ReadLock;
  assert(!RuntimeCacheContextValid(&Context));
  Context.PendingUpdate = &Pending;
  ((VARIABLE_STORE_HEADER *)Shared)->Size = 4095;
  assert(!RuntimeCacheContextValid(&Context));
  ((VARIABLE_STORE_HEADER *)Shared)->Size = 4096;
  Context.RuntimeHobCache = (VOID *)(Shared+8192);
  assert(!RuntimeCacheContextValid(&Context));
  Context.RuntimeHobCache = NULL;
  assert(RuntimeCacheContextValid(&Context));
  {
    VARIABLE_RUNTIME_CACHE_CONTEXT *Private = &Global.VariableGlobal.VariableRuntimeCacheContext;
    STATIC UINT8 NvData[4096] = {0};
    STATIC UINT8 VolData[4096] = {0};
    mNvVariableCache = (VOID *)NvData;
    mNvVariableCache->Size = sizeof(NvData);
    ((VARIABLE_STORE_HEADER *)VolData)->Size = sizeof(VolData);
    Global.VariableGlobal.VolatileVariableBase = (UINTN)VolData;
    Private->VariableRuntimeNvCache.Store = (VOID *)Shared;
    Private->VariableRuntimeVolatileCache.Store = (VOID *)(Shared+4096);
    Private->PendingUpdate = &Pending;
    Private->ReadLock = &Read;
    Private->VariableRuntimeNvCache.PendingUpdateOffset = 4090;
    Private->VariableRuntimeNvCache.PendingUpdateLength = 7;
    Pending = TRUE;
    Copies = 0;
    assert(FlushPendingRuntimeVariableCacheUpdates() == EFI_SECURITY_VIOLATION);
    assert(Copies == 0 && Pending);
    // A corrupt shared header cannot enlarge the private source extent.
    ((VARIABLE_STORE_HEADER *)Shared)->Size = 0xffffffff;
    assert(FlushPendingRuntimeVariableCacheUpdates() == EFI_SECURITY_VIOLATION);
    assert(Copies == 0 && Pending);
    Private->VariableRuntimeNvCache.PendingUpdateLength = 6;
    NvData[4095] = 0x5a;
    assert(FlushPendingRuntimeVariableCacheUpdates() == EFI_SUCCESS);
    assert(!Pending && Shared[4095] == 0x5a);
  }
  {
    struct { SMM_VARIABLE_COMMUNICATE_HEADER Header; UINT8 Data[sizeof(Context)]; } Request;
    UINT8 Scratch[sizeof(Context)];
    UINTN RequestSize = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + sizeof(Context);
    // The actual dispatcher must reject late/replacement registration.
    mVariableBufferPayload = Scratch;
    mVariableBufferPayloadSize = sizeof(Scratch);
    memset(&Request, 0, sizeof(Request));
    Request.Header.Function = SMM_VARIABLE_FUNCTION_INIT_RUNTIME_VARIABLE_CACHE_CONTEXT;
    memcpy(Request.Header.Data, &Context, sizeof(Context));
    // Reject an invalid first registration before any shared flag writes.
    Global.VariableGlobal.VariableRuntimeCacheContext.PendingUpdate = NULL;
    Context.PendingUpdate = (VOID *)0x40000000;
    memcpy(Request.Header.Data, &Context, sizeof(Context));
    assert(SmmVariableHandler(NULL, NULL, &Request, &RequestSize) == EFI_SUCCESS);
    assert(Request.Header.ReturnStatus == EFI_ACCESS_DENIED);
    assert(Global.VariableGlobal.VariableRuntimeCacheContext.PendingUpdate == NULL);
    Context.PendingUpdate = &Pending;
    memcpy(Request.Header.Data, &Context, sizeof(Context));
    assert(SmmVariableHandler(NULL, NULL, &Request, &RequestSize) == EFI_SUCCESS);
    assert(Request.Header.ReturnStatus == EFI_SUCCESS && Pending && !Read && !HobDone);
    assert(Global.VariableGlobal.VariableRuntimeCacheContext.PendingUpdate == &Pending);
    Global.VariableGlobal.VariableRuntimeCacheContext.PendingUpdate = NULL;
    mEndOfDxe = TRUE;
    assert(SmmVariableHandler(NULL, NULL, &Request, &RequestSize) == EFI_SUCCESS);
    assert(Request.Header.ReturnStatus == EFI_ACCESS_DENIED);
    mEndOfDxe = FALSE;
    Global.VariableGlobal.VariableRuntimeCacheContext.PendingUpdate = &Pending;
    // Independently reject replacement before EndOfDxe.
    assert(SmmVariableHandler(NULL, NULL, &Request, &RequestSize) == EFI_SUCCESS);
    assert(Request.Header.ReturnStatus == EFI_ACCESS_DENIED);
    // Cache registration must not disable normal pre-EndOfDxe variable locks.
    {
      SMM_VARIABLE_COMMUNICATE_LOCK_VARIABLE *Lock = (VOID *)Request.Header.Data;
      memset(Request.Header.Data, 0, sizeof(Context));
      Request.Header.Function = SMM_VARIABLE_FUNCTION_LOCK_VARIABLE;
      Lock->NameSize = 4;
      Lock->Name[0] = L'X';
      Lock->Name[1] = 0;
      RequestSize = SMM_VARIABLE_COMMUNICATE_HEADER_SIZE + OFFSET_OF(SMM_VARIABLE_COMMUNICATE_LOCK_VARIABLE,Name) + 4;
      assert(SmmVariableHandler(NULL, NULL, &Request, &RequestSize) == EFI_SUCCESS);
      assert(Request.Header.ReturnStatus == EFI_SUCCESS && LockRequests == 1);
    }
  }
  puts("PASS: MM cache registration bounds, aliasing and private copy extents");
  return 0;
}
