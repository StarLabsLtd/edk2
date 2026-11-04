/** @file
  Exercise the production X64/IA32 runtime-cache transport.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <assert.h>
#include <stdio.h>
#include <string.h>
#undef NULL
#include <Uefi.h>
extern EFI_GUID gVarCheckPolicyLibMmiHandlerGuid;
#include "CorebootMmCommunicationDxe.c"

VOID *EFIAPI CopyMem(VOID *d, CONST VOID *s, UINTN n) { return memcpy(d, s, n); }
VOID *EFIAPI ZeroMem(VOID *d, UINTN n) { return memset(d, 0, n); }

EFI_GUID gVarCheckPolicyLibMmiHandlerGuid = {.Data1=1};
EFI_GUID gEfiSmmVariableProtocolGuid = {.Data1=2};
BOOLEAN EFIAPI CompareGuid(CONST EFI_GUID *a, CONST EFI_GUID *b) { return !memcmp(a,b,sizeof(*a)); }
UINT8 EFIAPI IoWrite8(UINTN p, UINT8 v) { assert(0); return v; }
VOID EFIAPI MemoryFence(VOID) { __sync_synchronize(); }
UINTN EFIAPI MicroSecondDelay(UINTN n) { assert(0); return n; }
SPIN_LOCK *EFIAPI AcquireSpinLock(SPIN_LOCK *s) { return s; }
SPIN_LOCK *EFIAPI ReleaseSpinLock(SPIN_LOCK *s) { return s; }
UINT32 EFIAPI InterlockedCompareExchange32(volatile UINT32 *p, UINT32 c, UINT32 v) { return __sync_val_compare_and_swap(p,c,v); }
VOID EFIAPI CpuDeadLoop(VOID) { assert(0); }

int main(void)
{
  SMM_VARIABLE_COMMUNICATE_RUNTIME_VARIABLE_CACHE_CONTEXT Cache = {
    (VOID *)0x100000, (VOID *)0x100001, (VOID *)0x100002,
    NULL, (VOID *)0x200000, (VOID *)0x300000
  };
  SMM_VARIABLE_CACHE_CONTEXT32 Wire;
  SMM_VARIABLE_CACHE_INFO32 Info32 = {0, 0x7f000, 0x10000, TRUE, {0}};
  SMM_VARIABLE_COMMUNICATE_GET_RUNTIME_CACHE_INFO Info;
  UINTN Size = 0;
  assert(VariableFunctionSupported(SMM_VARIABLE_FUNCTION_INIT_RUNTIME_VARIABLE_CACHE_CONTEXT));
  assert(VariableFunctionSupported(SMM_VARIABLE_FUNCTION_SYNC_RUNTIME_CACHE));
  assert(VariableFunctionSupported(SMM_VARIABLE_FUNCTION_GET_RUNTIME_CACHE_INFO));
  assert(CopyVariablePayloadTo32(SMM_VARIABLE_FUNCTION_INIT_RUNTIME_VARIABLE_CACHE_CONTEXT,
    (VOID *)&Cache, sizeof(Cache), (VOID *)&Wire, sizeof(Wire), &Size) == EFI_SUCCESS);
  assert(Size == 24 && Wire.ReadLock == 0x100000 && Wire.PendingUpdate == 0x100001);
  assert(Wire.HobFlushComplete == 0x100002 && Wire.RuntimeHobCache == 0);
  assert(Wire.RuntimeNvCache == 0x200000 && Wire.RuntimeVolatileCache == 0x300000);
  assert(CopyVariablePayloadTo32(SMM_VARIABLE_FUNCTION_INIT_RUNTIME_VARIABLE_CACHE_CONTEXT,
    (VOID *)&Cache, sizeof(Cache)-1, (VOID *)&Wire, sizeof(Wire), &Size) == EFI_BAD_BUFFER_SIZE);
#if defined(MDE_CPU_X64)
  Cache.RuntimeNvCache = (VOID *)(UINTN)0x100000000ULL;
  assert(CopyVariablePayloadTo32(SMM_VARIABLE_FUNCTION_INIT_RUNTIME_VARIABLE_CACHE_CONTEXT,
    (VOID *)&Cache, sizeof(Cache), (VOID *)&Wire, sizeof(Wire), &Size) == EFI_BAD_BUFFER_SIZE);
#endif
  memset(&Info, 0xa5, sizeof(Info));
  assert(CopyVariablePayloadFrom32(SMM_VARIABLE_FUNCTION_GET_RUNTIME_CACHE_INFO,
    TRUE, (VOID *)&Info32, sizeof(Info32), (VOID *)&Info, sizeof(Info)) == EFI_SUCCESS);
  assert(Info.TotalHobStorageSize == 0 && Info.TotalNvStorageSize == 0x7f000);
  assert(Info.TotalVolatileStorageSize == 0x10000 && Info.AuthenticatedVariableUsage);
  assert(CopyVariablePayloadFrom32(SMM_VARIABLE_FUNCTION_GET_RUNTIME_CACHE_INFO,
    TRUE, (VOID *)&Info32, sizeof(Info32)-1, (VOID *)&Info, sizeof(Info)) == EFI_BAD_BUFFER_SIZE);
  assert(CopyVariablePayloadTo32(SMM_VARIABLE_FUNCTION_SYNC_RUNTIME_CACHE,
    NULL, 0, NULL, 0, &Size) == EFI_SUCCESS && Size == 0);
  puts("PASS: runtime cache transport");
  return 0;
}
