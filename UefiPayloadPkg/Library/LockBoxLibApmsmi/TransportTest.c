/** @file
  Exercise SMM credential acceptance and rejection through the production transport.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#include "LockBoxLibApmsmi.c"

STATIC EFI_BOOT_SERVICES mBoot;
EFI_BOOT_SERVICES *gBS = &mBoot;
STATIC UINT8 mPage[EFI_PAGE_SIZE];
STATIC UINTN mResult;
STATIC UINTN mCalls;
STATIC UINTN mFrees;

STATIC EFI_STATUS EFIAPI Allocate (
  EFI_ALLOCATE_TYPE Type, EFI_MEMORY_TYPE MemoryType, UINTN Pages,
  EFI_PHYSICAL_ADDRESS *Address
  )
{
  assert (Type == AllocateMaxAddress && MemoryType == EfiBootServicesData && Pages == 1);
  *Address = (UINTN)mPage;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS EFIAPI Free (EFI_PHYSICAL_ADDRESS Address, UINTN Pages)
{
  assert (Address == (UINTN)mPage && Pages == 1);
  for (UINTN Index = 0; Index < sizeof (mPage); Index++) {
    assert (mPage[Index] == 0);
  }
  mFrees++;
  return EFI_SUCCESS;
}

UINTN EFIAPI LockBoxTriggerSmi (UINTN Cmd, UINTN Arg, UINTN Retry)
{
  OPAL_S3_SMM_CTX *Context = (VOID *)Arg;
  assert (Cmd == 0x1ee && Retry == 5);
  assert (Context->PasswordLength == 1 && Context->Password[0] == 0x5a);
  mCalls++;
  return mResult;
}

VOID *EFIAPI CopyMem (VOID *Destination, CONST VOID *Source, UINTN Size)
{
  return memcpy (Destination, Source, Size);
}
VOID *EFIAPI ZeroMem (VOID *Buffer, UINTN Size)
{
  return memset (Buffer, 0, Size);
}
BOOLEAN EFIAPI CompareGuid (CONST GUID *Left, CONST GUID *Right)
{
  return memcmp (Left, Right, sizeof (*Left)) == 0;
}
BOOLEAN EFIAPI DebugPrintEnabled (VOID) { return FALSE; }
BOOLEAN EFIAPI DebugPrintLevelEnabled (UINTN Level) { return FALSE; }
VOID EFIAPI DebugPrint (UINTN Level, CONST CHAR8 *Format, ...) {}

int main (void)
{
  OPAL_DEVICE_LOCKBOX_DATA Record = {0};
  CONST UINTN Results[] = {0, 9, 10, 0x1ee};
  CONST RETURN_STATUS Expected[] = {
    RETURN_SUCCESS, RETURN_UNSUPPORTED, RETURN_DEVICE_ERROR, RETURN_DEVICE_ERROR
  };
  GUID Guid = OPAL_DEVICE_LOCKBOX_GUID;

  mBoot.AllocatePages = Allocate;
  mBoot.FreePages = Free;
  Record.Length = sizeof (Record);
  Record.PasswordLength = 1;
  Record.Password[0] = 0x5a;
  for (UINTN Index = 0; Index < sizeof (Results) / sizeof (Results[0]); Index++) {
    mResult = Results[Index];
    assert (SaveLockBox (&Guid, &Record, sizeof (Record)) == Expected[Index]);
    assert (mCalls == Index + 1 && mFrees == Index + 1);
  }
  puts ("OPAL transport: accepted, unsupported, rejected and unanswered handoffs; buffers wiped");
  return 0;
}
