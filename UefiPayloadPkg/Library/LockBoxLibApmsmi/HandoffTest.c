/** @file
  Production OPAL producer checks for incremental and full-snapshot LockBoxes.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/
#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#undef NULL
#define _PCD_GET_MODE_32_PcdSetupVideoHorizontalResolution 0
#define _PCD_GET_MODE_32_PcdSetupVideoVerticalResolution 0
#define _PCD_GET_MODE_32_PcdSetupConOutColumn 0
#define _PCD_GET_MODE_32_PcdSetupConOutRow 0
#define _PCD_GET_MODE_BOOL_PcdTcgStorageSimpleUi FALSE
#define _PCD_GET_MODE_BOOL_PcdSkipOpalPasswordPrompt FALSE
#define _PCD_SET_MODE_32_S_PcdConOutColumn(Value) (0)
#define _PCD_SET_MODE_32_S_PcdConOutRow(Value) (0)
#define _PCD_SET_MODE_32_S_PcdVideoHorizontalResolution(Value) (0)
#define _PCD_SET_MODE_32_S_PcdVideoVerticalResolution(Value) (0)
#include "../../../SecurityPkg/Tcg/Opal/OpalPassword/OpalDriver.c"

EFI_GUID gS3StorageDeviceInitListGuid;
STATIC BOOLEAN mCoreboot = TRUE;
STATIC BOOLEAN mFailHandoff;
STATIC BOOLEAN mListStored;
STATIC BOOLEAN mDetectionError;
STATIC jmp_buf mShutdown;
STATIC EFI_RUNTIME_SERVICES mRuntime;
EFI_RUNTIME_SERVICES *gRT = &mRuntime;

STATIC VOID EFIAPI Shutdown (
  EFI_RESET_TYPE Type,
  EFI_STATUS Status,
  UINTN DataSize,
  VOID *Data
  )
{
  (void)DataSize;
  (void)Data;
  assert (Type == EfiResetShutdown && EFI_ERROR (Status));
  assert (mOpalDriver.DeviceList->OpalDisk.PasswordLength == 0);
  for (UINTN Index = 0; Index < OPAL_MAX_PASSWORD_SIZE; Index++) {
    assert (mOpalDriver.DeviceList->OpalDisk.Password[Index] == 0);
  }
  longjmp (mShutdown, 1);
}
VOID EFIAPI CpuDeadLoop (VOID)
{
  abort ();
}
STATIC UINTN mSaves;
STATIC UINTN mExpectedCount;
STATIC UINT8 mExpectedDevices[2];

VOID *EFIAPI AllocateZeroPool (UINTN Size)
{
  return calloc (1, Size);
}
VOID EFIAPI FreePool (VOID *Buffer)
{
  free (Buffer);
}
VOID *EFIAPI CopyMem (VOID *Destination, CONST VOID *Source, UINTN Size)
{
  return memcpy (Destination, Source, Size);
}
VOID *EFIAPI ZeroMem (VOID *Buffer, UINTN Size)
{
  return memset (Buffer, 0, Size);
}
BOOLEAN EFIAPI DebugPrintEnabled (VOID)
{
  return FALSE;
}
BOOLEAN EFIAPI DebugPrintLevelEnabled (CONST UINTN Level)
{
  (void)Level;
  return FALSE;
}
BOOLEAN EFIAPI DebugAssertEnabled (VOID)
{
  return TRUE;
}
VOID EFIAPI DebugPrint (UINTN Level, CONST CHAR8 *Format, ...)
{
  (void)Level;
  (void)Format;
}
VOID EFIAPI DebugAssert (CONST CHAR8 *File, UINTN Line, CONST CHAR8 *Description)
{
  fprintf (stderr, "%s:%u: %s\n", File, (unsigned)Line, Description);
  abort ();
}
UINT8 EFIAPI PciRead8 (UINTN Address)
{
  (void)Address;
  abort ();
}
TCG_RESULT EFIAPI OpalGetSupportedAttributesInfo (
  OPAL_SESSION *Session,
  OPAL_DISK_SUPPORT_ATTRIBUTE *Attributes,
  UINT16 *ComId
  )
{
  (void)Session;
  (void)Attributes;
  (void)ComId;
  return TcgResultFailure;
}
VOID *EFIAPI AllocatePool (UINTN Size)
{
  return malloc (Size);
}
VOID *EFIAPI AllocateCopyPool (UINTN Size, CONST VOID *Source)
{
  VOID *Copy = malloc (Size);
  assert (Copy != NULL);
  return memcpy (Copy, Source, Size);
}
UINT16 EFIAPI ReadUnaligned16 (CONST VOID *Buffer)
{
  UINT16 Value;
  memcpy (&Value, Buffer, sizeof (Value));
  return Value;
}
RETURN_STATUS EFIAPI SetLockBoxAttributes (GUID *Guid, UINT64 Attributes)
{
  assert (Attributes == LOCK_BOX_ATTRIBUTE_RESTORE_IN_S3_ONLY);
  if (Guid == &gS3StorageDeviceInitListGuid) {
    if (mDetectionError) {
      return RETURN_DEVICE_ERROR;
    }
    return mCoreboot ? RETURN_UNSUPPORTED : (mListStored ? RETURN_SUCCESS : RETURN_NOT_FOUND);
  }
  return RETURN_SUCCESS;
}
RETURN_STATUS EFIAPI SaveLockBox (GUID *Guid, VOID *Buffer, UINTN Length)
{
  if (Guid == &gS3StorageDeviceInitListGuid) {
    mListStored = TRUE;
    return RETURN_SUCCESS;
  }
  assert (Guid == &mOpalDeviceLockBoxGuid);
  UINT8 *Cursor = Buffer;
  UINTN Count = 0;
  while (Length != 0) {
    OPAL_DEVICE_LOCKBOX_DATA *Record = (VOID *)Cursor;
    assert (Count < mExpectedCount);
    assert (Record->Length <= Length && Record->Length >= sizeof (*Record));
    assert (Record->Device.Device == mExpectedDevices[Count]);
    Cursor += Record->Length;
    Length -= Record->Length;
    Count++;
  }
  assert (Count == mExpectedCount);
  mSaves++;
  return mFailHandoff ? RETURN_DEVICE_ERROR : RETURN_SUCCESS;
}
RETURN_STATUS EFIAPI UpdateLockBox (GUID *Guid, UINTN Offset, VOID *Buffer, UINTN Length)
{
  (void)Guid;
  (void)Offset;
  (void)Buffer;
  (void)Length;
  abort ();
}

int main (void)
{
  struct {
    PCI_DEVICE_PATH Pci;
    NVME_NAMESPACE_DEVICE_PATH Nvme;
    EFI_DEVICE_PATH_PROTOCOL End;
  } Path[2] = {0};
  OPAL_DRIVER_DEVICE Devices[2] = {0};

  for (UINTN Index = 0; Index < 2; Index++) {
    Path[Index].Pci.Header = (EFI_DEVICE_PATH_PROTOCOL){HARDWARE_DEVICE_PATH, HW_PCI_DP, {sizeof (PCI_DEVICE_PATH), 0}};
    Path[Index].Pci.Device = (UINT8)Index;
    Path[Index].Nvme.Header = (EFI_DEVICE_PATH_PROTOCOL){MESSAGING_DEVICE_PATH, MSG_NVME_NAMESPACE_DP, {sizeof (NVME_NAMESPACE_DEVICE_PATH), 0}};
    Path[Index].End = (EFI_DEVICE_PATH_PROTOCOL){END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {END_DEVICE_PATH_LENGTH, 0}};
    Devices[Index].OpalDisk.OpalDevicePath = (VOID *)&Path[Index];
    Devices[Index].OpalDisk.PasswordLength = 1;
    Devices[Index].OpalDisk.Password[0] = 0x5a;
  }
  Devices[0].Next = &Devices[1];
  mOpalDriver.DeviceList = Devices;
  Devices[0].OpalDisk.S3HandoffPending = TRUE;
  mExpectedCount = 1;
  mExpectedDevices[0] = 0;
  assert (BuildOpalDeviceInfo () == EFI_SUCCESS);
  assert (!Devices[0].OpalDisk.S3HandoffPending && mSaves == 1);
  assert (Devices[0].OpalDisk.PasswordLength == 0 && Devices[0].OpalDisk.Password[0] == 0);

  // A later device must not resend an already completed credential.
  Devices[1].OpalDisk.S3HandoffPending = TRUE;
  mExpectedDevices[0] = 1;
  assert (BuildOpalDeviceInfo () == EFI_SUCCESS);
  assert (!Devices[1].OpalDisk.S3HandoffPending && mSaves == 2);
  assert (Devices[1].OpalDisk.PasswordLength == 0 && Devices[1].OpalDisk.Password[0] == 0);

  assert (BuildOpalDeviceInfo () == EFI_SUCCESS && mSaves == 2);
  mDetectionError = TRUE;
  assert (BuildOpalDeviceInfo () == EFI_DEVICE_ERROR && mSaves == 2);
  mDetectionError = FALSE;

  // Failed eligible handoffs remain pending and must not become success.
  Devices[0].OpalDisk.PasswordLength = 1;
  Devices[0].OpalDisk.Password[0] = 0x5a;
  Devices[0].OpalDisk.S3HandoffPending = TRUE;
  mExpectedDevices[0] = 0;
  mFailHandoff = TRUE;
  assert (BuildOpalDeviceInfo () == EFI_DEVICE_ERROR);
  assert (Devices[0].OpalDisk.S3HandoffPending);
  // The real password-update caller must wipe and halt before external dispatch.
  mRuntime.ResetSystem = Shutdown;
  if (setjmp (mShutdown) == 0) {
    UINT8 Password = 0x5a;
    OpalSupportUpdatePassword (&Devices[0].OpalDisk, &Password, 1);
    assert (FALSE);
  }
  mFailHandoff = FALSE;

  // Other LockBox owners retain full-snapshot behavior, including nonpending disks.
  mCoreboot = FALSE;
  Devices[0].OpalDisk.PasswordLength = 1;
  Devices[0].OpalDisk.Password[0] = 0x5a;
  Devices[1].OpalDisk.PasswordLength = 1;
  Devices[1].OpalDisk.Password[0] = 0x5a;
  mExpectedCount = 2;
  mExpectedDevices[1] = 1;
  assert (BuildOpalDeviceInfo () == EFI_SUCCESS);
  assert (!Devices[0].OpalDisk.S3HandoffPending);
  assert (Devices[0].OpalDisk.PasswordLength == 1 && Devices[1].OpalDisk.PasswordLength == 1);
  puts ("OPAL producer: incremental handoffs, failure retention and full snapshots passed");
  return 0;
}
