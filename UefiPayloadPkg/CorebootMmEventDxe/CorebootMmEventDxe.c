/** @file
  Forward DXE lifecycle events to the coreboot-owned MM service.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Guid/EventGroup.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Protocol/DxeMmReadyToLock.h>
#include <Protocol/MmCommunication2.h>

STATIC EFI_MM_COMMUNICATION2_PROTOCOL  *mMmCommunication;
STATIC BOOLEAN                         mEndOfDxeSent;
STATIC BOOLEAN                         mReadyToLockSent;

STATIC
EFI_STATUS
SendEvent (
  IN CONST EFI_GUID  *EventGuid
  )
{
  UINT8                      Buffer[OFFSET_OF (EFI_MM_COMMUNICATE_HEADER, Data) + 1];
  EFI_MM_COMMUNICATE_HEADER  *Header;
  UINTN                      Size;

  Header = (VOID *)Buffer;
  ZeroMem (Buffer, sizeof (Buffer));
  CopyGuid (&Header->HeaderGuid, EventGuid);
  Header->MessageLength = 1;
  Size                  = sizeof (Buffer);
  return mMmCommunication->Communicate (
                             mMmCommunication,
                             Buffer,
                             Buffer,
                             &Size
                             );
}

STATIC
EFI_STATUS
SendEndOfDxe (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mEndOfDxeSent) {
    return EFI_SUCCESS;
  }

  Status = SendEvent (&gEfiEndOfDxeEventGroupGuid);
  if (!EFI_ERROR (Status)) {
    mEndOfDxeSent = TRUE;
  }

  return Status;
}

STATIC
EFI_STATUS
SendReadyToLock (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mReadyToLockSent) {
    return EFI_SUCCESS;
  }

  Status = SendEndOfDxe ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SendEvent (&gEfiDxeMmReadyToLockProtocolGuid);
  if (!EFI_ERROR (Status)) {
    mReadyToLockSent = TRUE;
  }

  return Status;
}

STATIC
VOID
EFIAPI
ReadyToLockNotify (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;
  VOID        *Interface;

  Status = gBS->LocateProtocol (
                  &gEfiDxeMmReadyToLockProtocolGuid,
                  NULL,
                  &Interface
                  );
  if (EFI_ERROR (Status)) {
    return;
  }

  Status = SendReadyToLock ();
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to notify MM Ready To Lock: %r\n", Status));
    CpuDeadLoop ();
  }
}

STATIC
VOID
EFIAPI
ForwardEvent (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  EFI_STATUS  Status;

  if (CompareGuid (Context, &gEfiEndOfDxeEventGroupGuid)) {
    Status = SendEndOfDxe ();
  } else {
    Status = SendReadyToLock ();
    if (!EFI_ERROR (Status)) {
      Status = SendEvent (Context);
    }
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to forward MM lifecycle event: %r\n", Status));
    CpuDeadLoop ();
  }
}

EFI_STATUS
EFIAPI
CorebootMmEventEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  CONST EFI_GUID  *EventGroups[] = {
    &gEfiEndOfDxeEventGroupGuid,
    &gEfiEventExternalImageStartGuid,
    &gEfiEventReadyToBootGuid,
    &gEfiEventExitBootServicesGuid
  };
  EFI_EVENT       Events[ARRAY_SIZE (EventGroups)];
  EFI_EVENT       ReadyToLockEvent;
  EFI_STATUS      Status;
  UINTN           Index;
  VOID            *Registration;

  Status = gBS->LocateProtocol (
                  &gEfiMmCommunication2ProtocolGuid,
                  NULL,
                  (VOID **)&mMmCommunication
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  ReadyToLockNotify,
                  NULL,
                  &ReadyToLockEvent
                  );
  if (!EFI_ERROR (Status)) {
    Status = gBS->RegisterProtocolNotify (
                    &gEfiDxeMmReadyToLockProtocolGuid,
                    ReadyToLockEvent,
                    &Registration
                    );
  }

  if (!EFI_ERROR (Status)) {
    Status = gBS->SignalEvent (ReadyToLockEvent);
  }

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "Failed to register MM Ready To Lock notification: %r\n", Status));
    CpuDeadLoop ();
    return Status;
  }

  for (Index = 0; Index < ARRAY_SIZE (EventGroups); Index++) {
    Status = gBS->CreateEventEx (
                    EVT_NOTIFY_SIGNAL,
                    TPL_CALLBACK,
                    ForwardEvent,
                    (VOID *)EventGroups[Index],
                    EventGroups[Index],
                    &Events[Index]
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "Failed to register MM lifecycle event: %r\n", Status));
      CpuDeadLoop ();
      return Status;
    }
  }

  return EFI_SUCCESS;
}
