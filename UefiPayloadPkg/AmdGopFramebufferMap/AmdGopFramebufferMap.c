/** @file
  Install GOP framebuffer remap hooks for AMD external GOP.
**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Protocol/GraphicsOutput.h>
#include <Library/AmdGopFramebufferMapLib.h>

STATIC EFI_EVENT  mGopInstallEvent;
STATIC VOID       *mGopInstallRegistration;

STATIC
VOID
EFIAPI
OnGraphicsOutputInstalled (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  (VOID)Event;
  (VOID)Context;

  RemapAllGraphicsOutputFramebuffers ();
}

STATIC
VOID
EFIAPI
OnReadyToBoot (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  (VOID)Context;

  RemapAllGraphicsOutputFramebuffers ();
}

EFI_STATUS
EFIAPI
AmdGopFramebufferMapEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;
  EFI_EVENT   ReadyToBootEvent;

  AmdGopFramebufferMapLibSetImageHandle (ImageHandle);
  RemapAllGraphicsOutputFramebuffers ();

  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnGraphicsOutputInstalled,
                  NULL,
                  &mGopInstallEvent
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->RegisterProtocolNotify (
                  &gEfiGraphicsOutputProtocolGuid,
                  mGopInstallEvent,
                  &mGopInstallRegistration
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  gBS->SignalEvent (mGopInstallEvent);

  Status = gBS->CreateEventEx (
                  EVT_NOTIFY_SIGNAL,
                  TPL_CALLBACK,
                  OnReadyToBoot,
                  NULL,
                  &gEfiEventReadyToBootGuid,
                  &ReadyToBootEvent
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, "AmdGopFramebufferMap: ReadyToBoot event failed: %r\n", Status));
  }

  return EFI_SUCCESS;
}
