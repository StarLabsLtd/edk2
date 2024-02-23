/** @file
  This library implements the payload MM command interface.

  Copyright (c) 2024, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <PiDxe.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>

#include <Guid/PayloadMmInterfaceInfoGuid.h>

STATIC PAYLOAD_MM_INTERFACE_INFO  *PayloadMmInterfaceInfo = NULL;

/**
  Private copy of assembly function prototype.

**/
UINTN
EFIAPI
TriggerSmi (
  IN UINTN  Cmd,
  IN UINTN  Arg,
  IN UINTN  Retry
  );

/**
  Register payload MMI entrypoint with bootloader SMM.

  @param[in] MmiEntryPoint  The address of MMI entrypoint.

  @retval EFI_SUCCESS       Succeeded to register payload MMI entrypoint.
  @retval EFI_DEVICE_ERROR  Failed to register payload MMI entrypoint.

**/
EFI_STATUS
EFIAPI
PayloadMmCmdLoadAndCallCore (
  IN PAYLOAD_MM_LOAD_CONTEXT  *PayloadMmLoadContext
  )
{
  UINTN  Command;
  UINT8  Status;

  Command = PayloadMmInterfaceInfo->ApmCmd | (PAYLOAD_MM_CMD_LOAD_AND_CALL_CORE << 8);

  Status = TriggerSmi (Command, (UINTN)PayloadMmLoadContext, 3);
  DEBUG ((DEBUG_INFO, "Bootloader SMI returns 0x%x\n", Status));

  return (Status == PAYLOAD_MM_RET_SUCCESS) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

/**
  Constructor for the payload MM command interface.

  @retval EFI_SUCCESS      Init completed successfully.
  @retval EFI_UNSUPPORTED  Init failed.

**/
EFI_STATUS
EFIAPI
MmIplPlatformHookLibConstructor (
  VOID
  )
{
  EFI_HOB_GUID_TYPE  *GuidHob;

  GuidHob = GetFirstGuidHob (&gPayloadMmInterfaceInfoGuid);
  if (GuidHob == NULL) {
    DEBUG ((DEBUG_WARN, "PayloadMmCmdInterface used without platform support!\n"));
    return EFI_UNSUPPORTED;
  }

  PayloadMmInterfaceInfo = GET_GUID_HOB_DATA (GuidHob);
  return EFI_SUCCESS;
}
