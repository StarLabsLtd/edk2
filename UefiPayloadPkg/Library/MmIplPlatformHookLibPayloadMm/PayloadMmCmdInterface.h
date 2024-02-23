/** @file
  This library implements the payload MM command interface.

  Copyright (c) 2024, 9elements GmbH. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef _PAYLOAD_MM_CMD_INTERFACE_LIB_H_
#define _PAYLOAD_MM_CMD_INTERFACE_LIB_H_

#include <PiDxe.h>
#include <Guid/PayloadMmInterfaceInfoGuid.h>

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
  );

#endif
