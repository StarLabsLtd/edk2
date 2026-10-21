/** @file
  Interface between coreboot and the fixed EDK2 variable service.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi/UefiBaseType.h>
#include <Pi/PiMmCis.h>

#define COREBOOT_VARIABLE_SERVICE_REVISION  1
#define COREBOOT_VARIABLE_SERVICE_HEADER_SIZE  EFI_PAGE_SIZE
#define COREBOOT_VARIABLE_SERVICE_MESSAGE_CAPACITY  0x20000
#define COREBOOT_VARIABLE_SERVICE_BUFFER_SIZE  \
  (COREBOOT_VARIABLE_SERVICE_HEADER_SIZE + COREBOOT_VARIABLE_SERVICE_MESSAGE_CAPACITY)
#define COREBOOT_VARIABLE_BUFFER_SIGNATURE  SIGNATURE_32 ('E', 'V', 'A', 'R')

#define COREBOOT_VARIABLE_REGISTER_SUCCESS  0

#define COREBOOT_VARIABLE_BUFFER_IDLE          0
#define COREBOOT_VARIABLE_BUFFER_REQUEST       1
#define COREBOOT_VARIABLE_BUFFER_RESPONSE      2
#define COREBOOT_VARIABLE_BUFFER_CONSTRUCTING  3

// HOB passed by coreboot while the fixed MM firmware volume is initialized.
typedef struct {
  UINT16                  Revision;
  UINT16                  Size;
  UINT32                  Reserved;
  EFI_PHYSICAL_ADDRESS    CommunicationBuffer;
  UINT32                  CommunicationBufferSize;
  UINT32                  RegisterMmEntry;
} COREBOOT_VARIABLE_SERVICE_INFO;

STATIC_ASSERT (sizeof (COREBOOT_VARIABLE_SERVICE_INFO) == 24, "Coreboot service HOB ABI");
STATIC_ASSERT (OFFSET_OF (COREBOOT_VARIABLE_SERVICE_INFO, CommunicationBuffer) == 8, "Coreboot service HOB ABI");
STATIC_ASSERT (OFFSET_OF (COREBOOT_VARIABLE_SERVICE_INFO, CommunicationBufferSize) == 16, "Coreboot service HOB ABI");
STATIC_ASSERT (OFFSET_OF (COREBOOT_VARIABLE_SERVICE_INFO, RegisterMmEntry) == 20, "Coreboot service HOB ABI");

typedef
UINT32
(EFIAPI *COREBOOT_VARIABLE_REGISTER_MM_ENTRY)(
  IN UINT32  EntryPoint
  );

// Header at the start of the communication buffer published to the payload.
typedef struct {
  UINT32        Signature;
  UINT16        Revision;
  UINT16        HeaderSize;
  volatile UINT32 State;
  UINT32        Transaction;
  UINT32        MessageSize;
  UINT32        ResponseSize;
  UINT64        Status;
} COREBOOT_VARIABLE_SERVICE_BUFFER;

STATIC_ASSERT (OFFSET_OF (COREBOOT_VARIABLE_SERVICE_BUFFER, Status) == 24, "Coreboot buffer ABI");
STATIC_ASSERT (sizeof (COREBOOT_VARIABLE_SERVICE_BUFFER) == 32, "Coreboot buffer ABI");

extern EFI_GUID  gCorebootVariableServiceInfoGuid;
extern EFI_GUID  gCorebootVariableServiceReadyGuid;
