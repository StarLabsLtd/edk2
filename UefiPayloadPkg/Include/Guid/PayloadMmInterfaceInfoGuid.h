/** @file
  This file defines the structure of payload MM interface info.

  Copyright (c) 2025, 9elements GmbH<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef PAYLOAD_MM_INTERFACE_INFO_GUID_H_
#define PAYLOAD_MM_INTERFACE_INFO_GUID_H_

#include <Base.h>
#include <Library/BaseLib.h>

#pragma pack (push, 1)

//
// Payload MM interface info hob GUID
//
extern EFI_GUID  gPayloadMmInterfaceInfoGuid;

typedef struct {
  UINT8  Revision;
  UINT8  BootloaderSmmIs64Bit;
  UINT8  ApmCmd;
  UINT8  Reserved[5];
  // Downstream boot-only mapping information. Not allocatable by the MM core.
  UINT64 HandlerBase;
  UINT64 HandlerSize;
  UINT64 PayloadBase;
  UINT64 PayloadSize;
  UINT64 CfrMailbox;
  UINT32 CfrMailboxSize;
  UINT32 CfrSupportedOptions;
} PAYLOAD_MM_INTERFACE_INFO;

//
// Payload MM command interface
//
#define PAYLOAD_MM_RET_SUCCESS  0
#define PAYLOAD_MM_RET_FAILURE  1

/*
 * The data below describes a load request from the payload MM loader (ring0) to bootloader SMM,
 * and the arguments that the loader wants passed to the payload MM core module.
 */
#define PAYLOAD_MM_CMD_LOAD_AND_CALL_CORE  1
#define PAYLOAD_MM_CMD_CLOSE_LOADER        2
#define PAYLOAD_MM_APM_COMMAND             0xE8

#define PLD_MM_CORE_LOAD_CONTEXT_REVISION  1

typedef struct {
  UINT32   *StackPointers;
  UINT32   PageTable;
  // Control-flow variables also used by assembly code.
  BOOLEAN  Intel5LevelPagingNeeded;
  BOOLEAN  XdSupported;
  BOOLEAN  MsrIa32MiscEnableSupported;
  UINT8    LoadStatus;
} PAYLOAD_MM_EDK2_PRIVATE_DATA;

typedef struct {
  UINT16  HeaderSize;
  UINT8   HeaderRevision;
  UINT8   Reserved;
  UINT64  MmCoreSourceAddress;
  UINT32  MmCoreDestinationAddress;
  UINT32  MmCoreSize;
  UINT32  MmEntryPointOffset;
  UINT64  MmEntryPointArg1;
  UINT64  MmEntryPointArg2;
  UINT64  MmEntryPointArg3;
  UINT64  ImplementationPrivateData;
} PAYLOAD_MM_LOAD_CONTEXT;

/*
 * Used to communicate payload MM loader (ring0) arguments from bootloader SMM to payload MM.
 */
typedef struct {
  UINT64  MmEntryPointArg1;
  UINT64  MmEntryPointArg2;
  UINT64  MmEntryPointArg3;
  UINT64  ImplementationPrivateData;
} PAYLOAD_MM_CORE_CALL_CONTEXT;

/*
 * The data below is shared between the bootloader and payload MM in the shared memory, located in
 * the first 4K of the payload MM subregion. It must be provided by the payload MM at runtime,
 * as it describes the data required by the bootloader to call payload MM.
 */
#define PLD_MM_STRUCT_MAGIC    0x5f4d4d5f444c505f  /* '_PLD_MM_' */
#define PLD_MM_SHARED_STRUCT_REVISION  1

typedef struct {
  UINT64  HeaderMagic;
  UINT16  SharedInfoSize;
  UINT8   HeaderRevision;
  UINT8   Reserved;
  UINT32  MmEntryPointAddress;
} PAYLOAD_MM_SHARED_INFO;

#pragma pack (pop)

#endif
