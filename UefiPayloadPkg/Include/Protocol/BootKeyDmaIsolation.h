/** @file
  Boot-key DMA isolation protocol.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#include <Uefi.h>

#define BOOT_KEY_DMA_ISOLATION_PROTOCOL_GUID \
  { 0x74334e17, 0xbc49, 0x4bed, { 0xb0, 0xd7, 0x48, 0x11, 0x97, 0x8d, 0x3e, 0x60 } }

#define BOOT_KEY_DMA_ISOLATION_PROTOCOL_REVISION  1

typedef struct _BOOT_KEY_DMA_ISOLATION_PROTOCOL BOOT_KEY_DMA_ISOLATION_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *BOOT_KEY_DMA_VERIFY)(
  IN BOOT_KEY_DMA_ISOLATION_PROTOCOL  *This
  );

typedef
EFI_STATUS
(EFIAPI *BOOT_KEY_DMA_AUTHORIZE_POST_GATE)(
  IN BOOT_KEY_DMA_ISOLATION_PROTOCOL  *This
  );

struct _BOOT_KEY_DMA_ISOLATION_PROTOCOL {
  UINT64                              Revision;
  BOOT_KEY_DMA_VERIFY                 Verify;
  BOOT_KEY_DMA_AUTHORIZE_POST_GATE    AuthorizePostGate;
};

extern EFI_GUID  gBootKeyDmaIsolationProtocolGuid;
