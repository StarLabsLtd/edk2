/** @file
  Finalization protocol for a verified Star Labs EC staging operation.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#pragma once

#define STAR_LABS_EC_MIRROR_PENDING_PROTOCOL_GUID \
  { 0x4ca78055, 0xdfd3, 0x4489, { 0xb3, 0x15, 0xce, 0xae, 0x7f, 0x29, 0x0a, 0x03 } }

#define STAR_LABS_EC_MIRROR_PENDING_REVISION  1U

struct _STAR_LABS_EC_MIRROR_PENDING_PROTOCOL {
  UINT32   Revision;
  UINT16   BoardId;
  UINT16   ChipId;
  UINT32   Version;
  UINT8    MinimumBattery;
  BOOLEAN  Finalized;
  BOOLEAN  ResetSafe;
  UINT8    ImageDigest[32];
};

typedef struct _STAR_LABS_EC_MIRROR_PENDING_PROTOCOL STAR_LABS_EC_MIRROR_PENDING_PROTOCOL;

extern EFI_GUID  gStarLabsEcMirrorPendingProtocolGuid;
