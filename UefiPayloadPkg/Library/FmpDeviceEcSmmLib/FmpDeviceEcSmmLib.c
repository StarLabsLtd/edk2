/** @file
  EC-only FMP implementation for Star Labs Merlin.

  The authenticated FMP capsule is the mutation authority.  This library
  validates the inner fixed record, live EC identity, power, version, geometry,
  and image digest before using the scoped SMMSTORE EC-region commands.  It has
  no direct internal-EC flash primitive.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Guid/SystemResourceTable.h>
#include <IndustryStandard/StarLabsEcIfu.h>
#include <LastAttemptStatus.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FmpDeviceLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/PrintLib.h>
#include <Library/SmmStoreLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/StarLabsEcMirrorPending.h>

#define EC_STATUS_PORT  0x66U
#define EC_DATA_PORT    0x62U
#define EC_STATUS_OBF   BIT0
#define EC_STATUS_IBF   BIT1
#define EC_COMMAND_READ 0x80U
#define EC_COMMAND_WRITE 0x81U
#define EC_IO_RETRIES   1000U
#define EC_IO_DELAY_US  50U
#define FLASH_RETRIES   3U

#define EC_IFU_STATUS_FORMAT    0x1801U
#define EC_IFU_STATUS_TARGET    0x1802U
#define EC_IFU_STATUS_POWER     0x1803U
#define EC_IFU_STATUS_ROLLBACK  0x1804U
#define EC_IFU_STATUS_GEOMETRY  0x1805U
#define EC_IFU_STATUS_STAGE     0x1806U
#define EC_IFU_STATUS_VERIFY    0x1807U
#define EC_IFU_STATUS_MIRROR    0x1808U

typedef struct {
  CONST UINT8  *Policy;
  CONST UINT8  *Image;
  UINT16       BoardId;
  UINT16       ChipId;
  UINT8        MinimumBattery;
  UINT32       Version;
  BOOLEAN      AllowReinstall;
} EC_IFU_IMAGE;

typedef struct {
  UINT16  BoardId;
  UINT16  ChipId;
  UINT32  Version;
} EC_TARGET;

STATIC EFI_STATUS  mSmmStoreStatus = EFI_NOT_READY;
STATIC EFI_HANDLE  mMirrorPendingHandle;
STATIC STAR_LABS_EC_MIRROR_PENDING_PROTOCOL  mMirrorPending;

STATIC
EFI_STATUS
ExpectedMirrorSignature (
  IN  UINT16  BoardId,
  IN  UINT16  ChipId,
  OUT UINT8   Signature[STARLABS_EC_MIRROR_SIZE]
  )
{
  STATIC CONST UINT8  CommonTail[8] = { 0x85, 0x12, 0x5a, 0x5a, 0xaa, 0x3f, 0x55, 0x55 };
  UINT8               PchId;

  SetMem (Signature, 8, 0xa5);
  CopyMem (&Signature[8], CommonTail, sizeof (CommonTail));
  if ((ChipId == STARLABS_EC_CHIP_IT8987) && (BoardId == 0x0004)) {
    Signature[7] = 0x94;
    return EFI_SUCCESS;
  }

  if (ChipId != STARLABS_EC_CHIP_IT5570) {
    return EFI_UNSUPPORTED;
  }

  switch (BoardId) {
    case 0x0003:
    case 0x0008:
      PchId = 0xa5;
      break;
    case 0x0001:
    case 0x0002:
    case 0x0005:
    case 0x0006:
    case 0x0007:
    case 0x0009:
    case 0x000a:
    case 0x000b:
    case 0x000c:
    case 0x000d:
      PchId = 0xa4;
      break;
    default:
      return EFI_UNSUPPORTED;
  }

  Signature[6] = PchId;
  Signature[7] = 0x95;
  return EFI_SUCCESS;
}

STATIC
UINT16
ReadLe16 (
  IN CONST UINT8  *Buffer
  )
{
  return ReadUnaligned16 ((CONST UINT16 *)(CONST VOID *)Buffer);
}

STATIC
UINT32
ReadLe32 (
  IN CONST UINT8  *Buffer
  )
{
  return ReadUnaligned32 ((CONST UINT32 *)(CONST VOID *)Buffer);
}

STATIC
UINT64
ReadLe64 (
  IN CONST UINT8  *Buffer
  )
{
  return ReadUnaligned64 ((CONST UINT64 *)(CONST VOID *)Buffer);
}

STATIC
BOOLEAN
BufferIsZero (
  IN CONST UINT8  *Buffer,
  IN UINTN        Size
  )
{
  UINTN  Index;

  for (Index = 0; Index < Size; ++Index) {
    if (Buffer[Index] != 0) {
      return FALSE;
    }
  }

  return TRUE;
}

STATIC
BOOLEAN
FixedAsciiIsCanonical (
  IN CONST UINT8  *Buffer,
  IN UINTN        Size,
  IN BOOLEAN      RequireNul
  )
{
  BOOLEAN  SawNul;
  UINTN    Index;

  if ((Buffer == NULL) || (Size == 0)) {
    return FALSE;
  }

  SawNul = FALSE;
  for (Index = 0; Index < Size; ++Index) {
    if (Buffer[Index] == 0) {
      SawNul = TRUE;
    } else if (SawNul || (Buffer[Index] < 0x20) || (Buffer[Index] > 0x7e)) {
      return FALSE;
    }
  }

  return (Buffer[0] != 0) && (!RequireNul || SawNul);
}

STATIC
VOID
EcDrainOutput (
  VOID
  )
{
  UINTN  Attempt;

  for (Attempt = 0; Attempt < 16; ++Attempt) {
    if ((IoRead8 (EC_STATUS_PORT) & EC_STATUS_OBF) == 0) {
      return;
    }

    IoRead8 (EC_DATA_PORT);
    MicroSecondDelay (EC_IO_DELAY_US);
  }
}

STATIC
EFI_STATUS
EcWaitStatus (
  IN UINT8  Mask,
  IN UINT8  Expected
  )
{
  UINTN  Attempt;

  for (Attempt = 0; Attempt < EC_IO_RETRIES; ++Attempt) {
    if ((IoRead8 (EC_STATUS_PORT) & Mask) == Expected) {
      return EFI_SUCCESS;
    }

    MicroSecondDelay (EC_IO_DELAY_US);
  }

  return EFI_TIMEOUT;
}

STATIC
EFI_STATUS
EcRead (
  IN  UINT8  Offset,
  OUT UINT8  *Value
  )
{
  EFI_STATUS  Status;

  if (Value == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  EcDrainOutput ();
  Status = EcWaitStatus (EC_STATUS_IBF, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_STATUS_PORT, EC_COMMAND_READ);
  Status = EcWaitStatus (EC_STATUS_IBF, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_DATA_PORT, Offset);
  Status = EcWaitStatus (EC_STATUS_OBF, EC_STATUS_OBF);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *Value = IoRead8 (EC_DATA_PORT);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EcWrite (
  IN UINT8  Offset,
  IN UINT8  Value
  )
{
  EFI_STATUS  Status;

  EcDrainOutput ();
  Status = EcWaitStatus (EC_STATUS_IBF, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_STATUS_PORT, EC_COMMAND_WRITE);
  Status = EcWaitStatus (EC_STATUS_IBF, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_DATA_PORT, Offset);
  Status = EcWaitStatus (EC_STATUS_IBF, 0);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  IoWrite8 (EC_DATA_PORT, Value);
  return EcWaitStatus (EC_STATUS_IBF, 0);
}

STATIC
EFI_STATUS
EcReadBytes (
  IN  UINT8  Offset,
  OUT UINT8  *Buffer,
  IN  UINTN  Size
  )
{
  EFI_STATUS  Status;
  UINTN       Index;

  for (Index = 0; Index < Size; ++Index) {
    Status = EcRead ((UINT8)(Offset + Index), &Buffer[Index]);
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ClearMirrorRequest (
  VOID
  )
{
  UINTN       Attempt;
  UINT8       MirrorFlag;
  EFI_STATUS  Status;

  Status = EFI_DEVICE_ERROR;
  for (Attempt = 0; Attempt < FLASH_RETRIES; ++Attempt) {
    Status = EcWrite (STARLABS_EC_MIRROR_REQUEST_OFFSET, 0);
    if (!EFI_ERROR (Status)) {
      Status = EcRead (STARLABS_EC_MIRROR_REQUEST_OFFSET, &MirrorFlag);
    }

    if (!EFI_ERROR (Status) && (MirrorFlag == 0)) {
      return EFI_SUCCESS;
    }
  }

  return EFI_DEVICE_ERROR;
}

STATIC
EFI_STATUS
ReadTarget (
  OUT EC_TARGET  *Target
  )
{
  UINT8       First[STARLABS_EC_TARGET_INFO_SIZE];
  UINT8       Second[STARLABS_EC_TARGET_INFO_SIZE];
  UINT8       Checksum;
  UINT8       Major;
  UINT8       Minor;
  UINTN       Index;
  EFI_STATUS  Status;

  if (Target == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = EcReadBytes (STARLABS_EC_TARGET_INFO_OFFSET, First, sizeof (First));
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EcReadBytes (STARLABS_EC_TARGET_INFO_OFFSET, Second, sizeof (Second));
  if (EFI_ERROR (Status) || (CompareMem (First, Second, sizeof (First)) != 0)) {
    return EFI_DEVICE_ERROR;
  }

  if ((CompareMem (First, STARLABS_EC_TARGET_INFO_MAGIC, 4) != 0) ||
      (First[4] != STARLABS_EC_TARGET_INFO_VERSION) ||
      (First[5] != STARLABS_EC_TARGET_INFO_SIZE))
  {
    return EFI_COMPROMISED_DATA;
  }

  Checksum = 0;
  for (Index = 0; Index < sizeof (First) - 1; ++Index) {
    Checksum ^= First[Index];
  }

  if ((Checksum != First[15]) ||
      (ReadLe16 (&First[10]) != STARLABS_EC_TARGET_INFO_FEATURES) ||
      (First[12] != 64) || (First[13] != 128) || (First[14] != 1))
  {
    return EFI_COMPROMISED_DATA;
  }

  Status = EcRead (STARLABS_EC_VERSION_MAJOR_OFFSET, &Major);
  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_VERSION_MINOR_OFFSET, &Minor);
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Target->BoardId = ReadLe16 (&First[6]);
  Target->ChipId  = ReadLe16 (&First[8]);
  Target->Version = ((UINT32)Major << 16) | Minor;
  if ((Target->BoardId != PcdGet16 (PcdStarLabsEcBoardId)) ||
      (Target->ChipId != PcdGet16 (PcdStarLabsEcChipId)))
  {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
CheckPower (
  IN UINT8  MinimumBattery
  )
{
  UINT8       First[3];
  UINT8       Second[3];
  EFI_STATUS  Status;
  UINT16      BatteryPercent;

  Status = EcRead (STARLABS_EC_POWER_STATE_OFFSET, &First[0]);
  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_BATTERY_PERCENT_OFFSET, &First[1]);
  }

  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_BATTERY_PERCENT_OFFSET + 1, &First[2]);
  }

  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_POWER_STATE_OFFSET, &Second[0]);
  }

  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_BATTERY_PERCENT_OFFSET, &Second[1]);
  }

  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_BATTERY_PERCENT_OFFSET + 1, &Second[2]);
  }

  if (EFI_ERROR (Status) || (CompareMem (First, Second, sizeof (First)) != 0)) {
    return EFI_DEVICE_ERROR;
  }

  if ((First[0] & STARLABS_EC_POWER_AC_PRESENT) == 0) {
    return EFI_ACCESS_DENIED;
  }

  if (MinimumBattery == 0) {
    return EFI_SUCCESS;
  }

  BatteryPercent = ReadLe16 (&First[1]);
  if (((First[0] & STARLABS_EC_POWER_BATTERY_PRESENT) == 0) ||
      (BatteryPercent > 100) || (BatteryPercent < MinimumBattery))
  {
    return EFI_ACCESS_DENIED;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FindDescriptor (
  IN  CONST UINT8  *Image,
  OUT CONST UINT8  **Descriptor
  )
{
  CONST UINT8  *Found;
  UINTN        Index;

  Found = NULL;
  for (Index = 0; Index <= STARLABS_EC_IFU_IMAGE_SIZE - 8; ++Index) {
    if (CompareMem (&Image[Index], STARLABS_EC_IFU_DESCRIPTOR_MAGIC, 8) == 0) {
      if ((Found != NULL) ||
          (Index > STARLABS_EC_IFU_IMAGE_SIZE - STARLABS_EC_IFU_DESCRIPTOR_SIZE))
      {
        return EFI_COMPROMISED_DATA;
      }

      Found = &Image[Index];
    }
  }

  if (Found == NULL) {
    return EFI_COMPROMISED_DATA;
  }

  *Descriptor = Found;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ValidateContainer (
  IN  CONST VOID    *Buffer,
  IN  UINTN         BufferSize,
  IN  UINT32        CapsuleFwVersion,
  OUT EC_IFU_IMAGE  *Parsed,
  OUT UINT32        *LastAttemptStatus
  )
{
  CONST UINT8  *Raw;
  CONST UINT8  *Policy;
  CONST UINT8  *Image;
  CONST UINT8  *Descriptor;
  EC_TARGET    Target;
  UINT8        Digest[SHA256_DIGEST_SIZE];
  UINT8        ExpectedMirror[STARLABS_EC_MIRROR_SIZE];
  UINT16       ChipId;
  UINT8        DescriptorChip;
  UINT32       Version;
  UINT64       Rollback;
  UINT32       PolicyFlags;
  EFI_STATUS   Status;

  if ((Buffer == NULL) || (Parsed == NULL) || (LastAttemptStatus == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *LastAttemptStatus = EC_IFU_STATUS_FORMAT;
  if (BufferSize != STARLABS_EC_IFU_CONTAINER_SIZE) {
    return EFI_COMPROMISED_DATA;
  }

  Raw    = Buffer;
  Policy = &Raw[STARLABS_EC_IFU_POLICY_OFFSET];
  Image  = &Raw[STARLABS_EC_IFU_IMAGE_OFFSET];
  if ((CompareMem (Raw, STARLABS_EC_IFU_HEADER_MAGIC, 8) != 0) ||
      (ReadLe16 (&Raw[8]) != STARLABS_EC_IFU_HEADER_VERSION) ||
      (ReadLe16 (&Raw[10]) != STARLABS_EC_IFU_HEADER_SIZE) ||
      (ReadLe32 (&Raw[12]) != STARLABS_EC_IFU_POLICY_SIZE) ||
      (ReadLe32 (&Raw[16]) != STARLABS_EC_IFU_IMAGE_SIZE) ||
      (ReadLe16 (&Raw[20]) != STARLABS_EC_IFU_SIGNATURE_SIZE) ||
      (ReadLe16 (&Raw[22]) != 0) || (ReadLe64 (&Raw[24]) != 0) ||
      (CompareMem (Policy, STARLABS_EC_IFU_POLICY_MAGIC, 8) != 0) ||
      (ReadLe16 (&Policy[8]) != STARLABS_EC_IFU_POLICY_VERSION) ||
      (ReadLe16 (&Policy[10]) != STARLABS_EC_IFU_POLICY_SIZE))
  {
    return EFI_COMPROMISED_DATA;
  }

  PolicyFlags = ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_FLAGS_OFFSET]);
  if ((Policy[STARLABS_EC_IFU_POLICY_POWER_FLAGS_OFFSET] != STARLABS_EC_IFU_POWER_AC_REQUIRED) ||
      (Policy[STARLABS_EC_IFU_POLICY_MINIMUM_BATTERY_OFFSET] > 100) ||
      ((PolicyFlags & ~STARLABS_EC_IFU_POLICY_ALLOW_REINSTALL) != 0) ||
      (ReadLe64 (&Policy[STARLABS_EC_IFU_POLICY_FEATURES_OFFSET]) !=
       STARLABS_EC_IFU_REQUIRED_FEATURES) ||
      !FixedAsciiIsCanonical (
         &Policy[STARLABS_EC_IFU_POLICY_BOARD_NAME_OFFSET],
         STARLABS_EC_IFU_POLICY_BOARD_NAME_SIZE,
         TRUE
         ) ||
      !FixedAsciiIsCanonical (
         &Policy[STARLABS_EC_IFU_POLICY_RELEASE_OFFSET],
         STARLABS_EC_IFU_POLICY_RELEASE_SIZE,
         FALSE
         ) ||
      BufferIsZero (&Policy[STARLABS_EC_IFU_POLICY_KEY_ID_OFFSET], SHA256_DIGEST_SIZE) ||
      BufferIsZero (&Raw[STARLABS_EC_IFU_SIGNATURE_OFFSET], STARLABS_EC_IFU_SIGNATURE_SIZE))
  {
    return EFI_COMPROMISED_DATA;
  }

  if ((ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_INTERNAL_SIZE_OFFSET]) !=
       STARLABS_EC_INTERNAL_SIZE) ||
      (ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_EXTERNAL_SIZE_OFFSET]) !=
       STARLABS_EC_EXTERNAL_SIZE) ||
      (ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_ERASE_SIZE_OFFSET]) !=
       STARLABS_EC_ERASE_SIZE) ||
      (ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_IMAGE_REGION_OFFSET]) != 0) ||
      (ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_IMAGE_REGION_SIZE_OFFSET]) !=
       STARLABS_EC_IFU_IMAGE_SIZE) ||
      (ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_PRESERVE_OFFSET]) !=
       STARLABS_EC_PERSISTENT_OFFSET) ||
      (ReadLe32 (&Policy[STARLABS_EC_IFU_POLICY_PRESERVE_SIZE_OFFSET]) !=
       STARLABS_EC_PERSISTENT_SIZE))
  {
    *LastAttemptStatus = EC_IFU_STATUS_GEOMETRY;
    return EFI_COMPROMISED_DATA;
  }

  if (!Sha256HashAll (Image, STARLABS_EC_IFU_IMAGE_SIZE, Digest) ||
      (CompareMem (
         Digest,
         &Policy[STARLABS_EC_IFU_POLICY_IMAGE_SHA256_OFFSET],
         sizeof (Digest)
         ) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Status = FindDescriptor (Image, &Descriptor);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ChipId = ReadLe16 (&Policy[STARLABS_EC_IFU_POLICY_CHIP_ID_OFFSET]);
  if (ReadLe16 (&Policy[STARLABS_EC_IFU_POLICY_BOARD_ID_OFFSET]) == 0) {
    return EFI_COMPROMISED_DATA;
  }

  Status = ExpectedMirrorSignature (
             ReadLe16 (&Policy[STARLABS_EC_IFU_POLICY_BOARD_ID_OFFSET]),
             ChipId,
             ExpectedMirror
             );
  if (EFI_ERROR (Status)) {
    return EFI_COMPROMISED_DATA;
  }

  if (ChipId == STARLABS_EC_CHIP_IT5570) {
    DescriptorChip = STARLABS_EC_IFU_DESCRIPTOR_CHIP_IT5570;
  } else if (ChipId == STARLABS_EC_CHIP_IT8987) {
    DescriptorChip = STARLABS_EC_IFU_DESCRIPTOR_CHIP_IT8987;
  } else {
    return EFI_COMPROMISED_DATA;
  }

  Version = ((UINT32)Policy[STARLABS_EC_IFU_POLICY_IMAGE_MAJOR_OFFSET] << 16) |
            Policy[STARLABS_EC_IFU_POLICY_IMAGE_MINOR_OFFSET];
  if ((Descriptor[8] != STARLABS_EC_IFU_DESCRIPTOR_VERSION) ||
      (Descriptor[9] != STARLABS_EC_IFU_DESCRIPTOR_SIZE) ||
      (Descriptor[STARLABS_EC_IFU_DESCRIPTOR_CHIP_OFFSET] != DescriptorChip) ||
      (Descriptor[STARLABS_EC_IFU_DESCRIPTOR_FEATURES_OFFSET] !=
       STARLABS_EC_IFU_DESCRIPTOR_FEATURES) ||
      (ReadLe16 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_BOARD_ID_OFFSET]) !=
       ReadLe16 (&Policy[STARLABS_EC_IFU_POLICY_BOARD_ID_OFFSET])) ||
      (Descriptor[STARLABS_EC_IFU_DESCRIPTOR_IMAGE_MAJOR_OFFSET] !=
       Policy[STARLABS_EC_IFU_POLICY_IMAGE_MAJOR_OFFSET]) ||
      (Descriptor[STARLABS_EC_IFU_DESCRIPTOR_IMAGE_MINOR_OFFSET] !=
       Policy[STARLABS_EC_IFU_POLICY_IMAGE_MINOR_OFFSET]) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_CODE_OFFSET]) != 0) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_CODE_SIZE_OFFSET]) !=
       STARLABS_EC_IFU_IMAGE_SIZE) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_INTERNAL_OFFSET]) !=
       STARLABS_EC_INTERNAL_SIZE) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_PERSISTENT_OFFSET]) !=
       STARLABS_EC_PERSISTENT_OFFSET) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_PERSISTENT_SIZE]) !=
       STARLABS_EC_PERSISTENT_SIZE) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_MIRROR_OFFSET]) !=
       STARLABS_EC_MIRROR_OFFSET) ||
      (ReadLe32 (&Descriptor[STARLABS_EC_IFU_DESCRIPTOR_MIRROR_SIZE]) !=
       STARLABS_EC_MIRROR_SIZE) ||
      !FixedAsciiIsCanonical (
         &Descriptor[STARLABS_EC_IFU_DESCRIPTOR_BOARD_NAME_OFFSET],
         STARLABS_EC_IFU_DESCRIPTOR_BOARD_NAME_SIZE,
         TRUE
         ) ||
      (CompareMem (
         &Descriptor[STARLABS_EC_IFU_DESCRIPTOR_BOARD_NAME_OFFSET],
         &Policy[STARLABS_EC_IFU_POLICY_BOARD_NAME_OFFSET],
         STARLABS_EC_IFU_DESCRIPTOR_BOARD_NAME_SIZE
         ) != 0) ||
      (CompareMem (
         &Image[STARLABS_EC_MIRROR_OFFSET],
         ExpectedMirror,
         STARLABS_EC_MIRROR_SIZE
         ) != 0) ||
      (CompareMem (
         &Policy[STARLABS_EC_IFU_POLICY_MIRROR_SIGNATURE_OFFSET],
         ExpectedMirror,
         STARLABS_EC_MIRROR_SIZE
         ) != 0))
  {
    return EFI_COMPROMISED_DATA;
  }

  Rollback = ReadLe64 (&Policy[STARLABS_EC_IFU_POLICY_ROLLBACK_OFFSET]);
  if ((Rollback != Version) ||
      ((CapsuleFwVersion != 0) && (CapsuleFwVersion != Version)) ||
      (Version < PcdGet32 (PcdStarLabsEcLowestSupportedVersion)))
  {
    *LastAttemptStatus = EC_IFU_STATUS_ROLLBACK;
    return EFI_INCOMPATIBLE_VERSION;
  }

  *LastAttemptStatus = EC_IFU_STATUS_TARGET;
  Status             = ReadTarget (&Target);
  if (EFI_ERROR (Status) ||
      (Target.BoardId != ReadLe16 (&Policy[STARLABS_EC_IFU_POLICY_BOARD_ID_OFFSET])) ||
      (Target.ChipId != ChipId))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if ((Version < Target.Version) ||
      ((Version == Target.Version) &&
       ((PolicyFlags & STARLABS_EC_IFU_POLICY_ALLOW_REINSTALL) == 0)))
  {
    *LastAttemptStatus = EC_IFU_STATUS_ROLLBACK;
    return EFI_INCOMPATIBLE_VERSION;
  }

  *LastAttemptStatus = EC_IFU_STATUS_POWER;
  Status             = CheckPower (Policy[STARLABS_EC_IFU_POLICY_MINIMUM_BATTERY_OFFSET]);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Parsed->Policy         = Policy;
  Parsed->Image          = Image;
  Parsed->BoardId        = Target.BoardId;
  Parsed->ChipId         = Target.ChipId;
  Parsed->MinimumBattery = Policy[STARLABS_EC_IFU_POLICY_MINIMUM_BATTERY_OFFSET];
  Parsed->Version        = Version;
  Parsed->AllowReinstall = (PolicyFlags & STARLABS_EC_IFU_POLICY_ALLOW_REINSTALL) != 0;
  *LastAttemptStatus     = LAST_ATTEMPT_STATUS_SUCCESS;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
CheckEcRegionGeometry (
  IN UINTN  BlockSize
  )
{
  UINT8       Byte;
  UINTN       NumBytes;
  UINTN       BlockCount;
  EFI_STATUS  Status;

  if ((BlockSize == 0) || (BlockSize > STARLABS_EC_IFU_IMAGE_SIZE) ||
      ((STARLABS_EC_IFU_IMAGE_SIZE % BlockSize) != 0))
  {
    return EFI_UNSUPPORTED;
  }

  BlockCount = STARLABS_EC_IFU_IMAGE_SIZE / BlockSize;
  NumBytes   = 1;
  Status     = SmmStoreLibReadEcBlock (BlockCount - 1, BlockSize - 1, &NumBytes, &Byte);
  if (EFI_ERROR (Status) || (NumBytes != 1)) {
    return EFI_DEVICE_ERROR;
  }

  NumBytes = 1;
  Status   = SmmStoreLibReadEcBlock (BlockCount, 0, &NumBytes, &Byte);
  return EFI_ERROR (Status) ? EFI_SUCCESS : EFI_BAD_BUFFER_SIZE;
}

STATIC
EFI_STATUS
EFIAPI
FinalizeEcMirror (
  IN STAR_LABS_EC_MIRROR_PENDING_PROTOCOL  *This
  )
{
  EC_TARGET    Target;
  EFI_STATUS   Status;
  UINTN        BlockSize;
  UINTN        BlockCount;
  UINTN        Block;
  UINTN        NumBytes;
  UINT8        Digest[SHA256_DIGEST_SIZE];
  UINT8        MirrorFlag;
  UINT8        *Verify;

  if ((This != &mMirrorPending) ||
      (This->Revision != STAR_LABS_EC_MIRROR_PENDING_REVISION))
  {
    return EFI_INVALID_PARAMETER;
  }

  This->Finalized = FALSE;
  This->ResetSafe = TRUE;

  Status = ReadTarget (&Target);
  if (EFI_ERROR (Status) || (Target.BoardId != This->BoardId) ||
      (Target.ChipId != This->ChipId))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Status = CheckPower (This->MinimumBattery);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = SmmStoreLibGetBlockSize (&BlockSize);
  if (!EFI_ERROR (Status)) {
    Status = CheckEcRegionGeometry (BlockSize);
  }

  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = EcRead (STARLABS_EC_MIRROR_REQUEST_OFFSET, &MirrorFlag);
  if (EFI_ERROR (Status) || (MirrorFlag != 0)) {
    if (EFI_ERROR (ClearMirrorRequest ())) {
      This->ResetSafe = FALSE;
    }

    return EFI_NOT_READY;
  }

  Verify = AllocatePool (STARLABS_EC_IFU_IMAGE_SIZE);
  if (Verify == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  BlockCount = STARLABS_EC_IFU_IMAGE_SIZE / BlockSize;
  for (Block = 0; Block < BlockCount; ++Block) {
    NumBytes = BlockSize;
    Status   = SmmStoreLibReadEcBlock (
                 Block,
                 0,
                 &NumBytes,
                 &Verify[Block * BlockSize]
                 );
    if (EFI_ERROR (Status) || (NumBytes != BlockSize)) {
      Status = EFI_DEVICE_ERROR;
      goto Done;
    }
  }

  if (!Sha256HashAll (Verify, STARLABS_EC_IFU_IMAGE_SIZE, Digest) ||
      (CompareMem (Digest, This->ImageDigest, sizeof (Digest)) != 0))
  {
    Status = EFI_SECURITY_VIOLATION;
    goto Done;
  }

  Status = CheckPower (This->MinimumBattery);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  Status = EcWrite (STARLABS_EC_MIRROR_REQUEST_OFFSET, STARLABS_EC_MIRROR_REQUEST);
  if (!EFI_ERROR (Status)) {
    Status = EcRead (STARLABS_EC_MIRROR_REQUEST_OFFSET, &MirrorFlag);
  }

  if (EFI_ERROR (Status) || (MirrorFlag != STARLABS_EC_MIRROR_REQUEST)) {
    if (EFI_ERROR (ClearMirrorRequest ())) {
      This->ResetSafe = FALSE;
    }

    Status = EFI_DEVICE_ERROR;
  } else {
    This->Finalized = TRUE;
  }

Done:
  FreePool (Verify);
  return Status;
}

STATIC
EFI_STATUS
ProgramEcRegion (
  IN CONST EC_IFU_IMAGE                               *Parsed,
  IN EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS   Progress OPTIONAL,
  OUT UINT32                                          *LastAttemptStatus
  )
{
  EFI_STATUS  Status;
  UINTN       BlockSize;
  UINTN       BlockCount;
  UINTN       Block;
  UINTN       Attempt;
  UINTN       NumBytes;
  UINT8       *Verify;
  UINT8       MirrorFlag;

  if (EFI_ERROR (mSmmStoreStatus)) {
    return mSmmStoreStatus;
  }

  if (mMirrorPendingHandle != NULL) {
    return EFI_ALREADY_STARTED;
  }

  Status = SmmStoreLibGetBlockSize (&BlockSize);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = CheckEcRegionGeometry (BlockSize);
  if (EFI_ERROR (Status)) {
    *LastAttemptStatus = EC_IFU_STATUS_GEOMETRY;
    return Status;
  }

  mMirrorPending.Revision = STAR_LABS_EC_MIRROR_PENDING_REVISION;
  mMirrorPending.BoardId  = Parsed->BoardId;
  mMirrorPending.ChipId   = Parsed->ChipId;
  mMirrorPending.Version  = Parsed->Version;
  mMirrorPending.MinimumBattery = Parsed->MinimumBattery;
  mMirrorPending.Finalized      = FALSE;
  mMirrorPending.ResetSafe      = TRUE;
  CopyMem (
    mMirrorPending.ImageDigest,
    &Parsed->Policy[STARLABS_EC_IFU_POLICY_IMAGE_SHA256_OFFSET],
    sizeof (mMirrorPending.ImageDigest)
    );
  Status = gBS->InstallProtocolInterface (
                  &mMirrorPendingHandle,
                  &gStarLabsEcMirrorPendingProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &mMirrorPending
                  );
  if (EFI_ERROR (Status)) {
    if (EFI_ERROR (ClearMirrorRequest ())) {
      CpuDeadLoop ();
    }

    return Status;
  }

  Status = EcRead (STARLABS_EC_MIRROR_REQUEST_OFFSET, &MirrorFlag);
  if (EFI_ERROR (Status) || (MirrorFlag != 0)) {
    if (EFI_ERROR (ClearMirrorRequest ())) {
      mMirrorPending.ResetSafe = FALSE;
    }

    *LastAttemptStatus = EC_IFU_STATUS_MIRROR;
    return EFI_NOT_READY;
  }

  Verify = AllocatePool (BlockSize);
  if (Verify == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  BlockCount = STARLABS_EC_IFU_IMAGE_SIZE / BlockSize;
  for (Block = 0; Block < BlockCount; ++Block) {
    Status = CheckPower (Parsed->MinimumBattery);
    if (EFI_ERROR (Status)) {
      *LastAttemptStatus = EC_IFU_STATUS_POWER;
      goto Done;
    }

    *LastAttemptStatus = EC_IFU_STATUS_STAGE;
    for (Attempt = 0; Attempt < FLASH_RETRIES; ++Attempt) {
      Status = CheckPower (Parsed->MinimumBattery);
      if (EFI_ERROR (Status)) {
        *LastAttemptStatus = EC_IFU_STATUS_POWER;
        goto Done;
      }

      Status = SmmStoreLibEraseEcBlock (Block);
      if (!EFI_ERROR (Status)) {
        break;
      }
    }

    if (EFI_ERROR (Status)) {
      goto Done;
    }

    Status = CheckPower (Parsed->MinimumBattery);
    if (EFI_ERROR (Status)) {
      *LastAttemptStatus = EC_IFU_STATUS_POWER;
      goto Done;
    }

    *LastAttemptStatus = EC_IFU_STATUS_STAGE;
    Status             = EFI_DEVICE_ERROR;
    for (Attempt = 0; Attempt < FLASH_RETRIES; ++Attempt) {
      Status = CheckPower (Parsed->MinimumBattery);
      if (EFI_ERROR (Status)) {
        *LastAttemptStatus = EC_IFU_STATUS_POWER;
        goto Done;
      }

      NumBytes = BlockSize;
      Status   = SmmStoreLibWriteEcBlock (
                   Block,
                   0,
                   &NumBytes,
                   (UINT8 *)&Parsed->Image[Block * BlockSize]
                   );
      if (!EFI_ERROR (Status) && (NumBytes == BlockSize)) {
        break;
      }

      Status = EFI_DEVICE_ERROR;
    }

    if (EFI_ERROR (Status)) {
      goto Done;
    }

    *LastAttemptStatus = EC_IFU_STATUS_VERIFY;
    Status             = EFI_DEVICE_ERROR;
    for (Attempt = 0; Attempt < FLASH_RETRIES; ++Attempt) {
      NumBytes = BlockSize;
      Status   = SmmStoreLibReadEcBlock (Block, 0, &NumBytes, Verify);
      if (!EFI_ERROR (Status) && (NumBytes == BlockSize) &&
          (CompareMem (Verify, &Parsed->Image[Block * BlockSize], BlockSize) == 0))
      {
        break;
      }

      Status = EFI_VOLUME_CORRUPTED;
    }

    if (EFI_ERROR (Status)) {
      goto Done;
    }

    if (Progress != NULL) {
      Progress ((UINTN)(5 + ((Block + 1) * 90 / BlockCount)));
    }
  }

  *LastAttemptStatus = EC_IFU_STATUS_MIRROR;
  Status             = FinalizeEcMirror (&mMirrorPending);
  if (EFI_ERROR (Status)) {
    goto Done;
  }

  if (Progress != NULL) {
    Progress (100);
  }

  *LastAttemptStatus = LAST_ATTEMPT_STATUS_SUCCESS;
  Status             = EFI_SUCCESS;

Done:
  FreePool (Verify);
  return Status;
}

EFI_STATUS
EFIAPI
RegisterFmpInstaller (
  IN FMP_DEVICE_LIB_REGISTER_FMP_INSTALLER  Function
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
RegisterFmpUninstaller (
  IN FMP_DEVICE_LIB_REGISTER_FMP_UNINSTALLER  Function
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
FmpDeviceSetContext (
  IN EFI_HANDLE  Handle,
  IN OUT VOID    **Context
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
FmpDeviceGetSize (
  OUT UINTN  *Size
  )
{
  if (Size == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Size = STARLABS_EC_IFU_CONTAINER_SIZE;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceGetImageTypeIdGuidPtr (
  OUT EFI_GUID  **Guid
  )
{
  if (Guid == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (PcdGetSize (PcdExclusiveFmpImageTypeIdGuid) != sizeof (EFI_GUID)) {
    return EFI_UNSUPPORTED;
  }

  *Guid = (EFI_GUID *)PcdGetPtr (PcdExclusiveFmpImageTypeIdGuid);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceGetAttributes (
  OUT UINT64  *Supported,
  OUT UINT64  *Setting
  )
{
  if ((Supported == NULL) || (Setting == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *Supported = IMAGE_ATTRIBUTE_IMAGE_UPDATABLE |
               IMAGE_ATTRIBUTE_AUTHENTICATION_REQUIRED |
               IMAGE_ATTRIBUTE_IN_USE;
  *Setting = *Supported;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceGetLowestSupportedVersion (
  OUT UINT32  *LowestSupportedVersion
  )
{
  if (LowestSupportedVersion == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *LowestSupportedVersion = PcdGet32 (PcdStarLabsEcLowestSupportedVersion);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceGetVersionString (
  OUT CHAR16  **VersionString
  )
{
  EC_TARGET   Target;
  EFI_STATUS  Status;

  if (VersionString == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *VersionString = NULL;
  Status         = ReadTarget (&Target);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  *VersionString = AllocateZeroPool (16 * sizeof (CHAR16));
  if (*VersionString == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  UnicodeSPrint (*VersionString, 16 * sizeof (CHAR16), L"%u.%u", Target.Version >> 16, Target.Version & 0xff);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceGetVersion (
  OUT UINT32  *Version
  )
{
  EC_TARGET   Target;
  EFI_STATUS  Status;

  if (Version == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Status = ReadTarget (&Target);
  if (!EFI_ERROR (Status)) {
    *Version = Target.Version;
  }

  return Status;
}

EFI_STATUS
EFIAPI
FmpDeviceGetHardwareInstance (
  OUT UINT64  *HardwareInstance
  )
{
  if (HardwareInstance == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *HardwareInstance = PcdGet16 (PcdStarLabsEcBoardId);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceGetImage (
  OUT    VOID   *Image,
  IN OUT UINTN  *ImageSize
  )
{
  return EFI_UNSUPPORTED;
}

EFI_STATUS
EFIAPI
FmpDeviceCheckImage (
  IN  CONST VOID  *Image,
  IN  UINTN       ImageSize,
  OUT UINT32      *ImageUpdatable
  )
{
  UINT32  LastAttemptStatus;

  return FmpDeviceCheckImageWithStatus (
           Image,
           ImageSize,
           ImageUpdatable,
           &LastAttemptStatus
           );
}

EFI_STATUS
EFIAPI
FmpDeviceCheckImageWithStatus (
  IN  CONST VOID  *Image,
  IN  UINTN       ImageSize,
  OUT UINT32      *ImageUpdatable,
  OUT UINT32      *LastAttemptStatus
  )
{
  EC_IFU_IMAGE  Parsed;
  EFI_STATUS    Status;

  if ((Image == NULL) || (ImageUpdatable == NULL) || (LastAttemptStatus == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Status = ValidateContainer (Image, ImageSize, 0, &Parsed, LastAttemptStatus);
  if (Status == EFI_INCOMPATIBLE_VERSION) {
    *ImageUpdatable = IMAGE_UPDATABLE_INVALID_OLD;
  } else if (EFI_ERROR (Status)) {
    *ImageUpdatable = IMAGE_UPDATABLE_INVALID;
  } else {
    *ImageUpdatable = IMAGE_UPDATABLE_VALID;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceSetImage (
  IN  CONST VOID                                     *Image,
  IN  UINTN                                          ImageSize,
  IN  CONST VOID                                     *VendorCode OPTIONAL,
  IN  EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS  Progress OPTIONAL,
  IN  UINT32                                         CapsuleFwVersion,
  OUT CHAR16                                         **AbortReason
  )
{
  UINT32  LastAttemptStatus;

  return FmpDeviceSetImageWithStatus (
           Image,
           ImageSize,
           VendorCode,
           Progress,
           CapsuleFwVersion,
           AbortReason,
           &LastAttemptStatus
           );
}

EFI_STATUS
EFIAPI
FmpDeviceSetImageWithStatus (
  IN  CONST VOID                                     *Image,
  IN  UINTN                                          ImageSize,
  IN  CONST VOID                                     *VendorCode OPTIONAL,
  IN  EFI_FIRMWARE_MANAGEMENT_UPDATE_IMAGE_PROGRESS  Progress OPTIONAL,
  IN  UINT32                                         CapsuleFwVersion,
  OUT CHAR16                                         **AbortReason,
  OUT UINT32                                         *LastAttemptStatus
  )
{
  EC_IFU_IMAGE  Parsed;
  EFI_STATUS    Status;

  if ((Image == NULL) || (AbortReason == NULL) || (LastAttemptStatus == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  *AbortReason = NULL;
  if (VendorCode != NULL) {
    *LastAttemptStatus = EC_IFU_STATUS_FORMAT;
    return EFI_UNSUPPORTED;
  }

  Status = ValidateContainer (
             Image,
             ImageSize,
             CapsuleFwVersion,
             &Parsed,
             LastAttemptStatus
             );
  if (EFI_ERROR (Status)) {
    return EFI_ABORTED;
  }

  if (Progress != NULL) {
    Progress (5);
  }

  Status = ProgramEcRegion (&Parsed, Progress, LastAttemptStatus);
  return EFI_ERROR (Status) ? EFI_ABORTED : EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceLock (
  VOID
  )
{
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FmpDeviceEcSmmLibConstructor (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  if ((PcdGet16 (PcdStarLabsEcBoardId) == 0) ||
      ((PcdGet16 (PcdStarLabsEcChipId) != STARLABS_EC_CHIP_IT5570) &&
       (PcdGet16 (PcdStarLabsEcChipId) != STARLABS_EC_CHIP_IT8987)) ||
      (PcdGet32 (PcdStarLabsEcLowestSupportedVersion) == 0))
  {
    mSmmStoreStatus = EFI_UNSUPPORTED;
    return EFI_SUCCESS;
  }

  mSmmStoreStatus = SmmStoreLibInitialize ();
  return EFI_SUCCESS;
}
