/** @file
  OPAL S3 password handoff via APMC-triggered SMI.

  This library provides an OpalS3PasswordLib implementation for platforms
  that expose an APMC SMI interface and an SMM handler which accepts an OPAL
  password for the current sleep cycle.

  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <IndustryStandard/Pci.h>
#include <Protocol/DevicePath.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/OpalS3PasswordLib.h>
#include <Library/PciLib.h>

#define OPAL_S3_APM_CNT_SVC              0xEE
#define OPAL_S3_SMM_SUBCMD_SET_SECRET    0x01
#define OPAL_S3_SMM_SUBCMD_CLEAR_SECRET  0x02

#define OPAL_S3_SMM_CTX_SIGNATURE  SIGNATURE_32 ('O', 'P', 'S', '3')
#define OPAL_S3_SMM_CTX_VERSION    0x0001

#pragma pack(push, 1)
typedef struct {
  UINT32    Signature;
  UINT16    Version;
  UINT16    Size;

  UINT8     Bus;
  UINT8     Device;
  UINT8     Function;
  UINT8     Reserved0;

  UINT16    OpalBaseComId;
  UINT16    Reserved1;

  UINT8     PasswordLength;
  UINT8     Reserved2[3];
  UINT8     Password[OPAL_S3_PASSWORD_MAX_LEN];
} OPAL_S3_SMM_CTX;
#pragma pack(pop)

typedef struct {
  UINT16    Segment;
  UINT8     Bus;
  UINT8     Device;
  UINT8     Function;
} OPAL_PCI_DEVICE;

#if defined (MDE_CPU_X64)
//
// Platform SMM ABI: set RAX/RBX then outb to APMC (0xB2).
//
UINTN
EFIAPI
OpalS3TriggerSmi (
  IN UINTN  Cmd,
  IN UINTN  Arg,
  IN UINTN  Retry
  );
#else
STATIC
UINTN
EFIAPI
OpalS3TriggerSmi (
  IN UINTN  Cmd,
  IN UINTN  Arg,
  IN UINTN  Retry
  )
{
  return Cmd;
}
#endif

STATIC
EFI_STATUS
GetNvmePciLocationFromDevicePath (
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  OUT OPAL_PCI_DEVICE           *PciDevice
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *Tmp;
  EFI_DEVICE_PATH_PROTOCOL  *Tmp2;
  UINT8                     BusNum;
  PCI_DEVICE_PATH           *PciDevPath;

  if ((DevicePath == NULL) || (PciDevice == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  BusNum = 0;
  Tmp    = DevicePath;
  Tmp2   = NextDevicePathNode (DevicePath);

  while (!IsDevicePathEnd (Tmp2)) {
    if ((Tmp->Type == HARDWARE_DEVICE_PATH) && (Tmp->SubType == HW_PCI_DP)) {
      PciDevPath = (PCI_DEVICE_PATH *)Tmp;

      if ((Tmp2->Type == HARDWARE_DEVICE_PATH) && (Tmp2->SubType == HW_PCI_DP)) {
        //
        // PCI-PCI bridge, advance BusNum.
        //
        BusNum = PciRead8 (
                   PCI_LIB_ADDRESS (
                     BusNum,
                     PciDevPath->Device,
                     PciDevPath->Function,
                     PCI_BRIDGE_SECONDARY_BUS_REGISTER_OFFSET
                     )
                   );
      } else if ((Tmp2->Type == MESSAGING_DEVICE_PATH) &&
                 (Tmp2->SubType == MSG_NVME_NAMESPACE_DP))
      {
        //
        // NVMe endpoint found.
        //
        PciDevice->Segment  = 0;
        PciDevice->Bus      = BusNum;
        PciDevice->Device   = PciDevPath->Device;
        PciDevice->Function = PciDevPath->Function;
        return EFI_SUCCESS;
      }
    }

    Tmp  = NextDevicePathNode (Tmp);
    Tmp2 = NextDevicePathNode (Tmp2);
  }

  return EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
SendSmmSvc (
  IN UINT8                 Subcmd,
  IN EFI_PHYSICAL_ADDRESS  CtxPhys OPTIONAL
  )
{
  UINTN  Cmd;
  UINTN  Result;

  Cmd = (UINTN)(((UINTN)Subcmd << 8) | OPAL_S3_APM_CNT_SVC);

  Result = OpalS3TriggerSmi (Cmd, (UINTN)CtxPhys, 5);
  if (Result == Cmd) {
    DEBUG ((DEBUG_VERBOSE, "%a(): no SMM response\n", __func__));
    return EFI_DEVICE_ERROR;
  }

  if (Result != 0) {
    DEBUG ((DEBUG_VERBOSE, "%a(): SMM returned error: 0x%lx\n", __func__, (UINT64)Result));
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
OpalS3PasswordLibSetSecret (
  IN EFI_DEVICE_PATH_PROTOCOL  *OpalDevicePath,
  IN UINT16                    OpalBaseComId,
  IN CONST VOID                *Password,
  IN UINTN                     PasswordLength
  )
{
  EFI_STATUS            Status;
  OPAL_PCI_DEVICE       PciDevice;
  EFI_PHYSICAL_ADDRESS  CtxPhys;
  OPAL_S3_SMM_CTX       *Ctx;

  if ((OpalDevicePath == NULL) || (Password == NULL) || (PasswordLength == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  if (PasswordLength > OPAL_S3_PASSWORD_MAX_LEN) {
    return EFI_INVALID_PARAMETER;
  }

  Status = GetNvmePciLocationFromDevicePath (OpalDevicePath, &PciDevice);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Allocate a below-4G, page-aligned buffer and pass its physical address to
  // SMM. SMM must treat this buffer as untrusted and copy the secret before
  // returning.
  //
  CtxPhys = 0xFFFFFFFF;
  Status  = gBS->AllocatePages (
                   AllocateMaxAddress,
                   EfiBootServicesData,
                   1,
                   &CtxPhys
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Ctx = (OPAL_S3_SMM_CTX *)(UINTN)CtxPhys;
  ZeroMem (Ctx, EFI_PAGE_SIZE);

  Ctx->Signature      = OPAL_S3_SMM_CTX_SIGNATURE;
  Ctx->Version        = OPAL_S3_SMM_CTX_VERSION;
  Ctx->Size           = sizeof (*Ctx);
  Ctx->Bus            = PciDevice.Bus;
  Ctx->Device         = PciDevice.Device;
  Ctx->Function       = PciDevice.Function;
  Ctx->OpalBaseComId  = OpalBaseComId;
  Ctx->PasswordLength = (UINT8)PasswordLength;
  CopyMem (Ctx->Password, Password, PasswordLength);

  Status = SendSmmSvc (OPAL_S3_SMM_SUBCMD_SET_SECRET, CtxPhys);

  //
  // Best-effort: clear password in non-SMRAM context after SMM copied it.
  //
  ZeroMem (Ctx->Password, sizeof (Ctx->Password));
  Ctx->PasswordLength = 0;
  gBS->FreePages (CtxPhys, 1);

  return Status;
}

EFI_STATUS
EFIAPI
OpalS3PasswordLibClearSecret (
  VOID
  )
{
  return SendSmmSvc (OPAL_S3_SMM_SUBCMD_CLEAR_SECRET, 0);
}
