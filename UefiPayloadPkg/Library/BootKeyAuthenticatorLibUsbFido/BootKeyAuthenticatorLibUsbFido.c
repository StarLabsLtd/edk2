/** @file
  USB HID FIDO/U2F boot-key authenticator.

  The provider deliberately implements only the CTAPHID framing and U2F
  register/authenticate messages needed by the boot-key policy. It does not
  connect storage, network, option-ROM, or Driver#### paths.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Usb.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyAuthenticatorLib.h>
#include <Library/BootKeyCredentialStoreLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/RngLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/DevicePath.h>
#include <Protocol/PciIo.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/UsbIo.h>

#define FIDO_HID_CLASS                   3
#define FIDO_HID_SUBCLASS                0
#define FIDO_HID_PROTOCOL                0
#define FIDO_USAGE_PAGE                  0xf1d0
#define FIDO_USAGE_CTAPHID               0x01
#define FIDO_YUBICO_VENDOR_ID            0x1050
#define FIDO_REPORT_SIZE                 64
#define FIDO_REPORT_DESCRIPTOR_MAX_SIZE  256
#define FIDO_INIT_DATA_SIZE              57
#define FIDO_CONT_DATA_SIZE              59
#define FIDO_MAX_MESSAGE_SIZE            1024
#define FIDO_USB_CONTROL_TIMEOUT_MS      40
// CTAPHID permits up to 100 ms between keepalive messages.  The per-report
// timeout remains beyond that bound, while one shared deadline bounds the
// complete transaction.
#define FIDO_USB_REPORT_TIMEOUT_MS            250
#define FIDO_CALL_TIMEOUT_NS                  850000000ULL
#define FIDO_BROADCAST_CHANNEL                0xffffffffU
#define FIDO_HID_INIT                         0x86
#define FIDO_HID_MSG                          0x83
#define FIDO_HID_YUBICO_GET_DEVICE_INFO       0xc2
#define FIDO_HID_KEEPALIVE                    0xbb
#define FIDO_HID_ERROR                        0xbf
#define FIDO_YUBICO_DEVICE_INFO_SERIAL_TAG    0x02
#define FIDO_U2F_REGISTER                     0x01
#define FIDO_U2F_AUTHENTICATE                 0x02
#define FIDO_U2F_AUTH_ENFORCE_USER            0x03
#define FIDO_U2F_AUTH_CHECK_ONLY              0x07
#define FIDO_U2F_REGISTER_RESERVED            0x05
#define FIDO_U2F_SW_NO_ERROR                  0x9000
#define FIDO_U2F_SW_CONDITIONS_NOT_SATISFIED  0x6985
#define FIDO_U2F_SW_WRONG_DATA                0x6a80
#define FIDO_U2F_PUBLIC_KEY_SIZE              65
#define FIDO_U2F_AUTH_FIXED_RESPONSE_SIZE     5
#define FIDO_DER_INTEGER_MAX_SIZE             33
#define FIDO_RECEIVE_REPORT_LIMIT             2
#define FIDO_INTERFACE_SCAN_LIMIT             4
#define FIDO_DEVICE_PATH_MAX_SIZE             1024
#define FIDO_INTEL_CLIENT_XHCI_PCI_DEVICE     0x14
#define FIDO_INTEL_CLIENT_XHCI_PCI_FUNCTION   0

typedef struct {
  EFI_HANDLE             Handle;
  EFI_USB_IO_PROTOCOL    *UsbIo;
  UINT8                  InEndpoint;
  UINT8                  OutEndpoint;
  UINT16                 ReportSize;
  UINT16                 VendorId;
  UINT16                 ProductId;
  UINT8                  InterfaceNumber;
  UINT8                  DeviceIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
  UINT8                  DevicePathDigest[SHA256_DIGEST_SIZE];
  BOOLEAN                DeviceIdentityValid;
  UINT32                 Channel;
  BOOLEAN                TransactionPending;
  UINT8                  PendingCommand;
  EFI_HANDLE             PendingHandle;
  UINT8                  PendingRequestDigest[SHA256_DIGEST_SIZE];
  BOOLEAN                AuthenticationPending;
  UINT8                  PendingAuthenticationControl;
  UINTN                  PendingCredentialIndex;
} FIDO_USB_CONTEXT;

typedef struct {
  UINT64    CounterStart;
  UINT64    CounterEnd;
  UINT64    LastCounter;
  UINT64    ElapsedNs;
} FIDO_DEADLINE;

#pragma pack (1)
typedef struct {
  USB_CLASS_DEVICE_PATH       Fido;
  EFI_DEVICE_PATH_PROTOCOL    End;
} FIDO_USB_CLASS_DEVICE_PATH;

typedef struct {
  PCI_DEVICE_PATH             Pci;
  EFI_DEVICE_PATH_PROTOCOL    End;
} FIDO_PCI_CONTROLLER_DEVICE_PATH;
#pragma pack ()

STATIC FIDO_USB_CONTEXT  mFido;
STATIC UINTN             mFidoScanOffset;
STATIC UINTN             mFidoControllerOffset;
STATIC UINTN             mFidoRootBridgeOffset;
STATIC BOOLEAN           mFidoPciControllerConnected;

STATIC
VOID
FidoStartDeadline (
  OUT FIDO_DEADLINE  *Deadline
  )
{
  Deadline->ElapsedNs = 0;
  GetPerformanceCounterProperties (
    &Deadline->CounterStart,
    &Deadline->CounterEnd
    );
  Deadline->LastCounter = GetPerformanceCounter ();
}

STATIC
UINTN
FidoRemainingTimeoutMs (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  UINT64  CurrentCounter;
  UINT64  ElapsedTicks;
  UINT64  RemainingMs;

  CurrentCounter = GetPerformanceCounter ();
  if (Deadline->CounterStart < Deadline->CounterEnd) {
    ElapsedTicks = (CurrentCounter >= Deadline->LastCounter) ?
                   CurrentCounter - Deadline->LastCounter :
                   (Deadline->CounterEnd - Deadline->LastCounter) +
                   (CurrentCounter - Deadline->CounterStart) + 1;
  } else {
    ElapsedTicks = (CurrentCounter <= Deadline->LastCounter) ?
                   Deadline->LastCounter - CurrentCounter :
                   (Deadline->LastCounter - Deadline->CounterEnd) +
                   (Deadline->CounterStart - CurrentCounter) + 1;
  }

  Deadline->LastCounter = CurrentCounter;
  Deadline->ElapsedNs  += GetTimeInNanoSecond (ElapsedTicks);
  if (Deadline->ElapsedNs >= FIDO_CALL_TIMEOUT_NS) {
    return 0;
  }

  RemainingMs = (FIDO_CALL_TIMEOUT_NS - Deadline->ElapsedNs) /
                1000000ULL;
  return (UINTN)MIN (RemainingMs, FIDO_USB_REPORT_TIMEOUT_MS);
}

STATIC
EFI_STATUS
FidoUsbControlTransfer (
  IN     EFI_USB_IO_PROTOCOL     *UsbIo,
  IN     EFI_USB_DEVICE_REQUEST  *Request,
  IN OUT VOID                    *Data,
  IN     UINTN                   DataSize,
  IN OUT FIDO_DEADLINE           *Deadline
  )
{
  EFI_STATUS  Status;
  UINTN       Timeout;
  UINT32      UsbStatus;

  Timeout = FidoRemainingTimeoutMs (Deadline);
  Timeout = MIN (Timeout, FIDO_USB_CONTROL_TIMEOUT_MS);
  if (Timeout == 0) {
    return EFI_TIMEOUT;
  }

  UsbStatus = EFI_USB_ERR_SYSTEM;
  Status    = UsbIo->UsbControlTransfer (
                       UsbIo,
                       Request,
                       EfiUsbDataIn,
                       Timeout,
                       Data,
                       DataSize,
                       &UsbStatus
                       );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return (UsbStatus == EFI_USB_NOERROR) ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

STATIC FIDO_USB_CLASS_DEVICE_PATH  mFidoDevicePath = {
  {
    {
      MESSAGING_DEVICE_PATH,
      MSG_USB_CLASS_DP,
      { sizeof (USB_CLASS_DEVICE_PATH),    0 }
    },
    0xffff,
    0xffff,
    FIDO_HID_CLASS,
    FIDO_HID_SUBCLASS,
    FIDO_HID_PROTOCOL
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 }
  }
};

STATIC FIDO_PCI_CONTROLLER_DEVICE_PATH  mFidoControllerDevicePath = {
  {
    {
      HARDWARE_DEVICE_PATH,
      HW_PCI_DP,
      { sizeof (PCI_DEVICE_PATH),          0 }
    },
    FIDO_INTEL_CLIENT_XHCI_PCI_FUNCTION,
    FIDO_INTEL_CLIENT_XHCI_PCI_DEVICE
  },
  {
    END_DEVICE_PATH_TYPE,
    END_ENTIRE_DEVICE_PATH_SUBTYPE,
    { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 }
  }
};

STATIC
EFI_STATUS
FidoConnectIntelClientXhciController (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  EFI_HANDLE  *Handles;
  UINTN       HandleCount;
  UINTN       Index;
  EFI_STATUS  Status;

  if (mFidoPciControllerConnected) {
    return EFI_SUCCESS;
  }

  Handles = NULL;
  Status  = gBS->LocateHandleBuffer (
                   ByProtocol,
                   &gEfiPciRootBridgeIoProtocolGuid,
                   NULL,
                   &HandleCount,
                   &Handles
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (HandleCount == 0) {
    mFidoRootBridgeOffset = 0;
    if (Handles != NULL) {
      FreePool (Handles);
    }

    return EFI_NOT_FOUND;
  }

  Index                 = mFidoRootBridgeOffset % HandleCount;
  mFidoRootBridgeOffset = (Index + 1) % HandleCount;
  if (FidoRemainingTimeoutMs (Deadline) == 0) {
    FreePool (Handles);
    return EFI_TIMEOUT;
  }

  Status = gBS->ConnectController (
                  Handles[Index],
                  NULL,
                  (EFI_DEVICE_PATH_PROTOCOL *)&mFidoControllerDevicePath,
                  FALSE
                  );
  if (!EFI_ERROR (Status)) {
    mFidoPciControllerConnected = TRUE;
  }

  FreePool (Handles);
  return EFI_ERROR (Status) ? EFI_NOT_FOUND : EFI_SUCCESS;
}

STATIC
EFI_STATUS
FidoConnectUsbClassPath (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  EFI_STATUS           Status;
  EFI_HANDLE           *Handles;
  EFI_PCI_IO_PROTOCOL  *PciIo;
  UINTN                HandleCount;
  UINTN                Index;
  UINTN                ScanOffset;
  UINTN                StartIndex;
  UINT8                ClassCode[3];

  //
  // The gate runs before PlatformConsoleInit(), so PciBusDxe has not created
  // child PciIo handles on a fresh BDS path. Connect only the fixed 00:14.0
  // Intel client xHCI path; do not enumerate unrelated PCI devices before the
  // authentication boundary.
  //
  Status = FidoConnectIntelClientXhciController (Deadline);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handles = NULL;
  Status  = gBS->LocateHandleBuffer (
                   ByProtocol,
                   &gEfiPciIoProtocolGuid,
                   NULL,
                   &HandleCount,
                   &Handles
                   );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  if (HandleCount == 0) {
    mFidoControllerOffset = 0;
    if (Handles != NULL) {
      FreePool (Handles);
    }

    return EFI_NOT_FOUND;
  }

  StartIndex = mFidoControllerOffset % HandleCount;
  Status     = EFI_NOT_FOUND;
  for (ScanOffset = 0; ScanOffset < HandleCount; ScanOffset++) {
    Index  = (StartIndex + ScanOffset) % HandleCount;
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gEfiPciIoProtocolGuid,
                    (VOID **)&PciIo
                    );
    if (EFI_ERROR (Status)) {
      continue;
    }

    Status = PciIo->Pci.Read (
                          PciIo,
                          EfiPciIoWidthUint8,
                          PCI_CLASSCODE_OFFSET,
                          sizeof (ClassCode),
                          ClassCode
                          );
    if (EFI_ERROR (Status) ||
        (ClassCode[2] != PCI_CLASS_SERIAL) ||
        (ClassCode[1] != PCI_CLASS_SERIAL_USB))
    {
      Status = EFI_NOT_FOUND;
      continue;
    }

    mFidoControllerOffset = (Index + 1) % HandleCount;
    if (FidoRemainingTimeoutMs (Deadline) == 0) {
      Status = EFI_TIMEOUT;
      break;
    }

    Status = gBS->ConnectController (
                    Handles[Index],
                    NULL,
                    (EFI_DEVICE_PATH_PROTOCOL *)&mFidoDevicePath,
                    FALSE
                    );
    break;
  }

  if (Handles != NULL) {
    FreePool (Handles);
  }

  return EFI_ERROR (Status) ? EFI_NOT_FOUND : EFI_SUCCESS;
}

STATIC
UINT32
FidoReadBe32 (
  IN CONST UINT8  *Data
  )
{
  return ((UINT32)Data[0] << 24) | ((UINT32)Data[1] << 16) |
         ((UINT32)Data[2] << 8) | Data[3];
}

STATIC
VOID
FidoWriteBe32 (
  OUT UINT8   *Data,
  IN  UINT32  Value
  )
{
  Data[0] = (UINT8)(Value >> 24);
  Data[1] = (UINT8)(Value >> 16);
  Data[2] = (UINT8)(Value >> 8);
  Data[3] = (UINT8)Value;
}

STATIC
EFI_STATUS
FidoUsbTransfer (
  IN     UINT8          Endpoint,
  IN OUT UINT8          *Report,
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  EFI_STATUS  Status;
  UINTN       Length;
  UINTN       Timeout;
  UINT32      UsbStatus;

  Timeout = FidoRemainingTimeoutMs (Deadline);
  if (Timeout == 0) {
    return EFI_TIMEOUT;
  }

  Length = mFido.ReportSize;
  Status = mFido.UsbIo->UsbSyncInterruptTransfer (
                          mFido.UsbIo,
                          Endpoint,
                          Report,
                          &Length,
                          Timeout,
                          &UsbStatus
                          );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((UsbStatus != EFI_USB_NOERROR) || (Length != mFido.ReportSize)) {
    return EFI_DEVICE_ERROR;
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
FidoReportDescriptorMatches (
  IN     EFI_USB_IO_PROTOCOL  *UsbIo,
  IN     UINT8                InterfaceNumber,
  IN OUT FIDO_DEADLINE        *Deadline
  )
{
  UINT8                   Descriptor[FIDO_REPORT_DESCRIPTOR_MAX_SIZE];
  EFI_USB_HID_DESCRIPTOR  HidDescriptor;
  EFI_USB_DEVICE_REQUEST  Request;
  UINT16                  ReportDescriptorSize;
  EFI_STATUS              Status;
  UINTN                   Index;

  ZeroMem (&HidDescriptor, sizeof (HidDescriptor));
  ZeroMem (&Request, sizeof (Request));
  Request.RequestType = USB_HID_GET_DESCRIPTOR_REQ_TYPE;
  Request.Request     = USB_REQ_GET_DESCRIPTOR;
  Request.Value       = (UINT16)(USB_DESC_TYPE_HID << 8);
  Request.Index       = InterfaceNumber;
  Request.Length      = sizeof (HidDescriptor);
  Status              = FidoUsbControlTransfer (
                          UsbIo,
                          &Request,
                          &HidDescriptor,
                          sizeof (HidDescriptor),
                          Deadline
                          );
  if (EFI_ERROR (Status) ||
      (HidDescriptor.Length < sizeof (HidDescriptor)) ||
      (HidDescriptor.DescriptorType != USB_DESC_TYPE_HID) ||
      (HidDescriptor.NumDescriptors != 1) ||
      (HidDescriptor.HidClassDesc[0].DescriptorType != USB_DESC_TYPE_REPORT))
  {
    return FALSE;
  }

  ReportDescriptorSize = ReadUnaligned16 (
                           (CONST UINT16 *)&HidDescriptor.HidClassDesc[0].DescriptorLength
                           );
  if ((ReportDescriptorSize < 5) ||
      (ReportDescriptorSize > sizeof (Descriptor)))
  {
    return FALSE;
  }

  ZeroMem (Descriptor, sizeof (Descriptor));
  ZeroMem (&Request, sizeof (Request));
  Request.RequestType = USB_HID_GET_DESCRIPTOR_REQ_TYPE;
  Request.Request     = USB_REQ_GET_DESCRIPTOR;
  Request.Value       = (UINT16)(USB_DESC_TYPE_REPORT << 8);
  Request.Index       = InterfaceNumber;
  Request.Length      = ReportDescriptorSize;
  Status              = FidoUsbControlTransfer (
                          UsbIo,
                          &Request,
                          Descriptor,
                          ReportDescriptorSize,
                          Deadline
                          );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  //
  // FIDO authenticators advertise the 16-bit FIDO usage page followed by the
  // CTAPHID usage. Rejecting a generic HID interface keeps discovery scoped to
  // the one pre-OS device class the boot policy permits.
  //
  for (Index = 0; Index + 4 < ReportDescriptorSize; Index++) {
    if ((Descriptor[Index] == 0x06) &&
        (Descriptor[Index + 1] == (UINT8)FIDO_USAGE_PAGE) &&
        (Descriptor[Index + 2] == (UINT8)(FIDO_USAGE_PAGE >> 8)) &&
        (Descriptor[Index + 3] == 0x09) &&
        (Descriptor[Index + 4] == FIDO_USAGE_CTAPHID))
    {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
BOOLEAN
FidoInterfaceMatches (
  IN     EFI_USB_IO_PROTOCOL  *UsbIo,
  OUT    UINT8                *InEndpoint,
  OUT    UINT8                *OutEndpoint,
  OUT    UINT16               *ReportSize,
  IN OUT FIDO_DEADLINE        *Deadline
  )
{
  EFI_USB_DEVICE_DESCRIPTOR     Device;
  EFI_USB_INTERFACE_DESCRIPTOR  Interface;
  EFI_USB_ENDPOINT_DESCRIPTOR   Endpoint;
  EFI_STATUS                    Status;
  UINT8                         Index;

  ZeroMem (&Device, sizeof (Device));
  Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, &Device);
  if (EFI_ERROR (Status) || (Device.IdVendor != FIDO_YUBICO_VENDOR_ID)) {
    return FALSE;
  }

  ZeroMem (&Interface, sizeof (Interface));
  Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &Interface);
  if (EFI_ERROR (Status) ||
      (Interface.InterfaceClass != FIDO_HID_CLASS) ||
      (Interface.InterfaceSubClass != FIDO_HID_SUBCLASS) ||
      (Interface.InterfaceProtocol != FIDO_HID_PROTOCOL) ||
      !FidoReportDescriptorMatches (
         UsbIo,
         Interface.InterfaceNumber,
         Deadline
         ))
  {
    return FALSE;
  }

  *InEndpoint  = 0;
  *OutEndpoint = 0;
  *ReportSize  = 0;
  for (Index = 0; Index < Interface.NumEndpoints; Index++) {
    ZeroMem (&Endpoint, sizeof (Endpoint));
    Status = UsbIo->UsbGetEndpointDescriptor (UsbIo, Index, &Endpoint);
    if (EFI_ERROR (Status) ||
        ((Endpoint.Attributes & USB_ENDPOINT_TYPE_MASK) != USB_ENDPOINT_INTERRUPT))
    {
      continue;
    }

    if ((Endpoint.EndpointAddress & USB_ENDPOINT_DIR_IN) != 0) {
      *InEndpoint = Endpoint.EndpointAddress;
    } else {
      *OutEndpoint = Endpoint.EndpointAddress;
    }

    if ((*ReportSize == 0) || (Endpoint.MaxPacketSize < *ReportSize)) {
      *ReportSize = Endpoint.MaxPacketSize;
    }
  }

  return (*InEndpoint != 0) && (*OutEndpoint != 0) &&
         (*ReportSize == FIDO_REPORT_SIZE);
}

STATIC
EFI_STATUS
FidoReadDeviceBinding (
  IN  EFI_HANDLE           Handle,
  IN  EFI_USB_IO_PROTOCOL  *UsbIo,
  OUT UINT16               *VendorId,
  OUT UINT16               *ProductId,
  OUT UINT8                *InterfaceNumber,
  OUT UINT8                DevicePathDigest[SHA256_DIGEST_SIZE]
  )
{
  EFI_USB_DEVICE_DESCRIPTOR     Device;
  EFI_USB_INTERFACE_DESCRIPTOR  Interface;
  EFI_DEVICE_PATH_PROTOCOL      *DevicePath;
  UINTN                         DevicePathSize;
  EFI_STATUS                    Status;

  if ((Handle == NULL) || (UsbIo == NULL) || (VendorId == NULL) ||
      (ProductId == NULL) || (InterfaceNumber == NULL) ||
      (DevicePathDigest == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = UsbIo->UsbGetDeviceDescriptor (UsbIo, &Device);
  if (EFI_ERROR (Status) || (Device.IdVendor != FIDO_YUBICO_VENDOR_ID)) {
    return EFI_UNSUPPORTED;
  }

  Status = UsbIo->UsbGetInterfaceDescriptor (UsbIo, &Interface);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DevicePath = NULL;
  Status     = gBS->HandleProtocol (
                      Handle,
                      &gEfiDevicePathProtocolGuid,
                      (VOID **)&DevicePath
                      );
  if (EFI_ERROR (Status) || (DevicePath == NULL)) {
    return EFI_UNSUPPORTED;
  }

  DevicePathSize = GetDevicePathSize (DevicePath);
  if ((DevicePathSize == 0) ||
      (DevicePathSize > FIDO_DEVICE_PATH_MAX_SIZE) ||
      !Sha256HashAll (
         (CONST UINT8 *)DevicePath,
         DevicePathSize,
         DevicePathDigest
         ))
  {
    return EFI_UNSUPPORTED;
  }

  *VendorId        = Device.IdVendor;
  *ProductId       = Device.IdProduct;
  *InterfaceNumber = Interface.InterfaceNumber;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FidoFindInterface (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  EFI_HANDLE           *Handles;
  EFI_STATUS           Status;
  EFI_USB_IO_PROTOCOL  *UsbIo;
  UINTN                HandleCount;
  UINTN                Index;
  UINTN                ScanCount;
  UINTN                ScanOffset;
  UINTN                StartIndex;
  UINT8                InEndpoint;
  UINT8                OutEndpoint;
  UINT16               ReportSize;
  UINT16               VendorId;
  UINT16               ProductId;
  UINT8                InterfaceNumber;
  UINT8                DevicePathDigest[SHA256_DIGEST_SIZE];

  Handles     = NULL;
  HandleCount = 0;
  Status      = gBS->LocateHandleBuffer (
                       ByProtocol,
                       &gEfiUsbIoProtocolGuid,
                       NULL,
                       &HandleCount,
                       &Handles
                       );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (HandleCount == 0) {
    mFidoScanOffset = 0;
    if (Handles != NULL) {
      FreePool (Handles);
    }

    return EFI_NOT_FOUND;
  }

  // Bound each callback, but rotate the batch so every USB interface is
  // eventually examined even when non-FIDO handles precede the key.
  StartIndex = mFidoScanOffset % HandleCount;
  ScanCount  = MIN (HandleCount, FIDO_INTERFACE_SCAN_LIMIT);
  Status     = EFI_NOT_FOUND;
  for (ScanOffset = 0; ScanOffset < ScanCount; ScanOffset++) {
    Index = (StartIndex + ScanOffset) % HandleCount;
    UsbIo = NULL;
    if (EFI_ERROR (
          gBS->HandleProtocol (
                 Handles[Index],
                 &gEfiUsbIoProtocolGuid,
                 (VOID **)&UsbIo
                 )
          ) ||
        !FidoInterfaceMatches (
           UsbIo,
           &InEndpoint,
           &OutEndpoint,
           &ReportSize,
           Deadline
           ))
    {
      continue;
    }

    Status = FidoReadDeviceBinding (
               Handles[Index],
               UsbIo,
               &VendorId,
               &ProductId,
               &InterfaceNumber,
               DevicePathDigest
               );
    if (EFI_ERROR (Status)) {
      continue;
    }

    mFido.UsbIo           = UsbIo;
    mFido.Handle          = Handles[Index];
    mFido.InEndpoint      = InEndpoint;
    mFido.OutEndpoint     = OutEndpoint;
    mFido.ReportSize      = ReportSize;
    mFido.VendorId        = VendorId;
    mFido.ProductId       = ProductId;
    mFido.InterfaceNumber = InterfaceNumber;
    CopyMem (
      mFido.DevicePathDigest,
      DevicePathDigest,
      sizeof (mFido.DevicePathDigest)
      );
    Status          = EFI_SUCCESS;
    mFidoScanOffset = (Index + 1) % HandleCount;
    break;
  }

  if (EFI_ERROR (Status)) {
    mFidoScanOffset = (StartIndex + ScanCount) % HandleCount;
  }

  FreePool (Handles);
  return Status;
}

STATIC
EFI_STATUS
FidoCurrentDeviceStatus (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  EFI_USB_DEVICE_REQUEST  Request;
  EFI_USB_IO_PROTOCOL     *UsbIo;
  UINT8                   InEndpoint;
  UINT8                   OutEndpoint;
  UINT16                  ReportSize;
  UINT16                  VendorId;
  UINT16                  ProductId;
  UINT8                   InterfaceNumber;
  UINT8                   DevicePathDigest[SHA256_DIGEST_SIZE];
  UINT16                  DeviceStatus;
  EFI_STATUS              Status;

  UsbIo = NULL;
  if ((mFido.Handle == NULL) ||
      EFI_ERROR (
        gBS->HandleProtocol (
               mFido.Handle,
               &gEfiUsbIoProtocolGuid,
               (VOID **)&UsbIo
               )
        ) ||
      (UsbIo != mFido.UsbIo))
  {
    return EFI_NOT_FOUND;
  }

  ZeroMem (&Request, sizeof (Request));
  DeviceStatus        = 0;
  Request.RequestType = USB_DEV_GET_STATUS_REQ_TYPE_D;
  Request.Request     = USB_REQ_GET_STATUS;
  Request.Length      = sizeof (DeviceStatus);
  Status              = FidoUsbControlTransfer (
                          UsbIo,
                          &Request,
                          &DeviceStatus,
                          sizeof (DeviceStatus),
                          Deadline
                          );
  if (EFI_ERROR (Status) ||
      !FidoInterfaceMatches (
         UsbIo,
         &InEndpoint,
         &OutEndpoint,
         &ReportSize,
         Deadline
         ))
  {
    return EFI_NOT_READY;
  }

  if ((InEndpoint != mFido.InEndpoint) ||
      (OutEndpoint != mFido.OutEndpoint) ||
      (ReportSize != mFido.ReportSize))
  {
    return EFI_NOT_FOUND;
  }

  Status = FidoReadDeviceBinding (
             mFido.Handle,
             UsbIo,
             &VendorId,
             &ProductId,
             &InterfaceNumber,
             DevicePathDigest
             );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_READY;
  }

  return ((VendorId == mFido.VendorId) &&
          (ProductId == mFido.ProductId) &&
          (InterfaceNumber == mFido.InterfaceNumber) &&
          (CompareMem (
             DevicePathDigest,
             mFido.DevicePathDigest,
             sizeof (DevicePathDigest)
             ) == 0)) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC
EFI_STATUS
FidoSendMessage (
  IN     UINT32         Channel,
  IN     UINT8          Command,
  IN     CONST UINT8    *Message,
  IN     UINTN          MessageSize,
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  UINT8       Report[FIDO_REPORT_SIZE];
  UINTN       ChunkSize;
  UINTN       Offset;
  UINT8       Sequence;
  EFI_STATUS  Status;

  if ((Message == NULL) || (MessageSize > FIDO_MAX_MESSAGE_SIZE)) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Report, sizeof (Report));
  FidoWriteBe32 (Report, Channel);
  Report[4] = Command;
  Report[5] = (UINT8)(MessageSize >> 8);
  Report[6] = (UINT8)MessageSize;
  ChunkSize = MIN (MessageSize, FIDO_INIT_DATA_SIZE);
  CopyMem (&Report[7], Message, ChunkSize);
  Status = FidoUsbTransfer (mFido.OutEndpoint, Report, Deadline);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Offset   = ChunkSize;
  Sequence = 0;
  while (Offset < MessageSize) {
    ZeroMem (Report, sizeof (Report));
    FidoWriteBe32 (Report, Channel);
    Report[4] = Sequence++;
    ChunkSize = MIN (MessageSize - Offset, FIDO_CONT_DATA_SIZE);
    CopyMem (&Report[5], Message + Offset, ChunkSize);
    Status = FidoUsbTransfer (mFido.OutEndpoint, Report, Deadline);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Offset += ChunkSize;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FidoReceiveMessage (
  IN     UINT32         Channel,
  IN     UINT8          ExpectedCommand,
  OUT    UINT8          *Message,
  IN OUT UINTN          *MessageSize,
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  UINT8       Report[FIDO_REPORT_SIZE];
  UINTN       Capacity;
  UINTN       ChunkSize;
  UINTN       Offset;
  UINTN       TotalSize;
  UINT8       Sequence;
  EFI_STATUS  Status;
  UINTN       ReportCount;

  if ((Message == NULL) || (MessageSize == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Capacity    = *MessageSize;
  ReportCount = 0;
  do {
    if (ReportCount++ == FIDO_RECEIVE_REPORT_LIMIT) {
      return EFI_TIMEOUT;
    }

    ZeroMem (Report, sizeof (Report));
    Status = FidoUsbTransfer (mFido.InEndpoint, Report, Deadline);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (FidoReadBe32 (Report) != Channel) {
      continue;
    }

    if (Report[4] == FIDO_HID_KEEPALIVE) {
      return EFI_NOT_READY;
    }

    if (Report[4] == FIDO_HID_ERROR) {
      return EFI_DEVICE_ERROR;
    }
  } while (Report[4] != ExpectedCommand);

  TotalSize = ((UINTN)Report[5] << 8) | Report[6];
  if ((TotalSize > Capacity) || (TotalSize > FIDO_MAX_MESSAGE_SIZE)) {
    *MessageSize = TotalSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  ChunkSize = MIN (TotalSize, FIDO_INIT_DATA_SIZE);
  CopyMem (Message, &Report[7], ChunkSize);
  Offset   = ChunkSize;
  Sequence = 0;
  while (Offset < TotalSize) {
    ZeroMem (Report, sizeof (Report));
    Status = FidoUsbTransfer (mFido.InEndpoint, Report, Deadline);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if ((FidoReadBe32 (Report) != Channel) || (Report[4] != Sequence++)) {
      return EFI_PROTOCOL_ERROR;
    }

    ChunkSize = MIN (TotalSize - Offset, FIDO_CONT_DATA_SIZE);
    CopyMem (Message + Offset, &Report[5], ChunkSize);
    Offset += ChunkSize;
  }

  *MessageSize = TotalSize;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FidoTransaction (
  IN     UINT8          Command,
  IN     CONST UINT8    *Request,
  IN     UINTN          RequestSize,
  OUT    UINT8          *Response,
  IN OUT UINTN          *ResponseSize,
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  UINT8       BoundRequestDigest[1 + SHA256_DIGEST_SIZE];
  UINT8       RequestDigest[SHA256_DIGEST_SIZE];
  EFI_STATUS  Status;

  if ((Request == NULL) ||
      !Sha256HashAll (Request, RequestSize, RequestDigest))
  {
    return EFI_INVALID_PARAMETER;
  }

  BoundRequestDigest[0] = Command;
  CopyMem (&BoundRequestDigest[1], RequestDigest, sizeof (RequestDigest));
  if (!Sha256HashAll (
         BoundRequestDigest,
         sizeof (BoundRequestDigest),
         RequestDigest
         ))
  {
    return EFI_DEVICE_ERROR;
  }

  if (mFido.TransactionPending) {
    if ((mFido.PendingCommand != Command) ||
        (mFido.PendingHandle != mFido.Handle) ||
        (CompareMem (
           mFido.PendingRequestDigest,
           RequestDigest,
           sizeof (RequestDigest)
           ) != 0))
    {
      ZeroMem (&mFido, sizeof (mFido));
      return EFI_PROTOCOL_ERROR;
    }
  } else {
    Status = FidoSendMessage (
               mFido.Channel,
               Command,
               Request,
               RequestSize,
               Deadline
               );
    if (EFI_ERROR (Status)) {
      ZeroMem (&mFido, sizeof (mFido));
      return Status;
    }

    mFido.TransactionPending = TRUE;
    mFido.PendingCommand     = Command;
    mFido.PendingHandle      = mFido.Handle;
    CopyMem (
      mFido.PendingRequestDigest,
      RequestDigest,
      sizeof (RequestDigest)
      );
  }

  Status = FidoReceiveMessage (
             mFido.Channel,
             Command,
             Response,
             ResponseSize,
             Deadline
             );
  if ((Status == EFI_NOT_READY) || (Status == EFI_TIMEOUT)) {
    //
    // A user-presence transaction may legitimately outlive one bounded USB
    // poll.  Preserve its channel and request binding across callbacks.  The
    // next public operation validates the USB handle and device path before
    // receiving again; a confirmed removal still discards the complete state.
    //
    return EFI_NOT_READY;
  }

  if (EFI_ERROR (Status)) {
    ZeroMem (&mFido, sizeof (mFido));
    return Status;
  }

  mFido.TransactionPending = FALSE;
  mFido.PendingCommand     = 0;
  mFido.PendingHandle      = NULL;
  ZeroMem (
    mFido.PendingRequestDigest,
    sizeof (mFido.PendingRequestDigest)
    );
  return Status;
}

STATIC
EFI_STATUS
FidoReadYubicoDeviceIdentity (
  OUT UINT8             Identity[BOOT_KEY_DEVICE_IDENTITY_SIZE],
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  UINT8       EmptyRequest;
  UINT8       Response[256];
  UINT8       IdentityInput[sizeof (mFido.VendorId) + sizeof (UINT32)];
  UINTN       Offset;
  UINTN       ResponseSize;
  UINTN       TotalSize;
  UINTN       ValueSize;
  BOOLEAN     SerialFound;
  EFI_STATUS  Status;

  EmptyRequest = 0;
  ResponseSize = sizeof (Response);
  Status       = FidoTransaction (
                   FIDO_HID_YUBICO_GET_DEVICE_INFO,
                   &EmptyRequest,
                   0,
                   Response,
                   &ResponseSize,
                   Deadline
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (ResponseSize < 1) {
    return EFI_PROTOCOL_ERROR;
  }

  TotalSize = (UINTN)Response[0] + 1;
  if (TotalSize != ResponseSize) {
    return EFI_PROTOCOL_ERROR;
  }

  SerialFound = FALSE;
  Offset      = 1;
  while (Offset < TotalSize) {
    if (TotalSize - Offset < 2) {
      return EFI_PROTOCOL_ERROR;
    }

    ValueSize = Response[Offset + 1];
    if (ValueSize > TotalSize - Offset - 2) {
      return EFI_PROTOCOL_ERROR;
    }

    if (Response[Offset] == FIDO_YUBICO_DEVICE_INFO_SERIAL_TAG) {
      if (SerialFound || (ValueSize != sizeof (UINT32)) ||
          (FidoReadBe32 (&Response[Offset + 2]) == 0))
      {
        return EFI_SECURITY_VIOLATION;
      }

      WriteUnaligned16 ((UINT16 *)IdentityInput, mFido.VendorId);
      CopyMem (
        &IdentityInput[sizeof (mFido.VendorId)],
        &Response[Offset + 2],
        sizeof (UINT32)
        );
      SerialFound = TRUE;
    }

    Offset += 2 + ValueSize;
  }

  if (!SerialFound ||
      !Sha256HashAll (
         IdentityInput,
         sizeof (IdentityInput),
         Identity
         ))
  {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
FidoInitializeChannel (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  UINT8       Nonce[8];
  UINT8       Response[32];
  UINTN       ResponseSize;
  UINT64      RandomNonce;
  EFI_STATUS  Status;

  if (!GetRandomNumber64 (&RandomNonce)) {
    return EFI_DEVICE_ERROR;
  }

  CopyMem (Nonce, &RandomNonce, sizeof (Nonce));

  ResponseSize = sizeof (Response);
  Status       = FidoSendMessage (
                   FIDO_BROADCAST_CHANNEL,
                   FIDO_HID_INIT,
                   Nonce,
                   sizeof (Nonce),
                   Deadline
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = FidoReceiveMessage (
             FIDO_BROADCAST_CHANNEL,
             FIDO_HID_INIT,
             Response,
             &ResponseSize,
             Deadline
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if ((ResponseSize < 17) ||
      (CompareMem (Response, Nonce, sizeof (Nonce)) != 0))
  {
    return EFI_PROTOCOL_ERROR;
  }

  mFido.Channel = FidoReadBe32 (&Response[8]);
  return (mFido.Channel == 0) ? EFI_PROTOCOL_ERROR : EFI_SUCCESS;
}

STATIC
EFI_STATUS
FidoParseDerLength (
  IN  CONST UINT8  *Data,
  IN  UINTN        DataSize,
  OUT UINTN        *HeaderSize,
  OUT UINTN        *ValueSize
  )
{
  UINTN  LengthBytes;
  UINTN  Index;
  UINTN  Length;

  if ((Data == NULL) || (DataSize < 2) ||
      (HeaderSize == NULL) || (ValueSize == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  if ((Data[1] & 0x80) == 0) {
    *HeaderSize = 2;
    *ValueSize  = Data[1];
    return (*ValueSize <= DataSize - 2) ? EFI_SUCCESS : EFI_PROTOCOL_ERROR;
  }

  LengthBytes = Data[1] & 0x7f;
  if ((LengthBytes == 0) || (LengthBytes > sizeof (UINTN)) ||
      (LengthBytes > DataSize - 2))
  {
    return EFI_PROTOCOL_ERROR;
  }

  Length = 0;
  for (Index = 0; Index < LengthBytes; Index++) {
    if (Length > (MAX_UINTN >> 8)) {
      return EFI_PROTOCOL_ERROR;
    }

    Length = (Length << 8) | Data[2 + Index];
  }

  *HeaderSize = 2 + LengthBytes;
  *ValueSize  = Length;
  return (Length <= DataSize - *HeaderSize) ? EFI_SUCCESS : EFI_PROTOCOL_ERROR;
}

STATIC
EFI_STATUS
FidoParseDerSignature (
  IN  CONST UINT8  *Der,
  IN  UINTN        DerSize,
  OUT UINT8        Signature[BOOT_KEY_ES256_SIGNATURE_SIZE]
  )
{
  UINTN       HeaderSize;
  UINTN       EncodedIntegerSize;
  UINTN       IntegerSize;
  UINTN       SequenceSize;
  UINTN       Offset;
  UINTN       SourceOffset;
  UINTN       Component;
  EFI_STATUS  Status;

  if ((Der == NULL) || (Signature == NULL) || (DerSize < 8) || (Der[0] != 0x30)) {
    return EFI_PROTOCOL_ERROR;
  }

  Status = FidoParseDerLength (Der, DerSize, &HeaderSize, &SequenceSize);
  if (EFI_ERROR (Status) || (HeaderSize + SequenceSize != DerSize)) {
    return EFI_PROTOCOL_ERROR;
  }

  ZeroMem (Signature, BOOT_KEY_ES256_SIGNATURE_SIZE);
  Offset = HeaderSize;
  for (Component = 0; Component < 2; Component++) {
    if ((Offset >= DerSize) || (Der[Offset] != 0x02)) {
      return EFI_PROTOCOL_ERROR;
    }

    Status = FidoParseDerLength (
               &Der[Offset],
               DerSize - Offset,
               &HeaderSize,
               &IntegerSize
               );
    if (EFI_ERROR (Status) || (IntegerSize == 0) ||
        (IntegerSize > FIDO_DER_INTEGER_MAX_SIZE))
    {
      return EFI_PROTOCOL_ERROR;
    }

    EncodedIntegerSize = IntegerSize;
    SourceOffset       = Offset + HeaderSize;
    if (IntegerSize == FIDO_DER_INTEGER_MAX_SIZE) {
      // A 256-bit positive integer whose high bit is set requires exactly one
      // leading zero in DER.  Validate that padding before removing it.
      if ((Der[SourceOffset] != 0) ||
          ((Der[SourceOffset + 1] & 0x80) == 0))
      {
        return EFI_PROTOCOL_ERROR;
      }

      SourceOffset++;
      IntegerSize--;
    } else if (((Der[SourceOffset] & 0x80) != 0) ||
               ((IntegerSize > 1) && (Der[SourceOffset] == 0) &&
                ((Der[SourceOffset + 1] & 0x80) == 0)))
    {
      // Reject negative and non-minimally encoded DER integers.
      return EFI_PROTOCOL_ERROR;
    }

    CopyMem (
      &Signature[(Component * 32) + (32 - IntegerSize)],
      &Der[SourceOffset],
      IntegerSize
      );
    Offset += HeaderSize + EncodedIntegerSize;
  }

  return (Offset == DerSize) ? EFI_SUCCESS : EFI_PROTOCOL_ERROR;
}

STATIC
UINT16
FidoStatusWord (
  IN CONST UINT8  *Response,
  IN UINTN        ResponseSize
  )
{
  if ((Response == NULL) || (ResponseSize < 2)) {
    return 0;
  }

  return (UINT16)(((UINT16)Response[ResponseSize - 2] << 8) |
                  Response[ResponseSize - 1]);
}

STATIC
EFI_STATUS
FidoAuthenticateCredential (
  IN  CONST UINT8         Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN  CONST UINT8         RpIdHash[BOOT_KEY_RP_ID_HASH_SIZE],
  IN  CONST UINT8         *CredentialId,
  IN  UINTN               CredentialIdSize,
  IN  UINT8               Control,
  OUT BOOT_KEY_ASSERTION  *Assertion OPTIONAL,
  IN OUT FIDO_DEADLINE    *Deadline
  )
{
  UINT8       Request[7 + 32 + 32 + 1 + BOOT_KEY_CREDENTIAL_ID_MAX_SIZE + 2];
  UINT8       Response[FIDO_MAX_MESSAGE_SIZE];
  UINTN       PayloadSize;
  UINTN       ResponseSize;
  UINT16      StatusWord;
  EFI_STATUS  Status;

  if ((CredentialId == NULL) || (CredentialIdSize == 0) ||
      (CredentialIdSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE))
  {
    return EFI_INVALID_PARAMETER;
  }

  PayloadSize = 32 + 32 + 1 + CredentialIdSize;
  Request[0]  = 0;
  Request[1]  = FIDO_U2F_AUTHENTICATE;
  Request[2]  = Control;
  Request[3]  = 0;
  Request[4]  = 0;
  Request[5]  = (UINT8)(PayloadSize >> 8);
  Request[6]  = (UINT8)PayloadSize;
  CopyMem (&Request[7], Challenge, 32);
  CopyMem (&Request[39], RpIdHash, 32);
  Request[71] = (UINT8)CredentialIdSize;
  CopyMem (&Request[72], CredentialId, CredentialIdSize);
  Request[72 + CredentialIdSize] = 0;
  Request[73 + CredentialIdSize] = 0;

  ResponseSize = sizeof (Response);
  Status       = FidoTransaction (
                   FIDO_HID_MSG,
                   Request,
                   74 + CredentialIdSize,
                   Response,
                   &ResponseSize,
                   Deadline
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  StatusWord = FidoStatusWord (Response, ResponseSize);
  if (StatusWord == FIDO_U2F_SW_CONDITIONS_NOT_SATISFIED) {
    return EFI_NOT_READY;
  }

  if (StatusWord == FIDO_U2F_SW_WRONG_DATA) {
    return EFI_NOT_FOUND;
  }

  if ((StatusWord != FIDO_U2F_SW_NO_ERROR) ||
      (Control == FIDO_U2F_AUTH_CHECK_ONLY))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if ((Assertion == NULL) ||
      (ResponseSize <= FIDO_U2F_AUTH_FIXED_RESPONSE_SIZE + 2))
  {
    return EFI_PROTOCOL_ERROR;
  }

  ZeroMem (Assertion, sizeof (*Assertion));
  CopyMem (Assertion->AuthenticatorData, RpIdHash, BOOT_KEY_RP_ID_HASH_SIZE);
  CopyMem (
    &Assertion->AuthenticatorData[BOOT_KEY_RP_ID_HASH_SIZE],
    Response,
    FIDO_U2F_AUTH_FIXED_RESPONSE_SIZE
    );
  return FidoParseDerSignature (
           &Response[FIDO_U2F_AUTH_FIXED_RESPONSE_SIZE],
           ResponseSize - FIDO_U2F_AUTH_FIXED_RESPONSE_SIZE - 2,
           Assertion->Signature
           );
}

STATIC
EFI_STATUS
FidoPrepare (
  IN OUT FIDO_DEADLINE  *Deadline
  )
{
  EFI_STATUS  Status;

  if (mFido.Channel != 0) {
    Status = FidoCurrentDeviceStatus (Deadline);
    if (!EFI_ERROR (Status)) {
      if (mFido.DeviceIdentityValid) {
        return EFI_SUCCESS;
      }

      Status = FidoReadYubicoDeviceIdentity (
                 mFido.DeviceIdentity,
                 Deadline
                 );
      if (!EFI_ERROR (Status)) {
        mFido.DeviceIdentityValid = TRUE;
        return EFI_SUCCESS;
      }

      if (Status == EFI_NOT_READY) {
        return Status;
      }

      // A complete but invalid identity response is terminal for this
      // interface. Drop it and continue discovery from the next handle.
      ZeroMem (&mFido, sizeof (mFido));
    } else {
      // Any uncertain transport failure invalidates the channel, but only a
      // proven removal permits rediscovery in this callback.
      ZeroMem (&mFido, sizeof (mFido));
      if (Status != EFI_NOT_FOUND) {
        return EFI_NOT_READY;
      }
    }
  }

  ZeroMem (&mFido, sizeof (mFido));
  Status = FidoConnectUsbClassPath (Deadline);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_FOUND)) {
    return Status;
  }

  Status = FidoFindInterface (Deadline);
  if (EFI_ERROR (Status)) {
    return EFI_NOT_READY;
  }

  Status = FidoInitializeChannel (Deadline);
  if (EFI_ERROR (Status)) {
    ZeroMem (&mFido, sizeof (mFido));
    return Status;
  }

  Status = FidoReadYubicoDeviceIdentity (mFido.DeviceIdentity, Deadline);
  if (!EFI_ERROR (Status)) {
    mFido.DeviceIdentityValid = TRUE;
    return EFI_SUCCESS;
  }

  if (Status != EFI_NOT_READY) {
    // Do not select this interface again on the next bounded discovery pass.
    ZeroMem (&mFido, sizeof (mFido));
  }

  return EFI_NOT_READY;
}

EFI_STATUS
EFIAPI
BootKeyAuthenticatorPrepare (
  VOID
  )
{
  FIDO_DEADLINE  Deadline;

  FidoStartDeadline (&Deadline);
  return FidoPrepare (&Deadline);
}

EFI_STATUS
EFIAPI
BootKeyGetAssertion (
  IN  CONST CHAR8                *RpId,
  IN  CONST UINT8                ClientDataHash[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  IN  CONST UINT8        *CONST  *CredentialIds,
  IN  CONST UINTN                *CredentialIdSizes,
  IN  UINTN                      CredentialCount,
  OUT BOOT_KEY_ASSERTION         *Assertion
  )
{
  UINT8          RpIdHash[BOOT_KEY_RP_ID_HASH_SIZE];
  UINT8          Control;
  FIDO_DEADLINE  Deadline;
  EFI_STATUS     Status;
  UINTN          Index;

  FidoStartDeadline (&Deadline);

  if ((RpId == NULL) || (ClientDataHash == NULL) || (CredentialIds == NULL) ||
      (CredentialIdSizes == NULL) || (CredentialCount == 0) ||
      (CredentialCount > BOOT_KEY_MAX_ENROLLED_CREDENTIALS) ||
      (Assertion == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = (mFido.Channel == 0) ? EFI_NOT_FOUND :
           FidoCurrentDeviceStatus (&Deadline);
  if (EFI_ERROR (Status)) {
    ZeroMem (&mFido, sizeof (mFido));
    if (Status != EFI_NOT_FOUND) {
      return EFI_NOT_READY;
    }

    Status = FidoPrepare (&Deadline);
    if (Status != EFI_SUCCESS) {
      return EFI_NOT_READY;
    }

    // Resume authentication on the next bounded platform callback rather
    // than combining discovery and a complete transaction in one call.
    return EFI_NOT_READY;
  }

  if (!Sha256HashAll ((CONST UINT8 *)RpId, AsciiStrLen (RpId), RpIdHash)) {
    return EFI_DEVICE_ERROR;
  }

  Index   = 0;
  Control = FIDO_U2F_AUTH_CHECK_ONLY;
  if (mFido.AuthenticationPending) {
    if (mFido.PendingCredentialIndex >= CredentialCount) {
      ZeroMem (&mFido, sizeof (mFido));
      return EFI_SECURITY_VIOLATION;
    }

    Index   = mFido.PendingCredentialIndex;
    Control = mFido.PendingAuthenticationControl;
    if ((Control != FIDO_U2F_AUTH_CHECK_ONLY) &&
        (Control != FIDO_U2F_AUTH_ENFORCE_USER))
    {
      ZeroMem (&mFido, sizeof (mFido));
      return EFI_SECURITY_VIOLATION;
    }
  }

  Status = FidoAuthenticateCredential (
             ClientDataHash,
             RpIdHash,
             CredentialIds[Index],
             CredentialIdSizes[Index],
             Control,
             (Control == FIDO_U2F_AUTH_ENFORCE_USER) ? Assertion : NULL,
             &Deadline
             );
  if ((Control == FIDO_U2F_AUTH_CHECK_ONLY) &&
      (Status == EFI_NOT_READY) && !mFido.TransactionPending)
  {
    mFido.AuthenticationPending        = TRUE;
    mFido.PendingAuthenticationControl = FIDO_U2F_AUTH_ENFORCE_USER;
    mFido.PendingCredentialIndex       = Index;
    return EFI_NOT_READY;
  }

  if (Status == EFI_NOT_READY) {
    mFido.AuthenticationPending        = TRUE;
    mFido.PendingAuthenticationControl = Control;
    mFido.PendingCredentialIndex       = Index;
    return EFI_NOT_READY;
  }

  mFido.AuthenticationPending = FALSE;
  if ((Control == FIDO_U2F_AUTH_CHECK_ONLY) && (Status == EFI_NOT_FOUND)) {
    Index++;
    if (Index < CredentialCount) {
      mFido.AuthenticationPending        = TRUE;
      mFido.PendingAuthenticationControl = FIDO_U2F_AUTH_CHECK_ONLY;
      mFido.PendingCredentialIndex       = Index;
      return EFI_NOT_READY;
    }

    ZeroMem (&mFido, sizeof (mFido));
    return EFI_NOT_READY;
  }

  if (Status == EFI_SUCCESS) {
    Assertion->CredentialIdSize = CredentialIdSizes[Index];
    CopyMem (
      Assertion->CredentialId,
      CredentialIds[Index],
      CredentialIdSizes[Index]
      );
  }

  return Status;
}

EFI_STATUS
EFIAPI
BootKeyMakeCredential (
  IN  CONST CHAR8  *RpId,
  IN  CONST UINT8  Challenge[BOOT_KEY_CLIENT_DATA_HASH_SIZE],
  OUT UINT8        *CredentialId,
  IN OUT UINTN     *CredentialIdSize,
  OUT UINT8        PublicKey[FIDO_U2F_PUBLIC_KEY_SIZE],
  OUT UINT8        *AttestationCertificate,
  IN OUT UINTN     *AttestationCertificateSize,
  OUT UINT8        Signature[BOOT_KEY_ES256_SIGNATURE_SIZE]
  )
{
  UINT8          Request[7 + 64 + 2];
  UINT8          Response[FIDO_MAX_MESSAGE_SIZE];
  UINT8          RpIdHash[BOOT_KEY_RP_ID_HASH_SIZE];
  UINTN          CertificateHeaderSize;
  UINTN          CertificateSize;
  UINTN          KeyHandleSize;
  UINTN          Offset;
  UINTN          ResponseSize;
  FIDO_DEADLINE  Deadline;
  EFI_STATUS     Status;

  FidoStartDeadline (&Deadline);

  if ((RpId == NULL) || (Challenge == NULL) ||
      (CredentialId == NULL) || (CredentialIdSize == NULL) ||
      (PublicKey == NULL) || (AttestationCertificate == NULL) ||
      (AttestationCertificateSize == NULL) || (Signature == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  Status = (mFido.Channel == 0) ? EFI_NOT_FOUND :
           FidoCurrentDeviceStatus (&Deadline);
  if (EFI_ERROR (Status)) {
    ZeroMem (&mFido, sizeof (mFido));
    if (Status != EFI_NOT_FOUND) {
      return EFI_NOT_READY;
    }

    Status = FidoPrepare (&Deadline);
    if (Status != EFI_SUCCESS) {
      return EFI_NOT_READY;
    }

    // Resume provisioning on the next bounded platform callback rather than
    // combining discovery and a complete transaction in one call.
    return EFI_NOT_READY;
  }

  if (!Sha256HashAll ((CONST UINT8 *)RpId, AsciiStrLen (RpId), RpIdHash)) {
    return EFI_DEVICE_ERROR;
  }

  Request[0] = 0;
  Request[1] = FIDO_U2F_REGISTER;
  Request[2] = 0;
  Request[3] = 0;
  Request[4] = 0;
  Request[5] = 0;
  Request[6] = 64;
  CopyMem (&Request[7], Challenge, 32);
  CopyMem (&Request[39], RpIdHash, 32);
  Request[71] = 0;
  Request[72] = 0;

  ResponseSize = sizeof (Response);
  Status       = FidoTransaction (
                   FIDO_HID_MSG,
                   Request,
                   sizeof (Request),
                   Response,
                   &ResponseSize,
                   &Deadline
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (FidoStatusWord (Response, ResponseSize) ==
      FIDO_U2F_SW_CONDITIONS_NOT_SATISFIED)
  {
    return EFI_NOT_READY;
  }

  if ((FidoStatusWord (Response, ResponseSize) != FIDO_U2F_SW_NO_ERROR) ||
      (ResponseSize < 1 + FIDO_U2F_PUBLIC_KEY_SIZE + 1 + 2) ||
      (Response[0] != FIDO_U2F_REGISTER_RESERVED))
  {
    return EFI_SECURITY_VIOLATION;
  }

  CopyMem (PublicKey, &Response[1], FIDO_U2F_PUBLIC_KEY_SIZE);
  KeyHandleSize = Response[1 + FIDO_U2F_PUBLIC_KEY_SIZE];
  Offset        = 1 + FIDO_U2F_PUBLIC_KEY_SIZE + 1;
  if ((KeyHandleSize == 0) ||
      (KeyHandleSize > BOOT_KEY_CREDENTIAL_ID_MAX_SIZE) ||
      (KeyHandleSize > ResponseSize - Offset - 2))
  {
    return EFI_PROTOCOL_ERROR;
  }

  if (*CredentialIdSize < KeyHandleSize) {
    *CredentialIdSize = KeyHandleSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (CredentialId, &Response[Offset], KeyHandleSize);
  *CredentialIdSize = KeyHandleSize;
  Offset           += KeyHandleSize;

  if ((Offset >= ResponseSize - 2) || (Response[Offset] != 0x30)) {
    return EFI_PROTOCOL_ERROR;
  }

  Status = FidoParseDerLength (
             &Response[Offset],
             ResponseSize - Offset - 2,
             &CertificateHeaderSize,
             &CertificateSize
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  CertificateSize += CertificateHeaderSize;
  if ((*AttestationCertificateSize < CertificateSize) ||
      (CertificateSize > ResponseSize - Offset - 2))
  {
    *AttestationCertificateSize = CertificateSize;
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (AttestationCertificate, &Response[Offset], CertificateSize);
  *AttestationCertificateSize = CertificateSize;
  Offset                     += CertificateSize;

  return FidoParseDerSignature (
           &Response[Offset],
           ResponseSize - Offset - 2,
           Signature
           );
}

EFI_STATUS
EFIAPI
BootKeyGetAuthenticatorIdentity (
  OUT UINT8  Identity[BOOT_KEY_DEVICE_IDENTITY_SIZE]
  )
{
  FIDO_DEADLINE  Deadline;
  UINT8          CurrentIdentity[BOOT_KEY_DEVICE_IDENTITY_SIZE];
  EFI_STATUS     Status;

  FidoStartDeadline (&Deadline);
  if ((Identity == NULL) ||
      !mFido.DeviceIdentityValid ||
      EFI_ERROR (FidoCurrentDeviceStatus (&Deadline)))
  {
    return EFI_NOT_READY;
  }

  Status = FidoReadYubicoDeviceIdentity (CurrentIdentity, &Deadline);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (CompareMem (
        CurrentIdentity,
        mFido.DeviceIdentity,
        sizeof (CurrentIdentity)
        ) != 0)
  {
    ZeroMem (&mFido, sizeof (mFido));
    return EFI_SECURITY_VIOLATION;
  }

  CopyMem (Identity, CurrentIdentity, BOOT_KEY_DEVICE_IDENTITY_SIZE);
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyAuthenticatorRequireRemoval (
  VOID
  )
{
  FIDO_DEADLINE  Deadline;
  EFI_STATUS     Status;

  FidoStartDeadline (&Deadline);
  if (mFido.UsbIo == NULL) {
    return EFI_SUCCESS;
  }

  Status = FidoCurrentDeviceStatus (&Deadline);
  if (Status != EFI_NOT_FOUND) {
    return EFI_NOT_READY;
  }

  ZeroMem (&mFido, sizeof (mFido));
  return EFI_SUCCESS;
}
