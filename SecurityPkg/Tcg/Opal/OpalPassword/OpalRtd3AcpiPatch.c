/** @file
  Disable storage runtime D3 (RTD3) for Opal-managed NVMe drives.

  When a storage device uses Opal locking, the device may require an unlock
  sequence after power is removed. If platform firmware enables Runtime D3cold
  (RTD3) for the PCIe root port that hosts the NVMe controller, S3 resume can
  fail on platforms where the UEFI payload does not run on resume.

  Platforms commonly expose a per-root-port ACPI control named RD3C to enable
  or disable storage RTD3. This module locates the ACPI scope for the root port
  that hosts an Opal-enabled NVMe drive and patches RD3C to 0 at boot.

SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "OpalDriver.h"

#include <IndustryStandard/Acpi.h>
#include <IndustryStandard/AcpiAml.h>
#include <Protocol/AcpiSystemDescriptionTable.h>

#define INTEL_PCH_PCIE_LCAP_PN  0x4F

STATIC UINT32  mPatchedRtd3RootPortMask;

STATIC
BOOLEAN
IsNvmeDevicePath (
  IN EFI_DEVICE_PATH_PROTOCOL  *DevicePath
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *Node;

  if (DevicePath == NULL) {
    return FALSE;
  }

  Node = DevicePath;
  while (!IsDevicePathEnd (Node)) {
    if ((Node->Type == MESSAGING_DEVICE_PATH) &&
        (Node->SubType == MSG_NVME_NAMESPACE_DP))
    {
      return TRUE;
    }

    Node = NextDevicePathNode (Node);
  }

  return FALSE;
}

STATIC
EFI_STATUS
GetRootPortBdfFromDevicePath (
  IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath,
  OUT UINT8                     *Device,
  OUT UINT8                     *Function
  )
{
  EFI_DEVICE_PATH_PROTOCOL  *Node;
  PCI_DEVICE_PATH           *PciDevPath;

  if ((DevicePath == NULL) || (Device == NULL) || (Function == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Node = DevicePath;
  while (!IsDevicePathEnd (Node)) {
    if ((Node->Type == HARDWARE_DEVICE_PATH) && (Node->SubType == HW_PCI_DP)) {
      PciDevPath = (PCI_DEVICE_PATH *)Node;
      *Device    = PciDevPath->Device;
      *Function  = PciDevPath->Function;
      return EFI_SUCCESS;
    }

    Node = NextDevicePathNode (Node);
  }

  return EFI_NOT_FOUND;
}

STATIC
VOID
UpdateAcpiTableChecksum (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Table
  )
{
  UINT8   Sum;
  UINT32  Index;
  UINT8   *Bytes;

  if ((Table == NULL) || (Table->Length < sizeof (*Table))) {
    return;
  }

  Bytes           = (UINT8 *)Table;
  Table->Checksum = 0;

  Sum = 0;
  for (Index = 0; Index < Table->Length; Index++) {
    Sum = (UINT8)(Sum + Bytes[Index]);
  }

  Table->Checksum = (UINT8)(0 - Sum);
}

STATIC
UINT32
GetAmlPkgLength (
  IN  CONST UINT8   *Buffer,
  IN  UINT32        BufferLen,
  OUT       UINT32  *PkgLength
  )
{
  UINT8   LeadByte;
  UINT8   ByteCount;
  UINT32  Length;
  UINT32  Index;

  if ((Buffer == NULL) || (PkgLength == NULL) || (BufferLen == 0)) {
    return 0;
  }

  LeadByte  = Buffer[0];
  ByteCount = (LeadByte >> 6) & 0x03U;

  if (ByteCount == 0) {
    *PkgLength = LeadByte;
    return 1;
  }

  if (1 + ByteCount > BufferLen) {
    return 0;
  }

  Length = (LeadByte & 0x0FU);
  for (Index = 0; Index < ByteCount; Index++) {
    Length |= ((UINT32)Buffer[1 + Index]) << (4 + (Index * 8));
  }

  *PkgLength = Length;
  return 1 + ByteCount;
}

STATIC
BOOLEAN
PatchRd3cInScope (
  IN EFI_ACPI_DESCRIPTION_HEADER  *Table,
  IN CONST UINT8                  *ScopeName,
  IN UINT32                       ScopeNameLen
  )
{
  UINT8   *Aml;
  UINT32  AmlLen;
  UINT32  Pos;

  if ((Table == NULL) ||
      (ScopeName == NULL) ||
      (ScopeNameLen == 0) ||
      (Table->Length <= sizeof (EFI_ACPI_DESCRIPTION_HEADER)))
  {
    return FALSE;
  }

  Aml    = (UINT8 *)Table + sizeof (EFI_ACPI_DESCRIPTION_HEADER);
  AmlLen = Table->Length - (UINT32)sizeof (EFI_ACPI_DESCRIPTION_HEADER);

  for (Pos = 0; Pos + 2 < AmlLen; Pos++) {
    UINT32  PkgLen;
    UINT32  PkgLenBytes;
    UINT32  PkgStart;
    UINT32  NameStart;
    UINT32  TermListStart;
    UINT32  PkgEnd;
    UINT32  InnerPos;

    if (Aml[Pos] != AML_SCOPE_OP) {
      continue;
    }

    PkgStart    = Pos + 1;
    PkgLenBytes = GetAmlPkgLength (&Aml[PkgStart], AmlLen - PkgStart, &PkgLen);
    if (PkgLenBytes == 0) {
      continue;
    }

    if (PkgStart + PkgLen > AmlLen) {
      continue;
    }

    NameStart = PkgStart + PkgLenBytes;
    if (NameStart + ScopeNameLen > AmlLen) {
      continue;
    }

    if (CompareMem (&Aml[NameStart], ScopeName, ScopeNameLen) != 0) {
      continue;
    }

    TermListStart = NameStart + ScopeNameLen;
    PkgEnd        = PkgStart + PkgLen;
    if (TermListStart >= PkgEnd) {
      continue;
    }

    for (InnerPos = TermListStart; InnerPos + 1 + 4 < PkgEnd; InnerPos++) {
      UINT32  ValuePos;

      if (Aml[InnerPos] != AML_NAME_OP) {
        continue;
      }

      if (CompareMem (&Aml[InnerPos + 1], "RD3C", 4) != 0) {
        continue;
      }

      ValuePos = InnerPos + 1 + 4;
      if (ValuePos >= PkgEnd) {
        continue;
      }

      switch (Aml[ValuePos]) {
        case AML_ZERO_OP:
          return TRUE;
        case AML_ONE_OP:
          Aml[ValuePos] = AML_ZERO_OP;
          return TRUE;
        case AML_BYTE_PREFIX:
          if (ValuePos + 1 < PkgEnd) {
            Aml[ValuePos + 1] = 0;
            return TRUE;
          }

          return FALSE;
        case AML_WORD_PREFIX:
          if (ValuePos + 2 < PkgEnd) {
            Aml[ValuePos + 1] = 0;
            Aml[ValuePos + 2] = 0;
            return TRUE;
          }

          return FALSE;
        case AML_DWORD_PREFIX:
          if (ValuePos + 4 < PkgEnd) {
            ZeroMem (&Aml[ValuePos + 1], 4);
            return TRUE;
          }

          return FALSE;
        case AML_QWORD_PREFIX:
          if (ValuePos + 8 < PkgEnd) {
            ZeroMem (&Aml[ValuePos + 1], 8);
            return TRUE;
          }

          return FALSE;
        default:
          return FALSE;
      }
    }

    return FALSE;
  }

  return FALSE;
}

STATIC
VOID
DisableStorageRtd3ForRootPort (
  IN UINT8  RootPortDevice,
  IN UINT8  RootPortFunction
  )
{
  EFI_STATUS            Status;
  EFI_ACPI_SDT_PROTOCOL *AcpiSdt;
  UINT8                 PortNumber;
  UINT32                Index;
  BOOLEAN               Patched;
  CHAR8                 RpName[5];
  UINT8                 ScopeSbPci0[1 + 1 + 1 + 4 + 4 + 4];
  UINT8                 ScopeSbPc00[1 + 1 + 1 + 4 + 4 + 4];

  PortNumber = PciRead8 (PCI_LIB_ADDRESS (0, RootPortDevice, RootPortFunction, INTEL_PCH_PCIE_LCAP_PN));
  if (PortNumber == 0) {
    return;
  }

  if ((PortNumber <= 32) &&
      ((mPatchedRtd3RootPortMask & (1U << (PortNumber - 1))) != 0))
  {
    return;
  }

  AsciiSPrint (RpName, sizeof (RpName), "RP%02u", PortNumber);

  ScopeSbPci0[0] = AML_ROOT_CHAR;
  ScopeSbPci0[1] = AML_MULTI_NAME_PREFIX;
  ScopeSbPci0[2] = 0x03;
  CopyMem (&ScopeSbPci0[3], "_SB_", 4);
  CopyMem (&ScopeSbPci0[7], "PCI0", 4);
  CopyMem (&ScopeSbPci0[11], RpName, 4);

  ScopeSbPc00[0] = AML_ROOT_CHAR;
  ScopeSbPc00[1] = AML_MULTI_NAME_PREFIX;
  ScopeSbPc00[2] = 0x03;
  CopyMem (&ScopeSbPc00[3], "_SB_", 4);
  CopyMem (&ScopeSbPc00[7], "PC00", 4);
  CopyMem (&ScopeSbPc00[11], RpName, 4);

  Status = gBS->LocateProtocol (&gEfiAcpiSdtProtocolGuid, NULL, (VOID **)&AcpiSdt);
  if (EFI_ERROR (Status) || (AcpiSdt == NULL)) {
    return;
  }

  Patched = FALSE;
  for (Index = 0; ; Index++) {
    EFI_ACPI_SDT_HEADER          *Table;
    EFI_ACPI_DESCRIPTION_HEADER  *TableHeader;
    UINTN                        TableKey;
    UINT32                       Version;

    Status = AcpiSdt->GetAcpiTable (Index, &Table, &Version, &TableKey);
    if (EFI_ERROR (Status)) {
      break;
    }

    TableHeader = (EFI_ACPI_DESCRIPTION_HEADER *)Table;
    if ((TableHeader->Signature != SIGNATURE_32 ('S', 'S', 'D', 'T')) &&
        (TableHeader->Signature != SIGNATURE_32 ('D', 'S', 'D', 'T')))
    {
      continue;
    }

    if (PatchRd3cInScope (TableHeader, ScopeSbPci0, sizeof (ScopeSbPci0)) ||
        PatchRd3cInScope (TableHeader, ScopeSbPc00, sizeof (ScopeSbPc00)))
    {
      UpdateAcpiTableChecksum (TableHeader);
      Patched = TRUE;
    }
  }

  if (Patched) {
    if (PortNumber <= 32) {
      mPatchedRtd3RootPortMask |= (1U << (PortNumber - 1));
    }

    DEBUG ((DEBUG_INFO, "OpalPassword: Disabled RTD3 (RD3C=0) for %a\n", RpName));
  }
}

VOID
OpalDisableStorageRtd3IfOpalEnabled (
  IN OPAL_DRIVER_DEVICE  *Dev
  )
{
  EFI_STATUS  Status;
  UINT8       RootPortDevice;
  UINT8       RootPortFunction;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;

  if (Dev == NULL) {
    return;
  }

  if (!Dev->OpalDisk.LockingFeature.LockingEnabled) {
    return;
  }

  DevicePath = Dev->OpalDisk.OpalDevicePath;
  if (DevicePath == NULL) {
    DevicePath = Dev->OpalDevicePath;
  }

  if (!IsNvmeDevicePath (DevicePath)) {
    return;
  }

  Status = GetRootPortBdfFromDevicePath (DevicePath, &RootPortDevice, &RootPortFunction);
  if (EFI_ERROR (Status)) {
    return;
  }

  DisableStorageRtd3ForRootPort (RootPortDevice, RootPortFunction);
}
