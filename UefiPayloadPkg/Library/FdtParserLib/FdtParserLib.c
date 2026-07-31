/** @file
  Copyright (c) 2024, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiPei.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/IoLib.h>
#include <Guid/MemoryAllocationHob.h>
#include <Guid/DebugPrintErrorLevel.h>
#include <Guid/SerialPortInfoGuid.h>
#include <Guid/MemoryMapInfoGuid.h>
#include <Guid/AcpiBoardInfoGuid.h>
#include <Guid/GraphicsInfoHob.h>
#include <Guid/SmmStoreInfoGuid.h>
#include <Guid/UniversalPayloadBase.h>
#include <UniversalPayload/SmbiosTable.h>
#include <UniversalPayload/AcpiTable.h>
#include <UniversalPayload/UniversalPayload.h>
#include <UniversalPayload/ExtraData.h>
#include <UniversalPayload/SerialPortInfo.h>
#include <UniversalPayload/DeviceTree.h>
#include <UniversalPayload/PciRootBridges.h>
#include <IndustryStandard/SmBios.h>
#include <Library/PrintLib.h>
#include <Library/FdtLib.h>
#include <Protocol/PciHostBridgeResourceAllocation.h>
#include <Protocol/PciIo.h>
#include <Guid/PciSegmentInfoGuid.h>
#include <Coreboot.h>

typedef enum {
  ReservedMemory = 1,
  Memory,
  FrameBuffer,
  PciRootBridge,
  Options,
  SerialPort,
  DoNothing
} FDT_NODE_TYPE;

#define MEMORY_ATTRIBUTE_DEFAULT  (EFI_RESOURCE_ATTRIBUTE_PRESENT | \
                                   EFI_RESOURCE_ATTRIBUTE_INITIALIZED | \
                                   EFI_RESOURCE_ATTRIBUTE_TESTED | \
                                   EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE | \
                                   EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE | \
                                   EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE | \
                                   EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE)

#define ROOT_BRIDGE_SUPPORTS_DEFAULT  (EFI_PCI_IO_ATTRIBUTE_VGA_IO_16 | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_PALETTE_IO_16 | \
                                       EFI_PCI_IO_ATTRIBUTE_ISA_IO_16 | \
                                       EFI_PCI_IO_ATTRIBUTE_IDE_PRIMARY_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_MEMORY | \
                                       EFI_PCI_IO_ATTRIBUTE_VGA_PALETTE_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_ISA_IO | \
                                       EFI_PCI_IO_ATTRIBUTE_ISA_MOTHERBOARD_IO)

#define UPL_ALIGN_DOWN(Addr)  ((UINT64)(Addr) & ~(UINT64)(EFI_PAGE_SIZE - 1))

extern VOID                         *mHobList;
UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES  *mPciRootBridgeInfo = NULL;
INT32                               mNode[0x500]        = { 0 };
UINT32                              mNodeIndex          = 0;
UPL_PCI_SEGMENT_INFO_HOB            *mUplPciSegmentInfoHob;

/**
  Build a Handoff Information Table HOB

  This function initializes a HOB region from EfiMemoryBegin to
  EfiMemoryTop. And EfiFreeMemoryBottom and EfiFreeMemoryTop should
  be inside the HOB region.

  @param[in] EfiMemoryBottom       Total memory start address
  @param[in] EfiMemoryTop          Total memory end address.
  @param[in] EfiFreeMemoryBottom   Free memory start address
  @param[in] EfiFreeMemoryTop      Free memory end address.

  @return   The pointer to the handoff HOB table.

**/
EFI_HOB_HANDOFF_INFO_TABLE *
EFIAPI
HobConstructor (
  IN VOID  *EfiMemoryBottom,
  IN VOID  *EfiMemoryTop,
  IN VOID  *EfiFreeMemoryBottom,
  IN VOID  *EfiFreeMemoryTop
  );

/**
  It will record the memory node initialized.

  @param[in]  Node           memory node is going to parsing.
**/
VOID
RecordMemoryNode (
  INT32  Node
  )
{
  DEBUG ((DEBUG_INFO, "\n RecordMemoryNode  %x , mNodeIndex :%x  \n", Node, mNodeIndex));
  if (mNodeIndex >= (sizeof (mNode) / sizeof (mNode[0]))) {
    DEBUG ((DEBUG_ERROR, "  Too many reserved-memory nodes\n"));
    return;
  }

  mNode[mNodeIndex] = Node;
  mNodeIndex++;
}

/**
  Check the memory node if initialized.

  @param[in]  Node           memory node is going to parsing.

  @return TRUE               memory node was initialized. don't parse it again.
  @return FALSE              memory node wasn't initialized, go to parse it.
**/
BOOLEAN
CheckMemoryNodeIfInit (
  INT32  Node
  )
{
  UINT32  i;

  for (i = 0; i < mNodeIndex; i++) {
    if (mNode[i] == Node) {
      return TRUE;
    }
  }

  return FALSE;
}

/**
  It will check device node from FDT.

  @param[in]  NodeString        Device node name string.
  @param[in]  Depth             Check layer of Device node, only parse the 1st layer

  @return FDT_NODE_TYPE         what type of the device node.
**/
FDT_NODE_TYPE
CheckNodeType (
  CHAR8  *NodeString,
  INT32  Depth
  )
{
  DEBUG ((DEBUG_INFO, "\n CheckNodeType  %a   \n", NodeString));
  if ((AsciiStrCmp (NodeString, "serial") == 0) ||
      (AsciiStrnCmp (NodeString, "serial@", AsciiStrLen ("serial@")) == 0)) {
    return SerialPort;
  } else if (AsciiStrnCmp (NodeString, "reserved-memory", AsciiStrLen ("reserved-memory")) == 0) {
    return ReservedMemory;
  } else if (AsciiStrnCmp (NodeString, "memory@", AsciiStrLen ("memory@")) == 0) {
    return Memory;
  } else if (AsciiStrnCmp (NodeString, "framebuffer@", AsciiStrLen ("framebuffer@")) == 0) {
    return FrameBuffer;
  } else if (AsciiStrnCmp (NodeString, "pci-rb", AsciiStrLen ("pci-rb")) == 0) {
    return PciRootBridge;
  } else if (AsciiStrCmp (NodeString, "options") == 0) {
    return Options;
  } else {
    return DoNothing;
  }
}

/**
  It will ParseMemory node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  SubNode           first node of the PCI root bridge node.
**/
VOID
ParseMemory (
  IN VOID   *Fdt,
  IN INT32  Node
  )
{
  UINT32              Attribute;
  UINT8               ECCAttribute;
  UINT32              ECCData, ECCData2;
  INT32               Property;
  CONST FDT_PROPERTY  *PropertyPtr;
  INT32               TempLen;
  CONST CHAR8         *TempStr;
  UINT64              *Data64;
  UINT32              *Data32;
  UINT64              StartAddress;
  UINT64              NumberOfBytes;

  Attribute    = MEMORY_ATTRIBUTE_DEFAULT;
  ECCAttribute = 0;
  ECCData      = ECCData2 = 0;
  for (Property = FdtFirstPropertyOffset (Fdt, Node); Property >= 0; Property = FdtNextPropertyOffset (Fdt, Property)) {
    PropertyPtr = FdtGetPropertyByOffset (Fdt, Property, &TempLen);
    TempStr     = FdtGetString (Fdt, Fdt32ToCpu (PropertyPtr->NameOffset), NULL);
    if (AsciiStrCmp (TempStr, "reg") == 0) {
      Data64        = (UINT64 *)(PropertyPtr->Data);
      StartAddress  = Fdt64ToCpu (ReadUnaligned64 (Data64));
      NumberOfBytes = Fdt64ToCpu (ReadUnaligned64 (Data64 + 1));
    } else if (AsciiStrCmp (TempStr, "ecc-detection-bits") == 0) {
      Data32  = (UINT32 *)(PropertyPtr->Data);
      ECCData = Fdt32ToCpu (*Data32);
    } else if (AsciiStrCmp (TempStr, "ecc-correction-bits") == 0) {
      Data32   = (UINT32 *)(PropertyPtr->Data);
      ECCData2 = Fdt32ToCpu (*Data32);
    }
  }

  if (ECCData == ECCData2) {
    if (ECCData == 1) {
      ECCAttribute = EFI_RESOURCE_ATTRIBUTE_SINGLE_BIT_ECC;
    } else if (ECCData == 2) {
      ECCAttribute = EFI_RESOURCE_ATTRIBUTE_MULTIPLE_BIT_ECC;
    }
  }

  if (ECCAttribute != 0) {
    Attribute |= ECCAttribute;
  }

  BuildResourceDescriptorHob (EFI_RESOURCE_SYSTEM_MEMORY, Attribute, StartAddress, NumberOfBytes);
}

/**
  It will ParseReservedMemory node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  SubNode           first node of the PCI root bridge node.
**/
VOID
ParseReservedMemory (
  IN VOID   *Fdt,
  IN INT32  Node
  )
{
  INT32                           SubNode;
  INT32                           TempLen;
  CONST CHAR8                     *TempStr;
  CONST FDT_PROPERTY              *PropertyPtr;
  UINT64                          *Data64;
  UINT64                          StartAddress;
  UINT64                          NumberOfBytes;
  UNIVERSAL_PAYLOAD_ACPI_TABLE    *PlatformAcpiTable;
  UNIVERSAL_PAYLOAD_SMBIOS_TABLE  *SmbiosTable;
  FDT_NODE_HEADER                 *NodePtr;
  UINT32                          Attribute;
  EFI_GUID                        *SmbiosTableGuid;

  PlatformAcpiTable = NULL;

  for (SubNode = FdtFirstSubnode (Fdt, Node); SubNode >= 0; SubNode = FdtNextSubnode (Fdt, SubNode)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + SubNode + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    DEBUG ((DEBUG_INFO, "\n      SubNode(%08X)  %a", SubNode, NodePtr->Name));
    PropertyPtr = FdtGetProperty (Fdt, SubNode, "reg", &TempLen);
    if ((PropertyPtr == NULL) || (TempLen < (INT32)(2 * sizeof (UINT64)))) {
      DEBUG ((DEBUG_WARN, "  reserved-memory node has no valid reg property\n"));
      continue;
    }

    Data64        = (UINT64 *)(PropertyPtr->Data);
    StartAddress  = Fdt64ToCpu (ReadUnaligned64 (Data64));
    NumberOfBytes = Fdt64ToCpu (ReadUnaligned64 (Data64 + 1));
    DEBUG ((DEBUG_INFO, "\n         Property  reg"));
    DEBUG ((DEBUG_INFO, "  %016lX  %016lX\n", StartAddress, NumberOfBytes));

    RecordMemoryNode (SubNode);

    if (AsciiStrnCmp (NodePtr->Name, "mmio@", AsciiStrLen ("mmio@")) == 0) {
      DEBUG ((DEBUG_INFO, "  MemoryMappedIO"));
      BuildResourceDescriptorHob (
        EFI_RESOURCE_MEMORY_MAPPED_IO,
        MEMORY_ATTRIBUTE_DEFAULT,
        StartAddress,
        NumberOfBytes
        );
    } else {
      PropertyPtr = FdtGetProperty (Fdt, SubNode, "compatible", &TempLen);
      TempStr     = NULL;
      if ((PropertyPtr != NULL) && (TempLen > 0)) {
        TempStr = (CHAR8 *)(PropertyPtr->Data);
        DEBUG ((DEBUG_INFO, "compatible:  %a\n", TempStr));
      }

      if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "boot-code", AsciiStrLen ("boot-code")) == 0)) {
        DEBUG ((DEBUG_INFO, "  boot-code\n"));
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiBootServicesCode);
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "boot-data", AsciiStrLen ("boot-data")) == 0)) {
        DEBUG ((DEBUG_INFO, "  boot-data\n"));
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiBootServicesData);
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "runtime-code", AsciiStrLen ("runtime-code")) == 0)) {
        DEBUG ((DEBUG_INFO, "  runtime-code\n"));
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiRuntimeServicesCode);
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "runtime-data", AsciiStrLen ("runtime-data")) == 0)) {
        DEBUG ((DEBUG_INFO, "  runtime-data\n"));
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiRuntimeServicesData);
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "special-purpose", AsciiStrLen ("special-purpose")) == 0)) {
        Attribute = MEMORY_ATTRIBUTE_DEFAULT | EFI_RESOURCE_ATTRIBUTE_SPECIAL_PURPOSE;
        DEBUG ((DEBUG_INFO, "  special-purpose memory\n"));
        BuildResourceDescriptorHob (EFI_RESOURCE_SYSTEM_MEMORY, Attribute, StartAddress, NumberOfBytes);
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "acpi-nvs", AsciiStrLen ("acpi-nvs")) == 0)) {
        DEBUG ((DEBUG_INFO, "\n ********* acpi-nvs ********\n"));
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiACPIMemoryNVS);
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "acpi", AsciiStrLen ("acpi")) == 0)) {
        DEBUG ((DEBUG_INFO, "  acpi, StartAddress:%x, NumberOfBytes:%x\n", StartAddress, NumberOfBytes));

        BuildMemoryAllocationHob (
          UPL_ALIGN_DOWN (StartAddress),
          ALIGN_VALUE (NumberOfBytes, EFI_PAGE_SIZE),
          EfiBootServicesData
          );
        PlatformAcpiTable = BuildGuidHob (&gUniversalPayloadAcpiTableGuid, sizeof (UNIVERSAL_PAYLOAD_ACPI_TABLE));
        if (PlatformAcpiTable != NULL) {
          DEBUG ((DEBUG_INFO, " build gUniversalPayloadAcpiTableGuid , NumberOfBytes:%x\n", NumberOfBytes));
          PlatformAcpiTable->Rsdp            = (EFI_PHYSICAL_ADDRESS)(UINTN)StartAddress;
          PlatformAcpiTable->Header.Revision = UNIVERSAL_PAYLOAD_ACPI_TABLE_REVISION;
          PlatformAcpiTable->Header.Length   = sizeof (UNIVERSAL_PAYLOAD_ACPI_TABLE);
        }
      } else if ((TempStr != NULL) && (AsciiStrnCmp (TempStr, "smbios", AsciiStrLen ("smbios")) == 0)) {
        DEBUG ((DEBUG_INFO, " build smbios, NumberOfBytes:%x\n", NumberOfBytes));
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiBootServicesData);
        SmbiosTableGuid = &gUniversalPayloadSmbios3TableGuid;
        if ((NumberOfBytes >= SMBIOS_ANCHOR_STRING_LENGTH) &&
            (CompareMem ((VOID *)(UINTN)StartAddress, SMBIOS_ANCHOR_STRING, SMBIOS_ANCHOR_STRING_LENGTH) == 0))
        {
          SmbiosTableGuid = &gUniversalPayloadSmbiosTableGuid;
        }

        SmbiosTable = BuildGuidHob (SmbiosTableGuid, sizeof (UNIVERSAL_PAYLOAD_SMBIOS_TABLE));
        if (SmbiosTable != NULL) {
          SmbiosTable->Header.Revision  = UNIVERSAL_PAYLOAD_SMBIOS_TABLE_REVISION;
          SmbiosTable->Header.Length    = sizeof (UNIVERSAL_PAYLOAD_SMBIOS_TABLE);
          SmbiosTable->SmBiosEntryPoint = (EFI_PHYSICAL_ADDRESS)(UINTN)(StartAddress);
        }
      } else {
        BuildMemoryAllocationHob (StartAddress, NumberOfBytes, EfiReservedMemoryType);
      }
    }
  }
}

/**
  It will ParseFrameBuffer node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  SubNode           first Sub node of the PCI root bridge node.

  @param[out] GmaStr            Graphic device node name string.

  @retval TRUE                  Framebuffer info HOB was built.
  @retval FALSE                 Framebuffer node was invalid or unsupported.
**/
BOOLEAN
ParseFrameBuffer (
  IN  VOID   *Fdt,
  IN  INT32  Node,
  OUT CHAR8  **GmaStr
  )
{
  INT32                      Property;
  INT32                      TempLen;
  CONST FDT_PROPERTY         *PropertyPtr;
  CONST CHAR8                *TempStr;
  UINT32                     *Data32;
  UINT64                     FrameBufferBase;
  UINT64                     FrameBufferSize;
  UINT32                     Width;
  UINT32                     Height;
  UINT32                     Stride;
  EFI_GRAPHICS_PIXEL_FORMAT  PixelFormat;
  EFI_PEI_GRAPHICS_INFO_HOB  *GraphicsInfo;
  CHAR8                      *LocalGmaStr;
  BOOLEAN                    HasReg;

  if (GmaStr == NULL) {
    return FALSE;
  }

  LocalGmaStr     = "Gma";
  FrameBufferBase = 0;
  FrameBufferSize = 0;
  Width           = 0;
  Height          = 0;
  Stride          = 0;
  PixelFormat     = PixelFormatMax;
  HasReg          = FALSE;

  for (Property = FdtFirstPropertyOffset (Fdt, Node); Property >= 0; Property = FdtNextPropertyOffset (Fdt, Property)) {
    PropertyPtr = FdtGetPropertyByOffset (Fdt, Property, &TempLen);
    TempStr     = FdtGetString (Fdt, Fdt32ToCpu (PropertyPtr->NameOffset), NULL);
    if (AsciiStrCmp (TempStr, "reg") == 0) {
      if (TempLen == (2 * sizeof (UINT64))) {
        FrameBufferBase = Fdt64ToCpu (ReadUnaligned64 ((CONST UINT64 *)&PropertyPtr->Data[0]));
        FrameBufferSize = Fdt64ToCpu (ReadUnaligned64 ((CONST UINT64 *)&PropertyPtr->Data[sizeof (UINT64)]));
      } else if (TempLen == (2 * sizeof (UINT32))) {
        Data32          = (UINT32 *)(PropertyPtr->Data);
        FrameBufferBase = Fdt32ToCpu (ReadUnaligned32 (Data32));
        FrameBufferSize = Fdt32ToCpu (ReadUnaligned32 (Data32 + 1));
      } else {
        DEBUG ((DEBUG_ERROR, "Framebuffer reg must contain address and size cells\n"));
        return FALSE;
      }

      HasReg = TRUE;
    } else if (AsciiStrCmp (TempStr, "width") == 0) {
      if (TempLen != sizeof (UINT32)) {
        return FALSE;
      }

      Data32 = (UINT32 *)(PropertyPtr->Data);
      Width  = Fdt32ToCpu (ReadUnaligned32 (Data32));
    } else if (AsciiStrCmp (TempStr, "height") == 0) {
      if (TempLen != sizeof (UINT32)) {
        return FALSE;
      }

      Data32 = (UINT32 *)(PropertyPtr->Data);
      Height = Fdt32ToCpu (ReadUnaligned32 (Data32));
    } else if (AsciiStrCmp (TempStr, "stride") == 0) {
      if (TempLen != sizeof (UINT32)) {
        return FALSE;
      }

      Data32 = (UINT32 *)(PropertyPtr->Data);
      Stride = Fdt32ToCpu (ReadUnaligned32 (Data32));
    } else if (AsciiStrCmp (TempStr, "format") == 0) {
      if (TempLen != sizeof ("a8r8g8b8")) {
        return FALSE;
      }

      TempStr = (CHAR8 *)(PropertyPtr->Data);
      if ((AsciiStrCmp (TempStr, "a8r8g8b8") == 0) || (AsciiStrCmp (TempStr, "x8r8g8b8") == 0)) {
        PixelFormat = PixelBlueGreenRedReserved8BitPerColor;
      } else if ((AsciiStrCmp (TempStr, "a8b8g8r8") == 0) || (AsciiStrCmp (TempStr, "x8b8g8r8") == 0)) {
        PixelFormat = PixelRedGreenBlueReserved8BitPerColor;
      } else {
        DEBUG ((DEBUG_ERROR, "Unsupported framebuffer format: %a\n", TempStr));
        return FALSE;
      }
    } else if (AsciiStrCmp (TempStr, "display") == 0) {
      LocalGmaStr = (CHAR8 *)(PropertyPtr->Data);
      LocalGmaStr++;
      DEBUG ((DEBUG_INFO, "  display (%s)", LocalGmaStr));
    }
  }

  if ((Stride == 0) && (Width <= (MAX_UINT32 / sizeof (UINT32)))) {
    Stride = Width * sizeof (UINT32);
  }

  if (!HasReg || (FrameBufferSize > MAX_UINT32) || (Width == 0) || (Height == 0) ||
      (Width > (MAX_UINT32 / sizeof (UINT32))) ||
      (Stride < (Width * sizeof (UINT32))) || ((Stride % sizeof (UINT32)) != 0) ||
      ((UINT64)Stride * Height > FrameBufferSize) || (PixelFormat == PixelFormatMax))
  {
    DEBUG ((DEBUG_ERROR, "Framebuffer node is incomplete or invalid\n"));
    return FALSE;
  }

  GraphicsInfo = BuildGuidHob (&gEfiGraphicsInfoHobGuid, sizeof (EFI_PEI_GRAPHICS_INFO_HOB));
  ASSERT (GraphicsInfo != NULL);
  if (GraphicsInfo == NULL) {
    return FALSE;
  }

  ZeroMem (GraphicsInfo, sizeof (EFI_PEI_GRAPHICS_INFO_HOB));
  GraphicsInfo->FrameBufferBase                   = FrameBufferBase;
  GraphicsInfo->FrameBufferSize                   = (UINT32)FrameBufferSize;
  GraphicsInfo->GraphicsMode.HorizontalResolution = Width;
  GraphicsInfo->GraphicsMode.VerticalResolution   = Height;
  GraphicsInfo->GraphicsMode.PixelFormat          = PixelFormat;
  GraphicsInfo->GraphicsMode.PixelsPerScanLine    = Stride / sizeof (UINT32);

  *GmaStr = LocalGmaStr;
  return TRUE;
}

/**
  It will ParseOptions node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  SubNode           first Sub node of the PCI root bridge node.
  @param[out] PciEnumDone       Init ParsePciRootBridge node for ParsePciRootBridge.
  @param[out] BootMode          Init the system boot mode
**/
VOID
ParseOptions (
  IN VOID            *Fdt,
  IN INT32           Node,
  OUT UINT8          *PciEnumDone,
  OUT EFI_BOOT_MODE  *BootMode
  )
{
  INT32                   SubNode;
  FDT_NODE_HEADER         *NodePtr;
  UNIVERSAL_PAYLOAD_BASE  *PayloadBase;
  CONST FDT_PROPERTY      *PropertyPtr;
  CONST CHAR8             *TempStr;
  INT32                   TempLen;
  UINT32                  *Data32;
  UINT64                  *Data64;
  UINT64                  StartAddress;
  UINT8                   SizeOfMemorySpace;

  for (SubNode = FdtFirstSubnode (Fdt, Node); SubNode >= 0; SubNode = FdtNextSubnode (Fdt, SubNode)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + SubNode + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    DEBUG ((DEBUG_INFO, "\n      SubNode(%08X)  %a", SubNode, NodePtr->Name));

    if ((AsciiStrnCmp (NodePtr->Name, "upl-image@", AsciiStrLen ("upl-image@")) == 0) ||
        (AsciiStrnCmp (NodePtr->Name, "upl-images@", AsciiStrLen ("upl-images@")) == 0))
    {
      DEBUG ((DEBUG_INFO, "  Found image@ node \n"));
      //
      // Build PayloadBase HOB .
      //
      PayloadBase = BuildGuidHob (&gUniversalPayloadBaseGuid, sizeof (UNIVERSAL_PAYLOAD_BASE));
      ASSERT (PayloadBase != NULL);
      if (PayloadBase == NULL) {
        return;
      }

      PayloadBase->Header.Revision = UNIVERSAL_PAYLOAD_BASE_REVISION;
      PayloadBase->Header.Length   = sizeof (UNIVERSAL_PAYLOAD_BASE);

      PropertyPtr = FdtGetProperty (Fdt, SubNode, "addr", &TempLen);

      ASSERT (TempLen > 0);
      if (TempLen > 0) {
        Data64       = (UINT64 *)(PropertyPtr->Data);
        StartAddress = Fdt64ToCpu (ReadUnaligned64 (Data64));
        DEBUG ((DEBUG_INFO, "\n         Property(00000000)  entry"));
        DEBUG ((DEBUG_INFO, "  %016lX\n", StartAddress));

        PayloadBase->Entry = (EFI_PHYSICAL_ADDRESS)StartAddress;
      }
    }

    if (AsciiStrnCmp (NodePtr->Name, "upl-params", AsciiStrLen ("upl-params")) == 0) {
      PropertyPtr = FdtGetProperty (Fdt, SubNode, "addr-width", &TempLen);
      if (TempLen > 0) {
        Data32 = (UINT32 *)(PropertyPtr->Data);
        DEBUG ((DEBUG_INFO, "\n         Property(00000000)  address_width"));
        DEBUG ((DEBUG_INFO, "  %X", Fdt32ToCpu (*Data32)));
        SizeOfMemorySpace = (UINT8)Fdt32ToCpu (*Data32);
        BuildCpuHob (SizeOfMemorySpace, PcdGet8 (SizeOfIoSpace));
      }

      PropertyPtr = FdtGetProperty (Fdt, SubNode, "pci-enum-done", &TempLen);
      if (PropertyPtr != NULL) {
        *PciEnumDone = 1;
        DEBUG ((DEBUG_INFO, "  Found PciEnumDone (%08X)\n", *PciEnumDone));
      } else {
        *PciEnumDone = 0;
        DEBUG ((DEBUG_INFO, "  Not Found PciEnumDone \n"));
      }

      PropertyPtr = FdtGetProperty (Fdt, SubNode, "boot-mode", &TempLen);
      if (TempLen > 0) {
        TempStr = (CHAR8 *)(PropertyPtr->Data);
        if (AsciiStrCmp (TempStr, "normal") == 0) {
          *BootMode = BOOT_WITH_FULL_CONFIGURATION;
        } else if (AsciiStrCmp (TempStr, "fast") == 0) {
          *BootMode = BOOT_WITH_MINIMAL_CONFIGURATION;
        } else if (AsciiStrCmp (TempStr, "full") == 0) {
          *BootMode = BOOT_WITH_FULL_CONFIGURATION_PLUS_DIAGNOSTICS;
        } else if (AsciiStrCmp (TempStr, "default") == 0) {
          *BootMode = BOOT_WITH_DEFAULT_SETTINGS;
        } else if (AsciiStrCmp (TempStr, "s4") == 0) {
          *BootMode = BOOT_ON_S4_RESUME;
        } else if (AsciiStrCmp (TempStr, "s3") == 0) {
          *BootMode = BOOT_ON_S3_RESUME;
        }
      }
    }
  }
}

/**
  It will Parsegraphic node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  SubNode           first Sub node of the PCI root bridge node.
**/
VOID
ParsegraphicNode (
  IN VOID   *Fdt,
  IN INT32  SubNode
  )
{
  EFI_PEI_GRAPHICS_DEVICE_INFO_HOB  *GraphicsDev;
  CONST FDT_PROPERTY                *PropertyPtr;
  UINT16                            GmaID;
  UINT32                            *Data32;
  INT32                             TempLen;

  DEBUG ((DEBUG_INFO, "  Found gma@ node \n"));
  GraphicsDev = NULL;
  //
  // Build Graphic info HOB .
  //
  GraphicsDev = BuildGuidHob (&gEfiGraphicsDeviceInfoHobGuid, sizeof (EFI_PEI_GRAPHICS_DEVICE_INFO_HOB));
  ASSERT (GraphicsDev != NULL);
  if (GraphicsDev == NULL) {
    return;
  }

  SetMem (GraphicsDev, sizeof (EFI_PEI_GRAPHICS_DEVICE_INFO_HOB), 0xFF);
  PropertyPtr = FdtGetProperty (Fdt, SubNode, "vendor-id", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32 = (UINT32 *)(PropertyPtr->Data);
    GmaID  = (UINT16)Fdt32ToCpu (*Data32);
    DEBUG ((DEBUG_INFO, "\n   vendor-id"));
    DEBUG ((DEBUG_INFO, "  %016lX\n", GmaID));
    GraphicsDev->VendorId = GmaID;
  }

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "device-id", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32 = (UINT32 *)(PropertyPtr->Data);
    GmaID  = (UINT16)Fdt32ToCpu (*Data32);
    DEBUG ((DEBUG_INFO, "\n   device-id"));
    DEBUG ((DEBUG_INFO, "  %016lX\n", GmaID));
    GraphicsDev->DeviceId = GmaID;
  }

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "revision-id", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32 = (UINT32 *)(PropertyPtr->Data);
    GmaID  = (UINT16)Fdt32ToCpu (*Data32);
    DEBUG ((DEBUG_INFO, "\n   revision-id"));
    DEBUG ((DEBUG_INFO, "  %016lX\n", GmaID));
    GraphicsDev->RevisionId = (UINT8)GmaID;
  }

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "subsystem-vendor-id", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32 = (UINT32 *)(PropertyPtr->Data);
    GmaID  = (UINT16)Fdt32ToCpu (*Data32);
    DEBUG ((DEBUG_INFO, "\n   subsystem-vendor-id"));
    DEBUG ((DEBUG_INFO, "  %016lX\n", GmaID));
    GraphicsDev->SubsystemVendorId = GmaID;
  }

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "subsystem-id", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32 = (UINT32 *)(PropertyPtr->Data);
    GmaID  = (UINT16)Fdt32ToCpu (*Data32);
    DEBUG ((DEBUG_INFO, "\n   subsystem-id"));
    DEBUG ((DEBUG_INFO, "  %016lX\n", GmaID));
    GraphicsDev->SubsystemId = GmaID;
  }
}

/**
  It will ParseSerialPort node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  SubNode           first Sub node of the PCI root bridge node.
  @param[in]  AddressCells      #address-cells for serial port node 'reg' property.
**/
VOID
ParseSerialPort (
  IN VOID    *Fdt,
  IN INT32   SubNode,
  IN UINT32  AddressCells
  )
{
  UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO  *Serial;
  CONST FDT_PROPERTY                  *PropertyPtr;
  INT32                               TempLen;
  UINT32                              *Data32;
  UINT32                              Value32;

  //
  // Create SerialPortInfo HOB.
  //
  Serial = BuildGuidHob (&gUniversalPayloadSerialPortInfoGuid, sizeof (UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO));
  ASSERT (Serial != NULL);
  if (Serial == NULL) {
    return;
  }

  Serial->Header.Revision = UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO_REVISION;
  Serial->Header.Length   = sizeof (UNIVERSAL_PAYLOAD_SERIAL_PORT_INFO);
  Serial->RegisterStride  = 1;
  Serial->UseMmio         = TRUE;

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "current-speed", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32           = (UINT32 *)(PropertyPtr->Data);
    Serial->BaudRate = Fdt32ToCpu (*Data32);
  }

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "reg-shift", &TempLen);
  if (TempLen > 0) {
    Data32                 = (UINT32 *)(PropertyPtr->Data);
    Serial->RegisterStride = (UINT8)(1 << Fdt32ToCpu (*Data32));
  }

  PropertyPtr = FdtGetProperty (Fdt, SubNode, "reg", &TempLen);
  ASSERT (TempLen > 0);
  if (TempLen > 0) {
    Data32  = (UINT32 *)(PropertyPtr->Data);
    Value32 = Fdt32ToCpu (Data32[0]);
    switch (AddressCells) {
      case 1:
        Serial->RegisterBase = Value32;
        if (Value32 < SIZE_64KB) {
          Serial->UseMmio = FALSE;
        }

        break;
      case 2:
        Serial->RegisterBase = Fdt32ToCpu (Data32[1]);
        if (Value32 == 1) {
          // IO type for Legacy serial
          Serial->UseMmio = FALSE;
        } else {
          Serial->RegisterBase |= LShiftU64 (Value32, 32);
        }

        break;
      case 3:
        // First U32 format: npt000ss bbbbbbbb dddddfff rrrrrrrr
        if ((Value32 & 0x03000000) == 0x01000000) {
          Serial->UseMmio = FALSE;
        }

        Serial->RegisterBase = LShiftU64 ((UINT64)Fdt32ToCpu (Data32[1]), 32) | Fdt32ToCpu (Data32[2]);
        break;
      default:
        DEBUG ((DEBUG_INFO, "ERROR: not supported address cells %d\n", AddressCells));
        break;
    }
  }

  DEBUG ((DEBUG_INFO, "Serial->UseMmio        = %x\n", Serial->UseMmio));
  DEBUG ((DEBUG_INFO, "Serial->RegisterBase   = 0x%x\n", Serial->RegisterBase));
  DEBUG ((DEBUG_INFO, "Serial->BaudRate       = %d\n", Serial->BaudRate));
  DEBUG ((DEBUG_INFO, "Serial->RegisterStride = %x\n", Serial->RegisterStride));
}

/**
  It will ParsePciRootBridge node from FDT.

  @param[in]  Fdt               Address of the Fdt data.
  @param[in]  Node              first node of the Fdt data.
  @param[in]  PciEnumDone       To use ParsePciRootBridge node.
  @param[in]  RootBridgeCount   Number of pci RootBridge.
  @param[in]  GmaStr            Graphic device node name string.
  @param[in]  index             Index of ParsePciRootBridge node.
**/
VOID
ParsePciRootBridge (
  IN VOID   *Fdt,
  IN INT32  Node,
  IN UINT8  RootBridgeCount,
  IN CHAR8  *GmaStr,
  IN UINT8  *index
  )
{
  INT32               SubNode;
  INT32               Property;
  FDT_NODE_HEADER     *NodePtr;
  CONST FDT_PROPERTY  *PropertyPtr;
  INT32               TempLen;
  UINT32              *Data32;
  UINT32              MemType;
  CONST CHAR8         *TempStr;
  UINT8               RbIndex;
  UINTN               HobDataSize;
  UINT32              Base;
  UINT32              AddressCells;

  if (RootBridgeCount == 0) {
    return;
  }

  RbIndex     = *index;
  HobDataSize = sizeof (UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES) + (RootBridgeCount * sizeof (UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGE));
  //
  // Create PCI Root Bridge Info Hob.
  //
  if (mPciRootBridgeInfo == NULL) {
    mPciRootBridgeInfo = BuildGuidHob (&gUniversalPayloadPciRootBridgeInfoGuid, HobDataSize);
    ASSERT (mPciRootBridgeInfo != NULL);
    if (mPciRootBridgeInfo == NULL) {
      return;
    }

    ZeroMem (mPciRootBridgeInfo, HobDataSize);
    mPciRootBridgeInfo->Header.Length    = (UINT16)HobDataSize;
    mPciRootBridgeInfo->Header.Revision  = UNIVERSAL_PAYLOAD_PCI_ROOT_BRIDGES_REVISION;
    mPciRootBridgeInfo->Count            = RootBridgeCount;
    mPciRootBridgeInfo->ResourceAssigned = FALSE;
  }

  if (mUplPciSegmentInfoHob == NULL) {
    HobDataSize           = sizeof (UPL_PCI_SEGMENT_INFO_HOB) + ((RootBridgeCount) * sizeof (UPL_SEGMENT_INFO));
    mUplPciSegmentInfoHob = BuildGuidHob (&gUplPciSegmentInfoHobGuid, HobDataSize);
    if (mUplPciSegmentInfoHob != NULL) {
      ZeroMem (mUplPciSegmentInfoHob, HobDataSize);
      mUplPciSegmentInfoHob->Header.Revision = UNIVERSAL_PAYLOAD_PCI_SEGMENT_INFO_REVISION;
      mUplPciSegmentInfoHob->Header.Length   = (UINT16)HobDataSize;
      mUplPciSegmentInfoHob->Count           = RootBridgeCount;
    }
  }

  AddressCells = 3;
  PropertyPtr  = FdtGetProperty (Fdt, Node, "#address-cells", &TempLen);
  if ((PropertyPtr != NULL) && (TempLen > 0)) {
    AddressCells = Fdt32ToCpu (*(UINT32 *)PropertyPtr->Data);
  }

  for (SubNode = FdtFirstSubnode (Fdt, Node); SubNode >= 0; SubNode = FdtNextSubnode (Fdt, SubNode)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + SubNode + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    DEBUG ((DEBUG_INFO, "\n      SubNode(%08X)  %a", SubNode, NodePtr->Name));

    if (AsciiStrnCmp (NodePtr->Name, GmaStr, AsciiStrLen (GmaStr)) == 0) {
      DEBUG ((DEBUG_INFO, "  Found gma@ node \n"));
      ParsegraphicNode (Fdt, SubNode);
    }

  }

  for (Property = FdtFirstPropertyOffset (Fdt, Node); Property >= 0; Property = FdtNextPropertyOffset (Fdt, Property)) {
    PropertyPtr = FdtGetPropertyByOffset (Fdt, Property, &TempLen);
    TempStr     = FdtGetString (Fdt, Fdt32ToCpu (PropertyPtr->NameOffset), NULL);

    if (AsciiStrCmp (TempStr, "ranges") == 0) {
      DEBUG ((DEBUG_INFO, "  Found ranges Property TempLen (%08X), limit %x\n", TempLen, TempLen / sizeof (UINT32)));
      // TODO:  In future we should fetch these values from fdt and avoid using these Pcds
      mPciRootBridgeInfo->RootBridge[RbIndex].AllocationAttributes = EFI_PCI_HOST_BRIDGE_COMBINE_MEM_PMEM | EFI_PCI_HOST_BRIDGE_MEM64_DECODE;
      mPciRootBridgeInfo->RootBridge[RbIndex].Supports             = ROOT_BRIDGE_SUPPORTS_DEFAULT;
      mPciRootBridgeInfo->RootBridge[RbIndex].PMemAbove4G.Base     = PcdGet64 (PcdPciReservedPMemAbove4GBBase);
      mPciRootBridgeInfo->RootBridge[RbIndex].PMemAbove4G.Limit    = PcdGet64 (PcdPciReservedPMemAbove4GBLimit);
      mPciRootBridgeInfo->RootBridge[RbIndex].PMem.Base            = PcdGet32 (PcdPciReservedPMemBase);
      mPciRootBridgeInfo->RootBridge[RbIndex].PMem.Limit           = PcdGet32 (PcdPciReservedPMemLimit);
      mPciRootBridgeInfo->RootBridge[RbIndex].UID                  = RbIndex;
      mPciRootBridgeInfo->RootBridge[RbIndex].HID                  = EISA_PNP_ID (0x0A03);
      mPciRootBridgeInfo->RootBridge[RbIndex].DmaAbove4G           = PcdGetBool (PcdPciAllocateMemoryAbove4GB);

      Data32 = (UINT32 *)(PropertyPtr->Data);
      for (Base = 0; Base < TempLen / sizeof (UINT32); Base = Base + DWORDS_TO_NEXT_ADDR_TYPE) {
        DEBUG ((DEBUG_INFO, "  Base :%x \n", Base));
        MemType = Fdt32ToCpu (*(Data32 + Base));
        if (((MemType) & (SS_64BIT_MEMORY_SPACE)) == SS_64BIT_MEMORY_SPACE) {
          mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Base  = Fdt32ToCpu (*(Data32 + Base + 2)) + LShiftU64 (Fdt32ToCpu (*(Data32 + Base + 1)), 32);
          mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Limit = mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Base + LShiftU64 (Fdt32ToCpu (*(Data32 + Base + 5)), 32) + Fdt32ToCpu (*(Data32 + Base + 6)) - 1;
        } else if (((MemType) & (SS_32BIT_MEMORY_SPACE)) == SS_32BIT_MEMORY_SPACE) {
          mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Base  = Fdt32ToCpu (*(Data32 + Base + 2));
          mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Limit = mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Base + Fdt32ToCpu (*(Data32 + Base + 6)) - 1;
        } else if (((MemType) & (SS_IO_SPACE)) == SS_IO_SPACE) {
          mPciRootBridgeInfo->RootBridge[RbIndex].Io.Base  = Fdt32ToCpu (*(Data32 + Base + 2));
          mPciRootBridgeInfo->RootBridge[RbIndex].Io.Limit = mPciRootBridgeInfo->RootBridge[RbIndex].Io.Base + Fdt32ToCpu (*(Data32 + Base + 6)) - 1;
        }
      }

      DEBUG ((DEBUG_INFO, "RootBridgeCount %x, index :%x\n", RootBridgeCount, RbIndex));

      DEBUG ((DEBUG_INFO, "PciRootBridge->Mem.Base %x, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Base));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Mem.limit %x, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Mem.Limit));

      DEBUG ((DEBUG_INFO, "PciRootBridge->MemAbove4G.Base %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Base));
      DEBUG ((DEBUG_INFO, "PciRootBridge->MemAbove4G.limit %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].MemAbove4G.Limit));

      DEBUG ((DEBUG_INFO, "PciRootBridge->Io.Base %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Io.Base));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Io.limit %llx, \n", mPciRootBridgeInfo->RootBridge[RbIndex].Io.Limit));
    }

    //
    // Check for the "dma-ranges" property to determine if the device supports
    // DMA (Direct Memory Access) addresses above the 4GiB boundary.
    //
    if (AsciiStrCmp (TempStr, "dma-ranges") == 0) {
      INT32   DmaRangesLength;
      INT32   ParentNode;
      UINT32  ChildAddrCells;
      UINT32  DmaRangeCells;
      UINT32  ParentAddrCells;
      UINT32  SizeCells;
      UINT32  TripletCells;

      Data32          = (UINT32 *)(PropertyPtr->Data);
      DmaRangesLength = TempLen;
      if ((DmaRangesLength <= 0) || ((DmaRangesLength % sizeof (UINT32)) != 0)) {
        continue;
      }

      DmaRangeCells = (UINT32)(DmaRangesLength / sizeof (UINT32));

      //
      // According to the device tree specification, a dma-ranges entry is a tuple of
      // (child-bus-address, parent-bus-address, size). The number of 32-bit cells
      // for each part of the tuple is defined by the '#address-cells' and '#size-cells'
      // properties.
      //
      ChildAddrCells  = AddressCells;
      ParentAddrCells = AddressCells;
      ParentNode      = FdtParentOffset (Fdt, Node);
      if (ParentNode >= 0) {
        PropertyPtr = FdtGetProperty (Fdt, ParentNode, "#address-cells", &TempLen);
        if ((PropertyPtr != NULL) && (TempLen == sizeof (UINT32))) {
          ParentAddrCells = Fdt32ToCpu (*(UINT32 *)PropertyPtr->Data);
        }
      }

      SizeCells = 2;
      PropertyPtr = FdtGetProperty (Fdt, Node, "#size-cells", &TempLen);
      if ((PropertyPtr != NULL) && (TempLen == sizeof (UINT32))) {
        SizeCells = Fdt32ToCpu (*(UINT32 *)PropertyPtr->Data);
      }

      if ((ChildAddrCells == 0) || (ParentAddrCells == 0) || (SizeCells == 0) ||
          (ParentAddrCells > 2) || (SizeCells > 2) ||
          (ChildAddrCells > DmaRangeCells) ||
          (ParentAddrCells > (DmaRangeCells - ChildAddrCells)) ||
          (SizeCells > (DmaRangeCells - ChildAddrCells - ParentAddrCells)))
      {
        continue;
      }

      TripletCells = ChildAddrCells + ParentAddrCells + SizeCells;
      for (Base = 0; Base + TripletCells <= DmaRangeCells; Base = Base + TripletCells) {
        UINT64  ParentBusAddress = 0;
        UINT64  DmaRangeSize     = 0;
        UINT32  ParentBase       = Base + ChildAddrCells;
        if (ParentAddrCells == 2) {
          ParentBusAddress = (UINT64)Fdt32ToCpu (*(Data32 + ParentBase)) << 32 |
                             (UINT64)Fdt32ToCpu (*(Data32 + ParentBase + 1));
        } else if (ParentAddrCells == 1) {
          ParentBusAddress = Fdt32ToCpu (*(Data32 + ParentBase));
        }

        UINT32  SizeBase = Base + ChildAddrCells + ParentAddrCells;
        if (SizeCells == 2) {
          DmaRangeSize = (UINT64)Fdt32ToCpu (*(Data32 + SizeBase)) << 32 |
                         (UINT64)Fdt32ToCpu (*(Data32 + SizeBase + 1));
        } else if (SizeCells == 1) {
          DmaRangeSize = Fdt32ToCpu (*(Data32 + SizeBase));
        }

        if ((DmaRangeSize != 0) &&
            ((ParentBusAddress > 0xFFFFFFFF) ||
             ((DmaRangeSize - 1) > (MAX_UINT64 - ParentBusAddress)) ||
             ((ParentBusAddress + DmaRangeSize - 1) > 0xFFFFFFFF)))
        {
          mPciRootBridgeInfo->RootBridge[RbIndex].DmaAbove4G = TRUE;
          DEBUG ((
            DEBUG_INFO,
            "DMA Above 4G supported: Parent=0x%llx, Size=0x%llx\n",
            ParentBusAddress,
            DmaRangeSize
            ));
          break;
        }
      }
    }

    if (AsciiStrCmp (TempStr, "reg") == 0) {
      UINT64  *Data64 = (UINT64 *)(PropertyPtr->Data);
      mUplPciSegmentInfoHob->SegmentInfo[RbIndex].BaseAddress = Fdt64ToCpu (ReadUnaligned64 (Data64));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Ecam.Base %llx, \n", mUplPciSegmentInfoHob->SegmentInfo[RbIndex].BaseAddress));
    }

    if (AsciiStrCmp (TempStr, "bus-range") == 0) {
      Data32                                                  = (UINT32 *)(PropertyPtr->Data);
      mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Base        = Fdt32ToCpu (*Data32) & 0xFF;
      mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Limit       = Fdt32ToCpu (*(Data32 + 1)) & 0xFF;
      mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Translation = 0;

      DEBUG ((DEBUG_INFO, "PciRootBridge->Bus.Base %x, index %x\n", mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Base, RbIndex));
      DEBUG ((DEBUG_INFO, "PciRootBridge->Bus.limit %x, index %x\n", mPciRootBridgeInfo->RootBridge[RbIndex].Bus.Limit, RbIndex));
    }
  }

  if (RbIndex > 0) {
    RbIndex--;
  }

  *index = RbIndex;
}

#ifndef UPL_DISABLE_SMMSTORE_BRIDGE
STATIC
UINT16
CorebootChecksum16 (
  IN CONST VOID  *Buffer,
  IN UINTN       Length
  )
{
  CONST UINT8  *Data;
  UINTN        Index;
  UINT32       Sum;
  UINT32       Value;

  Data = Buffer;
  Sum  = 0;
  for (Index = 0; Index < Length; Index++) {
    Value = Data[Index];
    if ((Index & 1) != 0) {
      Value <<= 8;
    }

    Sum += Value;
    if (Sum >= 0x10000) {
      Sum = (Sum + (Sum >> 16)) & 0xFFFF;
    }
  }

  return (UINT16)((~Sum) & 0xFFFF);
}

/**
  Validate a bounded coreboot table and find its SMMSTOREv2 record.

  Forward records are rejected because following one would leave the
  FDT-provided table bounds.
**/
STATIC
EFI_STATUS
FindCorebootSmmStore (
  IN  struct cb_header       *Header,
  IN  UINTN                  TableSize,
  OUT struct cb_smmstorev2   **SmmStore
  )
{
  UINT32                Index;
  UINTN                 Remaining;
  struct cb_record      *Record;
  struct cb_smmstorev2  *Found;

  *SmmStore = NULL;
  if ((Header == NULL) || (TableSize < sizeof (*Header)) ||
      (Header->signature != CB_HEADER_SIGNATURE))
  {
    return EFI_COMPROMISED_DATA;
  }

  if ((Header->header_bytes < sizeof (*Header)) ||
      (Header->header_bytes > TableSize) ||
      (Header->table_bytes == 0) ||
      (Header->table_bytes > TableSize - Header->header_bytes) ||
      (Header->table_entries > Header->table_bytes / sizeof (*Record)))
  {
    return EFI_COMPROMISED_DATA;
  }

  if ((CorebootChecksum16 (Header, Header->header_bytes) != 0) ||
      (CorebootChecksum16 ((UINT8 *)Header + Header->header_bytes, Header->table_bytes) != Header->table_checksum))
  {
    return EFI_CRC_ERROR;
  }

  Record    = (struct cb_record *)((UINT8 *)Header + Header->header_bytes);
  Remaining = Header->table_bytes;
  Found     = NULL;
  for (Index = 0; Index < Header->table_entries; Index++) {
    if ((Remaining < sizeof (*Record)) ||
        (Record->size < sizeof (*Record)) ||
        (Record->size > Remaining) ||
        ((Record->size & (sizeof (UINT32) - 1)) != 0))
    {
      return EFI_COMPROMISED_DATA;
    }

    if (Record->tag == CB_TAG_FORWARD) {
      return EFI_UNSUPPORTED;
    }

    if (Record->tag == CB_TAG_SMMSTOREV2) {
      if ((Record->size < sizeof (struct cb_smmstorev2)) || (Found != NULL)) {
        return EFI_COMPROMISED_DATA;
      }

      Found = (struct cb_smmstorev2 *)Record;
    }

    Remaining -= Record->size;
    Record     = (struct cb_record *)((UINT8 *)Record + Record->size);
  }

  if ((Remaining != 0) || (Found == NULL)) {
    return (Found == NULL) ? EFI_NOT_FOUND : EFI_COMPROMISED_DATA;
  }

  *SmmStore = Found;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
ValidateCorebootSmmStore (
  IN CONST struct cb_smmstorev2  *SmmStore
  )
{
  UINT64  BufferEnd;
  UINT64  StoreEnd;
  UINT64  StoreSize;

  if ((SmmStore->num_blocks == 0) || (SmmStore->block_size == 0) ||
      (SmmStore->com_buffer == 0) || (SmmStore->com_buffer_size < 16) ||
      (SmmStore->mmap_addr == 0) || (SmmStore->apm_cmd == 0))
  {
    return EFI_COMPROMISED_DATA;
  }

  StoreSize = (UINT64)SmmStore->num_blocks * SmmStore->block_size;
  StoreEnd  = (UINT64)SmmStore->mmap_addr + StoreSize;
  BufferEnd = (UINT64)SmmStore->com_buffer + SmmStore->com_buffer_size;
  if ((StoreSize == 0) || (StoreEnd > BASE_4GB) || (BufferEnd > BASE_4GB) ||
      (((UINT64)SmmStore->com_buffer < StoreEnd) &&
       ((UINT64)SmmStore->mmap_addr < BufferEnd)))
  {
    return EFI_COMPROMISED_DATA;
  }

  return EFI_SUCCESS;
}

/**
  Build the SMMSTORE info HOB from the coreboot table pointer in the UPL FDT.

  coreboot's UPL handoff describes the coreboot table as a DT node. The normal
  coreboot-table payload path already converts CB_TAG_SMMSTOREV2 into this HOB;
  recreate that bridge here so the UPL path can use the same SMMSTORE runtime
  implementation.

  @param[in]  Fdt               Address of the FDT data.
**/
STATIC
VOID
BuildCorebootSmmStoreHob (
  IN VOID  *Fdt
  )
{
  CONST FDT_PROPERTY    *PropertyPtr;
  CONST CHAR8           *TempStr;
  INT32                 TempLen;
  INT32                 Depth;
  INT32                 Node;
  UINT64                *Data64;
  UINT64                TableAddress;
  UINT64                TableSize;
  UINT64                TableEnd;
  UINT64                CbmemAddress;
  UINT64                CbmemSize;
  UINT64                CbmemEnd;
  EFI_STATUS            Status;
  struct cb_smmstorev2  *CbSmmStore;
  SMMSTORE_INFO         *SmmStoreInfo;
  FDT_NODE_HEADER       *NodePtr;

  Depth = 0;
  for (Node = FdtNextNode (Fdt, 0, &Depth); Node >= 0; Node = FdtNextNode (Fdt, Node, &Depth)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + Node + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    if (AsciiStrCmp (NodePtr->Name, "coreboot") != 0) {
      continue;
    }

    PropertyPtr = FdtGetProperty (Fdt, Node, "compatible", &TempLen);
    if ((PropertyPtr == NULL) || (TempLen <= 0) ||
        (((CONST CHAR8 *)PropertyPtr->Data)[TempLen - 1] != '\0'))
    {
      continue;
    }

    TempStr = (CONST CHAR8 *)PropertyPtr->Data;
    if (AsciiStrCmp (TempStr, "coreboot") != 0) {
      continue;
    }

    PropertyPtr = FdtGetProperty (Fdt, Node, "reg", &TempLen);
    if ((PropertyPtr == NULL) || (TempLen != (INT32)(4 * sizeof (UINT64))))
    {
      DEBUG ((DEBUG_ERROR, "UPL coreboot node must describe table and CBMEM bounds\n"));
      return;
    }

    Data64       = (UINT64 *)PropertyPtr->Data;
    TableAddress = Fdt64ToCpu (ReadUnaligned64 (Data64));
    TableSize    = Fdt64ToCpu (ReadUnaligned64 (Data64 + 1));
    CbmemAddress = Fdt64ToCpu (ReadUnaligned64 (Data64 + 2));
    CbmemSize    = Fdt64ToCpu (ReadUnaligned64 (Data64 + 3));
    if ((TableSize == 0) || (CbmemSize == 0) ||
        (TableAddress > MAX_UINT64 - TableSize) ||
        (CbmemAddress > MAX_UINT64 - CbmemSize) ||
        (TableAddress > MAX_UINTN) || (TableSize > MAX_UINTN) ||
        (TableAddress > MAX_UINTN - TableSize))
    {
      DEBUG ((DEBUG_ERROR, "UPL coreboot table or CBMEM range overflows\n"));
      return;
    }

    TableEnd = TableAddress + TableSize;
    CbmemEnd = CbmemAddress + CbmemSize;
    if ((TableAddress < CbmemAddress) || (TableEnd > CbmemEnd)) {
      DEBUG ((DEBUG_ERROR, "UPL coreboot table range is outside declared CBMEM\n"));
      return;
    }

    Status = FindCorebootSmmStore (
               (struct cb_header *)(UINTN)TableAddress,
               (UINTN)TableSize,
               &CbSmmStore
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "UPL coreboot SMMSTORE table validation failed: %r\n", Status));
      return;
    }

    Status = ValidateCorebootSmmStore (CbSmmStore);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "UPL coreboot SMMSTORE descriptor is invalid: %r\n", Status));
      return;
    }

    SmmStoreInfo = BuildGuidHob (&gEfiSmmStoreInfoHobGuid, sizeof (*SmmStoreInfo));
    if (SmmStoreInfo == NULL) {
      DEBUG ((DEBUG_ERROR, "Failed to build UPL SMMSTORE info HOB\n"));
      return;
    }

    SmmStoreInfo->ComBuffer     = CbSmmStore->com_buffer;
    SmmStoreInfo->ComBufferSize = CbSmmStore->com_buffer_size;
    SmmStoreInfo->BlockSize     = CbSmmStore->block_size;
    SmmStoreInfo->NumBlocks     = CbSmmStore->num_blocks;
    SmmStoreInfo->MmioAddress   = CbSmmStore->mmap_addr;
    SmmStoreInfo->ApmCmd        = CbSmmStore->apm_cmd;

    DEBUG ((DEBUG_INFO, "Created SmmStore info hob from UPL coreboot node\n"));
    DEBUG ((DEBUG_INFO, "  block size: 0x%x\n", CbSmmStore->block_size));
    DEBUG ((DEBUG_INFO, "  number of blocks: 0x%x\n", CbSmmStore->num_blocks));
    DEBUG ((DEBUG_INFO, "  communication buffer: 0x%x\n", CbSmmStore->com_buffer));
    DEBUG ((DEBUG_INFO, "  communication buffer size: 0x%x\n", CbSmmStore->com_buffer_size));
    DEBUG ((DEBUG_INFO, "  MMIO address of store: 0x%x\n", CbSmmStore->mmap_addr));
    return;
  }

  DEBUG ((DEBUG_WARN, "UPL FDT has no coreboot node for SMMSTORE handoff\n"));
}
#endif

/**
  It will parse FDT based on DTB from bootloaders.

  @param[in]  FdtBase               Address of the Fdt data.

  @return   The address to the new hob list
**/
UINTN
EFIAPI
ParseDtb (
  IN VOID  *FdtBase
  )
{
  VOID                  *Fdt;
  INT32                 Node;
  INT32                 Property;
  INT32                 Depth;
  FDT_NODE_HEADER       *NodePtr;
  CONST FDT_PROPERTY    *PropertyPtr;
  CONST CHAR8           *TempStr;
  INT32                 TempLen;
  UINT64                *Data64;
  UINT64                StartAddress;
  UINT64                NumberOfBytes;
  UINTN                 MinimalNeededSize;
  EFI_PHYSICAL_ADDRESS  FreeMemoryBottom;
  EFI_PHYSICAL_ADDRESS  FreeMemoryTop;
  EFI_PHYSICAL_ADDRESS  MemoryBottom;
  EFI_PHYSICAL_ADDRESS  MemoryTop;
  BOOLEAN               IsHobConstructed;
  UINTN                 NewHobList;
  UINT8                 RootBridgeCount;
  UINT8                 index;
  UINT8                 PciEnumDone;
  UINT8                 NodeType;
  EFI_BOOT_MODE         BootMode;
  CHAR8                 *GmaStr;
  INTN                  NumRsv;
  EFI_PHYSICAL_ADDRESS  Addr;
  UINT64                Size;
  UINT16                SegmentNumber;
  UINT64                CurrentPciBaseAddress;
  UINT64                NextPciBaseAddress;
  UINT8                 *RbSegNumAlreadyAssigned;
  UINT8                 NumberOfRbSegNumAlreadyAssigned;
  UINT32                RootAddressCells;
  UINT32                SerialAddressCells;
  INT32                 ParentNode;
  BOOLEAN               FrameBufferParsed;

  Fdt               = FdtBase;
  Depth             = 0;
  MinimalNeededSize = FixedPcdGet32 (PcdSystemMemoryUefiRegionSize);
  IsHobConstructed  = FALSE;
  NewHobList        = 0;
  RootBridgeCount   = 0;
  index             = 0;
  // TODO: This value comes from FDT. Currently there is a bug in implementation
  // which assumes node ordering. Which requires a fix.
  PciEnumDone      = 1;
  BootMode         = 0;
  NodeType         = 0;
  RootAddressCells = 2;
  GmaStr            = "Gma";
  FrameBufferParsed = FALSE;

  DEBUG ((DEBUG_INFO, "FDT = 0x%x  %x\n", Fdt, Fdt32ToCpu (*((UINT32 *)Fdt))));
  DEBUG ((DEBUG_INFO, "Start parsing DTB data\n"));
  DEBUG ((DEBUG_INFO, "MinimalNeededSize :%x\n", MinimalNeededSize));

  PropertyPtr = FdtGetProperty (Fdt, 0, "#address-cells", &TempLen);
  if ((PropertyPtr != NULL) && (TempLen > 0)) {
    RootAddressCells = Fdt32ToCpu (*(UINT32 *)PropertyPtr->Data);
    DEBUG ((DEBUG_INFO, " root #address-cells = 0x%x\n", RootAddressCells));
  }

  for (Node = FdtNextNode (Fdt, 0, &Depth); Node >= 0; Node = FdtNextNode (Fdt, Node, &Depth)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + Node + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    DEBUG ((DEBUG_INFO, "\n   Node(%08x)  %a   Depth %x\n", Node, NodePtr->Name, Depth));
    // memory node
    if (AsciiStrnCmp (NodePtr->Name, "memory@", AsciiStrLen ("memory@")) == 0) {
      for (Property = FdtFirstPropertyOffset (Fdt, Node); Property >= 0; Property = FdtNextPropertyOffset (Fdt, Property)) {
        PropertyPtr = FdtGetPropertyByOffset (Fdt, Property, &TempLen);
        TempStr     = FdtGetString (Fdt, Fdt32ToCpu (PropertyPtr->NameOffset), NULL);
        if (AsciiStrCmp (TempStr, "reg") == 0) {
          Data64        = (UINT64 *)(PropertyPtr->Data);
          StartAddress  = Fdt64ToCpu (ReadUnaligned64 (Data64));
          NumberOfBytes = Fdt64ToCpu (ReadUnaligned64 (Data64 + 1));
          DEBUG ((DEBUG_INFO, "\n         Property(%08X)  %a", Property, TempStr));
          DEBUG ((DEBUG_INFO, "  %016lX  %016lX", StartAddress, NumberOfBytes));
          // If parent node type is reserved-memory we are looking at special-purpose memory. Ignore it.
          ParentNode = FdtParentOffset (Fdt, Node);
          NodePtr    = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + ParentNode + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
          NodeType   = CheckNodeType (NodePtr->Name, Depth);
          if (!IsHobConstructed && (NodeType != ReservedMemory)) {
            if (sizeof (UINTN) == sizeof (UINT32)) {
              if (StartAddress >= (BASE_4GB - EFI_PAGE_SIZE)) {
                DEBUG ((DEBUG_INFO, "Skipping memory outside the IA32 HOB address limit\n"));
                continue;
              }

              if (NumberOfBytes > (BASE_4GB - EFI_PAGE_SIZE - StartAddress)) {
                NumberOfBytes = BASE_4GB - EFI_PAGE_SIZE - StartAddress;
              }
            }

            if (NumberOfBytes > MinimalNeededSize) {
              MemoryBottom     = StartAddress + NumberOfBytes - MinimalNeededSize;
              FreeMemoryBottom = MemoryBottom;
              FreeMemoryTop    = StartAddress + NumberOfBytes;
              MemoryTop        = FreeMemoryTop;

              DEBUG ((DEBUG_INFO, "MemoryBottom :0x%llx\n", MemoryBottom));
              DEBUG ((DEBUG_INFO, "FreeMemoryBottom :0x%llx\n", FreeMemoryBottom));
              DEBUG ((DEBUG_INFO, "FreeMemoryTop :0x%llx\n", FreeMemoryTop));
              DEBUG ((DEBUG_INFO, "MemoryTop :0x%llx\n", MemoryTop));
              mHobList         = HobConstructor ((VOID *)(UINTN)MemoryBottom, (VOID *)(UINTN)MemoryTop, (VOID *)(UINTN)FreeMemoryBottom, (VOID *)(UINTN)FreeMemoryTop);
              IsHobConstructed = TRUE;
              NewHobList       = (UINTN)mHobList;
              break;
            }
          }
        }
      }
    } else {
      PropertyPtr = FdtGetProperty (Fdt, Node, "compatible", &TempLen);
      if (PropertyPtr == NULL) {
        continue;
      }

      TempStr = (CHAR8 *)(PropertyPtr->Data);
      if (AsciiStrnCmp (TempStr, "pci-rb", AsciiStrLen ("pci-rb")) == 0) {
        RootBridgeCount++;
      }
    }
  }

  if (!IsHobConstructed) {
    DEBUG ((DEBUG_ERROR, "No usable memory node found for FDT HOB list\n"));
    return 0;
  }

  NumRsv = FdtGetNumberOfReserveMapEntries (Fdt);
  /* Look for an existing entry and add it to the efi mem map. */
  for (index = 0; index < NumRsv; index++) {
    if (FdtGetReserveMapEntry (Fdt, index, &Addr, &Size) != 0) {
      continue;
    }

    BuildMemoryAllocationHob (Addr, Size, EfiReservedMemoryType);
  }

#ifndef UPL_DISABLE_SMMSTORE_BRIDGE
  if (IsHobConstructed) {
    BuildCorebootSmmStoreHob (Fdt);
  }
#endif

  Depth = 0;
  for (Node = FdtNextNode (Fdt, 0, &Depth); Node >= 0; Node = FdtNextNode (Fdt, Node, &Depth)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + Node + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    if (CheckNodeType (NodePtr->Name, Depth) == FrameBuffer) {
      DEBUG ((DEBUG_INFO, "PreParseFrameBuffer\n"));
      if (ParseFrameBuffer (Fdt, Node, &GmaStr)) {
        FrameBufferParsed = TRUE;
      }
    }
  }

  index               = RootBridgeCount - 1;
  Depth               = 0;
  for (Node = FdtNextNode (Fdt, 0, &Depth); Node >= 0; Node = FdtNextNode (Fdt, Node, &Depth)) {
    NodePtr = (FDT_NODE_HEADER *)((CONST CHAR8 *)Fdt + Node + Fdt32ToCpu (((FDT_HEADER *)Fdt)->OffsetDtStruct));
    DEBUG ((DEBUG_INFO, "\n   Node(%08x)  %a   Depth %x", Node, NodePtr->Name, Depth));

    NodeType = CheckNodeType (NodePtr->Name, Depth);
    DEBUG ((DEBUG_INFO, "NodeType :0x%x\n", NodeType));
    switch (NodeType) {
      case SerialPort:
        SerialAddressCells = RootAddressCells;
        ParentNode         = FdtParentOffset (Fdt, Node);
        if (ParentNode >= 0) {
          PropertyPtr = FdtGetProperty (Fdt, ParentNode, "#address-cells", &TempLen);
          if ((PropertyPtr != NULL) && (TempLen == sizeof (UINT32))) {
            SerialAddressCells = Fdt32ToCpu (ReadUnaligned32 ((CONST UINT32 *)PropertyPtr->Data));
          }
        }

        ParseSerialPort (Fdt, Node, SerialAddressCells);
        break;
      case ReservedMemory:
        DEBUG ((DEBUG_INFO, "ParseReservedMemory\n"));
        ParseReservedMemory (Fdt, Node);
        break;
      case Memory:
        DEBUG ((DEBUG_INFO, "ParseMemory\n"));
        if (!CheckMemoryNodeIfInit (Node)) {
          ParseMemory (Fdt, Node);
        } else {
          DEBUG ((DEBUG_INFO, "Memory has initialized\n"));
        }

        break;
      case FrameBuffer:
        if (!FrameBufferParsed) {
          DEBUG ((DEBUG_INFO, "ParseFrameBuffer\n"));
          if (ParseFrameBuffer (Fdt, Node, &GmaStr)) {
            FrameBufferParsed = TRUE;
          }
        }

        break;
      case PciRootBridge:
        DEBUG ((DEBUG_INFO, "ParsePciRootBridge, index :%x \n", index));
        ParsePciRootBridge (Fdt, Node, RootBridgeCount, GmaStr, &index);
        DEBUG ((DEBUG_INFO, "After ParsePciRootBridge, index :%x\n", index));
        break;
      case Options:
        // FIXME: Need to ensure this node gets parsed first so that it gets
        // correct options to feed into other init like PciEnumDone etc.
        DEBUG ((DEBUG_INFO, "ParseOptions\n"));
        ParseOptions (Fdt, Node, &PciEnumDone, &BootMode);
        break;
      default:
        DEBUG ((DEBUG_INFO, "ParseNothing\n"));
        break;
    }
  }

  if ((NULL != mPciRootBridgeInfo) && (NULL != mUplPciSegmentInfoHob)) {
    // Post processing: TODO: Need to look into it. Such cross dependency on DT nodes
    // may not be good idea. Instead have this prop part of RB
    mPciRootBridgeInfo->ResourceAssigned = (BOOLEAN)PciEnumDone;

    //
    // Assign PCI Segment number after all root bridge info ready
    //
    SegmentNumber                   = 0;
    RbSegNumAlreadyAssigned         = AllocateZeroPool (sizeof (UINT8) * RootBridgeCount);
    NextPciBaseAddress              = 0;
    NumberOfRbSegNumAlreadyAssigned = 0;

    //
    // Always assign first root bridge segment number as 0
    //
    CurrentPciBaseAddress                               = mUplPciSegmentInfoHob->SegmentInfo[0].BaseAddress & ~0xFFFFFFF;
    NextPciBaseAddress                                  = CurrentPciBaseAddress;
    mUplPciSegmentInfoHob->SegmentInfo[0].SegmentNumber = SegmentNumber;
    mPciRootBridgeInfo->RootBridge[0].Segment           = SegmentNumber;
    RbSegNumAlreadyAssigned[0]                          = 1;
    NumberOfRbSegNumAlreadyAssigned++;

    while (NumberOfRbSegNumAlreadyAssigned < RootBridgeCount) {
      for (index = 1; index < RootBridgeCount; index++) {
        if (RbSegNumAlreadyAssigned[index] == 1) {
          continue;
        }

        if (CurrentPciBaseAddress == (mUplPciSegmentInfoHob->SegmentInfo[index].BaseAddress & ~0xFFFFFFF)) {
          mUplPciSegmentInfoHob->SegmentInfo[index].SegmentNumber = SegmentNumber;
          mPciRootBridgeInfo->RootBridge[index].Segment           = SegmentNumber;
          RbSegNumAlreadyAssigned[index]                          = 1;
          NumberOfRbSegNumAlreadyAssigned++;
        } else if (CurrentPciBaseAddress == NextPciBaseAddress) {
          NextPciBaseAddress = mUplPciSegmentInfoHob->SegmentInfo[index].BaseAddress & ~0xFFFFFFF;
        }
      }

      SegmentNumber++;
      CurrentPciBaseAddress = NextPciBaseAddress;
    }
  }

  ((EFI_HOB_HANDOFF_INFO_TABLE *)(mHobList))->BootMode = BootMode;
  DEBUG ((DEBUG_INFO, "\n"));

  return NewHobList;
}

/**
  It will Parse FDT -node based on information from bootloaders.

  @param[in]  FdtBase   The starting memory address of FdtBase

  @retval HobList   The base address of Hoblist.
**/
UINTN
EFIAPI
FdtNodeParser (
  IN VOID  *FdtBase
  )
{
  return ParseDtb (FdtBase);
}

/**
  It will initialize HOBs for UPL.

  @param[in]  FdtBase        Address of the Fdt data.

  @retval EFI_SUCCESS        If it completed successfully.
  @retval Others             If it failed to initialize HOBs.
**/
UINTN
EFIAPI
UplInitHob (
  IN VOID  *FdtBase
  )
{
  UINTN  NHobAddress;

  NHobAddress = 0;
  //
  // Check parameter type
  //
  if (FdtCheckHeader (FdtBase) == 0) {
    DEBUG ((DEBUG_INFO, "%a() FDT blob\n", __func__));
    NHobAddress = FdtNodeParser ((VOID *)FdtBase);
  } else {
    DEBUG ((DEBUG_INFO, "%a() HOb list\n", __func__));
    mHobList = FdtBase;

    return (UINTN)(mHobList);
  }

  return NHobAddress;
}
