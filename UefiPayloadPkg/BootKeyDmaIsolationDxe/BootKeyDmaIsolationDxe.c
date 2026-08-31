/** @file
  VT-d DMA bounce isolation for the boot-key security boundary.

  The measured coreboot/FSP handoff protects DRAM with VT-d Protected Memory
  Regions while this driver builds requester-ID translation tables. ACS source
  validation makes the xHCI requester identity trustworthy before PMR is
  replaced with translation. EDKII_IOMMU mappings are bounced through one
  reserved arena and cannot expose DXE code, stacks, TPM state, or the boot-key
  transaction to DMA.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <IndustryStandard/Pci.h>
#include <IndustryStandard/PciExpress21.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyIntelClientPlatformLib.h>
#include <Library/CbMemLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/PciSegmentLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BootKeyDmaIsolation.h>
#include <Protocol/IoMmu.h>
#include <Protocol/PciIo.h>

#define VTD_VERSION_REGISTER          0x00
#define VTD_CAPABILITY_REGISTER       0x08
#define VTD_EXT_CAPABILITY_REGISTER   0x10
#define VTD_GLOBAL_COMMAND_REGISTER   0x18
#define VTD_GLOBAL_STATUS_REGISTER    0x1c
#define VTD_ROOT_TABLE_REGISTER       0x20
#define VTD_CONTEXT_COMMAND_REGISTER  0x28
#define VTD_FAULT_STATUS_REGISTER     0x34
#define VTD_PROTECTED_MEMORY_ENABLE   0x64
#define VTD_LOW_MEMORY_BASE           0x68
#define VTD_LOW_MEMORY_LIMIT          0x6c
#define VTD_HIGH_MEMORY_BASE          0x70
#define VTD_HIGH_MEMORY_LIMIT         0x78

#define VTD_CAPABILITY_LOW_PMR         BIT5
#define VTD_CAPABILITY_HIGH_PMR        BIT6
#define VTD_CAPABILITY_RWBF            BIT4
#define VTD_CAPABILITY_SAGAW_4_LEVEL   BIT10
#define VTD_GLOBAL_COMMAND_QIE         BIT26
#define VTD_GLOBAL_COMMAND_WBF         BIT27
#define VTD_GLOBAL_COMMAND_SRTP        BIT30
#define VTD_GLOBAL_COMMAND_TE          BIT31
#define VTD_GLOBAL_STATUS_QIES         BIT26
#define VTD_GLOBAL_STATUS_WBFS         BIT27
#define VTD_GLOBAL_STATUS_RTPS         BIT30
#define VTD_GLOBAL_STATUS_TES          BIT31
#define VTD_GLOBAL_COMMAND_STATE_MASK  0x96ffffffU
#define VTD_CONTEXT_COMMAND_GLOBAL     BIT61
#define VTD_CONTEXT_COMMAND_MASK       (BIT61 | BIT62)
#define VTD_CONTEXT_COMMAND_INVALID    BIT63
#define VTD_IOTLB_COMMAND_GLOBAL       BIT60
#define VTD_IOTLB_COMMAND_MASK         (BIT60 | BIT61)
#define VTD_IOTLB_COMMAND_WRITE_DRAIN  BIT48
#define VTD_IOTLB_COMMAND_READ_DRAIN   BIT49
#define VTD_IOTLB_COMMAND_INVALID      BIT63
#define VTD_PMR_ENABLE                 BIT31
#define VTD_PMR_STATUS                 BIT0
#define VTD_FAULT_ERROR_MASK           (BIT0 | BIT1 | BIT2 | BIT3 | BIT4 | BIT5 | BIT6)
#define VTD_ROOT_ENTRY_COUNT         256
#define VTD_CONTEXT_ENTRY_COUNT      256
#define VTD_ENTRY_SIZE               16
#define VTD_ROOT_TABLE_PAGES         1
#define VTD_CONTEXT_TABLE_PAGES      VTD_ROOT_ENTRY_COUNT
#define VTD_SLPT_PD_PAGES            2
#define VTD_SLPT_FIXED_PAGES         (2 + VTD_SLPT_PD_PAGES)
#define VTD_SLPT_MAX_PT_PAGES        9
#define VTD_SLPT_PAGES               (VTD_SLPT_FIXED_PAGES + VTD_SLPT_MAX_PT_PAGES)
#define VTD_PAGE_ADDRESS_MASK        0x000ffffffffff000ULL
#define VTD_PAGE_READ                BIT0
#define VTD_PAGE_WRITE               BIT1
#define VTD_CONTEXT_PRESENT          BIT0
#define VTD_CONTEXT_ADDRESS_WIDTH_4  2
#define VTD_CONTEXT_DOMAIN_ID        1

#define PCI_CAPABILITY_MIN_OFFSET      0x40
#define PCI_CAPABILITY_MAX_OFFSET      0xfc
#define PCI_EXT_CAPABILITY_MIN_OFFSET  0x100
#define PCI_EXT_CAPABILITY_MAX_OFFSET  0xffc
#define PCI_EXT_CAPABILITY_ID_MASK     0xffffU
#define PCI_EXT_CAPABILITY_NEXT_MASK   0xfff00000U
#define PCI_EXT_CAPABILITY_NEXT_SHIFT  20
#define PCI_ACS_CAPABILITY_OFFSET      4
#define PCI_ACS_CONTROL_OFFSET         6
#define PCI_ACS_SOURCE_VALIDATION      BIT0

#define BOOT_KEY_DMA_MAX_ARENA_SIZE   SIZE_16MB
#define BOOT_KEY_DMA_MAX_ARENA_PAGES  EFI_SIZE_TO_PAGES (BOOT_KEY_DMA_MAX_ARENA_SIZE)
#define BOOT_KEY_DMA_BITMAP_WORDS     (BOOT_KEY_DMA_MAX_ARENA_PAGES / 64)

#define BOOT_KEY_DMA_MAP_SIGNATURE  SIGNATURE_64 ('B', 'K', 'D', 'M', 'A', 'P', '0', '1')
#define BOOT_KEY_DMA_ALLOCATION_SIGNATURE \
  SIGNATURE_64 ('B', 'K', 'D', 'A', 'L', 'L', '0', '1')

#define INTEL_CLIENT_XHCI_SEGMENT   0
#define INTEL_CLIENT_XHCI_BUS       0
#define INTEL_CLIENT_XHCI_DEVICE    0x14
#define INTEL_CLIENT_XHCI_FUNCTION  0

typedef struct {
  UINT64                   Signature;
  LIST_ENTRY               Link;
  EDKII_IOMMU_OPERATION    Operation;
  VOID                     *HostAddress;
  UINTN                    NumberOfBytes;
  EFI_PHYSICAL_ADDRESS     DeviceAddress;
  UINTN                    ArenaPage;
  UINTN                    ArenaPages;
  BOOLEAN                  Direct;
} BOOT_KEY_DMA_MAP;

typedef struct {
  UINT64        Signature;
  LIST_ENTRY    Link;
  VOID          *HostAddress;
  UINTN         ArenaPage;
  UINTN         Pages;
} BOOT_KEY_DMA_ALLOCATION;

STATIC EFI_PHYSICAL_ADDRESS  mDmaArenaBase;
STATIC UINTN                 mDmaArenaSize;
STATIC UINTN                 mDmaArenaPages;
STATIC UINT64                mDmaArenaBitmap[BOOT_KEY_DMA_BITMAP_WORDS];
STATIC LIST_ENTRY            mDmaMaps;
STATIC LIST_ENTRY            mDmaAllocations;
STATIC BOOLEAN               mPostGateDevicesAuthorized;
STATIC UINTN                 mVtdBaseAddress;
STATIC UINT32                mLowPmrLimitGranularity;
STATIC UINT64                mHighPmrLimitGranularity;
STATIC UINT64                *mVtdRootTable;
STATIC UINT8                 *mVtdContextTables;
STATIC UINT64                *mVtdSlpt;

STATIC
EFI_STATUS
BootKeyDmaFindPciCapability (
  IN  UINT64  PciAddress,
  IN  UINT8   CapabilityId,
  OUT UINTN   *CapabilityOffset
  )
{
  UINT8  Offset;
  UINTN  Iteration;

  *CapabilityOffset = 0;
  if ((PciSegmentRead16 (PciAddress + PCI_PRIMARY_STATUS_OFFSET) &
       EFI_PCI_STATUS_CAPABILITY) == 0)
  {
    return EFI_NOT_FOUND;
  }

  Offset = PciSegmentRead8 (PciAddress + PCI_CAPABILITY_POINTER_OFFSET);
  for (Iteration = 0; Iteration < 48; Iteration++) {
    Offset &= (UINT8) ~0x3U;
    if ((Offset < PCI_CAPABILITY_MIN_OFFSET) ||
        (Offset > PCI_CAPABILITY_MAX_OFFSET))
    {
      return EFI_COMPROMISED_DATA;
    }

    if (PciSegmentRead8 (PciAddress + Offset) == CapabilityId) {
      *CapabilityOffset = Offset;
      return EFI_SUCCESS;
    }

    Offset = PciSegmentRead8 (PciAddress + Offset + 1);
    if (Offset == 0) {
      return EFI_NOT_FOUND;
    }
  }

  return EFI_COMPROMISED_DATA;
}

STATIC
EFI_STATUS
BootKeyDmaFindPciExtendedCapability (
  IN  UINT64  PciAddress,
  IN  UINT16  CapabilityId,
  OUT UINTN   *CapabilityOffset
  )
{
  UINT32  Header;
  UINTN   Next;
  UINTN   Offset;
  UINTN   Iteration;

  *CapabilityOffset = 0;
  Offset            = PCI_EXT_CAPABILITY_MIN_OFFSET;
  for (Iteration = 0; Iteration < 960; Iteration++) {
    Header = PciSegmentRead32 (PciAddress + Offset);
    if ((Header == 0) || (Header == MAX_UINT32)) {
      return EFI_NOT_FOUND;
    }

    if ((Header & PCI_EXT_CAPABILITY_ID_MASK) == CapabilityId) {
      *CapabilityOffset = Offset;
      return EFI_SUCCESS;
    }

    Next = (Header & PCI_EXT_CAPABILITY_NEXT_MASK) >>
           PCI_EXT_CAPABILITY_NEXT_SHIFT;
    if (Next == 0) {
      return EFI_NOT_FOUND;
    }

    if (((Next & 0x3) != 0) ||
        (Next < PCI_EXT_CAPABILITY_MIN_OFFSET) ||
        (Next > PCI_EXT_CAPABILITY_MAX_OFFSET) || (Next <= Offset))
    {
      return EFI_COMPROMISED_DATA;
    }

    Offset = Next;
  }

  return EFI_COMPROMISED_DATA;
}

STATIC
EFI_STATUS
BootKeyDmaConfigureAcsSourceValidation (
  IN BOOLEAN  Enable
  )
{
  UINT16      AcsCapability;
  UINT16      AcsControl;
  UINT16      PcieCapability;
  UINTN       AcsOffset;
  UINTN       Device;
  UINTN       Function;
  UINTN       PcieOffset;
  UINT64      PciAddress;
  UINT8       PrimaryBus;
  UINT8       SecondaryBus;
  UINT8       SubordinateBus;
  EFI_STATUS  Status;

  for (Device = 0; Device <= PCI_MAX_DEVICE; Device++) {
    for (Function = 0; Function <= PCI_MAX_FUNC; Function++) {
      PciAddress = PCI_SEGMENT_LIB_ADDRESS (0, 0, Device, Function, 0);
      if (PciSegmentRead16 (PciAddress + PCI_VENDOR_ID_OFFSET) == MAX_UINT16) {
        continue;
      }

      if ((PciSegmentRead8 (PciAddress + PCI_CLASSCODE_OFFSET + 2) !=
           PCI_CLASS_BRIDGE) ||
          (PciSegmentRead8 (PciAddress + PCI_CLASSCODE_OFFSET + 1) !=
           PCI_CLASS_BRIDGE_P2P))
      {
        continue;
      }

      Status = BootKeyDmaFindPciCapability (
                 PciAddress,
                 PCI_EXPRESS_CAPABILITY_ID,
                 &PcieOffset
                 );
      if (EFI_ERROR (Status)) {
        return EFI_SECURITY_VIOLATION;
      }

      PcieCapability = PciSegmentRead16 (PciAddress + PcieOffset + 2);
      if (((PcieCapability >> 4) & 0xf) !=
          PCIE_DEVICE_PORT_TYPE_ROOT_PORT)
      {
        return EFI_SECURITY_VIOLATION;
      }

      PrimaryBus = PciSegmentRead8 (
                     PciAddress + PCI_BRIDGE_PRIMARY_BUS_REGISTER_OFFSET
                     );
      SecondaryBus = PciSegmentRead8 (
                       PciAddress + PCI_BRIDGE_SECONDARY_BUS_REGISTER_OFFSET
                       );
      SubordinateBus = PciSegmentRead8 (
                         PciAddress +
                         PCI_BRIDGE_SUBORDINATE_BUS_REGISTER_OFFSET
                         );
      if ((PrimaryBus != 0) || (SecondaryBus == 0) ||
          (SubordinateBus < SecondaryBus))
      {
        return EFI_SECURITY_VIOLATION;
      }

      Status = BootKeyDmaFindPciExtendedCapability (
                 PciAddress,
                 PCI_EXPRESS_EXTENDED_CAPABILITY_ACS_EXTENDED_ID,
                 &AcsOffset
                 );
      if (EFI_ERROR (Status)) {
        return EFI_SECURITY_VIOLATION;
      }

      AcsCapability = PciSegmentRead16 (
                        PciAddress + AcsOffset + PCI_ACS_CAPABILITY_OFFSET
                        );
      if ((AcsCapability & PCI_ACS_SOURCE_VALIDATION) == 0) {
        return EFI_SECURITY_VIOLATION;
      }

      AcsControl = PciSegmentRead16 (
                     PciAddress + AcsOffset + PCI_ACS_CONTROL_OFFSET
                     );
      if (Enable) {
        PciSegmentWrite16 (
          PciAddress + AcsOffset + PCI_ACS_CONTROL_OFFSET,
          AcsControl | PCI_ACS_SOURCE_VALIDATION
          );
        AcsControl = PciSegmentRead16 (
                       PciAddress + AcsOffset + PCI_ACS_CONTROL_OFFSET
                       );
      }

      if ((AcsControl & PCI_ACS_SOURCE_VALIDATION) == 0) {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }

  return EFI_SUCCESS;
}

STATIC
BOOLEAN
BootKeyDmaRangesOverlap (
  IN EFI_PHYSICAL_ADDRESS  FirstBase,
  IN UINTN                 FirstSize,
  IN EFI_PHYSICAL_ADDRESS  SecondBase,
  IN UINTN                 SecondSize
  )
{
  return (FirstBase < SecondBase + SecondSize) &&
         (SecondBase < FirstBase + FirstSize);
}

STATIC
EFI_STATUS
BootKeyDmaWaitMmio32 (
  IN UINTN   Address,
  IN UINT32  Mask,
  IN UINT32  Expected
  )
{
  UINTN  Iteration;

  for (Iteration = 0; Iteration < 1000000; Iteration++) {
    if ((MmioRead32 (Address) & Mask) == Expected) {
      return EFI_SUCCESS;
    }

    MicroSecondDelay (1);
  }

  return EFI_TIMEOUT;
}

STATIC
EFI_STATUS
BootKeyDmaWaitMmio64 (
  IN UINTN   Address,
  IN UINT64  Mask,
  IN UINT64  Expected
  )
{
  UINTN  Iteration;

  for (Iteration = 0; Iteration < 1000000; Iteration++) {
    if ((MmioRead64 (Address) & Mask) == Expected) {
      return EFI_SUCCESS;
    }

    MicroSecondDelay (1);
  }

  return EFI_TIMEOUT;
}

STATIC
EFI_STATUS
BootKeyDmaSetGlobalCommand (
  IN UINT32  Command,
  IN UINT32  Status,
  IN UINT32  Expected
  )
{
  UINT32  GlobalStatus;

  GlobalStatus = MmioRead32 (
                   mVtdBaseAddress + VTD_GLOBAL_STATUS_REGISTER
                   );
  MmioWrite32 (
    mVtdBaseAddress + VTD_GLOBAL_COMMAND_REGISTER,
    (GlobalStatus & VTD_GLOBAL_COMMAND_STATE_MASK) | Command
    );
  return BootKeyDmaWaitMmio32 (
           mVtdBaseAddress + VTD_GLOBAL_STATUS_REGISTER,
           Status,
           Expected
           );
}

STATIC
BOOLEAN
BootKeyDmaMemoryType (
  IN EFI_MEMORY_TYPE  Type
  )
{
  switch (Type) {
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
    case EfiRuntimeServicesCode:
    case EfiRuntimeServicesData:
    case EfiConventionalMemory:
    case EfiACPIReclaimMemory:
    case EfiACPIMemoryNVS:
    case EfiPersistentMemory:
      return TRUE;
    default:
      return FALSE;
  }
}

STATIC
EFI_STATUS
BootKeyDmaVerifyMemoryMap (
  IN UINT32  LowLimit,
  IN UINT64  HighBase,
  IN UINT64  HighLimit
  )
{
  EFI_MEMORY_DESCRIPTOR  *Descriptor;
  EFI_MEMORY_DESCRIPTOR  *MemoryMap;
  UINTN                  DescriptorSize;
  UINT64                 End;
  UINTN                  Index;
  UINTN                  MapKey;
  UINTN                  MemoryMapSize;
  UINT32                 DescriptorVersion;
  BOOLEAN                ArenaReserved;
  EFI_STATUS             Status;

  MemoryMap     = NULL;
  MemoryMapSize = 0;
  Status        = gBS->GetMemoryMap (
                         &MemoryMapSize,
                         MemoryMap,
                         &MapKey,
                         &DescriptorSize,
                         &DescriptorVersion
                         );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_DEVICE_ERROR;
  }

  if ((DescriptorSize < sizeof (*Descriptor)) ||
      (MemoryMapSize > MAX_UINTN - 2 * DescriptorSize))
  {
    return EFI_COMPROMISED_DATA;
  }

  MemoryMapSize += 2 * DescriptorSize;
  MemoryMap      = AllocatePool (MemoryMapSize);
  if (MemoryMap == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->GetMemoryMap (
                  &MemoryMapSize,
                  MemoryMap,
                  &MapKey,
                  &DescriptorSize,
                  &DescriptorVersion
                  );
  if (EFI_ERROR (Status)) {
    FreePool (MemoryMap);
    return Status;
  }

  ArenaReserved = FALSE;
  for (Index = 0; Index < MemoryMapSize / DescriptorSize; Index++) {
    Descriptor = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)MemoryMap +
                                           Index * DescriptorSize);
    if ((Descriptor->NumberOfPages > (MAX_UINT64 >> EFI_PAGE_SHIFT)) ||
        (Descriptor->PhysicalStart >
         MAX_UINT64 - EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages)))
    {
      Status = EFI_COMPROMISED_DATA;
      goto Done;
    }

    End = Descriptor->PhysicalStart +
          EFI_PAGES_TO_SIZE (Descriptor->NumberOfPages);
    if ((Descriptor->Type == EfiReservedMemoryType) &&
        (Descriptor->PhysicalStart <= mDmaArenaBase) &&
        (End >= mDmaArenaBase + mDmaArenaSize))
    {
      ArenaReserved = TRUE;
    }

    if (!BootKeyDmaMemoryType ((EFI_MEMORY_TYPE)Descriptor->Type) ||
        (Descriptor->NumberOfPages == 0))
    {
      continue;
    }

    if (Descriptor->PhysicalStart < SIZE_4GB) {
      if (MIN (End, SIZE_4GB) - 1 > LowLimit) {
        Status = EFI_SECURITY_VIOLATION;
        goto Done;
      }
    }

    if (End > SIZE_4GB) {
      if (((MmioRead32 (mVtdBaseAddress + VTD_CAPABILITY_REGISTER) &
            VTD_CAPABILITY_HIGH_PMR) == 0) ||
          (MAX (Descriptor->PhysicalStart, SIZE_4GB) < HighBase) ||
          (End - 1 > HighLimit))
      {
        Status = EFI_SECURITY_VIOLATION;
        goto Done;
      }
    }
  }

  Status = ArenaReserved ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;

Done:
  FreePool (MemoryMap);
  return Status;
}

STATIC
EFI_STATUS
BootKeyDmaVerifyPmr (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  DmaRangeBase;
  UINT32                DmaRangeSize;
  UINT32                LowBase;
  UINT32                LowLimit;
  UINT32                PmrEnable;
  UINT32                Version;
  UINT64                HighBase;
  UINT64                HighLimit;
  RETURN_STATUS         ReturnStatus;

  ReturnStatus = CbMemFindDmaRange (&DmaRangeBase, &DmaRangeSize);
  if (RETURN_ERROR (ReturnStatus) ||
      (DmaRangeBase != mDmaArenaBase) ||
      (DmaRangeSize != mDmaArenaSize))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Version = MmioRead32 (mVtdBaseAddress + VTD_VERSION_REGISTER);
  if ((Version == 0) || (Version == MAX_UINT32) ||
      ((MmioRead32 (mVtdBaseAddress + VTD_CAPABILITY_REGISTER) &
        VTD_CAPABILITY_LOW_PMR) == 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  PmrEnable = MmioRead32 (
                mVtdBaseAddress + VTD_PROTECTED_MEMORY_ENABLE
                );
  LowBase  = MmioRead32 (mVtdBaseAddress + VTD_LOW_MEMORY_BASE);
  LowLimit = MmioRead32 (mVtdBaseAddress + VTD_LOW_MEMORY_LIMIT);
  if (((PmrEnable & (VTD_PMR_ENABLE | VTD_PMR_STATUS)) !=
       (VTD_PMR_ENABLE | VTD_PMR_STATUS)) ||
      (LowBase != 0) ||
      ((UINT64)LowLimit + mLowPmrLimitGranularity != mDmaArenaBase) ||
      ((MmioRead32 (mVtdBaseAddress + VTD_FAULT_STATUS_REGISTER) &
        VTD_FAULT_ERROR_MASK) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  HighBase  = MmioRead64 (mVtdBaseAddress + VTD_HIGH_MEMORY_BASE);
  HighLimit = MmioRead64 (mVtdBaseAddress + VTD_HIGH_MEMORY_LIMIT);
  if ((HighBase != SIZE_4GB) ||
      (HighLimit < HighBase) ||
      ((HighLimit & (mHighPmrLimitGranularity - 1)) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  return BootKeyDmaVerifyMemoryMap (
           LowLimit | (mLowPmrLimitGranularity - 1),
           HighBase,
           HighLimit | (mHighPmrLimitGranularity - 1)
           );
}

STATIC
UINT64 *
BootKeyDmaContextEntry (
  IN UINTN  Bus,
  IN UINTN  Device,
  IN UINTN  Function
  )
{
  UINTN  ContextIndex;

  ContextIndex = (Device << 3) | Function;
  return (UINT64 *)(mVtdContextTables +
                    Bus * EFI_PAGE_SIZE +
                    ContextIndex * VTD_ENTRY_SIZE);
}

STATIC
EFI_STATUS
BootKeyDmaInvalidateVtdCaches (
  VOID
  )
{
  UINT64      Capability;
  UINT64      Command;
  UINT64      ExtendedCapability;
  UINTN       IotlbAddress;
  EFI_STATUS  Status;

  Capability = MmioRead64 (
                 mVtdBaseAddress + VTD_CAPABILITY_REGISTER
                 );
  if ((Capability & VTD_CAPABILITY_RWBF) != 0) {
    Status = BootKeyDmaSetGlobalCommand (
               VTD_GLOBAL_COMMAND_WBF,
               VTD_GLOBAL_STATUS_WBFS,
               0
               );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  Command = MmioRead64 (
              mVtdBaseAddress + VTD_CONTEXT_COMMAND_REGISTER
              );
  if ((Command & VTD_CONTEXT_COMMAND_INVALID) != 0) {
    return EFI_DEVICE_ERROR;
  }

  Command &= ~(VTD_CONTEXT_COMMAND_INVALID | VTD_CONTEXT_COMMAND_MASK);
  Command |= VTD_CONTEXT_COMMAND_INVALID | VTD_CONTEXT_COMMAND_GLOBAL;
  MmioWrite64 (
    mVtdBaseAddress + VTD_CONTEXT_COMMAND_REGISTER,
    Command
    );
  Status = BootKeyDmaWaitMmio64 (
             mVtdBaseAddress + VTD_CONTEXT_COMMAND_REGISTER,
             VTD_CONTEXT_COMMAND_INVALID,
             0
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ExtendedCapability = MmioRead64 (
                         mVtdBaseAddress +
                         VTD_EXT_CAPABILITY_REGISTER
                         );
  IotlbAddress = mVtdBaseAddress +
                 (((ExtendedCapability >> 8) & 0x3ff) * 16) + 8;
  if ((IotlbAddress < mVtdBaseAddress + PCI_EXT_CAPABILITY_MIN_OFFSET) ||
      (IotlbAddress > mVtdBaseAddress + PCI_EXT_CAPABILITY_MAX_OFFSET))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Command = MmioRead64 (IotlbAddress);
  if ((Command & VTD_IOTLB_COMMAND_INVALID) != 0) {
    return EFI_DEVICE_ERROR;
  }

  Command &= ~(VTD_IOTLB_COMMAND_INVALID | VTD_IOTLB_COMMAND_MASK);
  Command |= VTD_IOTLB_COMMAND_INVALID | VTD_IOTLB_COMMAND_GLOBAL;
  if ((Capability & BIT55) != 0) {
    Command |= VTD_IOTLB_COMMAND_READ_DRAIN;
  }

  if ((Capability & BIT54) != 0) {
    Command |= VTD_IOTLB_COMMAND_WRITE_DRAIN;
  }

  MmioWrite64 (IotlbAddress, Command);
  return BootKeyDmaWaitMmio64 (
           IotlbAddress,
           VTD_IOTLB_COMMAND_INVALID,
           0
           );
}

STATIC
EFI_STATUS
BootKeyDmaAuthorizeRequester (
  IN UINTN  Segment,
  IN UINTN  Bus,
  IN UINTN  Device,
  IN UINTN  Function
  )
{
  UINT64      *ContextEntry;
  UINT64      ExpectedHigh;
  UINT64      ExpectedLow;
  EFI_STATUS  Status;

  if ((Segment != 0) || (Bus > PCI_MAX_BUS) ||
      (Device > PCI_MAX_DEVICE) || (Function > PCI_MAX_FUNC) ||
      (mVtdContextTables == NULL) || (mVtdSlpt == NULL))
  {
    return EFI_SECURITY_VIOLATION;
  }

  ContextEntry = BootKeyDmaContextEntry (Bus, Device, Function);
  ExpectedLow  = ((UINT64)(UINTN)mVtdSlpt & VTD_PAGE_ADDRESS_MASK) |
                 VTD_CONTEXT_PRESENT;
  ExpectedHigh = VTD_CONTEXT_ADDRESS_WIDTH_4 |
                 LShiftU64 (VTD_CONTEXT_DOMAIN_ID, 8);
  if ((ContextEntry[0] != 0) || (ContextEntry[1] != 0)) {
    return ((ContextEntry[0] == ExpectedLow) &&
            (ContextEntry[1] == ExpectedHigh)) ?
           EFI_SUCCESS : EFI_SECURITY_VIOLATION;
  }

  ContextEntry[1] = ExpectedHigh;
  MemoryFence ();
  ContextEntry[0] = ExpectedLow;
  AsmWbinvd ();

  if ((MmioRead32 (mVtdBaseAddress + VTD_GLOBAL_STATUS_REGISTER) &
       VTD_GLOBAL_STATUS_TES) == 0)
  {
    return EFI_SUCCESS;
  }

  Status = BootKeyDmaInvalidateVtdCaches ();
  return EFI_ERROR (Status) ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyDmaBuildVtdTables (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  ContextBase;
  EFI_PHYSICAL_ADDRESS  RootBase;
  EFI_PHYSICAL_ADDRESS  SlptBase;
  UINT64                *ContextEntry;
  UINT64                *PageDirectory;
  UINT64                *PageDirectoryPointer;
  UINT64                *PageTable;
  UINT64                *Pml4;
  UINT64                Address;
  UINTN                 Bus;
  UINTN                 PageDirectoryIndex;
  UINTN                 PageDirectoryPage;
  UINTN                 PageDirectoryPointerIndex;
  UINTN                 PageTableIndex;
  UINTN                 PtPage;
  UINTN                 StartPageDirectoryIndex;
  UINTN                 StartPageDirectoryPointerIndex;

  mVtdRootTable = AllocateReservedPages (
                    VTD_ROOT_TABLE_PAGES + VTD_CONTEXT_TABLE_PAGES
                    );
  if (mVtdRootTable == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  mVtdContextTables = (UINT8 *)mVtdRootTable + EFI_PAGE_SIZE;
  mVtdSlpt          = AllocateReservedPages (VTD_SLPT_PAGES);
  if (mVtdSlpt == NULL) {
    FreePages (
      mVtdRootTable,
      VTD_ROOT_TABLE_PAGES + VTD_CONTEXT_TABLE_PAGES
      );
    mVtdRootTable     = NULL;
    mVtdContextTables = NULL;
    return EFI_OUT_OF_RESOURCES;
  }

  RootBase    = (EFI_PHYSICAL_ADDRESS)(UINTN)mVtdRootTable;
  ContextBase = (EFI_PHYSICAL_ADDRESS)(UINTN)mVtdContextTables;
  SlptBase    = (EFI_PHYSICAL_ADDRESS)(UINTN)mVtdSlpt;
  if ((((RootBase | ContextBase | SlptBase) & EFI_PAGE_MASK) != 0) ||
      (((RootBase | ContextBase | SlptBase) & ~VTD_PAGE_ADDRESS_MASK) != 0) ||
      BootKeyDmaRangesOverlap (
        RootBase,
        EFI_PAGES_TO_SIZE (
          VTD_ROOT_TABLE_PAGES + VTD_CONTEXT_TABLE_PAGES
          ),
        mDmaArenaBase,
        mDmaArenaSize
        ) ||
      BootKeyDmaRangesOverlap (
        SlptBase,
        EFI_PAGES_TO_SIZE (VTD_SLPT_PAGES),
        mDmaArenaBase,
        mDmaArenaSize
        ))
  {
    return EFI_SECURITY_VIOLATION;
  }

  ZeroMem (
    mVtdRootTable,
    EFI_PAGES_TO_SIZE (
      VTD_ROOT_TABLE_PAGES + VTD_CONTEXT_TABLE_PAGES
      )
    );
  ZeroMem (mVtdSlpt, EFI_PAGES_TO_SIZE (VTD_SLPT_PAGES));

  for (Bus = 0; Bus < VTD_ROOT_ENTRY_COUNT; Bus++) {
    mVtdRootTable[Bus * 2] =
      ((ContextBase + Bus * EFI_PAGE_SIZE) & VTD_PAGE_ADDRESS_MASK) |
      VTD_CONTEXT_PRESENT;
  }

  Pml4                 = mVtdSlpt;
  PageDirectoryPointer = mVtdSlpt + EFI_PAGE_SIZE / sizeof (UINT64);
  Pml4[0]              = ((UINT64)(UINTN)PageDirectoryPointer &
                          VTD_PAGE_ADDRESS_MASK) | VTD_PAGE_READ | VTD_PAGE_WRITE;

  StartPageDirectoryIndex        = (UINTN)(mDmaArenaBase >> 21);
  StartPageDirectoryPointerIndex = (UINTN)(mDmaArenaBase >> 30);
  for (Address = mDmaArenaBase;
       Address < mDmaArenaBase + mDmaArenaSize;
       Address += EFI_PAGE_SIZE)
  {
    PageDirectoryIndex        = (UINTN)(Address >> 21);
    PageDirectoryPointerIndex = (UINTN)(Address >> 30);
    PageDirectoryPage         = PageDirectoryPointerIndex -
                                StartPageDirectoryPointerIndex;
    if (PageDirectoryPage >= VTD_SLPT_PD_PAGES) {
      return EFI_SECURITY_VIOLATION;
    }

    PageDirectory = mVtdSlpt +
                    (2 + PageDirectoryPage) *
                    EFI_PAGE_SIZE / sizeof (UINT64);
    PageDirectoryPointer[PageDirectoryPointerIndex & 0x1ff] =
      ((UINT64)(UINTN)PageDirectory & VTD_PAGE_ADDRESS_MASK) |
      VTD_PAGE_READ | VTD_PAGE_WRITE;
    PtPage = PageDirectoryIndex - StartPageDirectoryIndex;
    if (PtPage >= VTD_SLPT_MAX_PT_PAGES) {
      return EFI_SECURITY_VIOLATION;
    }

    PageTable = mVtdSlpt +
                (VTD_SLPT_FIXED_PAGES + PtPage) *
                EFI_PAGE_SIZE / sizeof (UINT64);
    PageDirectory[PageDirectoryIndex & 0x1ff] =
      ((UINT64)(UINTN)PageTable & VTD_PAGE_ADDRESS_MASK) |
      VTD_PAGE_READ | VTD_PAGE_WRITE;
    PageTableIndex            = (UINTN)((Address >> EFI_PAGE_SHIFT) & 0x1ff);
    PageTable[PageTableIndex] = (Address & VTD_PAGE_ADDRESS_MASK) |
                                VTD_PAGE_READ | VTD_PAGE_WRITE;
  }

  ContextEntry = BootKeyDmaContextEntry (
                   INTEL_CLIENT_XHCI_BUS,
                   INTEL_CLIENT_XHCI_DEVICE,
                   INTEL_CLIENT_XHCI_FUNCTION
                   );
  ContextEntry[1] = VTD_CONTEXT_ADDRESS_WIDTH_4 |
                    LShiftU64 (VTD_CONTEXT_DOMAIN_ID, 8);
  ContextEntry[0] = (SlptBase & VTD_PAGE_ADDRESS_MASK) |
                    VTD_CONTEXT_PRESENT;
  AsmWbinvd ();
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyDmaEnableTranslation (
  VOID
  )
{
  UINT64      Capability;
  UINT32      GlobalStatus;
  UINT32      PmrEnable;
  EFI_STATUS  Status;

  Capability = MmioRead64 (
                 mVtdBaseAddress + VTD_CAPABILITY_REGISTER
                 );
  GlobalStatus = MmioRead32 (
                   mVtdBaseAddress + VTD_GLOBAL_STATUS_REGISTER
                   );
  if (((Capability & VTD_CAPABILITY_SAGAW_4_LEVEL) == 0) ||
      ((GlobalStatus & (VTD_GLOBAL_STATUS_TES | VTD_GLOBAL_STATUS_QIES)) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  MmioWrite64 (
    mVtdBaseAddress + VTD_ROOT_TABLE_REGISTER,
    (UINT64)(UINTN)mVtdRootTable
    );
  Status = BootKeyDmaSetGlobalCommand (
             VTD_GLOBAL_COMMAND_SRTP,
             VTD_GLOBAL_STATUS_RTPS,
             VTD_GLOBAL_STATUS_RTPS
             );
  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  Status = BootKeyDmaInvalidateVtdCaches ();
  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  Status = BootKeyDmaSetGlobalCommand (
             VTD_GLOBAL_COMMAND_TE,
             VTD_GLOBAL_STATUS_TES,
             VTD_GLOBAL_STATUS_TES
             );
  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  MmioWrite32 (
    mVtdBaseAddress + VTD_PROTECTED_MEMORY_ENABLE,
    0
    );
  Status = BootKeyDmaWaitMmio32 (
             mVtdBaseAddress + VTD_PROTECTED_MEMORY_ENABLE,
             VTD_PMR_STATUS,
             0
             );
  if (EFI_ERROR (Status)) {
    return EFI_DEVICE_ERROR;
  }

  PmrEnable = MmioRead32 (
                mVtdBaseAddress + VTD_PROTECTED_MEMORY_ENABLE
                );
  return ((PmrEnable & (VTD_PMR_ENABLE | VTD_PMR_STATUS)) == 0) ?
         EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}

STATIC
EFI_STATUS
BootKeyDmaVerifySlpt (
  VOID
  )
{
  UINT64  *Entries;
  UINT64  Address;
  UINT64  Expected;
  UINTN   EndPageDirectoryIndex;
  UINTN   EndPageDirectoryPointerIndex;
  UINTN   Index;
  UINTN   Page;
  UINTN   PageDirectoryIndex;
  UINTN   PageDirectoryPointerIndex;
  UINTN   StartPageDirectoryIndex;
  UINTN   StartPageDirectoryPointerIndex;

  StartPageDirectoryIndex = (UINTN)(mDmaArenaBase >> 21);
  EndPageDirectoryIndex   = (UINTN)(
                                    (mDmaArenaBase + mDmaArenaSize - 1) >> 21
                                    );
  StartPageDirectoryPointerIndex = (UINTN)(mDmaArenaBase >> 30);
  EndPageDirectoryPointerIndex   = (UINTN)(
                                           (mDmaArenaBase + mDmaArenaSize - 1) >> 30
                                           );
  if ((EndPageDirectoryIndex - StartPageDirectoryIndex >=
       VTD_SLPT_MAX_PT_PAGES) ||
      (EndPageDirectoryPointerIndex -
       StartPageDirectoryPointerIndex >= VTD_SLPT_PD_PAGES))
  {
    return EFI_SECURITY_VIOLATION;
  }

  for (Page = 0; Page < VTD_SLPT_PAGES; Page++) {
    Entries = mVtdSlpt + Page * EFI_PAGE_SIZE / sizeof (UINT64);
    for (Index = 0; Index < EFI_PAGE_SIZE / sizeof (UINT64); Index++) {
      Expected = 0;
      if ((Page == 0) && (Index == 0)) {
        Expected = ((UINT64)(UINTN)(mVtdSlpt +
                                    EFI_PAGE_SIZE / sizeof (UINT64)) &
                    VTD_PAGE_ADDRESS_MASK) |
                   VTD_PAGE_READ | VTD_PAGE_WRITE;
      } else if (Page == 1) {
        PageDirectoryPointerIndex = Index;
        if ((PageDirectoryPointerIndex >=
             StartPageDirectoryPointerIndex) &&
            (PageDirectoryPointerIndex <=
             EndPageDirectoryPointerIndex))
        {
          Expected = ((UINT64)(UINTN)(mVtdSlpt +
                                      (2 + PageDirectoryPointerIndex -
                                       StartPageDirectoryPointerIndex) *
                                      EFI_PAGE_SIZE / sizeof (UINT64)) &
                      VTD_PAGE_ADDRESS_MASK) |
                     VTD_PAGE_READ | VTD_PAGE_WRITE;
        }
      } else if (Page < VTD_SLPT_FIXED_PAGES) {
        PageDirectoryPointerIndex = StartPageDirectoryPointerIndex +
                                    Page - 2;
        PageDirectoryIndex = (PageDirectoryPointerIndex << 9) | Index;
        if ((PageDirectoryIndex >= StartPageDirectoryIndex) &&
            (PageDirectoryIndex <= EndPageDirectoryIndex))
        {
          Expected = ((UINT64)(UINTN)(mVtdSlpt +
                                      (VTD_SLPT_FIXED_PAGES +
                                       PageDirectoryIndex -
                                       StartPageDirectoryIndex) *
                                      EFI_PAGE_SIZE / sizeof (UINT64)) &
                      VTD_PAGE_ADDRESS_MASK) |
                     VTD_PAGE_READ | VTD_PAGE_WRITE;
        }
      } else {
        PageDirectoryIndex = StartPageDirectoryIndex +
                             Page - VTD_SLPT_FIXED_PAGES;
        Address = LShiftU64 (PageDirectoryIndex, 21) |
                  LShiftU64 (Index, EFI_PAGE_SHIFT);
        if ((Address >= mDmaArenaBase) &&
            (Address < mDmaArenaBase + mDmaArenaSize))
        {
          Expected = (Address & VTD_PAGE_ADDRESS_MASK) |
                     VTD_PAGE_READ | VTD_PAGE_WRITE;
        }
      }

      if (Entries[Index] != Expected) {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyDmaVerifyVtdTables (
  VOID
  )
{
  EFI_PHYSICAL_ADDRESS  ContextBase;
  UINT64                *ContextEntry;
  UINT64                ExpectedHigh;
  UINT64                ExpectedLow;
  UINT64                RootTableAddress;
  UINTN                 Bus;
  UINTN                 ContextIndex;

  if ((mVtdRootTable == NULL) || (mVtdContextTables == NULL) ||
      (mVtdSlpt == NULL))
  {
    return EFI_NOT_READY;
  }

  ContextBase = (EFI_PHYSICAL_ADDRESS)(UINTN)mVtdContextTables;
  for (Bus = 0; Bus < VTD_ROOT_ENTRY_COUNT; Bus++) {
    ExpectedLow = ((ContextBase + Bus * EFI_PAGE_SIZE) &
                   VTD_PAGE_ADDRESS_MASK) | VTD_CONTEXT_PRESENT;
    if ((mVtdRootTable[Bus * 2] != ExpectedLow) ||
        (mVtdRootTable[Bus * 2 + 1] != 0))
    {
      return EFI_SECURITY_VIOLATION;
    }

    for (ContextIndex = 0;
         ContextIndex < VTD_CONTEXT_ENTRY_COUNT;
         ContextIndex++)
    {
      ContextEntry = (UINT64 *)(mVtdContextTables +
                                Bus * EFI_PAGE_SIZE +
                                ContextIndex * VTD_ENTRY_SIZE);
      if ((ContextEntry[0] & VTD_CONTEXT_PRESENT) == 0) {
        if ((ContextEntry[0] != 0) || (ContextEntry[1] != 0)) {
          return EFI_SECURITY_VIOLATION;
        }

        continue;
      }

      if (!mPostGateDevicesAuthorized &&
          ((Bus != INTEL_CLIENT_XHCI_BUS) ||
           (ContextIndex != ((INTEL_CLIENT_XHCI_DEVICE << 3) |
                             INTEL_CLIENT_XHCI_FUNCTION))))
      {
        return EFI_SECURITY_VIOLATION;
      }

      ExpectedLow = ((UINT64)(UINTN)mVtdSlpt & VTD_PAGE_ADDRESS_MASK) |
                    VTD_CONTEXT_PRESENT;
      ExpectedHigh = VTD_CONTEXT_ADDRESS_WIDTH_4 |
                     LShiftU64 (VTD_CONTEXT_DOMAIN_ID, 8);
      if ((ContextEntry[0] != ExpectedLow) ||
          (ContextEntry[1] != ExpectedHigh))
      {
        return EFI_SECURITY_VIOLATION;
      }
    }
  }

  RootTableAddress = MmioRead64 (
                       mVtdBaseAddress + VTD_ROOT_TABLE_REGISTER
                       );
  if (((RootTableAddress & VTD_PAGE_ADDRESS_MASK) !=
       ((UINT64)(UINTN)mVtdRootTable & VTD_PAGE_ADDRESS_MASK)) ||
      ((RootTableAddress & ~VTD_PAGE_ADDRESS_MASK) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  return BootKeyDmaVerifySlpt ();
}

STATIC
EFI_STATUS
BootKeyDmaVerifyTranslation (
  VOID
  )
{
  UINT32      GlobalStatus;
  UINT32      PmrEnable;
  EFI_STATUS  Status;

  GlobalStatus = MmioRead32 (
                   mVtdBaseAddress + VTD_GLOBAL_STATUS_REGISTER
                   );
  PmrEnable = MmioRead32 (
                mVtdBaseAddress + VTD_PROTECTED_MEMORY_ENABLE
                );
  if (((GlobalStatus & VTD_GLOBAL_STATUS_TES) == 0) ||
      ((GlobalStatus & VTD_GLOBAL_STATUS_QIES) != 0) ||
      ((PmrEnable & (VTD_PMR_ENABLE | VTD_PMR_STATUS)) != 0) ||
      ((MmioRead32 (mVtdBaseAddress + VTD_FAULT_STATUS_REGISTER) &
        VTD_FAULT_ERROR_MASK) != 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Status = BootKeyDmaConfigureAcsSourceValidation (FALSE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return BootKeyDmaVerifyVtdTables ();
}

STATIC
BOOLEAN
BootKeyDmaPageAllocated (
  IN UINTN  Page
  )
{
  return (mDmaArenaBitmap[Page / 64] & LShiftU64 (1, Page % 64)) != 0;
}

STATIC
VOID
BootKeyDmaSetPageAllocated (
  IN UINTN    Page,
  IN BOOLEAN  Allocated
  )
{
  if (Allocated) {
    mDmaArenaBitmap[Page / 64] |= LShiftU64 (1, Page % 64);
  } else {
    mDmaArenaBitmap[Page / 64] &= ~LShiftU64 (1, Page % 64);
  }
}

STATIC
EFI_STATUS
BootKeyDmaAllocateArenaPages (
  IN  UINTN                 Pages,
  OUT UINTN                 *ArenaPage,
  OUT EFI_PHYSICAL_ADDRESS  *Address
  )
{
  EFI_TPL  OldTpl;
  UINTN    Candidate;
  UINTN    Index;

  if ((Pages == 0) || (Pages > mDmaArenaPages) ||
      (ArenaPage == NULL) || (Address == NULL))
  {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  for (Candidate = 0; Candidate <= mDmaArenaPages - Pages; Candidate++) {
    for (Index = 0; Index < Pages; Index++) {
      if (BootKeyDmaPageAllocated (Candidate + Index)) {
        break;
      }
    }

    if (Index != Pages) {
      Candidate += Index;
      continue;
    }

    for (Index = 0; Index < Pages; Index++) {
      BootKeyDmaSetPageAllocated (Candidate + Index, TRUE);
    }

    gBS->RestoreTPL (OldTpl);
    *ArenaPage = Candidate;
    *Address   = mDmaArenaBase + EFI_PAGES_TO_SIZE (Candidate);
    return EFI_SUCCESS;
  }

  gBS->RestoreTPL (OldTpl);
  return EFI_OUT_OF_RESOURCES;
}

STATIC
EFI_STATUS
BootKeyDmaFreeArenaPages (
  IN UINTN  ArenaPage,
  IN UINTN  Pages
  )
{
  EFI_TPL  OldTpl;
  UINTN    Index;

  if ((Pages == 0) || (ArenaPage >= mDmaArenaPages) ||
      (Pages > mDmaArenaPages - ArenaPage))
  {
    return EFI_INVALID_PARAMETER;
  }

  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  for (Index = 0; Index < Pages; Index++) {
    if (!BootKeyDmaPageAllocated (ArenaPage + Index)) {
      gBS->RestoreTPL (OldTpl);
      return EFI_INVALID_PARAMETER;
    }
  }

  for (Index = 0; Index < Pages; Index++) {
    BootKeyDmaSetPageAllocated (ArenaPage + Index, FALSE);
  }

  gBS->RestoreTPL (OldTpl);
  return EFI_SUCCESS;
}

STATIC
BOOLEAN
BootKeyDmaCommonBufferAllocated (
  IN VOID   *HostAddress,
  IN UINTN  NumberOfBytes
  )
{
  BOOT_KEY_DMA_ALLOCATION  *Allocation;
  LIST_ENTRY               *Link;
  UINTN                    Start;
  UINTN                    End;
  EFI_TPL                  OldTpl;
  BOOLEAN                  Found;

  Start = (UINTN)HostAddress;
  if ((NumberOfBytes == 0) || (Start > MAX_UINTN - NumberOfBytes)) {
    return FALSE;
  }

  End    = Start + NumberOfBytes;
  Found  = FALSE;
  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  for (Link = GetFirstNode (&mDmaAllocations);
       !IsNull (&mDmaAllocations, Link);
       Link = GetNextNode (&mDmaAllocations, Link))
  {
    Allocation = BASE_CR (Link, BOOT_KEY_DMA_ALLOCATION, Link);
    if ((Allocation->Signature == BOOT_KEY_DMA_ALLOCATION_SIGNATURE) &&
        (Start >= (UINTN)Allocation->HostAddress) &&
        (End <= (UINTN)Allocation->HostAddress +
         EFI_PAGES_TO_SIZE (Allocation->Pages)))
    {
      Found = TRUE;
      break;
    }
  }

  gBS->RestoreTPL (OldTpl);
  return Found;
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaMap (
  IN     EDKII_IOMMU_PROTOCOL   *This,
  IN     EDKII_IOMMU_OPERATION  Operation,
  IN     VOID                   *HostAddress,
  IN OUT UINTN                  *NumberOfBytes,
  OUT    EFI_PHYSICAL_ADDRESS   *DeviceAddress,
  OUT    VOID                   **Mapping
  )
{
  BOOT_KEY_DMA_MAP      *Map;
  EFI_PHYSICAL_ADDRESS  BounceAddress;
  EFI_TPL               OldTpl;
  EFI_STATUS            Status;

  if ((HostAddress == NULL) || (NumberOfBytes == NULL) ||
      (DeviceAddress == NULL) || (Mapping == NULL) ||
      (*NumberOfBytes == 0) ||
      ((UINTN)HostAddress > MAX_UINTN - *NumberOfBytes) ||
      (Operation >= EdkiiIoMmuOperationMaximum))
  {
    return EFI_INVALID_PARAMETER;
  }

  Map = AllocateZeroPool (sizeof (*Map));
  if (Map == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Map->Signature     = BOOT_KEY_DMA_MAP_SIGNATURE;
  Map->Operation     = Operation;
  Map->HostAddress   = HostAddress;
  Map->NumberOfBytes = *NumberOfBytes;
  Map->ArenaPages    = EFI_SIZE_TO_PAGES (*NumberOfBytes);

  if ((Operation == EdkiiIoMmuOperationBusMasterCommonBuffer) ||
      (Operation == EdkiiIoMmuOperationBusMasterCommonBuffer64))
  {
    if (!BootKeyDmaCommonBufferAllocated (HostAddress, *NumberOfBytes)) {
      FreePool (Map);
      return EFI_UNSUPPORTED;
    }

    Map->Direct        = TRUE;
    Map->DeviceAddress = (EFI_PHYSICAL_ADDRESS)(UINTN)HostAddress;
  } else {
    Status = BootKeyDmaAllocateArenaPages (
               Map->ArenaPages,
               &Map->ArenaPage,
               &BounceAddress
               );
    if (EFI_ERROR (Status)) {
      FreePool (Map);
      return Status;
    }

    Map->DeviceAddress = BounceAddress;
    ZeroMem ((VOID *)(UINTN)BounceAddress, EFI_PAGES_TO_SIZE (Map->ArenaPages));
    if ((Operation == EdkiiIoMmuOperationBusMasterRead) ||
        (Operation == EdkiiIoMmuOperationBusMasterRead64))
    {
      CopyMem ((VOID *)(UINTN)BounceAddress, HostAddress, *NumberOfBytes);
    }
  }

  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  InsertTailList (&mDmaMaps, &Map->Link);
  gBS->RestoreTPL (OldTpl);
  *DeviceAddress = Map->DeviceAddress;
  *Mapping       = Map;
  return EFI_SUCCESS;
}

STATIC
BOOLEAN
BootKeyDmaMapTracked (
  IN BOOT_KEY_DMA_MAP  *Map
  )
{
  LIST_ENTRY  *Link;

  for (Link = GetFirstNode (&mDmaMaps);
       !IsNull (&mDmaMaps, Link);
       Link = GetNextNode (&mDmaMaps, Link))
  {
    if (Link == &Map->Link) {
      return Map->Signature == BOOT_KEY_DMA_MAP_SIGNATURE;
    }
  }

  return FALSE;
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaUnmap (
  IN EDKII_IOMMU_PROTOCOL  *This,
  IN VOID                  *Mapping
  )
{
  BOOT_KEY_DMA_MAP  *Map;
  EFI_TPL           OldTpl;
  EFI_STATUS        Status;

  if (Mapping == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Map    = (BOOT_KEY_DMA_MAP *)Mapping;
  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  if (!BootKeyDmaMapTracked (Map)) {
    gBS->RestoreTPL (OldTpl);
    return EFI_INVALID_PARAMETER;
  }

  RemoveEntryList (&Map->Link);
  gBS->RestoreTPL (OldTpl);

  if (!Map->Direct) {
    if ((Map->Operation == EdkiiIoMmuOperationBusMasterWrite) ||
        (Map->Operation == EdkiiIoMmuOperationBusMasterWrite64))
    {
      CopyMem (
        Map->HostAddress,
        (VOID *)(UINTN)Map->DeviceAddress,
        Map->NumberOfBytes
        );
    }

    ZeroMem (
      (VOID *)(UINTN)Map->DeviceAddress,
      EFI_PAGES_TO_SIZE (Map->ArenaPages)
      );
    Status = BootKeyDmaFreeArenaPages (Map->ArenaPage, Map->ArenaPages);
    if (EFI_ERROR (Status)) {
      Map->Signature = 0;
      FreePool (Map);
      return EFI_DEVICE_ERROR;
    }
  }

  Map->Signature = 0;
  FreePool (Map);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaAllocateBuffer (
  IN     EDKII_IOMMU_PROTOCOL  *This,
  IN     EFI_ALLOCATE_TYPE     Type,
  IN     EFI_MEMORY_TYPE       MemoryType,
  IN     UINTN                 Pages,
  IN OUT VOID                  **HostAddress,
  IN     UINT64                Attributes
  )
{
  BOOT_KEY_DMA_ALLOCATION  *Allocation;
  EFI_PHYSICAL_ADDRESS     Address;
  EFI_TPL                  OldTpl;
  EFI_STATUS               Status;

  if ((Attributes & EDKII_IOMMU_ATTRIBUTE_INVALID_FOR_ALLOCATE_BUFFER) != 0) {
    return EFI_UNSUPPORTED;
  }

  if ((HostAddress == NULL) || (Pages == 0) ||
      ((MemoryType != EfiBootServicesData) &&
       (MemoryType != EfiRuntimeServicesData)))
  {
    return EFI_INVALID_PARAMETER;
  }

  Allocation = AllocateZeroPool (sizeof (*Allocation));
  if (Allocation == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = BootKeyDmaAllocateArenaPages (
             Pages,
             &Allocation->ArenaPage,
             &Address
             );
  if (EFI_ERROR (Status)) {
    FreePool (Allocation);
    return Status;
  }

  Allocation->Signature   = BOOT_KEY_DMA_ALLOCATION_SIGNATURE;
  Allocation->HostAddress = (VOID *)(UINTN)Address;
  Allocation->Pages       = Pages;
  ZeroMem (Allocation->HostAddress, EFI_PAGES_TO_SIZE (Pages));
  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  InsertTailList (&mDmaAllocations, &Allocation->Link);
  gBS->RestoreTPL (OldTpl);
  *HostAddress = Allocation->HostAddress;
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaFreeBuffer (
  IN EDKII_IOMMU_PROTOCOL  *This,
  IN UINTN                 Pages,
  IN VOID                  *HostAddress
  )
{
  BOOT_KEY_DMA_ALLOCATION  *Allocation;
  LIST_ENTRY               *Link;
  EFI_TPL                  OldTpl;
  EFI_STATUS               Status;

  if ((HostAddress == NULL) || (Pages == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  Allocation = NULL;
  OldTpl     = gBS->RaiseTPL (TPL_NOTIFY);
  for (Link = GetFirstNode (&mDmaAllocations);
       !IsNull (&mDmaAllocations, Link);
       Link = GetNextNode (&mDmaAllocations, Link))
  {
    Allocation = BASE_CR (Link, BOOT_KEY_DMA_ALLOCATION, Link);
    if ((Allocation->Signature == BOOT_KEY_DMA_ALLOCATION_SIGNATURE) &&
        (Allocation->HostAddress == HostAddress) &&
        (Allocation->Pages == Pages))
    {
      RemoveEntryList (&Allocation->Link);
      break;
    }

    Allocation = NULL;
  }

  gBS->RestoreTPL (OldTpl);
  if (Allocation == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (HostAddress, EFI_PAGES_TO_SIZE (Pages));
  Status                = BootKeyDmaFreeArenaPages (Allocation->ArenaPage, Pages);
  Allocation->Signature = 0;
  FreePool (Allocation);
  return EFI_ERROR (Status) ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

STATIC
EFI_STATUS
BootKeyDmaValidateDevice (
  IN  EFI_HANDLE  DeviceHandle,
  OUT UINTN       *Segment,
  OUT UINTN       *Bus,
  OUT UINTN       *Device,
  OUT UINTN       *Function
  )
{
  EFI_PCI_IO_PROTOCOL  *PciIo;
  EFI_STATUS           Status;

  PciIo  = NULL;
  Status = gBS->HandleProtocol (
                  DeviceHandle,
                  &gEfiPciIoProtocolGuid,
                  (VOID **)&PciIo
                  );
  if (EFI_ERROR (Status) || (PciIo == NULL)) {
    return EFI_UNSUPPORTED;
  }

  Status = PciIo->GetLocation (PciIo, Segment, Bus, Device, Function);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (!mPostGateDevicesAuthorized &&
      ((*Segment != INTEL_CLIENT_XHCI_SEGMENT) || (*Bus != INTEL_CLIENT_XHCI_BUS) ||
       (*Device != INTEL_CLIENT_XHCI_DEVICE) || (*Function != INTEL_CLIENT_XHCI_FUNCTION)))
  {
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaSetAttribute (
  IN EDKII_IOMMU_PROTOCOL  *This,
  IN EFI_HANDLE            DeviceHandle,
  IN VOID                  *Mapping,
  IN UINT64                IoMmuAccess
  )
{
  BOOT_KEY_DMA_MAP  *Map;
  UINTN             Bus;
  UINTN             Device;
  UINTN             Function;
  EFI_TPL           OldTpl;
  UINTN             Segment;
  EFI_STATUS        Status;
  UINT64            RequiredAccess;

  if ((Mapping == NULL) ||
      ((IoMmuAccess & ~(EDKII_IOMMU_ACCESS_READ |
                        EDKII_IOMMU_ACCESS_WRITE)) != 0))
  {
    return EFI_INVALID_PARAMETER;
  }

  Map    = (BOOT_KEY_DMA_MAP *)Mapping;
  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  if (!BootKeyDmaMapTracked (Map)) {
    gBS->RestoreTPL (OldTpl);
    return EFI_INVALID_PARAMETER;
  }

  switch (Map->Operation) {
    case EdkiiIoMmuOperationBusMasterRead:
    case EdkiiIoMmuOperationBusMasterRead64:
      RequiredAccess = EDKII_IOMMU_ACCESS_READ;
      break;
    case EdkiiIoMmuOperationBusMasterWrite:
    case EdkiiIoMmuOperationBusMasterWrite64:
      RequiredAccess = EDKII_IOMMU_ACCESS_WRITE;
      break;
    case EdkiiIoMmuOperationBusMasterCommonBuffer:
    case EdkiiIoMmuOperationBusMasterCommonBuffer64:
      RequiredAccess = EDKII_IOMMU_ACCESS_READ | EDKII_IOMMU_ACCESS_WRITE;
      break;
    default:
      gBS->RestoreTPL (OldTpl);
      return EFI_UNSUPPORTED;
  }

  gBS->RestoreTPL (OldTpl);
  if (IoMmuAccess == 0) {
    return EFI_SUCCESS;
  }

  if (IoMmuAccess != RequiredAccess) {
    return EFI_INVALID_PARAMETER;
  }

  Status = BootKeyDmaValidateDevice (
             DeviceHandle,
             &Segment,
             &Bus,
             &Device,
             &Function
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  OldTpl = gBS->RaiseTPL (TPL_NOTIFY);
  Status = BootKeyDmaAuthorizeRequester (
             Segment,
             Bus,
             Device,
             Function
             );
  gBS->RestoreTPL (OldTpl);
  return Status;
}

STATIC
EFI_STATUS
BootKeyDmaVerifyBusMastersDisabled (
  VOID
  )
{
  UINTN   Bus;
  UINTN   Device;
  UINTN   Function;
  UINT64  PciAddress;

  for (Bus = 0; Bus <= PCI_MAX_BUS; Bus++) {
    for (Device = 0; Device <= PCI_MAX_DEVICE; Device++) {
      for (Function = 0; Function <= PCI_MAX_FUNC; Function++) {
        PciAddress = PCI_SEGMENT_LIB_ADDRESS (
                       0,
                       Bus,
                       Device,
                       Function,
                       0
                       );
        if (PciSegmentRead16 (PciAddress + PCI_VENDOR_ID_OFFSET) == MAX_UINT16) {
          continue;
        }

        if ((PciSegmentRead16 (PciAddress + PCI_COMMAND_OFFSET) &
             EFI_PCI_COMMAND_BUS_MASTER) != 0)
        {
          return EFI_SECURITY_VIOLATION;
        }
      }
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaVerify (
  IN BOOT_KEY_DMA_ISOLATION_PROTOCOL  *This
  )
{
  return BootKeyDmaVerifyTranslation ();
}

STATIC
EFI_STATUS
EFIAPI
BootKeyDmaAuthorizePostGate (
  IN BOOT_KEY_DMA_ISOLATION_PROTOCOL  *This
  )
{
  EFI_STATUS  Status;

  Status = BootKeyDmaVerifyTranslation ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mPostGateDevicesAuthorized = TRUE;
  return EFI_SUCCESS;
}

STATIC EDKII_IOMMU_PROTOCOL  mIoMmu = {
  EDKII_IOMMU_PROTOCOL_REVISION,
  BootKeyDmaSetAttribute,
  BootKeyDmaMap,
  BootKeyDmaUnmap,
  BootKeyDmaAllocateBuffer,
  BootKeyDmaFreeBuffer
};

STATIC BOOT_KEY_DMA_ISOLATION_PROTOCOL  mDmaIsolation = {
  BOOT_KEY_DMA_ISOLATION_PROTOCOL_REVISION,
  BootKeyDmaVerify,
  BootKeyDmaAuthorizePostGate
};

EFI_STATUS
EFIAPI
BootKeyDmaIsolationEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  CONST BOOT_KEY_INTEL_CLIENT_PLATFORM  *Platform;
  EFI_PHYSICAL_ADDRESS                  DmaRangeBase;
  UINT32                                DmaRangeSize;
  EFI_HANDLE                            Handle;
  EFI_STATUS                            Status;
  RETURN_STATUS                         ReturnStatus;

  if (!FixedPcdGetBool (PcdBootKeyDmaIsolationRequired)) {
    return EFI_UNSUPPORTED;
  }

  Status = BootKeyGetIntelClientPlatform (&Platform);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mVtdBaseAddress          = Platform->IncludeAllVtdBaseAddress;
  mLowPmrLimitGranularity  = Platform->LowPmrLimitGranularity;
  mHighPmrLimitGranularity = Platform->HighPmrLimitGranularity;

  //
  // Require measured coreboot to quiesce all requesters while PMR is still
  // active. Translation then admits only Intel client xHCI to the arena until
  // boot-key authentication succeeds.
  //
  Status = BootKeyDmaVerifyBusMastersDisabled ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ReturnStatus = CbMemFindDmaRange (&DmaRangeBase, &DmaRangeSize);
  if (RETURN_ERROR (ReturnStatus) ||
      (DmaRangeSize != FixedPcdGet32 (PcdBootKeyDmaArenaSize)) ||
      (DmaRangeSize == 0) || (DmaRangeSize > BOOT_KEY_DMA_MAX_ARENA_SIZE) ||
      ((DmaRangeBase & EFI_PAGE_MASK) != 0) ||
      ((DmaRangeSize & EFI_PAGE_MASK) != 0) ||
      (DmaRangeBase > SIZE_4GB - DmaRangeSize))
  {
    return EFI_SECURITY_VIOLATION;
  }

  mDmaArenaBase  = DmaRangeBase;
  mDmaArenaSize  = DmaRangeSize;
  mDmaArenaPages = EFI_SIZE_TO_PAGES (DmaRangeSize);
  InitializeListHead (&mDmaMaps);
  InitializeListHead (&mDmaAllocations);
  ZeroMem (mDmaArenaBitmap, sizeof (mDmaArenaBitmap));

  Status = BootKeyDmaVerifyPmr ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  ZeroMem ((VOID *)(UINTN)mDmaArenaBase, mDmaArenaSize);

  Status = BootKeyDmaConfigureAcsSourceValidation (TRUE);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = BootKeyDmaBuildVtdTables ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = BootKeyDmaEnableTranslation ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = BootKeyDmaVerifyTranslation ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Handle = NULL;
  return gBS->InstallMultipleProtocolInterfaces (
                &Handle,
                &gEdkiiIoMmuProtocolGuid,
                &mIoMmu,
                &gBootKeyDmaIsolationProtocolGuid,
                &mDmaIsolation,
                NULL
                );
}
