/** @file
  Intel client boot-key hardware-boundary verifier.

  Copyright (c) 2026, Star Labs Systems. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <PiDxe.h>
#include <Uefi.h>

#include <IndustryStandard/Pci.h>
#include <IndustryStandard/TpmPtp.h>
#include <Register/Intel/Cpuid.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BootKeyPlatformSecurityLib.h>
#include <Library/DebugLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/PciSegmentLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BootKeyDmaIsolation.h>
#include <Protocol/MpService.h>

#define INTEL_ROOT_BRIDGE(Register)  PCI_SEGMENT_LIB_ADDRESS (0, 0, 0, 0, (Register))
#define INTEL_SPI_DEVICE(Register)   PCI_SEGMENT_LIB_ADDRESS (0, 0, 31, 5, (Register))

#define INTEL_SPI_VENDOR_ID               0x8086
#define INTEL_CPUID_FAMILY_MODEL_MASK      0xfffffff0U
#define INTEL_CPUID_ALDER_LAKE_N           0x000b06e0U
#define INTEL_CPUID_RAPTOR_LAKE_U          0x000b06a0U
#define INTEL_CPUID_METEOR_LAKE            0x000a06a0U
#define INFINEON_TPM_VENDOR_ID             0x15d1
#define SLB9670_DEVICE_ID                  0x001b
#define SLB9672_DEVICE_ID                  0x001d
#define TPM_BASE_ADDRESS                   0xfed40000U
#define INTEL_SA_SMRAMC                   0x88
#define INTEL_SA_SMRAMC_D_OPEN            BIT6
#define INTEL_SA_SMRAMC_D_LCK             BIT4
#define INTEL_SA_SMRAMC_G_SMRAME          BIT3
#define INTEL_SPI_BAR0                    0x10
#define INTEL_SPI_BAR_MASK                0xfffff000U
#define INTEL_SPI_BIOS_CONTROL            0xdc
#define INTEL_SPI_BIOS_CONTROL_WPD        BIT0
#define INTEL_SPI_BIOS_CONTROL_LE         BIT1
#define INTEL_SPI_BIOS_CONTROL_EISS       BIT5
#define INTEL_SPI_BIOS_CONTROL_BILD       BIT7
#define INTEL_SPI_BIOS_CONTROL_EXT_LOCK   BIT28
#define INTEL_SPI_HSFSTS_CTL              0x04
#define INTEL_SPI_HSFSTS_FDV              BIT14
#define INTEL_SPI_HSFSTS_FLOCKDN          BIT15
#define INTEL_MSR_SMRR_PHYSBASE           0x1f2
#define INTEL_MSR_SMRR_PHYSMASK           0x1f3
#define INTEL_MSR_SMRR_MASK_LOCK          BIT10
#define INTEL_MSR_SMRR_MASK_VALID         BIT11
#define INTEL_MSR_SMRR_MEMORY_TYPE_MASK   0xff
#define INTEL_MSR_SMRR_MEMORY_TYPE_WB     0x06
#define INTEL_MSR_SMRR_ADDRESS_MASK       0x00000000fffff000ULL
#define INTEL_MSR_SMRR_BASE_ALLOWED       (INTEL_MSR_SMRR_ADDRESS_MASK | INTEL_MSR_SMRR_MEMORY_TYPE_MASK)
#define INTEL_MSR_SMRR_MASK_ALLOWED       (INTEL_MSR_SMRR_ADDRESS_MASK | INTEL_MSR_SMRR_MASK_LOCK | INTEL_MSR_SMRR_MASK_VALID)

typedef struct {
  UINT64     Base;
  UINT64     Size;
  BOOLEAN    Valid;
} INTEL_SMRR_CHECK;

STATIC
EFI_STATUS
IntelClientVerifyProcessorBoundary (
  VOID
  )
{
  UINT32  Ebx;
  UINT32  Ecx;
  UINT32  Edx;
  UINT32  ProcessorFamilyModel;
  UINT32  ProcessorSignature;

  AsmCpuid (CPUID_SIGNATURE, NULL, &Ebx, &Ecx, &Edx);
  AsmCpuid (CPUID_VERSION_INFO, &ProcessorSignature, NULL, NULL, NULL);
  ProcessorFamilyModel = ProcessorSignature & INTEL_CPUID_FAMILY_MODEL_MASK;

  if ((Ebx != CPUID_SIGNATURE_GENUINE_INTEL_EBX) ||
      (Edx != CPUID_SIGNATURE_GENUINE_INTEL_EDX) ||
      (Ecx != CPUID_SIGNATURE_GENUINE_INTEL_ECX) ||
      ((ProcessorFamilyModel != INTEL_CPUID_ALDER_LAKE_N) &&
       (ProcessorFamilyModel != INTEL_CPUID_RAPTOR_LAKE_U) &&
       (ProcessorFamilyModel != INTEL_CPUID_METEOR_LAKE)))
  {
    DEBUG ((
      DEBUG_ERROR,
      "Boot-key Intel client requires ADL-N, RPL-U or MTL: CPUID=0x%08x\n",
      ProcessorSignature
      ));
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

STATIC
VOID
EFIAPI
IntelClientCheckSmrrOnProcessor (
  IN VOID  *Buffer
  )
{
  INTEL_SMRR_CHECK  *Check;
  UINT64            SmrrBase;
  UINT64            SmrrMask;
  UINT64            SmrrSize;

  Check    = Buffer;
  SmrrBase = AsmReadMsr64 (INTEL_MSR_SMRR_PHYSBASE);
  SmrrMask = AsmReadMsr64 (INTEL_MSR_SMRR_PHYSMASK);
  SmrrSize = ((~SmrrMask) & INTEL_MSR_SMRR_ADDRESS_MASK) + SIZE_4KB;

  if (((SmrrMask & (INTEL_MSR_SMRR_MASK_LOCK | INTEL_MSR_SMRR_MASK_VALID)) !=
       (INTEL_MSR_SMRR_MASK_LOCK | INTEL_MSR_SMRR_MASK_VALID)) ||
      ((SmrrBase & INTEL_MSR_SMRR_MEMORY_TYPE_MASK) !=
       INTEL_MSR_SMRR_MEMORY_TYPE_WB) ||
      ((SmrrBase & ~INTEL_MSR_SMRR_BASE_ALLOWED) != 0) ||
      ((SmrrMask & ~INTEL_MSR_SMRR_MASK_ALLOWED) != 0) ||
      ((SmrrBase & INTEL_MSR_SMRR_ADDRESS_MASK) != Check->Base) ||
      (SmrrSize != Check->Size))
  {
    Check->Valid = FALSE;
  }
}

STATIC
EFI_STATUS
IntelClientVerifySmramBoundary (
  VOID
  )
{
  INTEL_SMRR_CHECK          Check;
  EFI_MP_SERVICES_PROTOCOL  *MpServices;
  UINTN                     *FailedCpuList;
  UINTN                     EnabledProcessors;
  UINTN                     NumberOfProcessors;
  UINT8                     Smramc;
  UINT64                    SmrrBase;
  UINT64                    SmrrMask;
  EFI_STATUS                Status;

  Smramc = PciSegmentRead8 (INTEL_ROOT_BRIDGE (INTEL_SA_SMRAMC));
  if (((Smramc & (INTEL_SA_SMRAMC_D_LCK | INTEL_SA_SMRAMC_G_SMRAME)) !=
       (INTEL_SA_SMRAMC_D_LCK | INTEL_SA_SMRAMC_G_SMRAME)) ||
      ((Smramc & INTEL_SA_SMRAMC_D_OPEN) != 0))
  {
    DEBUG ((DEBUG_ERROR, "Boot-key Intel client SMRAMC is not closed and locked: 0x%02x\n", Smramc));
    return EFI_SECURITY_VIOLATION;
  }

  ZeroMem (&Check, sizeof (Check));
  SmrrBase   = AsmReadMsr64 (INTEL_MSR_SMRR_PHYSBASE);
  SmrrMask   = AsmReadMsr64 (INTEL_MSR_SMRR_PHYSMASK);
  Check.Base = SmrrBase & INTEL_MSR_SMRR_ADDRESS_MASK;
  Check.Size = ((~SmrrMask) & INTEL_MSR_SMRR_ADDRESS_MASK) + SIZE_4KB;
  if (((SmrrMask & (INTEL_MSR_SMRR_MASK_LOCK | INTEL_MSR_SMRR_MASK_VALID)) !=
       (INTEL_MSR_SMRR_MASK_LOCK | INTEL_MSR_SMRR_MASK_VALID)) ||
      ((SmrrBase & INTEL_MSR_SMRR_MEMORY_TYPE_MASK) !=
       INTEL_MSR_SMRR_MEMORY_TYPE_WB) ||
      ((SmrrBase & ~INTEL_MSR_SMRR_BASE_ALLOWED) != 0) ||
      ((SmrrMask & ~INTEL_MSR_SMRR_MASK_ALLOWED) != 0) ||
      (Check.Base < SIZE_1MB) ||
      (Check.Size == 0) ||
      ((Check.Size & (Check.Size - 1)) != 0) ||
      ((Check.Base & (Check.Size - 1)) != 0) ||
      (Check.Base >= SIZE_4GB) ||
      (Check.Size > (SIZE_4GB - Check.Base)))
  {
    return EFI_SECURITY_VIOLATION;
  }

  Check.Valid = TRUE;
  IntelClientCheckSmrrOnProcessor (&Check);
  if (!Check.Valid) {
    return EFI_SECURITY_VIOLATION;
  }

  Status = gBS->LocateProtocol (&gEfiMpServiceProtocolGuid, NULL, (VOID **)&MpServices);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = MpServices->GetNumberOfProcessors (
                         MpServices,
                         &NumberOfProcessors,
                         &EnabledProcessors
                         );
  if (EFI_ERROR (Status) || (EnabledProcessors == 0) ||
      (NumberOfProcessors < EnabledProcessors))
  {
    return EFI_SECURITY_VIOLATION;
  }

  if (EnabledProcessors > 1) {
    FailedCpuList = NULL;
    Status        = MpServices->StartupAllAPs (
                                  MpServices,
                                  IntelClientCheckSmrrOnProcessor,
                                  TRUE,
                                  NULL,
                                  1000000,
                                  &Check,
                                  &FailedCpuList
                                  );
    if (FailedCpuList != NULL) {
      FreePool (FailedCpuList);
    }

    if (EFI_ERROR (Status) || !Check.Valid) {
      return EFI_SECURITY_VIOLATION;
    }
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
IntelClientVerifyDmaBoundary (
  VOID
  )
{
  BOOT_KEY_DMA_ISOLATION_PROTOCOL  *DmaIsolation;
  EFI_STATUS                       Status;

  if (!FixedPcdGetBool (PcdBootKeyDmaIsolationRequired)) {
    return EFI_SECURITY_VIOLATION;
  }

  DmaIsolation = NULL;
  Status       = gBS->LocateProtocol (
                        &gBootKeyDmaIsolationProtocolGuid,
                        NULL,
                        (VOID **)&DmaIsolation
                        );
  if (EFI_ERROR (Status) || (DmaIsolation == NULL) ||
      (DmaIsolation->Revision != BOOT_KEY_DMA_ISOLATION_PROTOCOL_REVISION) ||
      (DmaIsolation->Verify == NULL))
  {
    return EFI_SECURITY_VIOLATION;
  }

  return DmaIsolation->Verify (DmaIsolation);
}

STATIC
EFI_STATUS
IntelClientVerifyTpmBoundary (
  VOID
  )
{
  PTP_FIFO_INTERFACE_CAPABILITY  InterfaceCapability;
  PTP_FIFO_INTERFACE_IDENTIFIER  InterfaceId;
  UINT16                         DeviceId;
  UINT8                          StatusEx;
  UINT16                         VendorId;

  VendorId = MmioRead16 (
               TPM_BASE_ADDRESS + OFFSET_OF (PTP_FIFO_REGISTERS, Vid)
               );
  DeviceId = MmioRead16 (
               TPM_BASE_ADDRESS + OFFSET_OF (PTP_FIFO_REGISTERS, Did)
               );
  InterfaceId.Uint32 = MmioRead32 (
                         TPM_BASE_ADDRESS +
                         OFFSET_OF (PTP_FIFO_REGISTERS, InterfaceId)
                         );
  InterfaceCapability.Uint32 = MmioRead32 (
                                 TPM_BASE_ADDRESS +
                                 OFFSET_OF (PTP_FIFO_REGISTERS, InterfaceCapability)
                                 );
  StatusEx = MmioRead8 (
               TPM_BASE_ADDRESS + OFFSET_OF (PTP_FIFO_REGISTERS, StatusEx)
               );
  if ((VendorId != INFINEON_TPM_VENDOR_ID) ||
      ((DeviceId != SLB9670_DEVICE_ID) &&
       (DeviceId != SLB9672_DEVICE_ID)) ||
      (InterfaceId.Bits.InterfaceType !=
       PTP_INTERFACE_IDENTIFIER_INTERFACE_TYPE_FIFO) ||
      (InterfaceId.Bits.InterfaceVersion !=
       PTP_INTERFACE_IDENTIFIER_INTERFACE_VERSION_FIFO) ||
      (InterfaceId.Bits.CapFIFO == 0) ||
      (InterfaceId.Bits.CapCRB != 0) ||
      (InterfaceId.Bits.InterfaceSelector !=
       PTP_INTERFACE_IDENTIFIER_INTERFACE_SELECTOR_FIFO) ||
      (InterfaceCapability.Bits.InterfaceVersion !=
       INTERFACE_CAPABILITY_INTERFACE_VERSION_PTP) ||
      ((StatusEx & PTP_FIFO_STS_EX_TPM_FAMILY) !=
       PTP_FIFO_STS_EX_TPM_FAMILY_TPM20))
  {
    DEBUG ((
      DEBUG_ERROR,
      "Boot-key Intel client requires an Infineon SLB9670/SLB9672 FIFO TPM: VID=0x%04x DID=0x%04x IF=0x%08x CAP=0x%08x STS_EX=0x%02x\n",
      VendorId,
      DeviceId,
      InterfaceId.Uint32,
      InterfaceCapability.Uint32,
      StatusEx
      ));
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
IntelClientVerifySpiBoundary (
  VOID
  )
{
  UINT32  BiosControl;
  UINT32  Hsfs;
  UINT32  SpiBar;

  if ((PciSegmentRead16 (INTEL_SPI_DEVICE (PCI_VENDOR_ID_OFFSET)) !=
       INTEL_SPI_VENDOR_ID) ||
      ((PciSegmentRead16 (INTEL_SPI_DEVICE (PCI_COMMAND_OFFSET)) &
        EFI_PCI_COMMAND_MEMORY_SPACE) == 0))
  {
    return EFI_SECURITY_VIOLATION;
  }

  SpiBar = PciSegmentRead32 (INTEL_SPI_DEVICE (INTEL_SPI_BAR0)) & INTEL_SPI_BAR_MASK;
  if (SpiBar == 0) {
    return EFI_SECURITY_VIOLATION;
  }

  BiosControl = PciSegmentRead32 (INTEL_SPI_DEVICE (INTEL_SPI_BIOS_CONTROL));
  if (((BiosControl & INTEL_SPI_BIOS_CONTROL_WPD) != 0) ||
      ((BiosControl & (INTEL_SPI_BIOS_CONTROL_LE |
                       INTEL_SPI_BIOS_CONTROL_EISS |
                       INTEL_SPI_BIOS_CONTROL_BILD |
                       INTEL_SPI_BIOS_CONTROL_EXT_LOCK)) !=
       (INTEL_SPI_BIOS_CONTROL_LE |
        INTEL_SPI_BIOS_CONTROL_EISS |
        INTEL_SPI_BIOS_CONTROL_BILD |
        INTEL_SPI_BIOS_CONTROL_EXT_LOCK)))
  {
    DEBUG ((DEBUG_ERROR, "Boot-key Intel client BIOS control is not locked: 0x%08x\n", BiosControl));
    return EFI_SECURITY_VIOLATION;
  }

  Hsfs = MmioRead32 ((UINTN)SpiBar + INTEL_SPI_HSFSTS_CTL);
  if ((Hsfs & (INTEL_SPI_HSFSTS_FDV | INTEL_SPI_HSFSTS_FLOCKDN)) !=
      (INTEL_SPI_HSFSTS_FDV | INTEL_SPI_HSFSTS_FLOCKDN))
  {
    DEBUG ((
      DEBUG_ERROR,
      "Boot-key Intel client SPI controller is not locked: HSFS=0x%08x\n",
      Hsfs
      ));
    return EFI_SECURITY_VIOLATION;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootKeyVerifyPlatformSecurityBoundary (
  VOID
  )
{
  EFI_STATUS  Status;

  Status = IntelClientVerifyProcessorBoundary ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = IntelClientVerifyDmaBoundary ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = IntelClientVerifyTpmBoundary ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = IntelClientVerifySmramBoundary ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  return IntelClientVerifySpiBoundary ();
}
