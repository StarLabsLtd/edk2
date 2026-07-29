## SPDX-License-Identifier: BSD-2-Clause-Patent

# This is the cdk2 payload inventory. The source files in these EDK II
# modules are C; INF files remain the package metadata consumed by BaseTools.
# Keep this list limited to modules used by the coreboot x86 payload. Optional
# groups are selected by the cdk2 Kconfig and the matching DSC defines.

CDK2_PAYLOAD_LIBRARIES := \
    UefiPayloadPkg/cdk2/Library/Cdk2PlatformLib/Cdk2PlatformLib.inf

CDK2_REQUIRED_MODULES := \
    UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry.inf \
    MdeModulePkg/Core/Dxe/DxeMain.inf \
    MdeModulePkg/Universal/SecurityStubDxe/SecurityStubDxe.inf \
    MdeModulePkg/Universal/BdsDxe/BdsDxe.inf \
    MdeModulePkg/Universal/Metronome/Metronome.inf \
    MdeModulePkg/Universal/WatchdogTimerDxe/WatchdogTimer.inf \
    MdeModulePkg/Core/RuntimeDxe/RuntimeDxe.inf \
    MdeModulePkg/Universal/CapsuleRuntimeDxe/CapsuleRuntimeDxe.inf \
    MdeModulePkg/Universal/MonotonicCounterRuntimeDxe/MonotonicCounterRuntimeDxe.inf \
    MdeModulePkg/Universal/ResetSystemRuntimeDxe/ResetSystemRuntimeDxe.inf \
    PcAtChipsetPkg/PcatRealTimeClockRuntimeDxe/PcatRealTimeClockRuntimeDxe.inf \
    MdeModulePkg/Universal/PCD/Dxe/Pcd.inf \
    MdeModulePkg/Universal/ReportStatusCodeRouter/RuntimeDxe/ReportStatusCodeRouterRuntimeDxe.inf \
    MdeModulePkg/Universal/StatusCodeHandler/RuntimeDxe/StatusCodeHandlerRuntimeDxe.inf \
    MdeModulePkg/Universal/DevicePathDxe/DevicePathDxe.inf \
    MdeModulePkg/Universal/MemoryTest/NullMemoryTestDxe/NullMemoryTestDxe.inf \
    MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf \
    MdeModulePkg/Universal/PlatformDriOverrideDxe/PlatformDriOverrideDxe.inf \
    MdeModulePkg/Universal/EbcDxe/EbcDxe.inf \
    UefiPayloadPkg/BlSupportDxe/BlSupportDxe.inf \
    UefiPayloadPkg/EcAcpiBatteryStatusDxe/EcAcpiBatteryStatusDxe.inf \
    MdeModulePkg/Universal/SmbiosDxe/SmbiosDxe.inf \
    MdeModulePkg/Universal/Acpi/AcpiTableDxe/AcpiTableDxe.inf \
    MdeModulePkg/Universal/Variable/RuntimeDxe/VariableRuntimeDxe.inf \
    UefiCpuPkg/CpuDxe/CpuDxe.inf \
    PcAtChipsetPkg/HpetTimerDxe/HpetTimerDxe.inf

CDK2_PCI_MODULES := \
    UefiCpuPkg/CpuIo2Dxe/CpuIo2Dxe.inf \
    MdeModulePkg/Bus/Pci/PciBusDxe/PciBusDxe.inf \
    MdeModulePkg/Bus/Pci/PciHostBridgeDxe/PciHostBridgeDxe.inf

CDK2_STORAGE_MODULES := \
    MdeModulePkg/Universal/Disk/DiskIoDxe/DiskIoDxe.inf \
    MdeModulePkg/Universal/Disk/PartitionDxe/PartitionDxe.inf \
    MdeModulePkg/Universal/Disk/UnicodeCollation/EnglishDxe/EnglishDxe.inf \
    FatPkg/EnhancedFatDxe/Fat.inf

CDK2_CONSOLE_MODULES := \
    MdeModulePkg/Universal/Console/ConPlatformDxe/ConPlatformDxe.inf \
    MdeModulePkg/Universal/Console/ConSplitterDxe/ConSplitterDxe.inf

CDK2_GRAPHICS_MODULES := \
    MdeModulePkg/Universal/Console/GraphicsConsoleDxe/GraphicsConsoleDxe.inf \
    UefiPayloadPkg/GraphicsOutputDxe/GraphicsOutputDxe.inf

CDK2_SETUP_UI_MODULES := \
    UefiPayloadPkg/CfrSetupMenuDxe/CfrSetupMenuDxe.inf \
    MdeModulePkg/Application/UiApp/UiApp.inf \
    MdeModulePkg/Application/BootManagerMenuApp/BootManagerMenuApp.inf \
    MdeModulePkg/Universal/SetupBrowserDxe/SetupBrowserDxe.inf \
    MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf \
    UefiPayloadPkg/UserAuthPkg/UserAuthenticationDxe/UserAuthenticationDxe.inf

CDK2_USB_MODULES := \
    MdeModulePkg/Bus/Pci/UhciDxe/UhciDxe.inf \
    MdeModulePkg/Bus/Pci/EhciDxe/EhciDxe.inf \
    MdeModulePkg/Bus/Pci/XhciDxe/XhciDxe.inf \
    MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf \
    MdeModulePkg/Bus/Usb/UsbKbDxe/UsbKbDxe.inf \
    MdeModulePkg/Bus/Usb/UsbMassStorageDxe/UsbMassStorageDxe.inf \
    MdeModulePkg/Bus/Usb/UsbMouseDxe/UsbMouseDxe.inf

CDK2_ATA_MODULES := \
    MdeModulePkg/Bus/Pci/SataControllerDxe/SataControllerDxe.inf \
    MdeModulePkg/Bus/Ata/AtaBusDxe/AtaBusDxe.inf \
    MdeModulePkg/Bus/Ata/AtaAtapiPassThru/AtaAtapiPassThru.inf \
    MdeModulePkg/Bus/Scsi/ScsiBusDxe/ScsiBusDxe.inf \
    MdeModulePkg/Bus/Scsi/ScsiDiskDxe/ScsiDiskDxe.inf

CDK2_SD_MODULES := \
    MdeModulePkg/Bus/Pci/SdMmcPciHcDxe/SdMmcPciHcDxe.inf \
    MdeModulePkg/Bus/Sd/EmmcDxe/EmmcDxe.inf \
    MdeModulePkg/Bus/Sd/SdDxe/SdDxe.inf

CDK2_NVME_MODULES := \
    MdeModulePkg/Bus/Pci/NvmExpressDxe/NvmExpressDxe.inf

CDK2_SERIAL_MODULES := \
    MdeModulePkg/Universal/SerialDxe/SerialDxe.inf \
    MdeModulePkg/Universal/Console/TerminalDxe/TerminalDxe.inf

CDK2_PS2_MOUSE_MODULES := \
    MdeModulePkg/Bus/Isa/Ps2MouseDxe/Ps2MouseDxe.inf

CDK2_SHELL_MODULES := \
    ShellPkg/Application/Shell/Shell.inf

CDK2_SMM_MODULES := \
    UefiPayloadPkg/SmmAccessDxe/SmmAccessDxe.inf \
    UefiPayloadPkg/SmmControlRuntimeDxe/SmmControlRuntimeDxe.inf \
    UefiPayloadPkg/BlSupportSmm/BlSupportSmm.inf \
    MdeModulePkg/Core/PiSmmCore/PiSmmIpl.inf \
    MdeModulePkg/Core/PiSmmCore/PiSmmCore.inf \
    UefiPayloadPkg/PchSmiDispatchSmm/PchSmiDispatchSmm.inf \
    UefiCpuPkg/PiSmmCpuDxeSmm/PiSmmCpuDxeSmm.inf \
    UefiCpuPkg/CpuIo2Smm/CpuIo2Smm.inf

CDK2_SMMSTORE_MODULES := \
    UefiPayloadPkg/SmmStoreFvb/SmmStoreFvbRuntimeDxe.inf \
    MdeModulePkg/Universal/FaultTolerantWriteDxe/FaultTolerantWriteDxe.inf

CDK2_CAPSULE_MODULES := \
    FmpDevicePkg/FmpDxe/FmpDxe.inf

CDK2_ESRT_MODULES := \
    MdeModulePkg/Universal/EsrtDxe/EsrtDxe.inf

CDK2_CBMEM_TIMESTAMP_MODULES := \
    UefiPayloadPkg/CbMemTimestampDxe/CbMemTimestampDxe.inf

CDK2_SECURE_BOOT_MODULES := \
    UefiPayloadPkg/EnrollDefaultKeys/EnrollDefaultKeys.inf

CDK2_SECURE_BOOT_CONFIG_MODULES := \
    SecurityPkg/VariableAuthenticated/SecureBootConfigDxe/SecureBootConfigDxe.inf

CDK2_TPM12_MODULES := \
    SecurityPkg/Tcg/TcgDxe/TcgDxe.inf

CDK2_TPM12_CONFIG_MODULES := \
    SecurityPkg/Tcg/TcgConfigDxe/TcgConfigDxe.inf

CDK2_TPM2_MODULES := \
    SecurityPkg/Tcg/Tcg2Dxe/Tcg2Dxe.inf \
    UefiPayloadPkg/Tpm2AcpiTableDxe/Tpm2AcpiTableDxe.inf

CDK2_TPM2_CONFIG_MODULES := \
    SecurityPkg/Tcg/Tcg2Config/Tcg2ConfigDxe.inf

CDK2_FEATURE_MODULES := \
    $(CDK2_PCI_MODULES) \
    $(CDK2_STORAGE_MODULES) \
    $(CDK2_CONSOLE_MODULES) \
    $(CDK2_GRAPHICS_MODULES) \
    $(CDK2_SETUP_UI_MODULES) \
    $(CDK2_USB_MODULES) \
    $(CDK2_ATA_MODULES) \
    $(CDK2_SD_MODULES) \
    $(CDK2_NVME_MODULES) \
    $(CDK2_SERIAL_MODULES) \
    $(CDK2_PS2_MOUSE_MODULES) \
    $(CDK2_SHELL_MODULES) \
    $(CDK2_SMM_MODULES) \
    $(CDK2_SMMSTORE_MODULES) \
    $(CDK2_CAPSULE_MODULES) \
    $(CDK2_ESRT_MODULES) \
    $(CDK2_SECURE_BOOT_MODULES) \
    $(CDK2_SECURE_BOOT_CONFIG_MODULES) \
    $(CDK2_TPM12_MODULES) \
    $(CDK2_TPM12_CONFIG_MODULES) \
    $(CDK2_TPM2_MODULES) \
    $(CDK2_TPM2_CONFIG_MODULES)

CDK2_RETAINED_MODULES := $(sort $(CDK2_REQUIRED_MODULES) $(CDK2_FEATURE_MODULES))
CDK2_SELECTED_MODULES := $(CDK2_REQUIRED_MODULES)

define CDK2_SELECT_FEATURE_MODULES
ifeq ($(CONFIG_CDK2_$(1)),y)
CDK2_SELECTED_MODULES += $($(2))
endif
endef

$(eval $(call CDK2_SELECT_FEATURE_MODULES,PCI,CDK2_PCI_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,STORAGE,CDK2_STORAGE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,CONSOLE,CDK2_CONSOLE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,GRAPHICS,CDK2_GRAPHICS_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SETUP_UI,CDK2_SETUP_UI_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,USB,CDK2_USB_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,ATA,CDK2_ATA_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SD,CDK2_SD_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,NVME,CDK2_NVME_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SERIAL,CDK2_SERIAL_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,PS2_MOUSE,CDK2_PS2_MOUSE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SHELL,CDK2_SHELL_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SMM,CDK2_SMM_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SMMSTORE,CDK2_SMMSTORE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,CBMEM_TIMESTAMPS,CDK2_CBMEM_TIMESTAMP_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,CAPSULE,CDK2_CAPSULE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,ESRT,CDK2_ESRT_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SECURE_BOOT,CDK2_SECURE_BOOT_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SECURE_BOOT_CONFIG,CDK2_SECURE_BOOT_CONFIG_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,TPM12,CDK2_TPM12_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,TPM2,CDK2_TPM2_MODULES))

ifeq ($(CONFIG_CDK2_TPM_CONFIG),y)
ifeq ($(CONFIG_CDK2_TPM12),y)
CDK2_SELECTED_MODULES += $(CDK2_TPM12_CONFIG_MODULES)
endif
ifeq ($(CONFIG_CDK2_TPM2),y)
CDK2_SELECTED_MODULES += $(CDK2_TPM2_CONFIG_MODULES)
endif
endif

CDK2_SELECTED_MODULES := $(sort $(CDK2_SELECTED_MODULES))
