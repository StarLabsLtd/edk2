## SPDX-License-Identifier: BSD-2-Clause-Patent

# This is the cdk2 payload inventory. The source files in these EDK II
# modules are C; INF files remain the package metadata consumed by BaseTools.
# Keep this list limited to modules used by the coreboot x86 payload. Optional
# groups are selected by the cdk2 Kconfig and the matching DSC defines.

CDK2_PAYLOAD_LIBRARIES := \
    UefiPayloadPkg/cdk2/Library/Cdk2PlatformLib/Cdk2PlatformLib.inf

CDK2_EXTRA_DEFINES_NORMALIZED ?= $(subst ",,$(CDK2_EXTRA_DEFINES))
CDK2_TRUE_VALUES := TRUE true True ON on On 1 Y y
CDK2_FALSE_VALUES := FALSE false False OFF off Off 0 N n
CDK2_CANONICAL_BOOL_VALUES := TRUE FALSE
CDK2_BOOL_DEFINE_NAMES := \
    PCI_ENABLE STORAGE_ENABLE CONSOLE_ENABLE GRAPHICS_ENABLE SETUP_UI_ENABLE \
    CONNECT_ALL_DEVICES ESRT_SUPPORT CDK2_LATE_LINK SMM_SUPPORT \
    CAPSULE_SUPPORT SECURE_BOOT_ENABLE SECURE_BOOT_CONFIG_ENABLE \
    NVME_ENABLE USB_ENABLE ATA_ENABLE SD_ENABLE PS2_MOUSE_ENABLE \
    SIO_BUS_ENABLE PS2_KEYBOARD_ENABLE SERIAL_DRIVER_ENABLE \
    USE_CBMEM_FOR_CONSOLE CBMEM_TIMESTAMPS TPM1_ENABLE TPM2_ENABLE \
    TPM_CONFIG_ENABLE CPU_TIMER_LIB_ENABLE SECURITY_STUB_ENABLE \
    OPAL_PASSWORD_ENABLE LVGL_ENABLE
CDK2_VALUE_DEFINE_NAMES := \
    VARIABLE_SUPPORT MEMORY_TEST SHELL_TYPE TIMER_SUPPORT CAPSULE_MAIN_FW_GUID
CDK2_DEFINE_MATCHES = $(strip \
    $(filter --define=$(1)=%,$(CDK2_EXTRA_DEFINES_NORMALIZED)) \
    $(filter -D$(1)=%,$(CDK2_EXTRA_DEFINES_NORMALIZED)) \
    $(filter $(1)=%,$(CDK2_EXTRA_DEFINES_NORMALIZED)))
CDK2_DEFINE_VALUE = $(strip $(lastword \
    $(patsubst --define=$(1)=%,%,$(filter --define=$(1)=%,$(CDK2_EXTRA_DEFINES_NORMALIZED))) \
    $(patsubst -D$(1)=%,%,$(filter -D$(1)=%,$(CDK2_EXTRA_DEFINES_NORMALIZED))) \
    $(patsubst $(1)=%,%,$(filter $(1)=%,$(CDK2_EXTRA_DEFINES_NORMALIZED)))))
CDK2_EFFECTIVE_BOOL = $(if $(filter $(CDK2_TRUE_VALUES),$(call CDK2_DEFINE_VALUE,$(1))),y,$(if $(filter $(CDK2_FALSE_VALUES),$(call CDK2_DEFINE_VALUE,$(1))),n,$(2)))

define CDK2_REJECT_DUPLICATE_DEFINE
ifneq ($(word 2,$(call CDK2_DEFINE_MATCHES,$(1))),)
$$(error duplicate cdk2 define override for $(1): $(call CDK2_DEFINE_MATCHES,$(1)))
endif
endef

define CDK2_REJECT_NONCANONICAL_BOOL_DEFINE
ifneq ($(call CDK2_DEFINE_VALUE,$(1)),)
ifeq ($(filter $(CDK2_CANONICAL_BOOL_VALUES),$(call CDK2_DEFINE_VALUE,$(1))),)
$$(error cdk2 define $(1) must use TRUE or FALSE, not '$(call CDK2_DEFINE_VALUE,$(1))')
endif
endif
endef

$(foreach name,$(CDK2_BOOL_DEFINE_NAMES) $(CDK2_VALUE_DEFINE_NAMES),$(eval $(call CDK2_REJECT_DUPLICATE_DEFINE,$(name))))
$(foreach name,$(CDK2_BOOL_DEFINE_NAMES),$(eval $(call CDK2_REJECT_NONCANONICAL_BOOL_DEFINE,$(name))))

CDK2_EFFECTIVE_PCI := $(call CDK2_EFFECTIVE_BOOL,PCI_ENABLE,$(CONFIG_CDK2_PCI))
CDK2_EFFECTIVE_STORAGE := $(call CDK2_EFFECTIVE_BOOL,STORAGE_ENABLE,$(CONFIG_CDK2_STORAGE))
CDK2_EFFECTIVE_CONSOLE := $(call CDK2_EFFECTIVE_BOOL,CONSOLE_ENABLE,$(CONFIG_CDK2_CONSOLE))
CDK2_EFFECTIVE_GRAPHICS := $(call CDK2_EFFECTIVE_BOOL,GRAPHICS_ENABLE,$(CONFIG_CDK2_GRAPHICS))
CDK2_EFFECTIVE_SETUP_UI := $(call CDK2_EFFECTIVE_BOOL,SETUP_UI_ENABLE,$(CONFIG_CDK2_SETUP_UI))
CDK2_EFFECTIVE_CONNECT_ALL_DEVICES := $(call CDK2_EFFECTIVE_BOOL,CONNECT_ALL_DEVICES,$(CONFIG_CDK2_CONNECT_ALL_DEVICES))
CDK2_EFFECTIVE_ESRT := $(call CDK2_EFFECTIVE_BOOL,ESRT_SUPPORT,$(CONFIG_CDK2_ESRT))
CDK2_EFFECTIVE_LATE_LINK := $(call CDK2_EFFECTIVE_BOOL,CDK2_LATE_LINK,$(CONFIG_CDK2_LATE_LINK))
CDK2_EFFECTIVE_SMM := $(call CDK2_EFFECTIVE_BOOL,SMM_SUPPORT,$(CONFIG_CDK2_SMM))
CDK2_EFFECTIVE_CAPSULE := $(call CDK2_EFFECTIVE_BOOL,CAPSULE_SUPPORT,$(CONFIG_CDK2_CAPSULE))
CDK2_EFFECTIVE_SECURE_BOOT := $(call CDK2_EFFECTIVE_BOOL,SECURE_BOOT_ENABLE,$(CONFIG_CDK2_SECURE_BOOT))
CDK2_EFFECTIVE_SECURE_BOOT_CONFIG := $(call CDK2_EFFECTIVE_BOOL,SECURE_BOOT_CONFIG_ENABLE,$(CONFIG_CDK2_SECURE_BOOT_CONFIG))
CDK2_EFFECTIVE_NVME := $(call CDK2_EFFECTIVE_BOOL,NVME_ENABLE,$(CONFIG_CDK2_NVME))
CDK2_EFFECTIVE_USB := $(call CDK2_EFFECTIVE_BOOL,USB_ENABLE,$(CONFIG_CDK2_USB))
CDK2_EFFECTIVE_ATA := $(call CDK2_EFFECTIVE_BOOL,ATA_ENABLE,$(CONFIG_CDK2_ATA))
CDK2_EFFECTIVE_SD := $(call CDK2_EFFECTIVE_BOOL,SD_ENABLE,$(CONFIG_CDK2_SD))
CDK2_EFFECTIVE_PS2_MOUSE := $(call CDK2_EFFECTIVE_BOOL,PS2_MOUSE_ENABLE,$(CONFIG_CDK2_PS2_MOUSE))
CDK2_EFFECTIVE_SIO_BUS := $(call CDK2_EFFECTIVE_BOOL,SIO_BUS_ENABLE,$(CONFIG_CDK2_SIO_BUS))
CDK2_EFFECTIVE_PS2_KEYBOARD := $(call CDK2_EFFECTIVE_BOOL,PS2_KEYBOARD_ENABLE,$(CONFIG_CDK2_PS2_KEYBOARD))
CDK2_EFFECTIVE_SERIAL := $(call CDK2_EFFECTIVE_BOOL,SERIAL_DRIVER_ENABLE,$(CONFIG_CDK2_SERIAL))
CDK2_EFFECTIVE_CBMEM_CONSOLE := $(call CDK2_EFFECTIVE_BOOL,USE_CBMEM_FOR_CONSOLE,$(CONFIG_CDK2_CBMEM_CONSOLE))
CDK2_EFFECTIVE_CBMEM_TIMESTAMPS := $(call CDK2_EFFECTIVE_BOOL,CBMEM_TIMESTAMPS,$(CONFIG_CDK2_CBMEM_TIMESTAMPS))
CDK2_EFFECTIVE_TPM12 := $(call CDK2_EFFECTIVE_BOOL,TPM1_ENABLE,$(CONFIG_CDK2_TPM12))
CDK2_EFFECTIVE_TPM2 := $(call CDK2_EFFECTIVE_BOOL,TPM2_ENABLE,$(CONFIG_CDK2_TPM2))
CDK2_EFFECTIVE_TPM_CONFIG := $(call CDK2_EFFECTIVE_BOOL,TPM_CONFIG_ENABLE,$(CONFIG_CDK2_TPM_CONFIG))
CDK2_EFFECTIVE_CPU_TIMER := $(call CDK2_EFFECTIVE_BOOL,CPU_TIMER_LIB_ENABLE,$(CONFIG_CDK2_CPU_TIMER))
CDK2_EFFECTIVE_SECURITY_STUB := $(call CDK2_EFFECTIVE_BOOL,SECURITY_STUB_ENABLE,y)
CDK2_EFFECTIVE_OPAL_PASSWORD := $(call CDK2_EFFECTIVE_BOOL,OPAL_PASSWORD_ENABLE,n)
CDK2_EFFECTIVE_LVGL := $(call CDK2_EFFECTIVE_BOOL,LVGL_ENABLE,n)

CDK2_VARIABLE_SUPPORT_OVERRIDE := $(call CDK2_DEFINE_VALUE,VARIABLE_SUPPORT)
ifeq ($(CDK2_VARIABLE_SUPPORT_OVERRIDE),SMMSTORE)
CDK2_EFFECTIVE_SMMSTORE := y
else ifeq ($(CDK2_VARIABLE_SUPPORT_OVERRIDE),EMU)
CDK2_EFFECTIVE_SMMSTORE := n
else ifneq ($(CDK2_VARIABLE_SUPPORT_OVERRIDE),)
$(error unsupported cdk2 VARIABLE_SUPPORT value: $(CDK2_VARIABLE_SUPPORT_OVERRIDE))
else
CDK2_EFFECTIVE_SMMSTORE := $(CONFIG_CDK2_SMMSTORE)
endif

CDK2_MEMORY_TEST_OVERRIDE := $(call CDK2_DEFINE_VALUE,MEMORY_TEST)
CDK2_EFFECTIVE_MEMORY_TEST := $(strip $(if $(CDK2_MEMORY_TEST_OVERRIDE),$(CDK2_MEMORY_TEST_OVERRIDE),NULL))

CDK2_SHELL_TYPE_OVERRIDE := $(call CDK2_DEFINE_VALUE,SHELL_TYPE)
ifeq ($(CDK2_SHELL_TYPE_OVERRIDE),NONE)
CDK2_EFFECTIVE_SHELL := n
else ifeq ($(CDK2_SHELL_TYPE_OVERRIDE),BUILD_SHELL)
CDK2_EFFECTIVE_SHELL := y
else ifneq ($(CDK2_SHELL_TYPE_OVERRIDE),)
$(error unsupported cdk2 SHELL_TYPE value: $(CDK2_SHELL_TYPE_OVERRIDE))
else
CDK2_EFFECTIVE_SHELL := $(CONFIG_CDK2_SHELL)
endif

CDK2_TIMER_SUPPORT_OVERRIDE := $(call CDK2_DEFINE_VALUE,TIMER_SUPPORT)
ifeq ($(CDK2_TIMER_SUPPORT_OVERRIDE),HPET)
CDK2_EFFECTIVE_TIMER_SUPPORT := HPET
else ifeq ($(CDK2_TIMER_SUPPORT_OVERRIDE),LAPIC)
CDK2_EFFECTIVE_TIMER_SUPPORT := LAPIC
else ifneq ($(CDK2_TIMER_SUPPORT_OVERRIDE),)
$(error unsupported cdk2 TIMER_SUPPORT value: $(CDK2_TIMER_SUPPORT_OVERRIDE))
else ifeq ($(CONFIG_CDK2_HPET_TIMER),y)
CDK2_EFFECTIVE_TIMER_SUPPORT := HPET
else
CDK2_EFFECTIVE_TIMER_SUPPORT := LAPIC
endif

define CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD
ifneq ($(CDK2_EFFECTIVE_$(1)),y)
ifeq ($(call CDK2_DEFINE_VALUE,$(3)),TRUE)
$$(error cdk2 define $(3)=TRUE requires $(4)=TRUE)
endif
CDK2_EFFECTIVE_$(2) := n
endif
endef

define CDK2_REQUIRE_PARENT
ifneq ($(CDK2_EFFECTIVE_$(1)),y)
ifeq ($(CDK2_EFFECTIVE_$(2)),y)
$$(error cdk2 feature $(2) requires $(3)=TRUE)
endif
endif
endef

$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,PCI,STORAGE,STORAGE_ENABLE,PCI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,PCI,USB,USB_ENABLE,PCI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,PCI,SIO_BUS,SIO_BUS_ENABLE,PCI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,PCI,PS2_KEYBOARD,PS2_KEYBOARD_ENABLE,PCI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,PCI,PS2_MOUSE,PS2_MOUSE_ENABLE,PCI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,PCI,GRAPHICS,GRAPHICS_ENABLE,PCI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,STORAGE,NVME,NVME_ENABLE,STORAGE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,STORAGE,ATA,ATA_ENABLE,STORAGE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,STORAGE,SD,SD_ENABLE,STORAGE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,CONSOLE,GRAPHICS,GRAPHICS_ENABLE,CONSOLE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,CONSOLE,SETUP_UI,SETUP_UI_ENABLE,CONSOLE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,CONSOLE,SERIAL,SERIAL_DRIVER_ENABLE,CONSOLE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,CONSOLE,PS2_KEYBOARD,PS2_KEYBOARD_ENABLE,CONSOLE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,CONSOLE,PS2_MOUSE,PS2_MOUSE_ENABLE,CONSOLE_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,SERIAL,CBMEM_CONSOLE,USE_CBMEM_FOR_CONSOLE,SERIAL_DRIVER_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,SETUP_UI,SECURE_BOOT_CONFIG,SECURE_BOOT_CONFIG_ENABLE,SETUP_UI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,SETUP_UI,TPM_CONFIG,TPM_CONFIG_ENABLE,SETUP_UI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,SETUP_UI,LVGL,LVGL_ENABLE,SETUP_UI_ENABLE))
$(eval $(call CDK2_REQUIRE_PARENT_OR_DISABLE_CHILD,SECURE_BOOT,SECURE_BOOT_CONFIG,SECURE_BOOT_CONFIG_ENABLE,SECURE_BOOT_ENABLE))

ifneq ($(filter y,$(CDK2_EFFECTIVE_TPM12) $(CDK2_EFFECTIVE_TPM2)),)
else
ifeq ($(call CDK2_DEFINE_VALUE,TPM_CONFIG_ENABLE),TRUE)
$(error cdk2 define TPM_CONFIG_ENABLE=TRUE requires TPM1_ENABLE=TRUE or TPM2_ENABLE=TRUE)
endif
CDK2_EFFECTIVE_TPM_CONFIG := n
endif

ifeq ($(CDK2_EFFECTIVE_SECURE_BOOT),y)
ifneq ($(CDK2_EFFECTIVE_ESRT),y)
ifeq ($(call CDK2_DEFINE_VALUE,ESRT_SUPPORT),FALSE)
$(error cdk2 define ESRT_SUPPORT=FALSE conflicts with SECURE_BOOT_ENABLE=TRUE)
endif
CDK2_EFFECTIVE_ESRT := y
endif
endif

ifeq ($(CDK2_EFFECTIVE_CAPSULE),y)
ifneq ($(CDK2_EFFECTIVE_SMM),y)
$(error cdk2 feature CAPSULE requires SMM_SUPPORT=TRUE)
endif
ifneq ($(CDK2_EFFECTIVE_ESRT),y)
$(error cdk2 feature CAPSULE requires ESRT_SUPPORT=TRUE)
endif
ifneq ($(CDK2_EFFECTIVE_GRAPHICS),y)
$(error cdk2 feature CAPSULE requires GRAPHICS_ENABLE=TRUE)
endif
endif

$(eval $(call CDK2_REQUIRE_PARENT,SMM,SMMSTORE,SMM_SUPPORT))

CDK2_REQUIRED_MODULES := \
    UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry.inf \
    MdeModulePkg/Core/Dxe/DxeMain.inf \
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
    MdeModulePkg/Universal/HiiDatabaseDxe/HiiDatabaseDxe.inf \
    MdeModulePkg/Universal/EbcDxe/EbcDxe.inf \
    UefiPayloadPkg/BlSupportDxe/BlSupportDxe.inf \
    UefiPayloadPkg/EcAcpiBatteryStatusDxe/EcAcpiBatteryStatusDxe.inf \
    MdeModulePkg/Universal/SmbiosDxe/SmbiosDxe.inf \
    MdeModulePkg/Universal/Acpi/AcpiTableDxe/AcpiTableDxe.inf \
    MdeModulePkg/Universal/Variable/RuntimeDxe/VariableRuntimeDxe.inf \
    UefiCpuPkg/CpuDxe/CpuDxe.inf

ifeq ($(CDK2_EFFECTIVE_TIMER_SUPPORT),HPET)
CDK2_REQUIRED_MODULES += PcAtChipsetPkg/HpetTimerDxe/HpetTimerDxe.inf
else
CDK2_REQUIRED_MODULES += OvmfPkg/LocalApicTimerDxe/LocalApicTimerDxe.inf
endif

CDK2_SECURITY_STUB_MODULES := \
    MdeModulePkg/Universal/SecurityStubDxe/SecurityStubDxe.inf

CDK2_NULL_MEMORY_TEST_MODULES := \
    MdeModulePkg/Universal/MemoryTest/NullMemoryTestDxe/NullMemoryTestDxe.inf

CDK2_GENERIC_MEMORY_TEST_MODULES := \
    MdeModulePkg/Universal/MemoryTest/GenericMemoryTestDxe/GenericMemoryTestDxe.inf

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
    MdeModulePkg/Universal/PlatformDriOverrideDxe/PlatformDriOverrideDxe.inf \
    UefiPayloadPkg/UserAuthPkg/UserAuthenticationDxe/UserAuthenticationDxe.inf

ifeq ($(CDK2_EFFECTIVE_LVGL),y)
CDK2_SETUP_UI_MODULES += \
    3rdparty/LvglPkg/LvglDisplayEngineDxe/LvglDisplayEngineDxe.inf \
    3rdparty/LvglPkg/LvglSetupDxe/LvglSetupDxe.inf
else
CDK2_SETUP_UI_MODULES += \
    MdeModulePkg/Universal/DisplayEngineDxe/DisplayEngineDxe.inf
endif

CDK2_USB_MODULES := \
    MdeModulePkg/Bus/Pci/UhciDxe/UhciDxe.inf \
    MdeModulePkg/Bus/Pci/EhciDxe/EhciDxe.inf \
    MdeModulePkg/Bus/Pci/XhciDxe/XhciDxe.inf \
    MdeModulePkg/Bus/Usb/UsbBusDxe/UsbBusDxe.inf \
    MdeModulePkg/Bus/Usb/UsbKbDxe/UsbKbDxe.inf \
    MdeModulePkg/Bus/Usb/UsbMassStorageDxe/UsbMassStorageDxe.inf

ifeq ($(CDK2_EFFECTIVE_LVGL),y)
CDK2_USB_MODULES += \
    MdeModulePkg/Bus/Usb/UsbMouseAbsolutePointerDxe/UsbMouseAbsolutePointerDxe.inf
else
CDK2_USB_MODULES += \
    MdeModulePkg/Bus/Usb/UsbMouseDxe/UsbMouseDxe.inf
endif

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

CDK2_SIO_BUS_MODULES := \
    OvmfPkg/SioBusDxe/SioBusDxe.inf

CDK2_PS2_KEYBOARD_MODULES := \
    MdeModulePkg/Bus/Isa/Ps2KeyboardDxe/Ps2KeyboardDxe.inf

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

CDK2_OPAL_PASSWORD_MODULES := \
    SecurityPkg/Tcg/Opal/OpalPassword/OpalPasswordDxe.inf

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
    $(CDK2_SECURITY_STUB_MODULES) \
    $(CDK2_NULL_MEMORY_TEST_MODULES) \
    $(CDK2_GENERIC_MEMORY_TEST_MODULES) \
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
    $(CDK2_SIO_BUS_MODULES) \
    $(CDK2_PS2_KEYBOARD_MODULES) \
    $(CDK2_PS2_MOUSE_MODULES) \
    $(CDK2_SHELL_MODULES) \
    $(CDK2_SMM_MODULES) \
    $(CDK2_SMMSTORE_MODULES) \
    $(CDK2_CAPSULE_MODULES) \
    $(CDK2_ESRT_MODULES) \
    $(CDK2_SECURE_BOOT_MODULES) \
    $(CDK2_SECURE_BOOT_CONFIG_MODULES) \
    $(CDK2_OPAL_PASSWORD_MODULES) \
    $(CDK2_TPM12_MODULES) \
    $(CDK2_TPM12_CONFIG_MODULES) \
    $(CDK2_TPM2_MODULES) \
    $(CDK2_TPM2_CONFIG_MODULES)

CDK2_RETAINED_MODULES := $(sort $(CDK2_REQUIRED_MODULES) $(CDK2_FEATURE_MODULES))
CDK2_SELECTED_MODULES := $(CDK2_REQUIRED_MODULES)

ifneq ($(filter y,$(CDK2_EFFECTIVE_PS2_KEYBOARD) $(CDK2_EFFECTIVE_PS2_MOUSE)),)
ifneq ($(CDK2_EFFECTIVE_CONSOLE),y)
$(error CONFIG_CDK2_PS2_KEYBOARD/CONFIG_CDK2_PS2_MOUSE require CONFIG_CDK2_CONSOLE)
endif
ifneq ($(CDK2_EFFECTIVE_PCI),y)
$(error CONFIG_CDK2_PS2_KEYBOARD/CONFIG_CDK2_PS2_MOUSE require CONFIG_CDK2_PCI)
endif
CDK2_EFFECTIVE_SIO_BUS := y
endif

define CDK2_SELECT_FEATURE_MODULES
ifeq ($(CDK2_EFFECTIVE_$(1)),y)
CDK2_SELECTED_MODULES += $($(2))
endif
endef

$(eval $(call CDK2_SELECT_FEATURE_MODULES,SECURITY_STUB,CDK2_SECURITY_STUB_MODULES))
ifeq ($(CDK2_EFFECTIVE_MEMORY_TEST),GENERIC)
CDK2_SELECTED_MODULES += $(CDK2_GENERIC_MEMORY_TEST_MODULES)
else ifeq ($(CDK2_EFFECTIVE_MEMORY_TEST),NULL)
CDK2_SELECTED_MODULES += $(CDK2_NULL_MEMORY_TEST_MODULES)
else ifneq ($(filter NONE,$(CDK2_EFFECTIVE_MEMORY_TEST)),)
else
$(error unsupported cdk2 MEMORY_TEST value: $(CDK2_EFFECTIVE_MEMORY_TEST))
endif
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
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SIO_BUS,CDK2_SIO_BUS_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,PS2_KEYBOARD,CDK2_PS2_KEYBOARD_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,PS2_MOUSE,CDK2_PS2_MOUSE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SHELL,CDK2_SHELL_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SMM,CDK2_SMM_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SMMSTORE,CDK2_SMMSTORE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,CBMEM_TIMESTAMPS,CDK2_CBMEM_TIMESTAMP_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,CAPSULE,CDK2_CAPSULE_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,ESRT,CDK2_ESRT_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SECURE_BOOT,CDK2_SECURE_BOOT_MODULES))
ifeq ($(CDK2_EFFECTIVE_SECURE_BOOT),y)
$(eval $(call CDK2_SELECT_FEATURE_MODULES,SECURE_BOOT_CONFIG,CDK2_SECURE_BOOT_CONFIG_MODULES))
endif
$(eval $(call CDK2_SELECT_FEATURE_MODULES,OPAL_PASSWORD,CDK2_OPAL_PASSWORD_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,TPM12,CDK2_TPM12_MODULES))
$(eval $(call CDK2_SELECT_FEATURE_MODULES,TPM2,CDK2_TPM2_MODULES))

ifeq ($(CDK2_EFFECTIVE_TPM_CONFIG),y)
ifeq ($(CDK2_EFFECTIVE_TPM12),y)
CDK2_SELECTED_MODULES += $(CDK2_TPM12_CONFIG_MODULES)
endif
ifeq ($(CDK2_EFFECTIVE_TPM2),y)
CDK2_SELECTED_MODULES += $(CDK2_TPM2_CONFIG_MODULES)
endif
endif

CDK2_SELECTED_MODULES := $(sort $(CDK2_SELECTED_MODULES))
