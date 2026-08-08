# SPDX-License-Identifier: GPL-2.0-only

# Native cdk2 stage build fragment. It is included after the top-level Kconfig
# has been resolved, so the same generated config controls the freestanding and
# coreboot entry builds.

CDK2_NATIVE_BUILD_DIR ?= $(CDK2_BUILD_DIR)/native
CDK2_UTIL_DIR := $(CDK2_DIR)/util
CDK2_LIB_DIR := $(CDK2_DIR)/src/lib
CDK2_NATIVE_ELF ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage.elf
CDK2_NATIVE_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage.map
CDK2_NATIVE_COREBOOT_ELF ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-stage.elf
CDK2_NATIVE_COREBOOT_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-stage.map
CDK2_NATIVE_COREBOOT_IMAGE ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-image.elf
CDK2_NATIVE_COREBOOT_IMAGE_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-image.map
CDK2_NATIVE_FV_BLOB_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fv.o
CDK2_NATIVE_DIRECT_LINK_MAPS := $(CDK2_NATIVE_MAP) $(CDK2_NATIVE_COREBOOT_MAP) $(CDK2_NATIVE_COREBOOT_IMAGE_MAP)
CDK2_NATIVE_OVERRIDE_ELF ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage-override.elf
CDK2_NATIVE_OVERRIDE_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage-override.map
CDK2_NATIVE_PACKER ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvpack
CDK2_NATIVE_FVINFO ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvinfo
CDK2_NATIVE_FFSBUILD ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-ffsbuild
CDK2_NATIVE_FFSBUILD_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-ffsbuild-test
CDK2_NATIVE_FVREPLACE ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvreplace
CDK2_NATIVE_PERELOCCHECK ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-pereloccheck
CDK2_NATIVE_METRONOME_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-metronome-test
CDK2_NATIVE_METRONOME_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/metronome.o
CDK2_NATIVE_METRONOME_PE ?= $(CDK2_NATIVE_BUILD_DIR)/metronome.efi
CDK2_NATIVE_METRONOME_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/metronome.ffs
CDK2_NATIVE_METRONOME_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/metronome.depex
CDK2_NATIVE_METRONOME_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-metronome.fv
CDK2_NATIVE_WATCHDOG_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-watchdog-test
CDK2_NATIVE_WATCHDOG_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/watchdog.o
CDK2_NATIVE_WATCHDOG_PE ?= $(CDK2_NATIVE_BUILD_DIR)/watchdog.efi
CDK2_NATIVE_WATCHDOG_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/watchdog.ffs
CDK2_NATIVE_WATCHDOG_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/watchdog.depex
CDK2_NATIVE_WATCHDOG_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-watchdog.fv
CDK2_NATIVE_STATUS_CODE_ROUTER_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-status-code-router-test
CDK2_NATIVE_STATUS_CODE_ROUTER_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-router.o
CDK2_NATIVE_STATUS_CODE_ROUTER_PE ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-router.efi
CDK2_NATIVE_STATUS_CODE_ROUTER_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-router.ffs
CDK2_NATIVE_STATUS_CODE_ROUTER_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-router.depex
CDK2_NATIVE_STATUS_CODE_ROUTER_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-status-code-router.fv
CDK2_NATIVE_STATUS_CODE_HANDLER_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-status-code-handler-test
CDK2_NATIVE_STATUS_CODE_HANDLER_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-handler.o
CDK2_NATIVE_STATUS_CODE_HANDLER_PE ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-handler.efi
CDK2_NATIVE_STATUS_CODE_HANDLER_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-handler.ffs
CDK2_NATIVE_STATUS_CODE_HANDLER_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/status-code-handler.depex
CDK2_NATIVE_STATUS_CODE_HANDLER_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-status-code-handler.fv
CDK2_NATIVE_SERVICE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-services-test
CDK2_NATIVE_COREBOOT_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-test
CDK2_NATIVE_FV_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fv-test
CDK2_NATIVE_FVPACK_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvpack-test
CDK2_NATIVE_FVINFO_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvinfo-test
CDK2_NATIVE_PE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-pe-test
CDK2_NATIVE_MODULE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-module-test
CDK2_NATIVE_ELF_CHECK ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-elfcheck
CDK2_NATIVE_ELF_CHECK_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-elfcheck-test
CDK2_NATIVE_SECURITY_STUB_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-security-stub-test
CDK2_NATIVE_SECURITY_STUB_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/security-stub.o
CDK2_NATIVE_SECURITY_STUB_PE ?= $(CDK2_NATIVE_BUILD_DIR)/SecurityStubDxe.efi
CDK2_NATIVE_SECURITY_STUB_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/SecurityStubDxe.ffs
CDK2_NATIVE_SECURITY_STUB_FV ?= $(CDK2_NATIVE_BUILD_DIR)/security-stub.fv
CDK2_NATIVE_SECURITY_STUB_DEPEX_TOOL ?= $(CDK2_NATIVE_BUILD_DIR)/security-stub-depex
CDK2_NATIVE_SECURITY_STUB_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/SecurityStubDxe.depex
CDK2_NATIVE_NULL_MEMORY_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-null-memory-test-test
CDK2_NATIVE_NULL_MEMORY_TEST_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/null-memory-test.o
CDK2_NATIVE_NULL_MEMORY_TEST_PE ?= $(CDK2_NATIVE_BUILD_DIR)/null-memory-test.efi
CDK2_NATIVE_NULL_MEMORY_TEST_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/null-memory-test.ffs
CDK2_NATIVE_NULL_MEMORY_TEST_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/null-memory-test.depex
CDK2_NATIVE_NULL_MEMORY_TEST_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-null-memory-test.fv
CDK2_NATIVE_MONO_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-monotonic-counter-test
CDK2_NATIVE_MONO_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/monotonic-counter.o
CDK2_NATIVE_MONO_PE ?= $(CDK2_NATIVE_BUILD_DIR)/MonotonicCounterRuntimeDxe.efi
CDK2_NATIVE_MONO_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/MonotonicCounterRuntimeDxe.ffs
CDK2_NATIVE_MONO_DEPEX_TOOL ?= $(CDK2_NATIVE_BUILD_DIR)/monotonic-counter-depex
CDK2_NATIVE_MONO_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/MonotonicCounterRuntimeDxe.depex
CDK2_NATIVE_MONO_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-monotonic.fv
CDK2_NATIVE_CPU_IO2_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-cpu-io2-test
CDK2_NATIVE_CPU_IO2_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/cpu-io2.o
CDK2_NATIVE_CPU_IO2_PE ?= $(CDK2_NATIVE_BUILD_DIR)/CpuIo2Dxe.efi
CDK2_NATIVE_CPU_IO2_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/CpuIo2Dxe.ffs
CDK2_NATIVE_CPU_IO2_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/CpuIo2Dxe.depex
CDK2_NATIVE_CPU_IO2_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-cpu-io2.fv
CDK2_NATIVE_ENGLISH_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-english-test
CDK2_NATIVE_ENGLISH_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/english.o
CDK2_NATIVE_ENGLISH_PE ?= $(CDK2_NATIVE_BUILD_DIR)/EnglishDxe.efi
CDK2_NATIVE_ENGLISH_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/EnglishDxe.ffs
CDK2_NATIVE_ENGLISH_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-english.fv
CDK2_NATIVE_DISK_IO_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-disk-io-test
CDK2_NATIVE_DISK_IO_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/disk-io.o
CDK2_NATIVE_DISK_IO_PE ?= $(CDK2_NATIVE_BUILD_DIR)/DiskIoDxe.efi
CDK2_NATIVE_DISK_IO_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/DiskIoDxe.ffs
CDK2_NATIVE_DISK_IO_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-disk-io.fv
CDK2_NATIVE_SERIAL_IO_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-serial-io-test
CDK2_NATIVE_SERIAL_IO_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/serial-io.o
CDK2_NATIVE_SERIAL_IO_PE ?= $(CDK2_NATIVE_BUILD_DIR)/SerialDxe.efi
CDK2_NATIVE_SERIAL_IO_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/SerialDxe.depex
CDK2_NATIVE_SERIAL_IO_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/SerialDxe.ffs
CDK2_NATIVE_SERIAL_IO_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-serial-io.fv
CDK2_NATIVE_SMBIOS_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-smbios-test
CDK2_NATIVE_SMBIOS_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/smbios.o
CDK2_NATIVE_SMBIOS_PE ?= $(CDK2_NATIVE_BUILD_DIR)/SmbiosDxe.efi
CDK2_NATIVE_SMBIOS_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/SmbiosDxe.ffs
CDK2_NATIVE_SMBIOS_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/SmbiosDxe.depex
CDK2_NATIVE_SMBIOS_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-smbios.fv
CDK2_NATIVE_RESET_SYSTEM_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-reset-system-test
CDK2_NATIVE_RESET_SYSTEM_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/reset-system.o
CDK2_NATIVE_RESET_SYSTEM_PE ?= $(CDK2_NATIVE_BUILD_DIR)/ResetSystemRuntimeDxe.efi
CDK2_NATIVE_RESET_SYSTEM_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/ResetSystemRuntimeDxe.depex
CDK2_NATIVE_RESET_SYSTEM_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/ResetSystemRuntimeDxe.ffs
CDK2_NATIVE_RESET_SYSTEM_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-reset-system.fv
CDK2_NATIVE_PCAT_RTC_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-pcat-rtc-test
CDK2_NATIVE_PCAT_RTC_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/pcat-rtc.o
CDK2_NATIVE_PCAT_RTC_PE ?= $(CDK2_NATIVE_BUILD_DIR)/PcRtc.efi
CDK2_NATIVE_PCAT_RTC_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/PcRtc.depex
CDK2_NATIVE_PCAT_RTC_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/PcRtc.ffs
CDK2_NATIVE_PCAT_RTC_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-pcat-rtc.fv
CDK2_NATIVE_SMM_ACCESS_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-smm-access-test
CDK2_NATIVE_SMM_ACCESS_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/smm-access.o
CDK2_NATIVE_SMM_ACCESS_PE ?= $(CDK2_NATIVE_BUILD_DIR)/SmmAccessDxe.efi
CDK2_NATIVE_SMM_ACCESS_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/SmmAccessDxe.depex
CDK2_NATIVE_SMM_ACCESS_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/SmmAccessDxe.ffs
CDK2_NATIVE_SMM_ACCESS_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-smm-access.fv
CDK2_NATIVE_SMM_CONTROL_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-smm-control-test
CDK2_NATIVE_SMM_CONTROL_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/smm-control.o
CDK2_NATIVE_SMM_CONTROL_PE ?= $(CDK2_NATIVE_BUILD_DIR)/SmmControlRuntimeDxe.efi
CDK2_NATIVE_SMM_CONTROL_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/SmmControlRuntimeDxe.depex
CDK2_NATIVE_SMM_CONTROL_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/SmmControlRuntimeDxe.ffs
CDK2_NATIVE_SMM_CONTROL_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-smm-control.fv
CDK2_NATIVE_CPU_IO2_SMM_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-cpu-io2-smm-test
CDK2_NATIVE_CPU_IO2_SMM_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/cpu-io2-smm.o
CDK2_NATIVE_CPU_IO2_SMM_PE ?= $(CDK2_NATIVE_BUILD_DIR)/CpuIo2Smm.efi
CDK2_NATIVE_CPU_IO2_SMM_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/CpuIo2Smm.depex
CDK2_NATIVE_CPU_IO2_SMM_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/CpuIo2Smm.ffs
CDK2_NATIVE_CPU_IO2_SMM_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-cpu-io2-smm.fv
CDK2_NATIVE_PCH_SMI_DISPATCH_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-pch-smi-dispatch-test
CDK2_NATIVE_PCH_SMI_DISPATCH_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/pch-smi-dispatch.o
CDK2_NATIVE_PCH_SMI_DISPATCH_PE ?= $(CDK2_NATIVE_BUILD_DIR)/PchSmiDispatchSmm.efi
CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX_GEN ?= $(CDK2_NATIVE_BUILD_DIR)/pch-smi-depex-gen
CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/PchSmiDispatchSmm.depex
CDK2_NATIVE_PCH_SMI_DISPATCH_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/PchSmiDispatchSmm.ffs
CDK2_NATIVE_PCH_SMI_DISPATCH_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-pch-smi-dispatch.fv
CDK2_NATIVE_LOCAL_APIC_TIMER_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-local-apic-timer-test
CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-local-apic-timer-driver-test
CDK2_NATIVE_LOCAL_APIC_TIMER_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/local-apic-timer.o
CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/local-apic-timer-driver.o
CDK2_NATIVE_LOCAL_APIC_TIMER_PE ?= $(CDK2_NATIVE_BUILD_DIR)/LocalApicTimerDxe.efi
CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX_GEN ?= $(CDK2_NATIVE_BUILD_DIR)/local-apic-timer-depex-gen
CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/LocalApicTimerDxe.depex
CDK2_NATIVE_LOCAL_APIC_TIMER_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/LocalApicTimerDxe.ffs
CDK2_NATIVE_LOCAL_APIC_TIMER_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-local-apic-timer.fv
CDK2_NATIVE_CAPSULE_RUNTIME_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-capsule-runtime-test
CDK2_NATIVE_CAPSULE_RUNTIME_ABI_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-capsule-runtime-abi-test
CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-capsule-runtime-entry-test
CDK2_NATIVE_CAPSULE_RUNTIME_QEMU_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/capsule-runtime-qemu.o
CDK2_NATIVE_CAPSULE_RUNTIME_QEMU_PE ?= $(CDK2_NATIVE_BUILD_DIR)/CapsuleRuntimeQemu.efi
CDK2_NATIVE_CAPSULE_RUNTIME_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/capsule-runtime.o
CDK2_NATIVE_CAPSULE_RUNTIME_ABI_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/capsule-runtime-abi.o
CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/capsule-runtime-entry.o
CDK2_NATIVE_CAPSULE_RUNTIME_PE ?= $(CDK2_NATIVE_BUILD_DIR)/CapsuleRuntimeDxe.efi
CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX_GEN ?= $(CDK2_NATIVE_BUILD_DIR)/capsule-runtime-depex-gen
CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/CapsuleRuntimeDxe.depex
CDK2_NATIVE_CAPSULE_RUNTIME_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/CapsuleRuntimeDxe.ffs
CDK2_NATIVE_CAPSULE_RUNTIME_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-capsule-runtime.fv
CDK2_NATIVE_REMOVE_TCG1_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-without-tcg1.fv
CDK2_NATIVE_GRAPHICS_CONSOLE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-graphics-console-test
CDK2_NATIVE_GRAPHICS_PACKAGE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-graphics-package-test
CDK2_NATIVE_GRAPHICS_ENTRY_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-graphics-entry-test
CDK2_NATIVE_GRAPHICS_CONSOLE_OBJS := $(CDK2_NATIVE_BUILD_DIR)/graphics-console-model.o \
	$(CDK2_NATIVE_BUILD_DIR)/graphics-console-binding.o \
	$(CDK2_NATIVE_BUILD_DIR)/graphics-console-entry.o \
	$(CDK2_NATIVE_BUILD_DIR)/graphics-console-font_package.o \
	$(CDK2_NATIVE_BUILD_DIR)/graphics-console-font_data.o
CDK2_NATIVE_GRAPHICS_CONSOLE_PE ?= $(CDK2_NATIVE_BUILD_DIR)/GraphicsConsoleDxe.efi
CDK2_NATIVE_GRAPHICS_CONSOLE_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/GraphicsConsoleDxe.ffs
CDK2_NATIVE_GRAPHICS_CONSOLE_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-graphics-console.fv
CDK2_NATIVE_TCG2_TRANSPORT_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-tcg2-transport-test
CDK2_NATIVE_TCG2_COMMANDS_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-tcg2-commands-test
CDK2_NATIVE_TCG2_EVENT_LOG_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-tcg2-event-log-test
CDK2_NATIVE_TCG2_MEASURE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-tcg2-measure-test
CDK2_NATIVE_TCG2_SERVICE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-tcg2-service-test
CDK2_NATIVE_TCG2_OBJS ?= $(addprefix $(CDK2_NATIVE_BUILD_DIR)/tcg2-,driver.o tcg2_transport.o tcg2_commands.o tcg2_event_log.o tcg2_measure.o tcg2_service.o)
CDK2_NATIVE_TCG2_PE ?= $(CDK2_NATIVE_BUILD_DIR)/Tcg2Dxe.efi
CDK2_NATIVE_TCG2_DEPEX_GEN ?= $(CDK2_NATIVE_BUILD_DIR)/tcg2-depex-gen
CDK2_NATIVE_TCG2_DEPEX ?= $(CDK2_NATIVE_BUILD_DIR)/Tcg2Dxe.depex
CDK2_NATIVE_TCG2_FFS ?= $(CDK2_NATIVE_BUILD_DIR)/Tcg2Dxe.ffs
CDK2_NATIVE_TCG2_FV ?= $(CDK2_NATIVE_BUILD_DIR)/retained-native-tcg2.fv
CDK2_NATIVE_PRE_TCG2_FV ?= $(CDK2_NATIVE_GRAPHICS_CONSOLE_FV)
HOSTCC ?= cc
CDK2_NATIVE_CC ?= $(CC)
CDK2_NATIVE_HOST_CC ?= $(HOSTCC)
CDK2_NATIVE_OBJCOPY ?= objcopy
CDK2_NATIVE_NM ?= nm
CDK2_NATIVE_LD ?= ld
CDK2_NATIVE_COREBOOT_ENTRY ?= $(CDK2_NATIVE_BUILD_DIR)/entry32.o
CDK2_NATIVE_CFLAGS ?= -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -fno-asynchronous-unwind-tables -fno-unwind-tables -fdata-sections -ffunction-sections -fshort-wchar -m64 -mno-red-zone -mno-sse -mno-mmx -Os -Wall -Werror
CDK2_NATIVE_HOST_CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -fshort-wchar
CDK2_NATIVE_HOST_LDFLAGS ?=
CDK2_NATIVE_INCLUDES := -I$(CDK2_BUILD_DIR)/include -I$(CDK2_DIR)/include
CDK2_NATIVE_DEPFILES := $(CDK2_NATIVE_BUILD_DIR)/*.d
CDK2_NATIVE_STAGE_OBJS := \
	$(CDK2_NATIVE_BUILD_DIR)/entry.o \
	$(CDK2_NATIVE_BUILD_DIR)/module.o \
	$(CDK2_NATIVE_BUILD_DIR)/platform.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_checksum.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_hobs.o \
	$(CDK2_NATIVE_BUILD_DIR)/fv.o \
	$(CDK2_NATIVE_BUILD_DIR)/pe.o \
	$(CDK2_NATIVE_BUILD_DIR)/mem.o \
	$(CDK2_NATIVE_BUILD_DIR)/services.o \
	$(CDK2_NATIVE_BUILD_DIR)/payload.o
CDK2_NATIVE_COREBOOT_OBJS := \
	$(CDK2_NATIVE_COREBOOT_ENTRY) \
	$(CDK2_NATIVE_BUILD_DIR)/entry.o \
	$(CDK2_NATIVE_BUILD_DIR)/module.o \
	$(CDK2_NATIVE_BUILD_DIR)/platform.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_checksum.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_hobs.o \
	$(CDK2_NATIVE_BUILD_DIR)/fv.o \
	$(CDK2_NATIVE_BUILD_DIR)/pe.o \
	$(CDK2_NATIVE_BUILD_DIR)/mem.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_handoff.o \
	$(CDK2_NATIVE_BUILD_DIR)/services.o \
	$(CDK2_NATIVE_BUILD_DIR)/payload.o
CDK2_NATIVE_OVERRIDE_OBJS := \
	$(CDK2_NATIVE_STAGE_OBJS) \
	$(CDK2_NATIVE_BUILD_DIR)/override.o
CDK2_NATIVE_STAGE_LINK_INPUTS := $(foreach obj,$(CDK2_NATIVE_STAGE_OBJS),"$(obj)")
CDK2_NATIVE_COREBOOT_LINK_INPUTS := $(foreach obj,$(CDK2_NATIVE_COREBOOT_OBJS),"$(obj)")
CDK2_NATIVE_OVERRIDE_LINK_INPUTS := $(foreach obj,$(CDK2_NATIVE_OVERRIDE_OBJS),"$(obj)")
CDK2_NATIVE_HOST_TOOLS := \
	$(CDK2_NATIVE_PACKER) \
	$(CDK2_NATIVE_FVINFO) \
	$(CDK2_NATIVE_FFSBUILD) \
	$(CDK2_NATIVE_FFSBUILD_TEST) \
	$(CDK2_NATIVE_FVREPLACE) \
	$(CDK2_NATIVE_PERELOCCHECK) \
	$(CDK2_NATIVE_METRONOME_TEST) \
	$(CDK2_NATIVE_WATCHDOG_TEST) \
	$(CDK2_NATIVE_STATUS_CODE_ROUTER_TEST) \
	$(CDK2_NATIVE_STATUS_CODE_HANDLER_TEST) \
	$(CDK2_NATIVE_SERVICE_TEST) \
	$(CDK2_NATIVE_COREBOOT_TEST) \
	$(CDK2_NATIVE_FV_TEST) \
	$(CDK2_NATIVE_FVPACK_TEST) \
	$(CDK2_NATIVE_FVINFO_TEST) \
	$(CDK2_NATIVE_PE_TEST) \
	$(CDK2_NATIVE_MODULE_TEST) \
	$(CDK2_NATIVE_ELF_CHECK) \
	$(CDK2_NATIVE_ELF_CHECK_TEST) \
	$(CDK2_NATIVE_SECURITY_STUB_TEST) \
	$(CDK2_NATIVE_NULL_MEMORY_TEST) \
	$(CDK2_NATIVE_CPU_IO2_TEST) \
	$(CDK2_NATIVE_MONO_TEST) \
	$(CDK2_NATIVE_ENGLISH_TEST) \
	$(CDK2_NATIVE_DISK_IO_TEST) \
	$(CDK2_NATIVE_SERIAL_IO_TEST) \
	$(CDK2_NATIVE_SMBIOS_TEST) \
	$(CDK2_NATIVE_SMM_CONTROL_TEST) \
	$(CDK2_NATIVE_CPU_IO2_SMM_TEST) \
	$(CDK2_NATIVE_PCH_SMI_DISPATCH_TEST) \
	$(CDK2_NATIVE_LOCAL_APIC_TIMER_TEST) \
	$(CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_TEST) \
	$(CDK2_NATIVE_GRAPHICS_CONSOLE_TEST) \
	$(CDK2_NATIVE_GRAPHICS_PACKAGE_TEST) \
	$(CDK2_NATIVE_GRAPHICS_ENTRY_TEST) \
	$(CDK2_NATIVE_CAPSULE_RUNTIME_TEST) \
	$(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_TEST) \
	$(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_TEST)
CDK2_NATIVE_LINK_FLAGS := -static -no-pie -nostdlib -nostartfiles -nodefaultlibs -Wl,-z,max-page-size=0x1000 -Wl,-z,common-page-size=0x1000 -Wl,-T,"$(CDK2_NATIVE_DIR)/cdk2.ld"
CDK2_NATIVE_LINK_POST_MAP_FLAGS := -Wl,--gc-sections -Wl,--build-id=none

.PHONY: native-stage native-coreboot-stage native-coreboot-image native-metronome-fv native-security-stub-fv native-null-memory-test-fv native-null-memory-test-test native-watchdog-fv native-monotonic-counter-fv native-status-code-router-fv native-status-code-router-test native-status-code-handler-fv native-status-code-handler-test native-cpu-io2-fv native-cpu-io2-test native-english-test native-english-fv native-disk-io-fv native-disk-io-test native-serial-io-fv native-serial-io-test native-smbios-fv native-smbios-test native-reset-system-fv native-reset-system-test native-pcat-rtc-fv native-pcat-rtc-test native-smm-access-fv native-smm-access-test native-smm-control-fv native-smm-control-test native-cpu-io2-smm-fv native-cpu-io2-smm-test native-pch-smi-dispatch-test native-pch-smi-dispatch-fv native-local-apic-timer-test native-local-apic-timer-fv native-graphics-console-test native-graphics-console-fv native-capsule-runtime-test native-capsule-runtime-fv native-check native-pack native-service-test native-coreboot-test native-fv-test native-fvpack-test native-fvinfo native-fvinfo-test native-ffsbuild-test native-pe-test native-module-test native-security-stub-test native-elfcheck-test FORCE

ifeq ($(CONFIG_CDK2_NATIVE_STAGE),y)
CDK2_NATIVE_STAGE_DEPS := $(CDK2_NATIVE_ELF)
native-stage: $(CDK2_NATIVE_ELF)
native-coreboot-stage: $(CDK2_NATIVE_COREBOOT_ELF)

ifneq ($(strip $(CDK2_PAYLOAD_FV)),)
native-coreboot-image: $(CDK2_NATIVE_COREBOOT_IMAGE) $(CDK2_NATIVE_FV_TEST) \
		$(CDK2_NATIVE_ELF_CHECK)
	@"$(CDK2_NATIVE_FV_TEST)" "$(CDK2_NATIVE_FINAL_FV)"
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry cdk2_coreboot_entry32 --require-fv "$<"
else
native-coreboot-image:
	@printf '%s\n' 'native-coreboot-image requires CDK2_PAYLOAD_FV=/path/to/payload.fv' >&2
	@exit 1
endif

ifeq ($(CONFIG_CDK2_NATIVE_TCG2),y)
native-tcg2-fv: $(CDK2_NATIVE_TCG2_FV)
	@printf '%s\n' "native TCG2 FV: $(CDK2_NATIVE_TCG2_FV)"

$(CDK2_NATIVE_TCG2_OBJS): $(CDK2_NATIVE_BUILD_DIR)/tcg2-%.o: \
		$(CDK2_DIR)/src/modules/tcg2/%.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" -c "$<" -o "$@"

$(CDK2_NATIVE_TCG2_PE): $(CDK2_NATIVE_TCG2_OBJS) \
		$(CDK2_DIR)/src/modules/tcg2/tcg2.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(CDK2_NATIVE_LD) -mi386pep --subsystem 11 --entry cdk2_tcg2_entry \
		--image-base 0 --section-alignment 0x1000 --file-alignment 0x1000 \
		--build-id=none --no-insert-timestamp -s --nxcompat \
		-T "$(CDK2_DIR)/src/modules/tcg2/tcg2.ld" -o "$@" $(CDK2_NATIVE_TCG2_OBJS)
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 11 "$@"

$(CDK2_NATIVE_TCG2_DEPEX_GEN): $(CDK2_DIR)/src/modules/tcg2/depex.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_TCG2_DEPEX): $(CDK2_NATIVE_TCG2_DEPEX_GEN)
	@"$<" "$@"

$(CDK2_NATIVE_TCG2_FFS): $(CDK2_NATIVE_TCG2_PE) $(CDK2_NATIVE_TCG2_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" fdff263d-5f68-4591-87ba-b768f445a9af \
		Tcg2Dxe 1.0 0x1609e "$<" "$@" "$(CDK2_NATIVE_TCG2_DEPEX)"

$(CDK2_NATIVE_TCG2_FV): $(CDK2_NATIVE_PRE_TCG2_FV) $(CDK2_NATIVE_TCG2_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_TCG2_FV)" 0x38b828 \
		"$(CDK2_NATIVE_TCG2_FFS)" "$@"
else
native-tcg2-fv:
	@printf '%s\n' 'native TCG2: disabled by Kconfig'
endif
native-check: $(CDK2_CONFIG_HEADER) $(CDK2_NATIVE_ELF) $(CDK2_NATIVE_OVERRIDE_ELF) \
		$(CDK2_NATIVE_COREBOOT_ELF) $(CDK2_NATIVE_COREBOOT_ENTRY) \
		$(CDK2_NATIVE_HOST_TOOLS)
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_ELF)" | grep -Eq '[[:space:]]W[[:space:]]cdk2_platform_initialize_native_context$$'
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_ELF)" | grep -Eq '[[:space:]]W[[:space:]]cdk2_platform_late_init$$'
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_OVERRIDE_ELF)" | grep -Eq '[[:space:]]T[[:space:]]cdk2_platform_initialize_native_context$$'
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_OVERRIDE_ELF)" | grep -Eq '[[:space:]]T[[:space:]]cdk2_platform_late_init$$'
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_COREBOOT_ELF)" | grep -Eq '[[:space:]]T[[:space:]]cdk2_platform_initialize_native_context$$'
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_COREBOOT_ELF)" | grep -Eq '[[:space:]]W[[:space:]]cdk2_platform_late_init$$'
	@$(CDK2_NATIVE_NM) "$(CDK2_NATIVE_COREBOOT_ELF)" | grep -Eq '[[:space:]]T[[:space:]]cdk2_coreboot_entry32$$'
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry cdk2_native_stage_entry "$(CDK2_NATIVE_ELF)"
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry cdk2_coreboot_entry32 "$(CDK2_NATIVE_COREBOOT_ELF)"
	@test -s "$(CDK2_NATIVE_MAP)"
	@test -s "$(CDK2_NATIVE_COREBOOT_MAP)"
	@test -s "$(CDK2_NATIVE_OVERRIDE_MAP)"
	@test -x "$(CDK2_NATIVE_PACKER)"
	@"$(CDK2_NATIVE_SERVICE_TEST)"
	@"$(CDK2_NATIVE_COREBOOT_TEST)"
	@"$(CDK2_NATIVE_FV_TEST)"
	@"$(CDK2_NATIVE_FVPACK_TEST)" "$(CDK2_NATIVE_PACKER)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_FVINFO_TEST)" "$(CDK2_NATIVE_FVINFO)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_FFSBUILD_TEST)" "$(CDK2_NATIVE_FFSBUILD)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_METRONOME_TEST)"
	@"$(CDK2_NATIVE_WATCHDOG_TEST)"
	@"$(CDK2_NATIVE_STATUS_CODE_ROUTER_TEST)"
	@"$(CDK2_NATIVE_STATUS_CODE_HANDLER_TEST)"
	@"$(CDK2_NATIVE_GRAPHICS_CONSOLE_TEST)"
	@"$(CDK2_NATIVE_GRAPHICS_PACKAGE_TEST)"
	@"$(CDK2_NATIVE_GRAPHICS_ENTRY_TEST)"
	@"$(CDK2_NATIVE_PE_TEST)"
	@"$(CDK2_NATIVE_MODULE_TEST)"
	@"$(CDK2_NATIVE_SECURITY_STUB_TEST)"
	@"$(CDK2_NATIVE_NULL_MEMORY_TEST)"
	@"$(CDK2_NATIVE_MONO_TEST)"
	@"$(CDK2_NATIVE_ENGLISH_TEST)"
	@"$(CDK2_NATIVE_DISK_IO_TEST)"
	@"$(CDK2_NATIVE_SERIAL_IO_TEST)"
	@"$(CDK2_NATIVE_SMBIOS_TEST)"
	@"$(CDK2_NATIVE_SMM_CONTROL_TEST)"
	@"$(CDK2_NATIVE_CPU_IO2_SMM_TEST)"
	@"$(CDK2_NATIVE_PCH_SMI_DISPATCH_TEST)"
	@"$(CDK2_NATIVE_LOCAL_APIC_TIMER_TEST)"
	@"$(CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_TEST)"
	@"$(CDK2_NATIVE_CAPSULE_RUNTIME_TEST)"
	@"$(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_TEST)"
	@"$(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_TEST)"
	@"$(CDK2_NATIVE_ELF_CHECK_TEST)" "$(CDK2_NATIVE_ELF_CHECK)" "$(CDK2_NATIVE_BUILD_DIR)"
	@printf '%s\n' "native cdk2 stage: $(CDK2_NATIVE_ELF)"
	@printf '%s\n' "native cdk2 FV packer: $(CDK2_NATIVE_PACKER)"
else
CDK2_NATIVE_STAGE_DEPS :=
native-stage:
	@printf '%s\n' 'native cdk2 stage: disabled by Kconfig'

native-coreboot-stage:
	@printf '%s\n' 'native cdk2 coreboot stage: disabled by Kconfig'

native-check: $(CDK2_CONFIG_HEADER) $(CDK2_NATIVE_HOST_TOOLS)
	@"$(CDK2_NATIVE_SERVICE_TEST)"
	@"$(CDK2_NATIVE_COREBOOT_TEST)"
	@"$(CDK2_NATIVE_FV_TEST)"
	@"$(CDK2_NATIVE_FVPACK_TEST)" "$(CDK2_NATIVE_PACKER)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_FVINFO_TEST)" "$(CDK2_NATIVE_FVINFO)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_FFSBUILD_TEST)" "$(CDK2_NATIVE_FFSBUILD)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_WATCHDOG_TEST)"
	@"$(CDK2_NATIVE_STATUS_CODE_ROUTER_TEST)"
	@"$(CDK2_NATIVE_STATUS_CODE_HANDLER_TEST)"
	@"$(CDK2_NATIVE_PE_TEST)"
	@"$(CDK2_NATIVE_MODULE_TEST)"
	@"$(CDK2_NATIVE_ELF_CHECK_TEST)" "$(CDK2_NATIVE_ELF_CHECK)" "$(CDK2_NATIVE_BUILD_DIR)"
	@printf '%s\n' 'native cdk2 stage: disabled by Kconfig'
	@printf '%s\n' "native cdk2 FV packer: $(CDK2_NATIVE_PACKER)"
endif

native-pack: $(CDK2_NATIVE_PACKER)
	@printf '%s\n' "native cdk2 FV packer: $(CDK2_NATIVE_PACKER)"

native-service-test: $(CDK2_NATIVE_SERVICE_TEST)
	@"$(CDK2_NATIVE_SERVICE_TEST)"

native-coreboot-test: $(CDK2_NATIVE_COREBOOT_TEST)
	@"$(CDK2_NATIVE_COREBOOT_TEST)"

native-fv-test: $(CDK2_NATIVE_FV_TEST)
	@"$(CDK2_NATIVE_FV_TEST)"

native-fvpack-test: $(CDK2_NATIVE_FVPACK_TEST) $(CDK2_NATIVE_PACKER)
	@"$(CDK2_NATIVE_FVPACK_TEST)" "$(CDK2_NATIVE_PACKER)" "$(CDK2_NATIVE_BUILD_DIR)"

native-fvinfo: $(CDK2_NATIVE_FVINFO)
	@printf '%s\n' "native cdk2 FV inventory tool: $(CDK2_NATIVE_FVINFO)"

native-fvinfo-test: $(CDK2_NATIVE_FVINFO_TEST) $(CDK2_NATIVE_FVINFO)
	@"$(CDK2_NATIVE_FVINFO_TEST)" "$(CDK2_NATIVE_FVINFO)" "$(CDK2_NATIVE_BUILD_DIR)"

native-metronome-fv: $(CDK2_NATIVE_METRONOME_FV)
	@printf '%s\n' "native Metronome FV: $(CDK2_NATIVE_METRONOME_FV)"

native-ffsbuild-test: $(CDK2_NATIVE_FFSBUILD_TEST) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD_TEST)" "$(CDK2_NATIVE_FFSBUILD)" "$(CDK2_NATIVE_BUILD_DIR)"

native-watchdog-fv: $(CDK2_NATIVE_WATCHDOG_FV)
	@printf '%s\n' "native WatchdogTimer FV: $(CDK2_NATIVE_WATCHDOG_FV)"

native-status-code-router-fv: $(CDK2_NATIVE_STATUS_CODE_ROUTER_FV)
	@printf '%s\n' "native status-code router FV: $(CDK2_NATIVE_STATUS_CODE_ROUTER_FV)"

native-status-code-router-test: $(CDK2_NATIVE_STATUS_CODE_ROUTER_TEST)
	@"$(CDK2_NATIVE_STATUS_CODE_ROUTER_TEST)"

native-cpu-io2-test: $(CDK2_NATIVE_CPU_IO2_TEST)
	@"$<"

native-cpu-io2-fv: $(CDK2_NATIVE_CPU_IO2_FV)
	@printf '%s\n' "native CpuIo2 FV: $(CDK2_NATIVE_CPU_IO2_FV)"

native-status-code-handler-fv: $(CDK2_NATIVE_STATUS_CODE_HANDLER_FV)
	@printf '%s\n' "native status-code handler FV: $(CDK2_NATIVE_STATUS_CODE_HANDLER_FV)"

native-status-code-handler-test: $(CDK2_NATIVE_STATUS_CODE_HANDLER_TEST)
	@"$(CDK2_NATIVE_STATUS_CODE_HANDLER_TEST)"
native-disk-io-test: $(CDK2_NATIVE_DISK_IO_TEST)
	@"$<"

native-disk-io-fv: $(CDK2_NATIVE_DISK_IO_FV)
	@printf '%s\n' "native DiskIo FV: $(CDK2_NATIVE_DISK_IO_FV)"

native-serial-io-test: $(CDK2_NATIVE_SERIAL_IO_TEST)
	@"$(CDK2_NATIVE_SERIAL_IO_TEST)"

native-serial-io-fv: $(CDK2_NATIVE_SERIAL_IO_FV)
	@printf '%s\n' "native SerialIo FV: $(CDK2_NATIVE_SERIAL_IO_FV)"

native-smbios-test: $(CDK2_NATIVE_SMBIOS_TEST)
	@"$<"

native-smbios-fv: $(CDK2_NATIVE_SMBIOS_FV)
	@printf '%s\n' "native Smbios FV: $(CDK2_NATIVE_SMBIOS_FV)"

native-reset-system-test: $(CDK2_NATIVE_RESET_SYSTEM_TEST)
	@"$<"

native-reset-system-fv: $(CDK2_NATIVE_RESET_SYSTEM_FV)
	@printf '%s\n' "native ResetSystem FV: $(CDK2_NATIVE_RESET_SYSTEM_FV)"

native-pcat-rtc-test: $(CDK2_NATIVE_PCAT_RTC_TEST)
	@"$<"

native-pcat-rtc-fv: $(CDK2_NATIVE_PCAT_RTC_FV)
	@printf '%s\n' "native PC/AT RTC FV: $(CDK2_NATIVE_PCAT_RTC_FV)"

native-smm-access-test: $(CDK2_NATIVE_SMM_ACCESS_TEST)
	@"$<"

native-smm-access-fv: $(CDK2_NATIVE_SMM_ACCESS_FV)
	@printf '%s\n' "native SMM Access FV: $(CDK2_NATIVE_SMM_ACCESS_FV)"

native-smm-control-test: $(CDK2_NATIVE_SMM_CONTROL_TEST)
	@"$<"

native-smm-control-fv: $(CDK2_NATIVE_SMM_CONTROL_FV)
	@printf '%s\n' "native SMM Control FV: $(CDK2_NATIVE_SMM_CONTROL_FV)"

native-cpu-io2-smm-test: $(CDK2_NATIVE_CPU_IO2_SMM_TEST)
	@"$<"

native-cpu-io2-smm-fv: $(CDK2_NATIVE_CPU_IO2_SMM_FV)
	@printf '%s\n' "native SMM CPU I/O 2 FV: $(CDK2_NATIVE_CPU_IO2_SMM_FV)"

native-pch-smi-dispatch-test: $(CDK2_NATIVE_PCH_SMI_DISPATCH_TEST)
	@"$<"

native-tcg2-transport-test: $(CDK2_NATIVE_TCG2_TRANSPORT_TEST)
	@"$<"

native-tcg2-commands-test: $(CDK2_NATIVE_TCG2_COMMANDS_TEST)
	@"$<"

native-tcg2-event-log-test: $(CDK2_NATIVE_TCG2_EVENT_LOG_TEST)
	@"$<"

native-tcg2-measure-test: $(CDK2_NATIVE_TCG2_MEASURE_TEST)
	@"$<"

native-tcg2-service-test: $(CDK2_NATIVE_TCG2_SERVICE_TEST)
	@"$<"

native-pch-smi-dispatch-fv: $(CDK2_NATIVE_PCH_SMI_DISPATCH_FV)
	@printf '%s\n' "native PCH SMI dispatch FV: $(CDK2_NATIVE_PCH_SMI_DISPATCH_FV)"

native-local-apic-timer-test: $(CDK2_NATIVE_LOCAL_APIC_TIMER_TEST)
	@"$<"

native-local-apic-timer-fv: $(CDK2_NATIVE_LOCAL_APIC_TIMER_FV)
	@printf '%s\n' "native local APIC timer FV: $(CDK2_NATIVE_LOCAL_APIC_TIMER_FV)"

native-graphics-console-test: $(CDK2_NATIVE_GRAPHICS_CONSOLE_TEST) $(CDK2_NATIVE_GRAPHICS_PACKAGE_TEST) $(CDK2_NATIVE_GRAPHICS_ENTRY_TEST)
	@"$(CDK2_NATIVE_GRAPHICS_CONSOLE_TEST)"
	@"$(CDK2_NATIVE_GRAPHICS_PACKAGE_TEST)"
	@"$(CDK2_NATIVE_GRAPHICS_ENTRY_TEST)"

native-capsule-runtime-test: $(CDK2_NATIVE_CAPSULE_RUNTIME_TEST) \
		$(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_TEST) $(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_TEST) \
		$(CDK2_NATIVE_CAPSULE_RUNTIME_QEMU_PE)
	@"$(CDK2_NATIVE_CAPSULE_RUNTIME_TEST)"
	@"$(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_TEST)"
	@"$(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_TEST)"

native-capsule-runtime-fv: $(CDK2_NATIVE_CAPSULE_RUNTIME_FV)
	@printf '%s\n' "native capsule runtime FV: $(CDK2_NATIVE_CAPSULE_RUNTIME_FV)"
native-pe-test: $(CDK2_NATIVE_PE_TEST)
	@"$(CDK2_NATIVE_PE_TEST)"

native-module-test: $(CDK2_NATIVE_MODULE_TEST)
	@"$(CDK2_NATIVE_MODULE_TEST)"

native-security-stub-test: $(CDK2_NATIVE_SECURITY_STUB_TEST)
	@"$(CDK2_NATIVE_SECURITY_STUB_TEST)"

native-monotonic-counter-test: $(CDK2_NATIVE_MONO_TEST)
	@"$(CDK2_NATIVE_MONO_TEST)"

native-monotonic-counter-fv: $(CDK2_NATIVE_MONO_FV)
	@printf '%s\n' "native monotonic-counter FV: $(CDK2_NATIVE_MONO_FV)"

native-english-test: $(CDK2_NATIVE_ENGLISH_TEST)
	@"$(CDK2_NATIVE_ENGLISH_TEST)"

native-english-fv: $(CDK2_NATIVE_ENGLISH_FV)
	@printf '%s\n' "native EnglishDxe FV: $(CDK2_NATIVE_ENGLISH_FV)"

ifeq ($(CONFIG_CDK2_NATIVE_SECURITY_STUB),y)
native-security-stub-fv: $(CDK2_NATIVE_SECURITY_STUB_FV)
	@printf '%s\n' "native SecurityStubDxe FV: $(CDK2_NATIVE_SECURITY_STUB_FV)"

$(CDK2_NATIVE_SECURITY_STUB_FV): $(CDK2_NATIVE_METRONOME_FV) $(CDK2_NATIVE_SECURITY_STUB_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_METRONOME_FV)" 0x86900 "$(CDK2_NATIVE_SECURITY_STUB_FFS)" "$@"

$(CDK2_NATIVE_SECURITY_STUB_FFS): $(CDK2_NATIVE_SECURITY_STUB_PE) $(CDK2_NATIVE_SECURITY_STUB_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" f80697e9-7fd6-4665-8646-88e33ef71dfc SecurityStubDxe 1.0 0xa066 "$<" "$@" "$(CDK2_NATIVE_SECURITY_STUB_DEPEX)"

$(CDK2_NATIVE_SECURITY_STUB_PE): $(CDK2_NATIVE_SECURITY_STUB_OBJ) $(CDK2_DIR)/src/modules/security_stub/security_stub.ld $(CDK2_NATIVE_PERELOCCHECK)
	@SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(CDK2_NATIVE_LD) -mi386pep --subsystem 11 \
		--entry security_stub_initialize --image-base 0 --section-alignment 0x1000 \
		--file-alignment 0x1000 --build-id=none --no-insert-timestamp -s --nxcompat \
		-T "$(CDK2_DIR)/src/modules/security_stub/security_stub.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_SECURITY_STUB_OBJ): $(CDK2_DIR)/src/modules/security_stub/security_stub.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" -c "$<" -o "$@"

$(CDK2_NATIVE_SECURITY_STUB_DEPEX): $(CDK2_NATIVE_SECURITY_STUB_DEPEX_TOOL)
	@"$<" "$@"

$(CDK2_NATIVE_SECURITY_STUB_DEPEX_TOOL): $(CDK2_DIR)/src/modules/security_stub/depex.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"
else
native-security-stub-fv:
	@printf '%s\n' 'native SecurityStubDxe: disabled by Kconfig'
endif

native-null-memory-test-fv: $(CDK2_NATIVE_NULL_MEMORY_TEST_FV)
	@printf '%s\n' "native NullMemoryTest FV: $(CDK2_NATIVE_NULL_MEMORY_TEST_FV)"

native-null-memory-test-test: $(CDK2_NATIVE_NULL_MEMORY_TEST)
	@"$(CDK2_NATIVE_NULL_MEMORY_TEST)"

$(CDK2_NATIVE_NULL_MEMORY_TEST_OBJ): $(CDK2_DIR)/src/modules/null_memory_test/null_memory_test.c $(CDK2_DIR)/include/cdk2/null_memory_test.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -ffunction-sections -fdata-sections,$(CDK2_NATIVE_CFLAGS)) \
		-fno-ident -fcf-protection=none -mcmodel=large $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_NULL_MEMORY_TEST_PE): $(CDK2_NATIVE_NULL_MEMORY_TEST_OBJ) \
		$(CDK2_DIR)/src/modules/null_memory_test/null_memory_test.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(CDK2_NATIVE_LD) -mi386pep --subsystem 11 --entry cdk2_null_memory_test_entry \
		--image-base 0 --section-alignment 0x1000 --file-alignment 0x1000 \
		--build-id=none --no-insert-timestamp -s --nxcompat \
		-T "$(CDK2_DIR)/src/modules/null_memory_test/null_memory_test.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_NULL_MEMORY_TEST_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\261\314\272\046\102\157\324\021\274\347\000\200\307\074\210\201\010' > "$@"

$(CDK2_NATIVE_NULL_MEMORY_TEST_FFS): $(CDK2_NATIVE_NULL_MEMORY_TEST_PE) \
		$(CDK2_NATIVE_NULL_MEMORY_TEST_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 96b5c032-df4c-4b6e-8232-438dcf448d0e \
		NullMemoryTestDxe 1.0 0x506a "$<" "$@" "$(CDK2_NATIVE_NULL_MEMORY_TEST_DEPEX)"

$(CDK2_NATIVE_NULL_MEMORY_TEST_FV): $(CDK2_NATIVE_SECURITY_STUB_FV) \
		$(CDK2_NATIVE_NULL_MEMORY_TEST_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_SECURITY_STUB_FV)" 0x130228 \
		"$(CDK2_NATIVE_NULL_MEMORY_TEST_FFS)" "$@"

native-elfcheck-test: $(CDK2_NATIVE_ELF_CHECK) $(CDK2_NATIVE_ELF_CHECK_TEST)
	@"$(CDK2_NATIVE_ELF_CHECK_TEST)" "$(CDK2_NATIVE_ELF_CHECK)" "$(CDK2_NATIVE_BUILD_DIR)"

$(CDK2_NATIVE_BUILD_DIR):
	@mkdir -p "$@"

$(CDK2_NATIVE_COREBOOT_ENTRY): $(CDK2_NATIVE_DIR)/entry32.S | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) -c -ffreestanding -fno-pie -fno-stack-protector -o "$@" "$<"

$(CDK2_NATIVE_BUILD_DIR)/entry.o: $(CDK2_NATIVE_DIR)/entry.c $(CDK2_NATIVE_DIR)/entry.h $(CDK2_NATIVE_DIR)/module.h $(CDK2_NATIVE_DIR)/context.h $(CDK2_NATIVE_DIR)/symbols.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/module.o: $(CDK2_NATIVE_DIR)/module.c $(CDK2_NATIVE_DIR)/module.h $(CDK2_NATIVE_DIR)/context.h $(CDK2_NATIVE_DIR)/services.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/platform.o: $(CDK2_DIR)/src/platform/cdk2_platform_lib/cdk2_platform_lib.c $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot_handoff.o: $(CDK2_NATIVE_DIR)/coreboot_handoff.c $(CDK2_NATIVE_DIR)/coreboot_hobs.h $(CDK2_NATIVE_DIR)/fv.h $(CDK2_NATIVE_DIR)/pe.h $(CDK2_NATIVE_DIR)/symbols.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot.o: $(CDK2_NATIVE_DIR)/coreboot.c $(CDK2_NATIVE_DIR)/coreboot.h $(CDK2_DIR)/include/coreboot_tables.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot_checksum.o: $(CDK2_NATIVE_DIR)/coreboot_checksum.c $(CDK2_NATIVE_DIR)/coreboot_checksum.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot_hobs.o: $(CDK2_NATIVE_DIR)/coreboot_hobs.c $(CDK2_NATIVE_DIR)/coreboot_hobs.h $(CDK2_NATIVE_DIR)/coreboot.h $(CDK2_DIR)/include/pi/hob.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/fv.o: $(CDK2_NATIVE_DIR)/fv.c $(CDK2_NATIVE_DIR)/fv.h $(CDK2_DIR)/include/pi/firmware_file.h $(CDK2_DIR)/include/pi/firmware_volume.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/pe.o: $(CDK2_NATIVE_DIR)/pe.c $(CDK2_NATIVE_DIR)/pe.h $(CDK2_DIR)/include/industry_standard/pe_image.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/mem.o: $(CDK2_LIB_DIR)/mem.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/services.o: $(CDK2_NATIVE_DIR)/services.c $(CDK2_NATIVE_DIR)/services.h $(CDK2_NATIVE_DIR)/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/override.o: $(CDK2_NATIVE_DIR)/override.c $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_PACKER): $(CDK2_UTIL_DIR)/fvpack.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_FVINFO): $(CDK2_UTIL_DIR)/fvinfo.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_FFSBUILD): $(CDK2_UTIL_DIR)/ffsbuild.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_FVREPLACE): $(CDK2_UTIL_DIR)/fvreplace.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_PERELOCCHECK): $(CDK2_UTIL_DIR)/pereloccheck.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_SECURITY_STUB_TEST): $(CDK2_DIR)/tests/security_stub_test.c $(CDK2_DIR)/src/modules/security_stub/security_stub.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP \
		-MF "$(CDK2_NATIVE_BUILD_DIR)/security-stub-test.d" -MT "$@" \
		$(CDK2_NATIVE_INCLUDES) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_NULL_MEMORY_TEST): $(CDK2_DIR)/tests/null_memory_test_test.c $(CDK2_DIR)/src/modules/null_memory_test/null_memory_test.c $(CDK2_DIR)/include/cdk2/null_memory_test.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_MONO_TEST): $(CDK2_DIR)/tests/monotonic_counter_test.c $(CDK2_DIR)/src/modules/monotonic_counter/monotonic_counter.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_ENGLISH_TEST): $(CDK2_DIR)/tests/english_test.c $(CDK2_DIR)/src/modules/english/english.c $(CDK2_DIR)/include/cdk2/english.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_ELF_CHECK): $(CDK2_UTIL_DIR)/elfcheck.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_ELF_CHECK_TEST): $(CDK2_DIR)/tests/elfcheck_test.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/elfcheck-test.d" -MT "$@" $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_BUILD_DIR)/payload.o: $(CDK2_NATIVE_DIR)/payload.c $(CDK2_NATIVE_DIR)/services.h $(CDK2_NATIVE_DIR)/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_ELF): $(CDK2_NATIVE_STAGE_OBJS) $(CDK2_NATIVE_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,cdk2_native_stage_entry -o "$@" $(CDK2_NATIVE_STAGE_LINK_INPUTS)

$(CDK2_NATIVE_OVERRIDE_ELF): $(CDK2_NATIVE_OVERRIDE_OBJS) $(CDK2_NATIVE_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_OVERRIDE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,cdk2_native_stage_entry -o "$@" $(CDK2_NATIVE_OVERRIDE_LINK_INPUTS)

$(CDK2_NATIVE_COREBOOT_ELF): $(CDK2_NATIVE_COREBOOT_OBJS) $(CDK2_NATIVE_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_COREBOOT_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,cdk2_coreboot_entry32 -o "$@" $(CDK2_NATIVE_COREBOOT_LINK_INPUTS)

ifneq ($(strip $(CDK2_PAYLOAD_FV)),)
$(CDK2_NATIVE_METRONOME_OBJ): $(CDK2_DIR)/src/modules/metronome/metronome.c $(CDK2_DIR)/include/cdk2/metronome.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -ffunction-sections -fdata-sections,$(CDK2_NATIVE_CFLAGS)) \
		-fno-ident -fcf-protection=none -mcmodel=large $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_METRONOME_PE): $(CDK2_NATIVE_METRONOME_OBJ) $(CDK2_DIR)/src/modules/metronome/metronome.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_metronome_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s -T "$(CDK2_DIR)/src/modules/metronome/metronome.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_METRONOME_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_METRONOME_FFS): $(CDK2_NATIVE_METRONOME_PE) $(CDK2_NATIVE_METRONOME_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" c8339973-a563-4561-b858-d8476f9defc4 \
		Metronome 1.0 0x505a "$<" "$@" "$(CDK2_NATIVE_METRONOME_DEPEX)"

$(CDK2_NATIVE_METRONOME_FV): $(CDK2_PAYLOAD_FV) $(CDK2_NATIVE_METRONOME_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_PAYLOAD_FV)" 0x757a8 \
		"$(CDK2_NATIVE_METRONOME_FFS)" "$@"

ifeq ($(CONFIG_CDK2_NATIVE_WATCHDOG),y)
CDK2_NATIVE_PRE_STATUS_CODE_ROUTER_FV := $(CDK2_NATIVE_WATCHDOG_FV)

$(CDK2_NATIVE_WATCHDOG_OBJ): $(CDK2_DIR)/src/modules/watchdog/watchdog.c $(CDK2_DIR)/include/cdk2/watchdog.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -ffunction-sections -fdata-sections,$(CDK2_NATIVE_CFLAGS)) \
		-fno-ident -fcf-protection=none -mcmodel=large $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_WATCHDOG_PE): $(CDK2_NATIVE_WATCHDOG_OBJ) $(CDK2_DIR)/src/modules/watchdog/watchdog.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_watchdog_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s -T "$(CDK2_DIR)/src/modules/watchdog/watchdog.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_WATCHDOG_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\050\000\000\023\002\263\314\272\046\102\157\324\021\274\347\000\200\307\074\210\201\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\003\010' > "$@"

$(CDK2_NATIVE_WATCHDOG_FFS): $(CDK2_NATIVE_WATCHDOG_PE) $(CDK2_NATIVE_WATCHDOG_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" f099d67f-71ae-4c36-b2a3-dceb0eb2b7d8 \
		WatchdogTimer 1.0 0x5072 "$<" "$@" "$(CDK2_NATIVE_WATCHDOG_DEPEX)"

$(CDK2_NATIVE_WATCHDOG_FV): $(CDK2_NATIVE_NULL_MEMORY_TEST_FV) $(CDK2_NATIVE_WATCHDOG_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_NULL_MEMORY_TEST_FV)" 0x9eaf0 \
		"$(CDK2_NATIVE_WATCHDOG_FFS)" "$@"
else
CDK2_NATIVE_PRE_STATUS_CODE_ROUTER_FV := $(CDK2_NATIVE_NULL_MEMORY_TEST_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_STATUS_CODE_ROUTER),y)
CDK2_NATIVE_COMPOSED_FV := $(CDK2_NATIVE_STATUS_CODE_ROUTER_FV)

$(CDK2_NATIVE_STATUS_CODE_ROUTER_OBJ): $(CDK2_DIR)/src/modules/status_code_router/status_code_router.c $(CDK2_DIR)/include/cdk2/status_code_router.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -ffunction-sections -fdata-sections,$(CDK2_NATIVE_CFLAGS)) \
		-fno-ident -fcf-protection=none -mcmodel=large $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_STATUS_CODE_ROUTER_PE): $(CDK2_NATIVE_STATUS_CODE_ROUTER_OBJ) $(CDK2_DIR)/src/modules/status_code_router/status_code_router.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(CDK2_NATIVE_LD) -mi386pep --subsystem 12 --entry cdk2_status_code_router_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s -T "$(CDK2_DIR)/src/modules/status_code_router/status_code_router.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_STATUS_CODE_ROUTER_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_STATUS_CODE_ROUTER_FFS): $(CDK2_NATIVE_STATUS_CODE_ROUTER_PE) $(CDK2_NATIVE_STATUS_CODE_ROUTER_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" d93ce3d8-a7eb-4730-8c8e-cc466a9ecc3c \
		ReportStatusCodeRouterRuntimeDxe 1.0 0x608a "$<" "$@" \
		"$(CDK2_NATIVE_STATUS_CODE_ROUTER_DEPEX)"

$(CDK2_NATIVE_STATUS_CODE_ROUTER_FV): $(CDK2_NATIVE_PRE_STATUS_CODE_ROUTER_FV) $(CDK2_NATIVE_STATUS_CODE_ROUTER_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_STATUS_CODE_ROUTER_FV)" 0x4d630 \
		"$(CDK2_NATIVE_STATUS_CODE_ROUTER_FFS)" "$@"
else
CDK2_NATIVE_COMPOSED_FV := $(CDK2_NATIVE_PRE_STATUS_CODE_ROUTER_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_STATUS_CODE_HANDLER),y)
CDK2_NATIVE_PRE_MONOTONIC_FV := $(CDK2_NATIVE_STATUS_CODE_HANDLER_FV)

$(CDK2_NATIVE_STATUS_CODE_HANDLER_OBJ): $(CDK2_DIR)/src/modules/status_code_handler/status_code_handler.c $(CDK2_DIR)/include/cdk2/status_code_router.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -ffunction-sections -fdata-sections,$(CDK2_NATIVE_CFLAGS)) \
		-fno-ident -fcf-protection=none -mcmodel=large $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_STATUS_CODE_HANDLER_PE): $(CDK2_NATIVE_STATUS_CODE_HANDLER_OBJ) $(CDK2_DIR)/src/modules/status_code_handler/status_code_handler.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(CDK2_NATIVE_LD) -mi386pep --subsystem 12 --entry cdk2_status_code_handler_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s -T "$(CDK2_DIR)/src/modules/status_code_handler/status_code_handler.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_STATUS_CODE_HANDLER_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\050\000\000\023\002\066\051\041\206\166\016\310\101\240\072\052\362\374\034\071\342\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\003\010' > "$@"

$(CDK2_NATIVE_STATUS_CODE_HANDLER_FFS): $(CDK2_NATIVE_STATUS_CODE_HANDLER_PE) $(CDK2_NATIVE_STATUS_CODE_HANDLER_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 6c2004ef-4e0e-4be4-b14c-340eb4aa5891 \
		StatusCodeHandlerRuntimeDxe 1.0 0x608e "$<" "$@" \
		"$(CDK2_NATIVE_STATUS_CODE_HANDLER_DEPEX)"

$(CDK2_NATIVE_STATUS_CODE_HANDLER_FV): $(CDK2_NATIVE_COMPOSED_FV) $(CDK2_NATIVE_STATUS_CODE_HANDLER_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_COMPOSED_FV)" 0x536c0 \
		"$(CDK2_NATIVE_STATUS_CODE_HANDLER_FFS)" "$@"
else
CDK2_NATIVE_PRE_MONOTONIC_FV := $(CDK2_NATIVE_COMPOSED_FV)
endif

$(CDK2_NATIVE_MONO_OBJ): $(CDK2_DIR)/src/modules/monotonic_counter/monotonic_counter.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_MONO_PE): $(CDK2_NATIVE_MONO_OBJ) $(CDK2_DIR)/src/modules/monotonic_counter/monotonic_counter.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 12 --entry monotonic_counter_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/monotonic_counter/monotonic_counter.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_MONO_DEPEX_TOOL): $(CDK2_DIR)/src/modules/monotonic_counter/depex.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_MONO_DEPEX): $(CDK2_NATIVE_MONO_DEPEX_TOOL)
	@"$<" "$@"

$(CDK2_NATIVE_MONO_FFS): $(CDK2_NATIVE_MONO_PE) $(CDK2_NATIVE_MONO_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" ad608272-d07f-4964-801e-7bd3b7888652 \
		MonotonicCounterRuntimeDxe 1.0 0x40a2 "$<" "$@" "$(CDK2_NATIVE_MONO_DEPEX)"

$(CDK2_NATIVE_MONO_FV): $(CDK2_NATIVE_PRE_MONOTONIC_FV) $(CDK2_NATIVE_MONO_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_MONOTONIC_FV)" 0x9aa48 "$(CDK2_NATIVE_MONO_FFS)" "$@"

ifeq ($(CONFIG_CDK2_NATIVE_CPU_IO2),y)
CDK2_NATIVE_PRE_ENGLISH_FV := $(CDK2_NATIVE_CPU_IO2_FV)

$(CDK2_NATIVE_CPU_IO2_OBJ): $(CDK2_DIR)/src/modules/cpu_io2/cpu_io2.c $(CDK2_DIR)/include/cdk2/cpu_io2.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_CPU_IO2_PE): $(CDK2_NATIVE_CPU_IO2_OBJ) $(CDK2_DIR)/src/modules/cpu_io2/cpu_io2.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_cpu_io2_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/cpu_io2/cpu_io2.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_CPU_IO2_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_CPU_IO2_FFS): $(CDK2_NATIVE_CPU_IO2_PE) $(CDK2_NATIVE_CPU_IO2_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" a19b1fe7-c1bc-49f8-875f-54a5d542443f \
		CpuIo2Dxe 1.0 0x505a "$<" "$@" "$(CDK2_NATIVE_CPU_IO2_DEPEX)"

$(CDK2_NATIVE_CPU_IO2_FV): $(CDK2_NATIVE_MONO_FV) $(CDK2_NATIVE_CPU_IO2_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_MONO_FV)" 0x11c160 \
		"$(CDK2_NATIVE_CPU_IO2_FFS)" "$@"
else
CDK2_NATIVE_PRE_ENGLISH_FV := $(CDK2_NATIVE_MONO_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_DISK_IO),y)
CDK2_NATIVE_PRE_SERIAL_IO_FV := $(CDK2_NATIVE_DISK_IO_FV)

$(CDK2_NATIVE_DISK_IO_OBJ): $(CDK2_DIR)/src/modules/disk_io/disk_io.c $(CDK2_DIR)/include/cdk2/disk_io.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_DISK_IO_PE): $(CDK2_NATIVE_DISK_IO_OBJ) $(CDK2_DIR)/src/modules/disk_io/disk_io.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_disk_io_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/disk_io/disk_io.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_DISK_IO_FFS): $(CDK2_NATIVE_DISK_IO_PE) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 6b38f7b4-ad98-40e9-9093-aca2b5a253c4 \
		DiskIoDxe 1.0 0x8042 "$<" "$@"

$(CDK2_NATIVE_DISK_IO_FV): $(CDK2_NATIVE_ENGLISH_FV) $(CDK2_NATIVE_DISK_IO_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_ENGLISH_FV)" 0x2f7420 \
		"$(CDK2_NATIVE_DISK_IO_FFS)" "$@"
else
CDK2_NATIVE_PRE_SERIAL_IO_FV := $(CDK2_NATIVE_ENGLISH_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_SERIAL_IO),y)
CDK2_NATIVE_PRE_SMBIOS_FV := $(CDK2_NATIVE_SERIAL_IO_FV)

$(CDK2_NATIVE_SERIAL_IO_OBJ): $(CDK2_DIR)/src/modules/serial_io/serial_io.c $(CDK2_DIR)/include/cdk2/serial_io.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_SERIAL_IO_PE): $(CDK2_NATIVE_SERIAL_IO_OBJ) $(CDK2_DIR)/src/modules/serial_io/serial_io.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_serial_io_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/serial_io/serial_io.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_SERIAL_IO_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_SERIAL_IO_FFS): $(CDK2_NATIVE_SERIAL_IO_PE) $(CDK2_NATIVE_SERIAL_IO_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 9a5163e7-5c29-453f-825c-837a46a81e15 \
		SerialDxe 1.0 0x605a "$<" "$@" "$(CDK2_NATIVE_SERIAL_IO_DEPEX)"

$(CDK2_NATIVE_SERIAL_IO_FV): $(CDK2_NATIVE_PRE_SERIAL_IO_FV) $(CDK2_NATIVE_SERIAL_IO_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_SERIAL_IO_FV)" 0x2b5198 \
		"$(CDK2_NATIVE_SERIAL_IO_FFS)" "$@"
else
CDK2_NATIVE_PRE_SMBIOS_FV := $(CDK2_NATIVE_PRE_SERIAL_IO_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_SMBIOS),y)
CDK2_NATIVE_PRE_RESET_SYSTEM_FV := $(CDK2_NATIVE_SMBIOS_FV)

$(CDK2_NATIVE_SMBIOS_OBJ): $(CDK2_DIR)/src/modules/smbios/smbios.c $(CDK2_DIR)/include/cdk2/smbios.h $(CDK2_DIR)/include/cdk2/hob_payload.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_SMBIOS_PE): $(CDK2_NATIVE_SMBIOS_OBJ) $(CDK2_DIR)/src/modules/smbios/smbios.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_smbios_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/smbios/smbios.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_SMBIOS_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_SMBIOS_FFS): $(CDK2_NATIVE_SMBIOS_PE) $(CDK2_NATIVE_SMBIOS_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" f9d88642-0737-49bc-81b5-6889cd57d9ea \
		SmbiosDxe 1.0 0x705a "$<" "$@" "$(CDK2_NATIVE_SMBIOS_DEPEX)"

$(CDK2_NATIVE_SMBIOS_FV): $(CDK2_NATIVE_PRE_SMBIOS_FV) $(CDK2_NATIVE_SMBIOS_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_SMBIOS_FV)" 0x17d520 \
		"$(CDK2_NATIVE_SMBIOS_FFS)" "$@"
else
CDK2_NATIVE_PRE_RESET_SYSTEM_FV := $(CDK2_NATIVE_PRE_SMBIOS_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_RESET_SYSTEM),y)
CDK2_NATIVE_PRE_PCAT_RTC_FV := $(CDK2_NATIVE_RESET_SYSTEM_FV)

$(CDK2_NATIVE_RESET_SYSTEM_OBJ): $(CDK2_DIR)/src/modules/reset_system/reset_system.c $(CDK2_DIR)/include/cdk2/reset_system.h $(CDK2_DIR)/include/guid/acpi_board_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_RESET_SYSTEM_PE): $(CDK2_NATIVE_RESET_SYSTEM_OBJ) $(CDK2_DIR)/src/modules/reset_system/reset_system.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 12 --entry cdk2_reset_system_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/reset_system/reset_system.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_RESET_SYSTEM_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_RESET_SYSTEM_FFS): $(CDK2_NATIVE_RESET_SYSTEM_PE) $(CDK2_NATIVE_RESET_SYSTEM_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 4b28e4c7-ff36-4e10-93cf-a82159e777c5 \
		ResetSystemRuntimeDxe 1.0 0x6072 "$<" "$@" "$(CDK2_NATIVE_RESET_SYSTEM_DEPEX)"

$(CDK2_NATIVE_RESET_SYSTEM_FV): $(CDK2_NATIVE_PRE_RESET_SYSTEM_FV) $(CDK2_NATIVE_RESET_SYSTEM_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_RESET_SYSTEM_FV)" 0xa3b68 \
		"$(CDK2_NATIVE_RESET_SYSTEM_FFS)" "$@"
else
CDK2_NATIVE_PRE_PCAT_RTC_FV := $(CDK2_NATIVE_PRE_RESET_SYSTEM_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_PCAT_RTC),y)
CDK2_NATIVE_PRE_SMM_ACCESS_FV := $(CDK2_NATIVE_PCAT_RTC_FV)

$(CDK2_NATIVE_PCAT_RTC_OBJ): $(CDK2_DIR)/src/modules/pcat_rtc/pcat_rtc.c $(CDK2_DIR)/include/cdk2/pcat_rtc.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_PCAT_RTC_PE): $(CDK2_NATIVE_PCAT_RTC_OBJ) $(CDK2_DIR)/src/modules/pcat_rtc/pcat_rtc.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 12 --entry cdk2_pcat_rtc_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/pcat_rtc/pcat_rtc.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_PCAT_RTC_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\072\000\000\023\002\342\150\126\036\201\204\324\021\274\361\000\200\307\074\210\201\002\030\370\101\144\142\143\104\116\265\160\175\272\061\335\044\123\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\003\003\010' > "$@"

$(CDK2_NATIVE_PCAT_RTC_FFS): $(CDK2_NATIVE_PCAT_RTC_PE) $(CDK2_NATIVE_PCAT_RTC_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 378d7b65-8da9-4773-b6e4-a47826a833e1 \
		PcRtc 1.0 0x6076 "$<" "$@" "$(CDK2_NATIVE_PCAT_RTC_DEPEX)"

$(CDK2_NATIVE_PCAT_RTC_FV): $(CDK2_NATIVE_PRE_PCAT_RTC_FV) $(CDK2_NATIVE_PCAT_RTC_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_PCAT_RTC_FV)" 0x7a808 \
		"$(CDK2_NATIVE_PCAT_RTC_FFS)" "$@"
else
CDK2_NATIVE_PRE_SMM_ACCESS_FV := $(CDK2_NATIVE_PRE_PCAT_RTC_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_SMM_ACCESS),y)
CDK2_NATIVE_PRE_SMM_CONTROL_FV := $(CDK2_NATIVE_SMM_ACCESS_FV)

$(CDK2_NATIVE_SMM_ACCESS_OBJ): $(CDK2_DIR)/src/modules/smm_access/smm_access.c $(CDK2_DIR)/include/cdk2/smm_access.h $(CDK2_DIR)/include/guid/smram_memory.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_SMM_ACCESS_PE): $(CDK2_NATIVE_SMM_ACCESS_OBJ) $(CDK2_DIR)/src/modules/smm_access/smm_access.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_smm_access_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/smm_access/smm_access.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_SMM_ACCESS_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_SMM_ACCESS_FFS): $(CDK2_NATIVE_SMM_ACCESS_PE) $(CDK2_NATIVE_SMM_ACCESS_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 47579cf5-1e4f-4b41-99bb-a5c334846d3b \
		SmmAccessDxe 1.0 0x4062 "$<" "$@" "$(CDK2_NATIVE_SMM_ACCESS_DEPEX)"

$(CDK2_NATIVE_SMM_ACCESS_FV): $(CDK2_NATIVE_PRE_SMM_ACCESS_FV) $(CDK2_NATIVE_SMM_ACCESS_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_SMM_ACCESS_FV)" 0xa9be0 \
		"$(CDK2_NATIVE_SMM_ACCESS_FFS)" "$@"
else
CDK2_NATIVE_PRE_SMM_CONTROL_FV := $(CDK2_NATIVE_PRE_SMM_ACCESS_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_SMM_CONTROL),y)
CDK2_NATIVE_PRE_CPU_IO2_SMM_FV := $(CDK2_NATIVE_SMM_CONTROL_FV)

$(CDK2_NATIVE_SMM_CONTROL_OBJ): $(CDK2_DIR)/src/modules/smm_control/smm_control.c $(CDK2_DIR)/include/cdk2/smm_control.h $(CDK2_DIR)/include/guid/smm_register_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_SMM_CONTROL_PE): $(CDK2_NATIVE_SMM_CONTROL_OBJ) $(CDK2_DIR)/src/modules/smm_control/smm_control.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 12 --entry cdk2_smm_control_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/smm_control/smm_control.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_SMM_CONTROL_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\026\000\000\023\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\010' > "$@"

$(CDK2_NATIVE_SMM_CONTROL_FFS): $(CDK2_NATIVE_SMM_CONTROL_PE) $(CDK2_NATIVE_SMM_CONTROL_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" c3099578-f815-4a96-84a3-fc593760181d \
		SmmControlRuntimeDxe 1.0 0x5072 "$<" "$@" "$(CDK2_NATIVE_SMM_CONTROL_DEPEX)"

$(CDK2_NATIVE_SMM_CONTROL_FV): $(CDK2_NATIVE_PRE_SMM_CONTROL_FV) $(CDK2_NATIVE_SMM_CONTROL_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_SMM_CONTROL_FV)" 0xadc48 \
		"$(CDK2_NATIVE_SMM_CONTROL_FFS)" "$@"
else
CDK2_NATIVE_PRE_CPU_IO2_SMM_FV := $(CDK2_NATIVE_PRE_SMM_CONTROL_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_CPU_IO2_SMM),y)
CDK2_NATIVE_PRE_PCH_SMI_DISPATCH_FV := $(CDK2_NATIVE_CPU_IO2_SMM_FV)

$(CDK2_NATIVE_CPU_IO2_SMM_OBJ): $(CDK2_DIR)/src/modules/cpu_io2_smm/cpu_io2_smm.c $(CDK2_DIR)/include/cdk2/cpu_io2.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_CPU_IO2_SMM_PE): $(CDK2_NATIVE_CPU_IO2_SMM_OBJ) $(CDK2_DIR)/src/modules/cpu_io2_smm/cpu_io2_smm.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_cpu_io2_smm_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/cpu_io2_smm/cpu_io2_smm.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 11 "$@"

$(CDK2_NATIVE_CPU_IO2_SMM_DEPEX): | $(CDK2_NATIVE_BUILD_DIR)
	@printf '\072\000\000\034\002\366\360\243\023\112\046\360\076\362\340\336\305\022\064\057\064\002\267\277\314\364\340\366\375\107\235\324\020\250\361\120\301\221\002\164\053\160\302\014\200\061\101\207\106\217\265\270\234\344\254\003\003\010' > "$@"

$(CDK2_NATIVE_CPU_IO2_SMM_FFS): $(CDK2_NATIVE_CPU_IO2_SMM_PE) $(CDK2_NATIVE_CPU_IO2_SMM_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" a47ee2d8-f60e-42fd-8e58-7bd65ee4c29b \
		CpuIo2Smm 1.0 0x507e "$<" "$@" "$(CDK2_NATIVE_CPU_IO2_SMM_DEPEX)" \
		--file-type 0x0a --depex-type 0x1c

$(CDK2_NATIVE_CPU_IO2_SMM_FV): $(CDK2_NATIVE_PRE_CPU_IO2_SMM_FV) $(CDK2_NATIVE_CPU_IO2_SMM_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_CPU_IO2_SMM_FV)" 0xd0e20 \
		"$(CDK2_NATIVE_CPU_IO2_SMM_FFS)" "$@"
else
CDK2_NATIVE_PRE_PCH_SMI_DISPATCH_FV := $(CDK2_NATIVE_PRE_CPU_IO2_SMM_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_PCH_SMI_DISPATCH),y)
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_PCH_SMI_DISPATCH_FV)

$(CDK2_NATIVE_PCH_SMI_DISPATCH_OBJ): $(CDK2_DIR)/src/modules/pch_smi_dispatch/pch_smi_dispatch.c $(CDK2_DIR)/include/cdk2/pch_smi_dispatch.h $(CDK2_DIR)/include/guid/smm_register_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_PCH_SMI_DISPATCH_PE): $(CDK2_NATIVE_PCH_SMI_DISPATCH_OBJ) $(CDK2_DIR)/src/modules/pch_smi_dispatch/pch_smi_dispatch.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_pch_smi_dispatch_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/pch_smi_dispatch/pch_smi_dispatch.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 11 "$@"

$(CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX_GEN): $(CDK2_DIR)/src/modules/pch_smi_dispatch/depex.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX): $(CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX_GEN)
	@"$<" "$@"

$(CDK2_NATIVE_PCH_SMI_DISPATCH_FFS): $(CDK2_NATIVE_PCH_SMI_DISPATCH_PE) $(CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 60f343e3-2ae2-4aa7-b01e-bf9bd5c04a3b \
		PchSmiDispatchSmm 1.0 0x509e "$<" "$@" "$(CDK2_NATIVE_PCH_SMI_DISPATCH_DEPEX)" \
		--file-type 0x0a --depex-type 0x1c

$(CDK2_NATIVE_PCH_SMI_DISPATCH_FV): $(CDK2_NATIVE_PRE_PCH_SMI_DISPATCH_FV) $(CDK2_NATIVE_PCH_SMI_DISPATCH_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_PCH_SMI_DISPATCH_FV)" 0xf5f30 \
		"$(CDK2_NATIVE_PCH_SMI_DISPATCH_FFS)" "$@"
else
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_PRE_PCH_SMI_DISPATCH_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_LOCAL_APIC_TIMER),y)
CDK2_NATIVE_PRE_LOCAL_APIC_TIMER_FV := $(CDK2_NATIVE_FINAL_FV)
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_LOCAL_APIC_TIMER_FV)

$(CDK2_NATIVE_LOCAL_APIC_TIMER_OBJ): $(CDK2_DIR)/src/modules/local_apic_timer/local_apic_timer.c $(CDK2_DIR)/include/cdk2/local_apic_timer.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) -mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_OBJ): $(CDK2_DIR)/src/modules/local_apic_timer/driver.c $(CDK2_DIR)/include/cdk2/local_apic_timer.h $(CDK2_DIR)/include/guid/local_apic_timer_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) -mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_PE): $(CDK2_NATIVE_LOCAL_APIC_TIMER_OBJ) $(CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_OBJ) $(CDK2_DIR)/src/modules/local_apic_timer/local_apic_timer.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_local_apic_timer_entry --image-base 0 --section-alignment 0x1000 --file-alignment 0x1000 --build-id=none --no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/local_apic_timer/local_apic_timer.ld" -o "$@" $(CDK2_NATIVE_LOCAL_APIC_TIMER_OBJ) $(CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_OBJ)
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 11 "$@"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX_GEN): $(CDK2_DIR)/src/modules/local_apic_timer/depex.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX): $(CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX_GEN)
	@"$<" "$@"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_FFS): $(CDK2_NATIVE_LOCAL_APIC_TIMER_PE) $(CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 52fe8196-f9de-4d07-b22f-51f77a0e7c41 LocalApicTimerDxe 1.0 0x607a "$<" "$@" "$(CDK2_NATIVE_LOCAL_APIC_TIMER_DEPEX)"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_FV): $(CDK2_NATIVE_PRE_LOCAL_APIC_TIMER_FV) $(CDK2_NATIVE_LOCAL_APIC_TIMER_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_LOCAL_APIC_TIMER_FV)" 0x80880 "$(CDK2_NATIVE_LOCAL_APIC_TIMER_FFS)" "$@"
endif

$(CDK2_NATIVE_CAPSULE_RUNTIME_OBJ): $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c $(CDK2_DIR)/include/cdk2/capsule_runtime.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) -mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_OBJ): $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime_abi.c $(CDK2_DIR)/include/cdk2/capsule_runtime_abi.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) -mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_OBJ): $(CDK2_DIR)/src/modules/capsule_runtime/entry.c $(CDK2_DIR)/include/cdk2/capsule_runtime_entry.h $(CDK2_DIR)/include/cdk2/capsule_runtime_abi.h $(CDK2_DIR)/include/cdk2/capsule_runtime.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) -mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_CAPSULE_RUNTIME_PE): $(CDK2_NATIVE_CAPSULE_RUNTIME_OBJ) $(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_OBJ) $(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_OBJ) $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_capsule_runtime_entry --image-base 0 --section-alignment 0x1000 --file-alignment 0x200 --build-id=none --no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.ld" -o "$@" $(CDK2_NATIVE_CAPSULE_RUNTIME_OBJ) $(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_OBJ) $(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_OBJ)
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 11 --file-alignment 0x200 "$@"

$(CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX_GEN): $(CDK2_DIR)/src/modules/capsule_runtime/depex.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX): $(CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX_GEN)
	@"$<" "$@"

$(CDK2_NATIVE_CAPSULE_RUNTIME_FFS): $(CDK2_NATIVE_CAPSULE_RUNTIME_PE) $(CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" 42857f0a-13f2-4b21-8a23-53d3f714b840 CapsuleRuntimeDxe 1.0 0x407a "$<" "$@" "$(CDK2_NATIVE_CAPSULE_RUNTIME_DEPEX)"

.SECONDEXPANSION:
$(CDK2_NATIVE_CAPSULE_RUNTIME_FV): $$(CDK2_NATIVE_PRE_CAPSULE_RUNTIME_FV) $(CDK2_NATIVE_CAPSULE_RUNTIME_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_CAPSULE_RUNTIME_FV)" 0x969c8 "$(CDK2_NATIVE_CAPSULE_RUNTIME_FFS)" "$@"

# The admitted profile disables TPM 1.2.  Remove its unused driver while
# retaining Tcg2Dxe until the native TPM 2.0 replacement is admitted.
CDK2_NATIVE_PRE_REMOVE_TCG1_FV := $(CDK2_NATIVE_FINAL_FV)
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_REMOVE_TCG1_FV)

$(CDK2_NATIVE_REMOVE_TCG1_FV): $(CDK2_NATIVE_PRE_REMOVE_TCG1_FV) \
		$(CDK2_NATIVE_PACKER) $(CDK2_NATIVE_FVINFO)
	@"$(CDK2_NATIVE_PACKER)" --prune-dxe-fv --dxe-fv "$<" --output "$@" \
		--remove-guid a5683620-7998-4bb2-a377-1c1e31e1e215
	@! "$(CDK2_NATIVE_FVINFO)" "$@" | grep -qi \
		'a5683620-7998-4bb2-a377-1c1e31e1e215'
	@"$(CDK2_NATIVE_FVINFO)" "$@" | grep -qi \
		'fdff263d-5f68-4591-87ba-b768f445a9af'

CDK2_NATIVE_PRE_GRAPHICS_CONSOLE_FV := $(CDK2_NATIVE_FINAL_FV)
ifeq ($(CONFIG_CDK2_NATIVE_GRAPHICS_CONSOLE),y)
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_GRAPHICS_CONSOLE_FV)

native-graphics-console-fv: $(CDK2_NATIVE_GRAPHICS_CONSOLE_FV)
	@printf '%s\n' "native graphics console FV: $(CDK2_NATIVE_GRAPHICS_CONSOLE_FV)"
else
native-graphics-console-fv:
	@printf '%s\n' 'native GraphicsConsoleDxe: disabled by Kconfig'
endif

ifeq ($(CONFIG_CDK2_NATIVE_TCG2),y)
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_TCG2_FV)
endif

$(CDK2_NATIVE_BUILD_DIR)/graphics-console-%.o: \
	$(CDK2_DIR)/src/modules/graphics_console/%.c \
	$(CDK2_DIR)/include/cdk2/graphics_console.h \
	$(CDK2_DIR)/include/cdk2/graphics_console_binding.h \
	$(CDK2_DIR)/include/cdk2/graphics_console_font.h \
	$(CDK2_DIR)/include/cdk2/graphics_console_package.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/graphics-console-font_data.o: \
	$(CDK2_DIR)/src/modules/graphics_console/font_data.inc

$(CDK2_NATIVE_GRAPHICS_CONSOLE_PE): $(CDK2_NATIVE_GRAPHICS_CONSOLE_OBJS) $(CDK2_DIR)/src/modules/graphics_console/graphics_console.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(CDK2_NATIVE_LD) -mi386pep --subsystem 11 --entry cdk2_graphics_console_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat \
		-T "$(CDK2_DIR)/src/modules/graphics_console/graphics_console.ld" \
		-o "$@" $(CDK2_NATIVE_GRAPHICS_CONSOLE_OBJS)
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 11 "$@"

$(CDK2_NATIVE_GRAPHICS_CONSOLE_FFS): $(CDK2_NATIVE_GRAPHICS_CONSOLE_PE) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" cccb0c28-4b24-11d5-9a5a-0090273fc14d \
		GraphicsConsoleDxe 1.0 0x9056 "$<" "$@" -

ifeq ($(CONFIG_CDK2_NATIVE_GRAPHICS_CONSOLE),y)
$(CDK2_NATIVE_GRAPHICS_CONSOLE_FV): $(CDK2_NATIVE_PRE_GRAPHICS_CONSOLE_FV) $(CDK2_NATIVE_GRAPHICS_CONSOLE_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_GRAPHICS_CONSOLE_FV)" 0x2da328 \
		"$(CDK2_NATIVE_GRAPHICS_CONSOLE_FFS)" "$@"
endif

ifeq ($(CONFIG_CDK2_NATIVE_CAPSULE_RUNTIME),y)
CDK2_NATIVE_PRE_CAPSULE_RUNTIME_FV := $(CDK2_NATIVE_FINAL_FV)
CDK2_NATIVE_FINAL_FV := $(CDK2_NATIVE_CAPSULE_RUNTIME_FV)
else
CDK2_NATIVE_PRE_CAPSULE_RUNTIME_FV := $(CDK2_NATIVE_FINAL_FV)
endif

ifeq ($(CONFIG_CDK2_NATIVE_ENGLISH),y)
$(CDK2_NATIVE_ENGLISH_OBJ): $(CDK2_DIR)/src/modules/english/english.c $(CDK2_DIR)/include/cdk2/english.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) \
		-mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args \
		$(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_ENGLISH_PE): $(CDK2_NATIVE_ENGLISH_OBJ) $(CDK2_DIR)/src/modules/english/english.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 11 --entry cdk2_english_entry --image-base 0 \
		--section-alignment 0x1000 --file-alignment 0x1000 --build-id=none \
		--no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/src/modules/english/english.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" "$@"

$(CDK2_NATIVE_ENGLISH_FFS): $(CDK2_NATIVE_ENGLISH_PE) $(CDK2_NATIVE_FFSBUILD)
	@"$(CDK2_NATIVE_FFSBUILD)" cd3bafb6-50fb-4fe8-8e4e-ab74d2c1a600 \
		EnglishDxe 1.0 0x5046 "$<" "$@" -

$(CDK2_NATIVE_ENGLISH_FV): $(CDK2_NATIVE_PRE_ENGLISH_FV) $(CDK2_NATIVE_ENGLISH_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_PRE_ENGLISH_FV)" 0x3094b8 \
		"$(CDK2_NATIVE_ENGLISH_FFS)" "$@"
else
$(CDK2_NATIVE_ENGLISH_FV): $(CDK2_NATIVE_PRE_ENGLISH_FV)
	@cp "$<" "$@"
endif

$(CDK2_NATIVE_FV_BLOB_OBJ): $(CDK2_NATIVE_FINAL_FV) | $(CDK2_NATIVE_BUILD_DIR)
	@cd "$(dir $<)" && $(CDK2_NATIVE_OBJCOPY) -I binary -O elf64-x86-64 -B i386:x86-64 --rename-section .data=.cdk2.fv,alloc,load,readonly,data,contents "$(notdir $<)" "$(abspath $@)"

$(CDK2_NATIVE_COREBOOT_IMAGE): $(CDK2_NATIVE_COREBOOT_OBJS) $(CDK2_NATIVE_FV_BLOB_OBJ) $(CDK2_NATIVE_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_COREBOOT_IMAGE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,cdk2_coreboot_entry32 -o "$@" $(CDK2_NATIVE_COREBOOT_LINK_INPUTS) "$(CDK2_NATIVE_FV_BLOB_OBJ)"
endif

$(CDK2_NATIVE_CPU_IO2_TEST): $(CDK2_DIR)/tests/cpu_io2_test.c $(CDK2_DIR)/src/modules/cpu_io2/cpu_io2.c $(CDK2_DIR)/include/cdk2/cpu_io2.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_DISK_IO_TEST): $(CDK2_DIR)/tests/disk_io_test.c $(CDK2_DIR)/src/modules/disk_io/disk_io.c $(CDK2_DIR)/include/cdk2/disk_io.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_SERIAL_IO_TEST): $(CDK2_DIR)/tests/serial_io_test.c $(CDK2_DIR)/src/modules/serial_io/serial_io.c $(CDK2_DIR)/include/cdk2/serial_io.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_SMBIOS_TEST): $(CDK2_DIR)/tests/smbios_test.c $(CDK2_DIR)/src/modules/smbios/smbios.c $(CDK2_DIR)/include/cdk2/smbios.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_RESET_SYSTEM_TEST): $(CDK2_DIR)/tests/reset_system_test.c $(CDK2_DIR)/src/modules/reset_system/reset_system.c $(CDK2_DIR)/include/cdk2/reset_system.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_PCAT_RTC_TEST): $(CDK2_DIR)/tests/pcat_rtc_test.c $(CDK2_DIR)/src/modules/pcat_rtc/pcat_rtc.c $(CDK2_DIR)/include/cdk2/pcat_rtc.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_SMM_ACCESS_TEST): $(CDK2_DIR)/tests/smm_access_test.c $(CDK2_DIR)/src/modules/smm_access/smm_access.c $(CDK2_DIR)/include/cdk2/smm_access.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_SMM_CONTROL_TEST): $(CDK2_DIR)/tests/smm_control_test.c $(CDK2_DIR)/src/modules/smm_control/smm_control.c $(CDK2_DIR)/include/cdk2/smm_control.h $(CDK2_DIR)/include/guid/smm_register_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_CPU_IO2_SMM_TEST): $(CDK2_DIR)/tests/cpu_io2_smm_test.c $(CDK2_DIR)/src/modules/cpu_io2_smm/cpu_io2_smm.c $(CDK2_DIR)/include/cdk2/cpu_io2.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_PCH_SMI_DISPATCH_TEST): $(CDK2_DIR)/tests/pch_smi_dispatch_test.c $(CDK2_DIR)/src/modules/pch_smi_dispatch/pch_smi_dispatch.c $(CDK2_DIR)/include/cdk2/pch_smi_dispatch.h $(CDK2_DIR)/include/guid/smm_register_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_TEST): $(CDK2_DIR)/tests/local_apic_timer_test.c $(CDK2_DIR)/src/modules/local_apic_timer/local_apic_timer.c $(CDK2_DIR)/include/cdk2/local_apic_timer.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/local_apic_timer_test.c" "$(CDK2_DIR)/src/modules/local_apic_timer/local_apic_timer.c"

$(CDK2_NATIVE_LOCAL_APIC_TIMER_DRIVER_TEST): $(CDK2_DIR)/tests/local_apic_timer_driver_test.c $(CDK2_DIR)/src/modules/local_apic_timer/driver.c $(CDK2_DIR)/include/cdk2/local_apic_timer.h $(CDK2_DIR)/include/guid/local_apic_timer_info.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -DCDK2_LOCAL_APIC_TIMER_DRIVER_TEST $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/local_apic_timer_driver_test.c" "$(CDK2_DIR)/src/modules/local_apic_timer/driver.c"

$(CDK2_NATIVE_GRAPHICS_CONSOLE_TEST): $(CDK2_DIR)/tests/graphics_console_binding_test.c $(CDK2_DIR)/src/modules/graphics_console/binding.c $(CDK2_DIR)/src/modules/graphics_console/model.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -fshort-wchar $(CDK2_NATIVE_INCLUDES) \
		-o "$@" "$(CDK2_DIR)/tests/graphics_console_binding_test.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/binding.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/model.c"

$(CDK2_NATIVE_GRAPHICS_PACKAGE_TEST): $(CDK2_DIR)/tests/graphics_console_package_test.c $(CDK2_DIR)/src/modules/graphics_console/font_package.c $(CDK2_DIR)/src/modules/graphics_console/font_data.c $(CDK2_DIR)/src/modules/graphics_console/font_data.inc | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -fshort-wchar $(CDK2_NATIVE_INCLUDES) \
		-o "$@" "$(CDK2_DIR)/tests/graphics_console_package_test.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/font_package.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/font_data.c"

$(CDK2_NATIVE_GRAPHICS_ENTRY_TEST): $(CDK2_DIR)/tests/graphics_console_entry_test.c $(CDK2_DIR)/src/modules/graphics_console/entry.c $(CDK2_DIR)/src/modules/graphics_console/binding.c $(CDK2_DIR)/src/modules/graphics_console/model.c $(CDK2_DIR)/src/modules/graphics_console/font_package.c $(CDK2_DIR)/src/modules/graphics_console/font_data.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -fshort-wchar $(CDK2_NATIVE_INCLUDES) \
		-o "$@" "$(CDK2_DIR)/tests/graphics_console_entry_test.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/entry.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/binding.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/model.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/font_package.c" \
		"$(CDK2_DIR)/src/modules/graphics_console/font_data.c"

$(CDK2_NATIVE_CAPSULE_RUNTIME_TEST): $(CDK2_DIR)/tests/capsule_runtime_test.c $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c $(CDK2_DIR)/include/cdk2/capsule_runtime.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/capsule_runtime_test.c" "$(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c"

$(CDK2_NATIVE_CAPSULE_RUNTIME_ABI_TEST): $(CDK2_DIR)/tests/capsule_runtime_abi_test.c $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime_abi.c $(CDK2_DIR)/include/cdk2/capsule_runtime_abi.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/capsule_runtime_abi_test.c" "$(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c" "$(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime_abi.c"

$(CDK2_NATIVE_CAPSULE_RUNTIME_ENTRY_TEST): $(CDK2_DIR)/tests/capsule_runtime_entry_test.c $(CDK2_DIR)/src/modules/capsule_runtime/entry.c $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c $(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime_abi.c $(CDK2_DIR)/include/cdk2/capsule_runtime_entry.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -DCDK2_CAPSULE_ENTRY_TEST $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/capsule_runtime_entry_test.c" "$(CDK2_DIR)/src/modules/capsule_runtime/entry.c" "$(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime.c" "$(CDK2_DIR)/src/modules/capsule_runtime/capsule_runtime_abi.c"

$(CDK2_NATIVE_CAPSULE_RUNTIME_QEMU_OBJ): $(CDK2_DIR)/tests/capsule_runtime_qemu.c $(CDK2_DIR)/include/cdk2/capsule_runtime_entry.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(filter-out -fdata-sections -ffunction-sections,$(CDK2_NATIVE_CFLAGS)) -mcmodel=large -fno-ident -fcf-protection=none -maccumulate-outgoing-args $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_CAPSULE_RUNTIME_QEMU_PE): $(CDK2_NATIVE_CAPSULE_RUNTIME_QEMU_OBJ) $(CDK2_DIR)/tests/capsule_runtime_qemu.ld $(CDK2_NATIVE_PERELOCCHECK)
	@$(LD) -mi386pep --subsystem 10 --entry capsule_runtime_qemu_entry --image-base 0 --section-alignment 0x1000 --file-alignment 0x1000 --build-id=none --no-insert-timestamp -s --nxcompat -T "$(CDK2_DIR)/tests/capsule_runtime_qemu.ld" -o "$@" "$<"
	@"$(CDK2_NATIVE_PERELOCCHECK)" --subsystem 10 "$@"

$(CDK2_NATIVE_TCG2_COMMANDS_TEST): $(CDK2_DIR)/tests/tcg2_commands_test.c $(CDK2_DIR)/src/modules/tcg2/tcg2_commands.c $(CDK2_DIR)/src/modules/tcg2/tcg2_transport.c $(CDK2_DIR)/include/cdk2/tcg2_commands.h $(CDK2_DIR)/include/cdk2/tcg2_transport.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/tcg2_commands_test.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_commands.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_transport.c"

$(CDK2_NATIVE_TCG2_EVENT_LOG_TEST): $(CDK2_DIR)/tests/tcg2_event_log_test.c $(CDK2_DIR)/src/modules/tcg2/tcg2_event_log.c $(CDK2_DIR)/include/cdk2/tcg2_event_log.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/tcg2_event_log_test.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_event_log.c"

$(CDK2_NATIVE_TCG2_MEASURE_TEST): $(CDK2_DIR)/tests/tcg2_measure_test.c $(CDK2_DIR)/src/modules/tcg2/tcg2_measure.c $(CDK2_DIR)/src/modules/tcg2/tcg2_event_log.c $(CDK2_DIR)/include/cdk2/tcg2_measure.h $(CDK2_DIR)/include/cdk2/tcg2_event_log.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/tcg2_measure_test.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_measure.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_event_log.c"

$(CDK2_NATIVE_TCG2_SERVICE_TEST): $(CDK2_DIR)/tests/tcg2_service_test.c $(CDK2_DIR)/src/modules/tcg2/tcg2_service.c $(CDK2_DIR)/src/modules/tcg2/tcg2_measure.c $(CDK2_DIR)/src/modules/tcg2/tcg2_event_log.c $(CDK2_DIR)/include/cdk2/tcg2_service.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_DIR)/tests/tcg2_service_test.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_service.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_measure.c" "$(CDK2_DIR)/src/modules/tcg2/tcg2_event_log.c"

FORCE:

$(CDK2_NATIVE_SERVICE_TEST): $(CDK2_NATIVE_DIR)/payload.c $(CDK2_NATIVE_DIR)/services.c $(CDK2_NATIVE_DIR)/services.h $(CDK2_NATIVE_DIR)/context.h $(CDK2_NATIVE_DIR)/services_test.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/services-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/payload.c" "$(CDK2_NATIVE_DIR)/services.c" "$(CDK2_NATIVE_DIR)/services_test.c"

$(CDK2_NATIVE_COREBOOT_TEST): $(CDK2_NATIVE_DIR)/coreboot.c $(CDK2_NATIVE_DIR)/coreboot.h $(CDK2_NATIVE_DIR)/coreboot_checksum.c $(CDK2_NATIVE_DIR)/coreboot_checksum.h $(CDK2_NATIVE_DIR)/coreboot_hobs.c $(CDK2_NATIVE_DIR)/coreboot_hobs.h $(CDK2_NATIVE_DIR)/coreboot_handoff.c $(CDK2_NATIVE_DIR)/services.c $(CDK2_NATIVE_DIR)/services.h $(CDK2_NATIVE_DIR)/coreboot_test.c $(CDK2_DIR)/include/coreboot_tables.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -DCDK2_COREBOOT_BACKEND_TEST -ffunction-sections -fdata-sections -Wl,--gc-sections -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/coreboot-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/coreboot.c" "$(CDK2_NATIVE_DIR)/coreboot_checksum.c" "$(CDK2_NATIVE_DIR)/coreboot_hobs.c" "$(CDK2_NATIVE_DIR)/coreboot_handoff.c" "$(CDK2_NATIVE_DIR)/services.c" "$(CDK2_NATIVE_DIR)/coreboot_test.c"

$(CDK2_NATIVE_FV_TEST): $(CDK2_NATIVE_DIR)/fv.c $(CDK2_NATIVE_DIR)/fv.h $(CDK2_NATIVE_DIR)/fv_test.c $(CDK2_DIR)/include/pi/firmware_file.h $(CDK2_DIR)/include/pi/firmware_volume.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/fv-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/fv.c" "$(CDK2_NATIVE_DIR)/fv_test.c"

$(CDK2_NATIVE_FVPACK_TEST): $(CDK2_DIR)/tests/fvpack_test.c $(CDK2_DIR)/include/industry_standard/pe_image.h $(CDK2_DIR)/include/pi/firmware_file.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/fvpack-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_DIR)/tests/fvpack_test.c"

$(CDK2_NATIVE_FVINFO_TEST): $(CDK2_DIR)/tests/fvinfo_test.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/fvinfo-test.d" -MT "$@" $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_FFSBUILD_TEST): $(CDK2_DIR)/tests/ffsbuild_test.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/ffsbuild-test.d" -MT "$@" $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_METRONOME_TEST): $(CDK2_DIR)/tests/metronome_test.c $(CDK2_DIR)/src/modules/metronome/metronome.c $(CDK2_DIR)/include/cdk2/metronome.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_WATCHDOG_TEST): $(CDK2_DIR)/tests/watchdog_test.c $(CDK2_DIR)/src/modules/watchdog/watchdog.c $(CDK2_DIR)/include/cdk2/watchdog.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_STATUS_CODE_ROUTER_TEST): $(CDK2_DIR)/tests/status_code_router_test.c $(CDK2_DIR)/src/modules/status_code_router/status_code_router.c $(CDK2_DIR)/include/cdk2/status_code_router.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_STATUS_CODE_HANDLER_TEST): $(CDK2_DIR)/tests/status_code_handler_test.c $(CDK2_DIR)/src/modules/status_code_handler/status_code_handler.c $(CDK2_DIR)/include/cdk2/status_code_router.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) $(CDK2_NATIVE_INCLUDES) -o "$@" "$<"

$(CDK2_NATIVE_PE_TEST): $(CDK2_NATIVE_DIR)/pe.c $(CDK2_NATIVE_DIR)/pe.h $(CDK2_NATIVE_DIR)/pe_test.c $(CDK2_DIR)/include/industry_standard/pe_image.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/pe-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/pe.c" "$(CDK2_NATIVE_DIR)/pe_test.c"

$(CDK2_NATIVE_MODULE_TEST): $(CDK2_NATIVE_DIR)/entry.c $(CDK2_NATIVE_DIR)/entry.h $(CDK2_NATIVE_DIR)/module.h $(CDK2_NATIVE_DIR)/module_test.c $(CDK2_NATIVE_DIR)/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/module-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/entry.c" "$(CDK2_NATIVE_DIR)/module_test.c"

-include $(CDK2_NATIVE_DEPFILES)
