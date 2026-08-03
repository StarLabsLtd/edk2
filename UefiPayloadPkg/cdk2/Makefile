## SPDX-License-Identifier: BSD-2-Clause-Patent

# Coreboot-style entry point for the cdk2 payload. Kconfig owns the resolved
# feature set; the EDK II backend remains an optional PE/COFF and
# firmware-volume producer while the native stage owns the coreboot handoff.

SHELL := /bin/bash

PYTHON ?= python3
CDK2_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CDK2_ROOT := $(abspath $(CDK2_DIR)/../..)
CDK2_BUILD_DIR ?= $(CDK2_ROOT)/Build/cdk2
override CDK2_BUILD_DIR := $(abspath $(CDK2_BUILD_DIR))
CDK2_CONFIG ?= $(CDK2_BUILD_DIR)/.config
CDK2_DEFCONFIG ?= $(CDK2_DIR)/defconfig
CDK2_KCONFIG ?= $(CDK2_DIR)/Kconfig
CDK2_KCONFIG_TOOL ?= kconfig-conf
CDK2_KCONFIG_WORKDIR := $(CDK2_BUILD_DIR)/kconfig
CDK2_KCONFIG_INPUT := $(CDK2_KCONFIG_WORKDIR)/Kconfig
CDK2_DEFCONFIG_INPUT := $(CDK2_KCONFIG_WORKDIR)/defconfig
CDK2_CONFIG_HEADER ?= $(CDK2_BUILD_DIR)/include/cdk2/config.h
CDK2_OUTPUT ?= $(CDK2_BUILD_DIR)/UEFIPAYLOAD.fd
CDK2_MANIFEST ?= $(CDK2_BUILD_DIR)/cdk2-modules.txt
CDK2_LINK_MANIFEST ?= $(CDK2_BUILD_DIR)/cdk2-link.txt
CDK2_NATIVE_DIR := $(CDK2_DIR)/native
CDK2_BACKEND ?= edk2
CDK2_BACKEND_FILE ?= $(CDK2_DIR)$(CDK2_BACKEND)-backend.mk
CDK2_BACKEND_INTERFACE_VERSION := 1
CDK2_BACKEND_OUTPUT_DIRECTORY ?= $(patsubst $(CDK2_ROOT)/%,%,$(CDK2_BUILD_DIR))/edk2/UefiPayloadPkgX64
CDK2_BASETOOLS_BUILD_DIR ?= $(abspath $(CDK2_BUILD_DIR)/basetools)
CDK2_BASETOOLS_OUTPUT_ROOT ?= $(abspath $(CDK2_BASETOOLS_BUILD_DIR)/C)
CDK2_BASETOOLS_BIN ?= $(CDK2_BASETOOLS_OUTPUT_ROOT)/bin
CDK2_Q35_LINUX_EFI_DEFCONFIG ?= $(CDK2_DIR)/q35-linux-efi.defconfig
CDK2_Q35_LINUX_EFI_CHECK_DIR ?= $(CDK2_BUILD_DIR)/q35-linux-efi-check
CDK2_KCONFIG_ENV = KCONFIG_CONFIG="$(abspath $(CDK2_CONFIG))"
CDK2_SOURCE_DATE_EPOCH ?= $(shell epoch=$$(git -C "$(CDK2_ROOT)" log -1 --format=%ct -- $(CDK2_BACKEND_SOURCE_DATE_PATHS) 2>/dev/null); test -n "$$epoch" || epoch=0; printf '%s' "$$epoch")
SOURCE_DATE_EPOCH ?= $(CDK2_SOURCE_DATE_EPOCH)
export SOURCE_DATE_EPOCH
CDK2_CONFIG_TARGETS := build build-image check manifest metadata metadata-test modules native-stage \
	native-coreboot-stage native-coreboot-image native-check native-pack \
	native-service-test native-coreboot-test native-fv-test native-fvpack-test native-pe-test \
	native-module-test native-elfcheck-test native-linux-efi-boot-test q35-linux-efi-check \
	qemu-smmstore-cold-test print

# The coreboot wrapper deliberately clears MAKEOVERRIDES before entering cdk2
# so compiler variables cannot leak into the native build. Forward cdk2's own
# path/config/backend variables explicitly to the recursive configuration
# passes instead of silently falling back to Build/cdk2.
CDK2_RECURSIVE_ARGS := \
	CDK2_BUILD_DIR="$(CDK2_BUILD_DIR)" \
	CDK2_CONFIG="$(CDK2_CONFIG)" \
	CDK2_DEFCONFIG="$(CDK2_DEFCONFIG)" \
	CDK2_KCONFIG="$(CDK2_KCONFIG)" \
	CDK2_KCONFIG_TOOL="$(CDK2_KCONFIG_TOOL)" \
	CDK2_BACKEND="$(CDK2_BACKEND)" \
	CDK2_BACKEND_FILE="$(CDK2_BACKEND_FILE)" \
	CDK2_BACKEND_OUTPUT_DIRECTORY="$(CDK2_BACKEND_OUTPUT_DIRECTORY)" \
	$(if $(CDK2_EXTRA_DEFINES),CDK2_EXTRA_DEFINES="$(CDK2_EXTRA_DEFINES)") \
	$(if $(CC),CC="$(CC)") \
	$(if $(CDK2_NATIVE_CC),CDK2_NATIVE_CC="$(CDK2_NATIVE_CC)") \
	$(if $(CDK2_NATIVE_OBJCOPY),CDK2_NATIVE_OBJCOPY="$(CDK2_NATIVE_OBJCOPY)")

.PHONY: all build build-image config defconfig olddefconfig menuconfig prepare-kconfig check \
	manifest metadata metadata-test modules native-stage native-coreboot-stage native-coreboot-image native-check \
	native-pack native-service-test native-coreboot-test native-fv-test native-fvpack-test \
	native-pe-test native-module-test native-elfcheck-test native-linux-efi-boot-test \
	q35-linux-efi-check qemu-smmstore-cold-test print clean
.DELETE_ON_ERROR: $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER) $(CDK2_MANIFEST) $(CDK2_OUTPUT) $(CDK2_LINK_MANIFEST)

all: build

prepare-kconfig:
	@mkdir -p "$(CDK2_KCONFIG_WORKDIR)"
	@tr -d '\r' < "$(CDK2_KCONFIG)" > "$(CDK2_KCONFIG_INPUT)"
	@tr -d '\r' < "$(CDK2_DEFCONFIG)" > "$(CDK2_DEFCONFIG_INPUT)"

$(CDK2_CONFIG): $(CDK2_KCONFIG) $(CDK2_DEFCONFIG) | prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)" "$(dir $(CDK2_CONFIG))"
	@cd "$(CDK2_BUILD_DIR)" && \
		if test -s "$(CDK2_CONFIG)"; then \
			$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --olddefconfig kconfig/Kconfig; \
		else \
			$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig; \
		fi

config: $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER)

defconfig: prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)" "$(dir $(CDK2_CONFIG))"
	@cd "$(CDK2_BUILD_DIR)" && \
			$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_DIR)/Makefile" "$(CDK2_CONFIG_HEADER)"

olddefconfig: prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)" "$(dir $(CDK2_CONFIG))"
	@cd "$(CDK2_BUILD_DIR)" && \
			if test -s "$(CDK2_CONFIG)"; then \
				$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --olddefconfig kconfig/Kconfig; \
			else \
				$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig; \
			fi
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_DIR)/Makefile" "$(CDK2_CONFIG_HEADER)"

menuconfig: prepare-kconfig
	@command -v kconfig-mconf >/dev/null || { echo 'kconfig-mconf is required for menuconfig' >&2; exit 1; }
	@mkdir -p "$(dir $(CDK2_CONFIG))"
	@cd "$(CDK2_BUILD_DIR)" && $(CDK2_KCONFIG_ENV) kconfig-mconf kconfig/Kconfig
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_DIR)/Makefile" "$(CDK2_CONFIG_HEADER)"

$(CDK2_CONFIG_HEADER): $(CDK2_CONFIG)
	@mkdir -p "$(dir $@)"
	@set -e; tmp="$@.tmp"; { \
		printf '%s\n' '/* SPDX-License-Identifier: BSD-2-Clause-Patent */' '#ifndef CDK2_CONFIG_H' '#define CDK2_CONFIG_H'; \
		awk ' \
			/^CONFIG_[A-Za-z0-9_]+=y$$/ { print "#define " substr($$1, 1, length($$1) - 2) " 1"; next } \
			/^CONFIG_[A-Za-z0-9_]+=n$$/ { print "#define " substr($$1, 1, length($$1) - 2) " 0"; next } \
			/^# CONFIG_[A-Za-z0-9_]+ is not set$$/ { split($$2, disabled_name, " "); print "#define " disabled_name[1] " 0"; next } \
			/^CONFIG_[A-Za-z0-9_]+=/ { \
				config_name=$$0; \
				sub(/=.*/, "", config_name); \
				config_value=$$0; \
				sub(/^[^=]*=/, "", config_value); \
				print "#define " config_name " " config_value; \
				next \
			} \
		' "$(CDK2_CONFIG)"; \
		printf '%s\n' '#endif'; \
	} > "$$tmp"; mv "$$tmp" "$@"

ifeq ($(CDK2_CONFIG_READY),1)
include $(CDK2_CONFIG)
include $(CDK2_NATIVE_DIR)/Makefile

ifeq ($(CONFIG_CDK2_PAYLOAD),y)
else
$(error CONFIG_CDK2_PAYLOAD must be enabled in $(CDK2_CONFIG))
endif

ifeq ($(CONFIG_CDK2_BUILD_DEBUG),y)
CDK2_TARGET := DEBUG
else
CDK2_TARGET := RELEASE
endif

include $(CDK2_BACKEND_FILE)

ifneq ($(CDK2_BACKEND_INTERFACE_VERSION),$(CDK2_BACKEND_SUPPORTED_INTERFACE_VERSION))
$(error cdk2 backend interface mismatch: requested $(CDK2_BACKEND_INTERFACE_VERSION), backend supports $(CDK2_BACKEND_SUPPORTED_INTERFACE_VERSION))
endif

ifeq ($(CONFIG_CDK2_NATIVE_STAGE),y)
CDK2_DIRECT_OUTPUT ?= $(CDK2_NATIVE_COREBOOT_IMAGE)
else
CDK2_DIRECT_OUTPUT ?= $(CDK2_OUTPUT)
endif

$(foreach required,BUILD ASSEMBLE CHECK CLEAN WRITE_MANIFEST WRITE_LINK_MANIFEST PRINT_MODULES,$(if $(strip $(CDK2_BACKEND_$(required))),,$(error cdk2 backend '$(CDK2_BACKEND_NAME)' does not implement CDK2_BACKEND_$(required))))

build: build-image

build-image: $(CDK2_OUTPUT) native-coreboot-image native-check
	@test -s "$(CDK2_OUTPUT)"
	@test -s "$(CDK2_DIRECT_OUTPUT)"
	@sha256sum "$(CDK2_OUTPUT)" "$(CDK2_DIRECT_OUTPUT)"
	$(CDK2_BACKEND_WRITE_LINK_MANIFEST)

$(CDK2_OUTPUT): $(CDK2_MANIFEST) $(CDK2_CONFIG_HEADER) $(CDK2_BACKEND_FILE) \
		$(CDK2_BACKEND_BUILD_DEPS) \
		$(CDK2_NATIVE_STAGE_DEPS) $(CDK2_NATIVE_PACKER)
	@mkdir -p "$(dir $(CDK2_OUTPUT))"
	$(CDK2_BACKEND_BUILD)
	@printf '%s\n' "cdk2 $(CDK2_BACKEND_NAME) module closure: $(words $(CDK2_SELECTED_MODULES)) selected modules"
	$(CDK2_BACKEND_ASSEMBLE)

check: $(CDK2_CONFIG_HEADER) $(CDK2_BACKEND_METADATA_TEST) native-check $(CDK2_BACKEND_CHECK_DEPS)
	$(CDK2_BACKEND_CHECK)

manifest: $(CDK2_MANIFEST)

metadata: $(CDK2_BACKEND_METADATA) $(CDK2_BACKEND_MODULE_GUIDS)
	@printf '%s\n' "cdk2 module metadata: $(CDK2_BACKEND_METADATA)"

metadata-test:
	@env -u MAKEFLAGS -u MAKEOVERRIDES -u CDK2_BUILD_DIR -u CDK2_CONFIG -u CDK2_DEFCONFIG \
		-u CDK2_KCONFIG -u CDK2_KCONFIG_TOOL -u CDK2_BACKEND \
		-u CDK2_BACKEND_FILE -u CDK2_BACKEND_OUTPUT_DIRECTORY -u CDK2_EXTRA_DEFINES \
		$(PYTHON) "$(CDK2_DIR)/module_metadata_test.py"
	@env -u MAKEFLAGS -u MAKEOVERRIDES -u CDK2_BUILD_DIR -u CDK2_CONFIG -u CDK2_DEFCONFIG \
		-u CDK2_KCONFIG -u CDK2_KCONFIG_TOOL -u CDK2_BACKEND \
		-u CDK2_BACKEND_FILE -u CDK2_BACKEND_OUTPUT_DIRECTORY -u CDK2_EXTRA_DEFINES \
		$(PYTHON) "$(CDK2_DIR)/edk2_backend_test.py"

$(CDK2_MANIFEST): $(CDK2_CONFIG_HEADER) $(CDK2_BACKEND_FILE) $(CDK2_BACKEND_MANIFEST_DEPS)
	$(CDK2_BACKEND_CHECK)
	$(CDK2_BACKEND_WRITE_MANIFEST)

modules:
	@$(CDK2_BACKEND_PRINT_MODULES)

qemu-smmstore-cold-test:
	@$(PYTHON) "$(CDK2_DIR)/qemu_smmstore_cold_persistence_test.py"; status=$$?; \
	test "$$status" -eq 0 || test "$$status" -eq 77

q35-linux-efi-check:
	@rm -rf "$(CDK2_Q35_LINUX_EFI_CHECK_DIR)"
	@$(MAKE) --no-print-directory -f "$(CDK2_DIR)/Makefile" \
		CDK2_BUILD_DIR="$(CDK2_Q35_LINUX_EFI_CHECK_DIR)" \
		CDK2_CONFIG="$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/.config" \
		CDK2_CONFIG_HEADER="$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/include/cdk2/config.h" \
		CDK2_CONFIG_READY= \
		CDK2_DEFCONFIG="$(CDK2_Q35_LINUX_EFI_DEFCONFIG)" config
	@grep -Fx 'CONFIG_CDK2_LINUX_EFI_APPLICATION=y' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/.config" >/dev/null
	@grep -Fx 'CONFIG_CDK2_LINUX_EFI_APPLICATION_PATH="\\EFI\\Linux\\bzImage.efi"' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/.config" >/dev/null
	@grep -Fx 'CONFIG_CDK2_LINUX_EFI_APPLICATION_DESCRIPTION="Q35 Linux EFI"' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/.config" >/dev/null
	@grep -Fx '#define CONFIG_CDK2_LINUX_EFI_APPLICATION_PATH "\\EFI\\Linux\\bzImage.efi"' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/include/cdk2/config.h" >/dev/null
	@grep -Fx '#define CONFIG_CDK2_LINUX_EFI_APPLICATION_DESCRIPTION "Q35 Linux EFI"' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/include/cdk2/config.h" >/dev/null
	@$(MAKE) --no-print-directory -f "$(CDK2_DIR)/Makefile" \
		CDK2_BUILD_DIR="$(CDK2_Q35_LINUX_EFI_CHECK_DIR)" \
		CDK2_CONFIG="$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/.config" \
		CDK2_CONFIG_HEADER="$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/include/cdk2/config.h" \
		CDK2_CONFIG_READY= \
		CDK2_DEFCONFIG="$(CDK2_Q35_LINUX_EFI_DEFCONFIG)" print \
		> "$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/print.txt"
	@grep -F 'LINUX_EFI_APPLICATION_BOOT=TRUE' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/print.txt" >/dev/null
	@grep -F 'LINUX_EFI_APPLICATION_PATH=L"\\EFI\\Linux\\bzImage.efi"' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/print.txt" >/dev/null
	@grep -F 'LINUX_EFI_APPLICATION_DESCRIPTION=L"Q35 Linux EFI"' \
		"$(CDK2_Q35_LINUX_EFI_CHECK_DIR)/print.txt" >/dev/null
	@printf '%s\n' "cdk2 Q35 Linux EFI config: $(CDK2_Q35_LINUX_EFI_CHECK_DIR)"

print:
	$(info target=$(CDK2_TARGET))
	$(info backend=$(CDK2_BACKEND_NAME))
	$(info backend-file=$(CDK2_BACKEND_FILE))
	$(info backend-arches=$(CDK2_BACKEND_ARCHES))
	$(info backend-build-arch=$(CDK2_BACKEND_BUILD_ARCH))
	$(info config=$(CDK2_CONFIG))
	$(info config-header=$(CDK2_CONFIG_HEADER))
	$(info entry-image=$(CDK2_BACKEND_ENTRY_IMAGE))
	$(info dxe-fv=$(CDK2_BACKEND_DXE_FV))
	$(info fv-output=$(CDK2_OUTPUT))
	$(info direct-output=$(CDK2_DIRECT_OUTPUT))
	$(info descriptor=$(CDK2_BACKEND_DESCRIPTOR))
	$(info modules=$(CDK2_MANIFEST))
	$(info metadata=$(CDK2_BACKEND_METADATA))
	$(info link-manifest=$(CDK2_LINK_MANIFEST))
	$(info backend-ffs-list=$(CDK2_BACKEND_FFS_LIST))
	$(info backend-dxe-manifest=$(CDK2_BACKEND_DXE_MANIFEST))
	$(info source-date-epoch=$(SOURCE_DATE_EPOCH))
	$(info defines=$(CDK2_DEFINES))
	@true

clean:
	$(CDK2_BACKEND_CLEAN)
	rm -rf "$(CDK2_BUILD_DIR)"
else
$(CDK2_CONFIG_TARGETS): $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER)
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_DIR)/Makefile" CDK2_CONFIG_READY=1 $@

clean:
	rm -rf "$(CDK2_BUILD_DIR)"
endif
