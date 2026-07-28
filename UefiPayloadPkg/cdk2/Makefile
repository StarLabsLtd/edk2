## SPDX-License-Identifier: BSD-2-Clause-Patent

# Coreboot-style entry point for the cdk2 payload. Kconfig owns the resolved
# feature set; EDK II BaseTools remains the PE/COFF and firmware-volume
# backend until the native linker backend is complete.

SHELL := /bin/bash

CDK2_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
CDK2_ROOT := $(abspath $(CDK2_DIR)/../..)
CDK2_BUILD_DIR ?= $(CDK2_ROOT)/Build/cdk2
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
CDK2_CONFIG_TARGETS := build build-image check manifest modules native-stage \
	native-coreboot-stage native-coreboot-image native-check native-pack \
	native-service-test native-coreboot-test native-fv-test native-fvpack-test native-pe-test print

.PHONY: all build build-image config defconfig olddefconfig menuconfig prepare-kconfig check \
	manifest modules native-stage native-coreboot-stage native-coreboot-image native-check \
	native-pack native-service-test native-coreboot-test native-fv-test native-fvpack-test native-pe-test print clean

all: build

prepare-kconfig:
	@mkdir -p "$(CDK2_KCONFIG_WORKDIR)"
	@tr -d '\r' < "$(CDK2_KCONFIG)" > "$(CDK2_KCONFIG_INPUT)"
	@tr -d '\r' < "$(CDK2_DEFCONFIG)" > "$(CDK2_DEFCONFIG_INPUT)"

$(CDK2_CONFIG): $(CDK2_KCONFIG) $(CDK2_DEFCONFIG) | prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)"
	@cd "$(CDK2_BUILD_DIR)" && \
		if test -s .config; then \
			$(CDK2_KCONFIG_TOOL) --olddefconfig kconfig/Kconfig; \
		else \
			$(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig; \
		fi

config: $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER)

defconfig: prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)"
	@cd "$(CDK2_BUILD_DIR)" && \
		$(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig

olddefconfig: prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)"
	@cd "$(CDK2_BUILD_DIR)" && \
		if test -s .config; then \
			$(CDK2_KCONFIG_TOOL) --olddefconfig kconfig/Kconfig; \
		else \
			$(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig; \
		fi

menuconfig: prepare-kconfig
	@command -v kconfig-mconf >/dev/null || { echo 'kconfig-mconf is required for menuconfig' >&2; exit 1; }
	@cd "$(CDK2_BUILD_DIR)" && kconfig-mconf kconfig/Kconfig

$(CDK2_CONFIG_HEADER): $(CDK2_CONFIG)
	@mkdir -p "$(dir $@)"
	@{ \
		printf '%s\n' '/* SPDX-License-Identifier: BSD-2-Clause-Patent */' '#ifndef CDK2_CONFIG_H' '#define CDK2_CONFIG_H'; \
		awk ' \
			/^CONFIG_[A-Za-z0-9_]+=y$$/ { print "#define " substr($$1, 1, length($$1) - 2) " 1"; next } \
			/^CONFIG_[A-Za-z0-9_]+=n$$/ { print "#define " substr($$1, 1, length($$1) - 2) " 0"; next } \
			/^# CONFIG_[A-Za-z0-9_]+ is not set$$/ { split($$2, name, " "); print "#define " name[1] " 0"; next } \
			/^CONFIG_[A-Za-z0-9_]+=/ { split($$1, value, "="); print "#define " value[1] " " value[2]; next } \
		' "$(CDK2_CONFIG)"; \
		printf '%s\n' '#endif'; \
	} > "$@"

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

$(foreach required,BUILD ASSEMBLE CHECK CLEAN WRITE_MANIFEST PRINT_MODULES,$(if $(strip $(CDK2_BACKEND_$(required))),,$(error cdk2 backend '$(CDK2_BACKEND_NAME)' does not implement CDK2_BACKEND_$(required))))

build: build-image

build-image: manifest native-stage native-check
	@mkdir -p "$(dir $(CDK2_OUTPUT))"
	$(CDK2_BACKEND_BUILD)
	@printf '%s\n' "cdk2 $(CDK2_BACKEND_NAME) module closure: $(words $(CDK2_SELECTED_MODULES)) selected modules"
	$(CDK2_BACKEND_ASSEMBLE)
	$(MAKE) --no-print-directory -f "$(CDK2_DIR)/Makefile" CDK2_CONFIG_READY=1 native-coreboot-image
	@test -s "$(CDK2_OUTPUT)"
	@sha256sum "$(CDK2_OUTPUT)"

check: $(CDK2_CONFIG_HEADER)
	$(CDK2_BACKEND_CHECK)

manifest: check
	$(CDK2_BACKEND_WRITE_MANIFEST)

modules:
	@$(CDK2_BACKEND_PRINT_MODULES)

print:
	@printf 'target=%s\n' '$(CDK2_TARGET)'
	@printf 'backend=%s\n' '$(CDK2_BACKEND_NAME)'
	@printf 'backend-file=%s\n' '$(CDK2_BACKEND_FILE)'
	@printf 'backend-arches=%s\n' '$(CDK2_BACKEND_ARCHES)'
	@printf 'backend-build-arch=%s\n' '$(CDK2_BACKEND_BUILD_ARCH)'
	@printf 'config=%s\n' '$(CDK2_CONFIG)'
	@printf 'config-header=%s\n' '$(CDK2_CONFIG_HEADER)'
	@printf 'entry-image=%s\n' '$(CDK2_BACKEND_ENTRY_IMAGE)'
	@printf 'dxe-fv=%s\n' '$(CDK2_BACKEND_DXE_FV)'
	@printf 'output=%s\n' '$(CDK2_OUTPUT)'
	@printf 'descriptor=%s\n' '$(CDK2_BACKEND_DESCRIPTOR)'
	@printf 'modules=%s\n' '$(CDK2_MANIFEST)'
	@printf 'link-manifest=%s\n' '$(CDK2_LINK_MANIFEST)'
	@printf 'backend-ffs-list=%s\n' '$(CDK2_BACKEND_FFS_LIST)'
	@printf 'defines=%s\n' '$(CDK2_DEFINES)'

clean:
	$(CDK2_BACKEND_CLEAN)
	rm -rf "$(CDK2_BUILD_DIR)"
else
$(CDK2_CONFIG_TARGETS): $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER)
	@$(MAKE) --no-print-directory -f "$(CDK2_DIR)/Makefile" CDK2_CONFIG_READY=1 $@

clean:
	rm -rf "$(CDK2_BUILD_DIR)"
endif
