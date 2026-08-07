# SPDX-License-Identifier: GPL-2.0-only

# Native cdk2 build entry point. This file deliberately builds only source that
# is owned by cdk2; it does not dispatch to external package metadata or
# consume an already-built firmware volume.

SHELL := /bin/bash

override CDK2_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
override CDK2_ROOT := $(patsubst %/,%,$(CDK2_DIR))
CDK2_BUILD_DIR ?= $(CDK2_ROOT)/build/cdk2
override CDK2_BUILD_DIR := $(abspath $(CDK2_BUILD_DIR))
CDK2_CONFIG ?= $(CDK2_BUILD_DIR)/.config
CDK2_DEFCONFIG ?= $(CDK2_ROOT)/defconfig
CDK2_KCONFIG ?= $(CDK2_ROOT)/Kconfig
CDK2_KCONFIG_TOOL ?= kconfig-conf
CDK2_KCONFIG_WORKDIR := $(CDK2_BUILD_DIR)/kconfig
CDK2_KCONFIG_INPUT := $(CDK2_KCONFIG_WORKDIR)/Kconfig
CDK2_DEFCONFIG_INPUT := $(CDK2_KCONFIG_WORKDIR)/defconfig
CDK2_CONFIG_HEADER ?= $(CDK2_BUILD_DIR)/include/cdk2/config.h
CDK2_KCONFIG_AUTOCONFIG ?= $(CDK2_BUILD_DIR)/auto.conf
CDK2_KCONFIG_AUTOHEADER ?= $(CDK2_BUILD_DIR)/include/generated/autoconf.h
CDK2_KCONFIG_RUSTCCFG ?= $(CDK2_BUILD_DIR)/include/generated/rustc_cfg
CDK2_KCONFIG_SPLITCONFIG ?= $(CDK2_BUILD_DIR)/config/
CDK2_MANIFEST ?= $(CDK2_BUILD_DIR)/cdk2-native-sources.txt
CDK2_PAYLOAD_FV ?=
COREBOOT_CONFIG ?=
COREBOOT_OUTPUT_DIR ?=
override CDK2_NATIVE_DIR := $(CDK2_ROOT)/src/boot
CDK2_NATIVE_SOURCE_DATE_PATHS := Kconfig Makefile defconfig src include util tests configs
CDK2_SOURCE_DATE_EPOCH ?= $(shell epoch=$$(git -C "$(CDK2_ROOT)" log -1 --format=%ct -- $(CDK2_NATIVE_SOURCE_DATE_PATHS) 2>/dev/null); test -n "$$epoch" || epoch=0; printf '%s' "$$epoch")
SOURCE_DATE_EPOCH ?= $(CDK2_SOURCE_DATE_EPOCH)
export SOURCE_DATE_EPOCH

CDK2_KCONFIG_ENV = \
	KCONFIG_CONFIG="$(abspath $(CDK2_CONFIG))" \
	KCONFIG_AUTOCONFIG="$(abspath $(CDK2_KCONFIG_AUTOCONFIG))" \
	KCONFIG_AUTOHEADER="$(abspath $(CDK2_KCONFIG_AUTOHEADER))" \
	KCONFIG_RUSTCCFG="$(abspath $(CDK2_KCONFIG_RUSTCCFG))" \
	KCONFIG_SPLITCONFIG="$(abspath $(CDK2_KCONFIG_SPLITCONFIG))"

CDK2_CONFIG_TARGETS := build check manifest modules native-stage \
	native-coreboot-stage native-coreboot-image native-check native-pack native-service-test \
	native-coreboot-test native-fv-test native-fvpack-test native-pe-test \
	native-fvinfo native-fvinfo-test native-null-memory-test-fv \
	native-null-memory-test-test native-module-test native-elfcheck-test \
	native-ffsbuild-test native-security-stub-test native-security-stub-fv \
	native-metronome-fv native-watchdog-fv native-monotonic-counter-test \
	native-monotonic-counter-fv native-status-code-router-fv \
	native-status-code-router-test native-cpu-io2-test native-cpu-io2-fv \
	native-english-test native-english-fv native-status-code-handler-fv \
	native-status-code-handler-test manifest-check print

CDK2_RECURSIVE_ARGS := \
	CDK2_DIR="$(CDK2_DIR)" \
	CDK2_ROOT="$(CDK2_ROOT)" \
	CDK2_BUILD_DIR="$(CDK2_BUILD_DIR)" \
	CDK2_CONFIG="$(CDK2_CONFIG)" \
	CDK2_DEFCONFIG="$(CDK2_DEFCONFIG)" \
	CDK2_KCONFIG="$(CDK2_KCONFIG)" \
	CDK2_KCONFIG_TOOL="$(CDK2_KCONFIG_TOOL)" \
	CDK2_PAYLOAD_FV="$(CDK2_PAYLOAD_FV)" \
	CDK2_NATIVE_DIR="$(CDK2_NATIVE_DIR)" \
	$(if $(HOSTCC),HOSTCC="$(HOSTCC)") \
	$(if $(CC),CC="$(CC)") \
	$(if $(CDK2_NATIVE_CC),CDK2_NATIVE_CC="$(CDK2_NATIVE_CC)") \
	$(if $(CDK2_NATIVE_HOST_CC),CDK2_NATIVE_HOST_CC="$(CDK2_NATIVE_HOST_CC)") \
	$(if $(CDK2_NATIVE_OBJCOPY),CDK2_NATIVE_OBJCOPY="$(CDK2_NATIVE_OBJCOPY)") \
	$(if $(CDK2_NATIVE_NM),CDK2_NATIVE_NM="$(CDK2_NATIVE_NM)")

.PHONY: all build build-image config defconfig olddefconfig menuconfig \
	prepare-kconfig check manifest modules native-stage native-coreboot-stage \
	native-coreboot-image native-check native-pack native-service-test native-coreboot-test \
	native-fv-test native-fvpack-test native-pe-test native-module-test \
	native-fvinfo native-fvinfo-test native-ffsbuild-test native-security-stub-test \
	native-security-stub-fv native-null-memory-test-fv native-null-memory-test-test \
	native-metronome-fv native-watchdog-fv \
	native-monotonic-counter-test native-monotonic-counter-fv \
	native-status-code-router-fv native-status-code-router-test \
	native-cpu-io2-test native-cpu-io2-fv \
	native-english-test native-english-fv \
	native-status-code-handler-fv native-status-code-handler-test \
	native-elfcheck-test manifest-check print lint \
	lint-stable lint-extended test-lint \
	jenkins what-jenkins-does retained-fv-check coreboot-stage clean FORCE
.DELETE_ON_ERROR: $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER) $(CDK2_MANIFEST)

all: build

lint-stable:
	@util/lint/lint lint-stable

lint:
	@util/lint/lint lint-stable
	@util/lint/lint lint

lint-extended:
	@util/lint/lint lint-extended

test-lint: lint

what-jenkins-does: lint check manifest-check retained-fv-check
	@set -e; log="$$(mktemp "$${TMPDIR:-/tmp}/cdk2-build-image.XXXXXX")"; \
	if $(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_ROOT)/Makefile" build-image >"$$log" 2>&1; then \
		cat "$$log"; \
		rm -f "$$log"; \
		printf '%s\n' 'build-image unexpectedly succeeded before payload modules are native' >&2; \
		exit 1; \
	fi; \
	if ! grep -q 'no native payload-image target' "$$log"; then \
		cat "$$log"; \
		rm -f "$$log"; \
		printf '%s\n' 'build-image did not fail with the native-boundary message' >&2; \
		exit 1; \
	fi; \
	rm -f "$$log"; \
	printf '%s\n' 'build-image: expected native-boundary failure confirmed'

jenkins: what-jenkins-does

coreboot-stage:
	@test -n "$(COREBOOT_CONFIG)" || { \
		printf '%s\n' 'COREBOOT_CONFIG is required' >&2; \
		exit 1; \
	}
	@test -f "$(COREBOOT_CONFIG)" || { \
		printf '%s\n' 'COREBOOT_CONFIG does not exist: $(COREBOOT_CONFIG)' >&2; \
		exit 1; \
	}
	@test -n "$(COREBOOT_OUTPUT_DIR)" || { \
		printf '%s\n' 'COREBOOT_OUTPUT_DIR is required' >&2; \
		exit 1; \
	}
	@mkdir -p "$(abspath $(COREBOOT_OUTPUT_DIR))"
	@awk '/^CONFIG_CDK2_[A-Za-z0-9_]+=/ || /^# CONFIG_CDK2_[A-Za-z0-9_]+ is not set$$/' \
		"$(abspath $(COREBOOT_CONFIG))" > "$(abspath $(COREBOOT_OUTPUT_DIR))/.config.tmp"
	@test -s "$(abspath $(COREBOOT_OUTPUT_DIR))/.config.tmp" || { \
		rm -f "$(abspath $(COREBOOT_OUTPUT_DIR))/.config.tmp"; \
		printf '%s\n' 'COREBOOT_CONFIG contains no CONFIG_CDK2 options' >&2; \
		exit 1; \
	}
	@mv "$(abspath $(COREBOOT_OUTPUT_DIR))/.config.tmp" \
		"$(abspath $(COREBOOT_OUTPUT_DIR))/.config"
	@$(MAKE) --no-print-directory -f "$(CDK2_ROOT)/Makefile" \
		CDK2_BUILD_DIR="$(abspath $(COREBOOT_OUTPUT_DIR))" \
		CDK2_CONFIG="$(abspath $(COREBOOT_OUTPUT_DIR))/.config" \
		CDK2_KCONFIG_TOOL="$(CDK2_KCONFIG_TOOL)" \
		$(if $(HOSTCC),HOSTCC="$(HOSTCC)") \
		$(if $(CC),CC="$(CC)") \
		$(if $(OBJCOPY),CDK2_NATIVE_OBJCOPY="$(OBJCOPY)") \
		$(if $(NM),CDK2_NATIVE_NM="$(NM)") \
		native-coreboot-stage
	@printf '%s\n' "$(abspath $(COREBOOT_OUTPUT_DIR))/native/cdk2-coreboot-stage.elf"

retained-fv-check:
	@awk -F '\t' '\
		/^# baseline-retained=/ { split($$0, field, "="); baseline = field[2] + 0; next } \
		/^# retained=/ { split($$0, field, "="); declared = field[2] + 0; next } \
		/^#/ || /^$$/ { next } \
		NF != 3 { print "malformed retained-FV entry at line " NR > "/dev/stderr"; failed = 1; next } \
		$$1 !~ /^(retain|native|remove)$$/ { print "invalid retained-FV status at line " NR > "/dev/stderr"; failed = 1 } \
		seen[$$3]++ { print "duplicate retained-FV module: " $$3 > "/dev/stderr"; failed = 1 } \
		previous != "" && $$3 < previous { print "retained-FV modules are not sorted at line " NR > "/dev/stderr"; failed = 1 } \
		{ previous = $$3; if ($$1 == "retain") retained++ } \
		END { \
			if (baseline == 0) { print "missing retained-FV baseline" > "/dev/stderr"; failed = 1 } \
			if (retained != declared) { print "declared retained-FV count does not match inventory" > "/dev/stderr"; failed = 1 } \
			if (retained > baseline) { print "retained-FV count increased above baseline" > "/dev/stderr"; failed = 1 } \
			exit failed \
		}' migration/retained-fv.tsv

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
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_ROOT)/Makefile" "$(CDK2_CONFIG_HEADER)"

olddefconfig: prepare-kconfig
	@mkdir -p "$(CDK2_BUILD_DIR)" "$(dir $(CDK2_CONFIG))"
	@cd "$(CDK2_BUILD_DIR)" && \
		if test -s "$(CDK2_CONFIG)"; then \
			$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --olddefconfig kconfig/Kconfig; \
		else \
			$(CDK2_KCONFIG_ENV) $(CDK2_KCONFIG_TOOL) --defconfig=kconfig/defconfig kconfig/Kconfig; \
		fi
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_ROOT)/Makefile" "$(CDK2_CONFIG_HEADER)"

menuconfig: prepare-kconfig
	@command -v kconfig-mconf >/dev/null || { echo 'kconfig-mconf is required for menuconfig' >&2; exit 1; }
	@mkdir -p "$(dir $(CDK2_CONFIG))"
	@cd "$(CDK2_BUILD_DIR)" && $(CDK2_KCONFIG_ENV) kconfig-mconf kconfig/Kconfig
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_ROOT)/Makefile" "$(CDK2_CONFIG_HEADER)"

$(CDK2_CONFIG_HEADER): $(CDK2_CONFIG)
	@mkdir -p "$(dir $@)"
	@set -e; tmp="$@.tmp"; { \
		printf '%s\n' '/* SPDX-License-Identifier: GPL-2.0-only */' '#ifndef CDK2_CONFIG_H' '#define CDK2_CONFIG_H'; \
		awk ' \
			FILENAME == ARGV[1] { \
				if ($$1 == "config" && $$2 ~ /^CDK2_[A-Za-z0-9_]+$$/) { \
					config_name = "CONFIG_" $$2; \
					if (!(config_name in seen_config)) { \
						config_order[++config_count] = config_name; \
						seen_config[config_name] = 1; \
					} \
				} \
				next; \
			} \
			/^CONFIG_[A-Za-z0-9_]+=y$$/ { \
				config_name = $$1; \
				sub(/=y$$/, "", config_name); \
				config_value[config_name] = "1"; \
				next; \
			} \
			/^CONFIG_[A-Za-z0-9_]+=n$$/ { \
				config_name = $$1; \
				sub(/=n$$/, "", config_name); \
				config_value[config_name] = "0"; \
				next; \
			} \
			/^# CONFIG_[A-Za-z0-9_]+ is not set$$/ { \
				config_value[$$2] = "0"; \
				next; \
			} \
			/^CONFIG_[A-Za-z0-9_]+=/ { \
				config_name = $$0; \
				sub(/=.*/, "", config_name); \
				config_value[config_name] = $$0; \
				sub(/^[^=]*=/, "", config_value[config_name]); \
				next; \
			} \
			END { \
				for (order_index = 1; order_index <= config_count; order_index++) { \
					config_name = config_order[order_index]; \
					if (!(config_name in config_value)) { \
						config_value[config_name] = "0"; \
					} \
					print "#define " config_name " " config_value[config_name]; \
					printed[config_name] = 1; \
				} \
				for (config_name in config_value) { \
					if (!(config_name in printed)) { \
						print "#define " config_name " " config_value[config_name]; \
					} \
				} \
			} \
		' "$(CDK2_KCONFIG)" "$(CDK2_CONFIG)"; \
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

build: native-stage native-coreboot-stage native-check manifest-check

build-image:
	@printf '%s\n' 'cdk2 has no native payload-image target until the retained payload modules are ported to C/Make/Kconfig' >&2
	@exit 1

check: native-check

manifest: $(CDK2_MANIFEST)

$(CDK2_MANIFEST): $(CDK2_CONFIG_HEADER) FORCE
	@mkdir -p "$(dir $@)"
	@set -e; tmp="$@.tmp"; { \
		printf '%s\n' '# Native cdk2 source manifest'; \
		cd "$(CDK2_ROOT)" && \
			find src include util tests -type f \( -name '*.[chS]' -o -name '*.ld' \) -print | sort; \
	} > "$$tmp"; mv "$$tmp" "$@"

manifest-check: $(CDK2_MANIFEST)
	@while IFS= read -r path; do \
		case "$$path" in ''|\#*) continue ;; esac; \
		test -f "$(CDK2_ROOT)/$$path" || { \
			printf '%s\n' "manifest entry does not exist: $$path" >&2; \
			exit 1; \
		}; \
	done < "$(CDK2_MANIFEST)"

modules: manifest-check
	@sed '/^#/d' "$(CDK2_MANIFEST)"

print:
	$(info target=$(CDK2_TARGET))
	$(info config=$(CDK2_CONFIG))
	$(info config-header=$(CDK2_CONFIG_HEADER))
	$(info native-stage=$(CDK2_NATIVE_ELF))
	$(info native-coreboot-stage=$(CDK2_NATIVE_COREBOOT_ELF))
	$(info native-build-dir=$(CDK2_NATIVE_BUILD_DIR))
	$(info modules=$(CDK2_MANIFEST))
	$(info source-date-epoch=$(SOURCE_DATE_EPOCH))
	@true

clean:
	rm -rf "$(CDK2_BUILD_DIR)"
else
$(CDK2_CONFIG_TARGETS): $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER)
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_ROOT)/Makefile" CDK2_CONFIG_READY=1 $@

build-image: $(CDK2_CONFIG) $(CDK2_CONFIG_HEADER)
	@$(MAKE) --no-print-directory $(CDK2_RECURSIVE_ARGS) -f "$(CDK2_ROOT)/Makefile" CDK2_CONFIG_READY=1 $@

clean:
	rm -rf "$(CDK2_BUILD_DIR)"
endif
