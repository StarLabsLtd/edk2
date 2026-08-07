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
	$(CDK2_NATIVE_MONO_TEST)
CDK2_NATIVE_LINK_FLAGS := -static -no-pie -nostdlib -nostartfiles -nodefaultlibs -Wl,-z,max-page-size=0x1000 -Wl,-z,common-page-size=0x1000 -Wl,-T,"$(CDK2_NATIVE_DIR)/cdk2.ld"
CDK2_NATIVE_LINK_POST_MAP_FLAGS := -Wl,--gc-sections -Wl,--build-id=none

.PHONY: native-stage native-coreboot-stage native-coreboot-image native-metronome-fv native-security-stub-fv native-null-memory-test-fv native-null-memory-test-test native-watchdog-fv native-check native-pack native-service-test native-coreboot-test native-fv-test native-fvpack-test native-fvinfo native-fvinfo-test native-ffsbuild-test native-pe-test native-module-test native-security-stub-test native-elfcheck-test FORCE

ifeq ($(CONFIG_CDK2_NATIVE_STAGE),y)
CDK2_NATIVE_STAGE_DEPS := $(CDK2_NATIVE_ELF)
native-stage: $(CDK2_NATIVE_ELF)
native-coreboot-stage: $(CDK2_NATIVE_COREBOOT_ELF)

ifneq ($(strip $(CDK2_PAYLOAD_FV)),)
native-coreboot-image: $(CDK2_NATIVE_COREBOOT_IMAGE) $(CDK2_NATIVE_FV_TEST) \
		$(CDK2_NATIVE_ELF_CHECK)
	@"$(CDK2_NATIVE_FV_TEST)" "$(CDK2_NATIVE_MONO_FV)"
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry cdk2_coreboot_entry32 --require-fv "$<"
else
native-coreboot-image:
	@printf '%s\n' 'native-coreboot-image requires CDK2_PAYLOAD_FV=/path/to/payload.fv' >&2
	@exit 1
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
	@"$(CDK2_NATIVE_PE_TEST)"
	@"$(CDK2_NATIVE_MODULE_TEST)"
	@"$(CDK2_NATIVE_SECURITY_STUB_TEST)"
	@"$(CDK2_NATIVE_NULL_MEMORY_TEST)"
	@"$(CDK2_NATIVE_MONO_TEST)"
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
CDK2_NATIVE_COMPOSED_FV := $(CDK2_NATIVE_WATCHDOG_FV)

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
CDK2_NATIVE_COMPOSED_FV := $(CDK2_NATIVE_NULL_MEMORY_TEST_FV)
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

$(CDK2_NATIVE_MONO_FV): $(CDK2_NATIVE_COMPOSED_FV) $(CDK2_NATIVE_MONO_FFS) $(CDK2_NATIVE_FVREPLACE)
	@"$(CDK2_NATIVE_FVREPLACE)" "$(CDK2_NATIVE_COMPOSED_FV)" 0x9aa48 "$(CDK2_NATIVE_MONO_FFS)" "$@"

$(CDK2_NATIVE_FV_BLOB_OBJ): $(CDK2_NATIVE_MONO_FV) | $(CDK2_NATIVE_BUILD_DIR)
	@cd "$(dir $<)" && $(CDK2_NATIVE_OBJCOPY) -I binary -O elf64-x86-64 -B i386:x86-64 --rename-section .data=.cdk2.fv,alloc,load,readonly,data,contents "$(notdir $<)" "$(abspath $@)"

$(CDK2_NATIVE_COREBOOT_IMAGE): $(CDK2_NATIVE_COREBOOT_OBJS) $(CDK2_NATIVE_FV_BLOB_OBJ) $(CDK2_NATIVE_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_COREBOOT_IMAGE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,cdk2_coreboot_entry32 -o "$@" $(CDK2_NATIVE_COREBOOT_LINK_INPUTS) "$(CDK2_NATIVE_FV_BLOB_OBJ)"
endif

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

$(CDK2_NATIVE_PE_TEST): $(CDK2_NATIVE_DIR)/pe.c $(CDK2_NATIVE_DIR)/pe.h $(CDK2_NATIVE_DIR)/pe_test.c $(CDK2_DIR)/include/industry_standard/pe_image.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/pe-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/pe.c" "$(CDK2_NATIVE_DIR)/pe_test.c"

$(CDK2_NATIVE_MODULE_TEST): $(CDK2_NATIVE_DIR)/entry.c $(CDK2_NATIVE_DIR)/entry.h $(CDK2_NATIVE_DIR)/module.h $(CDK2_NATIVE_DIR)/module_test.c $(CDK2_NATIVE_DIR)/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_HOST_CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/module-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -I$(CDK2_NATIVE_DIR) $(CDK2_NATIVE_HOST_LDFLAGS) -o "$@" "$(CDK2_NATIVE_DIR)/entry.c" "$(CDK2_NATIVE_DIR)/module_test.c"

-include $(CDK2_NATIVE_DEPFILES)
