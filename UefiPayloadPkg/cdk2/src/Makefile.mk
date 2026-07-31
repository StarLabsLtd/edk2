## SPDX-License-Identifier: BSD-2-Clause-Patent

# Native cdk2 stage build fragment. It is included after the top-level Kconfig
# has been resolved, so the same generated config controls both backends.

CDK2_NATIVE_BUILD_DIR ?= $(CDK2_BUILD_DIR)/native
CDK2_NATIVE_ARCH_X86_DIR := $(CDK2_NATIVE_DIR)/arch/x86
CDK2_NATIVE_COMMON_DIR := $(CDK2_NATIVE_DIR)/common
CDK2_NATIVE_COREBOOT_DIR := $(CDK2_NATIVE_DIR)/drivers/coreboot
CDK2_NATIVE_PLATFORM_DIR := $(CDK2_NATIVE_DIR)/platform/default
CDK2_NATIVE_TOOLS_DIR := $(CDK2_NATIVE_DIR)/tools
CDK2_NATIVE_TESTS_DIR := $(CDK2_NATIVE_DIR)/tests
CDK2_NATIVE_ELF ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage.elf
CDK2_NATIVE_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage.map
CDK2_NATIVE_COREBOOT_ELF ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-stage.elf
CDK2_NATIVE_COREBOOT_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-stage.map
CDK2_NATIVE_COREBOOT_IMAGE ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-image.elf
CDK2_NATIVE_COREBOOT_IMAGE_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-image.map
CDK2_NATIVE_DIRECT_LINK_MAPS := $(CDK2_NATIVE_MAP) $(CDK2_NATIVE_COREBOOT_MAP) $(CDK2_NATIVE_COREBOOT_IMAGE_MAP)
CDK2_NATIVE_FV_BLOB_OBJ ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fv.o
CDK2_NATIVE_FV_BLOB_SYMBOL_BASENAME := $(subst -,_,$(subst .,_,$(notdir $(CDK2_OUTPUT))))
CDK2_NATIVE_FV_BLOB_SYMBOL_PREFIX := _binary_$(CDK2_NATIVE_FV_BLOB_SYMBOL_BASENAME)_
CDK2_NATIVE_OVERRIDE_ELF ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage-override.elf
CDK2_NATIVE_OVERRIDE_MAP ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-stage-override.map
CDK2_NATIVE_PACKER ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvpack
CDK2_NATIVE_SERVICE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-services-test
CDK2_NATIVE_COREBOOT_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-coreboot-test
CDK2_NATIVE_FV_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fv-test
CDK2_NATIVE_FVPACK_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-fvpack-test
CDK2_NATIVE_PE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-pe-test
CDK2_NATIVE_MODULE_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-module-test
CDK2_NATIVE_ELF_CHECK ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-elfcheck
CDK2_NATIVE_ELF_CHECK_TEST ?= $(CDK2_NATIVE_BUILD_DIR)/cdk2-elfcheck-test
CDK2_NATIVE_CC ?= $(CC)
CDK2_NATIVE_OBJCOPY ?= objcopy
CDK2_NATIVE_COREBOOT_ENTRY ?= $(CDK2_NATIVE_BUILD_DIR)/entry32.o
CDK2_NATIVE_CFLAGS ?= -ffreestanding -fno-builtin -fno-stack-protector -fno-pie -fno-asynchronous-unwind-tables -fno-unwind-tables -fdata-sections -ffunction-sections -fshort-wchar -m64 -mno-red-zone -mno-sse -mno-mmx -Os -Wall -Werror
CDK2_NATIVE_HOST_CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Werror -fshort-wchar
CDK2_NATIVE_INCLUDES := -I$(CDK2_BUILD_DIR)/include -I$(CDK2_DIR)/include -I$(CDK2_ROOT)/MdePkg -I$(CDK2_ROOT)/MdePkg/Include -I$(CDK2_ROOT)/MdePkg/Include/X64 -I$(CDK2_ROOT)/MdeModulePkg/Include -I$(CDK2_ROOT)/UefiPayloadPkg/Include
CDK2_NATIVE_DEPFILES := $(CDK2_NATIVE_BUILD_DIR)/*.d
CDK2_NATIVE_STAGE_OBJS := \
	$(CDK2_NATIVE_BUILD_DIR)/entry.o \
	$(CDK2_NATIVE_BUILD_DIR)/module.o \
	$(CDK2_NATIVE_BUILD_DIR)/platform.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_hobs.o \
	$(CDK2_NATIVE_BUILD_DIR)/fv.o \
	$(CDK2_NATIVE_BUILD_DIR)/pe.o \
	$(CDK2_NATIVE_BUILD_DIR)/services.o \
	$(CDK2_NATIVE_BUILD_DIR)/payload.o
CDK2_NATIVE_COREBOOT_OBJS := \
	$(CDK2_NATIVE_COREBOOT_ENTRY) \
	$(CDK2_NATIVE_BUILD_DIR)/entry.o \
	$(CDK2_NATIVE_BUILD_DIR)/module.o \
	$(CDK2_NATIVE_BUILD_DIR)/platform.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_hobs.o \
	$(CDK2_NATIVE_BUILD_DIR)/fv.o \
	$(CDK2_NATIVE_BUILD_DIR)/pe.o \
	$(CDK2_NATIVE_BUILD_DIR)/coreboot_backend.o \
	$(CDK2_NATIVE_BUILD_DIR)/services.o \
	$(CDK2_NATIVE_BUILD_DIR)/payload.o
CDK2_NATIVE_OVERRIDE_OBJS := \
	$(CDK2_NATIVE_STAGE_OBJS) \
	$(CDK2_NATIVE_BUILD_DIR)/override.o
CDK2_NATIVE_STAGE_LINK_INPUTS := $(foreach obj,$(CDK2_NATIVE_STAGE_OBJS),"$(obj)")
CDK2_NATIVE_COREBOOT_LINK_INPUTS := $(foreach obj,$(CDK2_NATIVE_COREBOOT_OBJS),"$(obj)")
CDK2_NATIVE_OVERRIDE_LINK_INPUTS := $(foreach obj,$(CDK2_NATIVE_OVERRIDE_OBJS),"$(obj)")
CDK2_NATIVE_LINK_FLAGS := -static -no-pie -nostdlib -nostartfiles -nodefaultlibs -Wl,-z,max-page-size=0x1000 -Wl,-z,common-page-size=0x1000 -Wl,-T,"$(CDK2_NATIVE_ARCH_X86_DIR)/cdk2.ld"
CDK2_NATIVE_LINK_POST_MAP_FLAGS := -Wl,--gc-sections -Wl,--build-id=none

.PHONY: native-stage native-coreboot-stage native-coreboot-image native-check native-pack native-service-test native-coreboot-test native-fv-test native-fvpack-test native-pe-test native-module-test native-elfcheck-test FORCE

ifeq ($(CONFIG_CDK2_NATIVE_STAGE),y)
native-stage: $(CDK2_NATIVE_ELF)
native-coreboot-stage: $(CDK2_NATIVE_COREBOOT_ELF)
native-coreboot-image: $(CDK2_NATIVE_COREBOOT_IMAGE) $(CDK2_NATIVE_FV_TEST) $(CDK2_NATIVE_ELF_CHECK)
	@"$(CDK2_NATIVE_FV_TEST)" "$(CDK2_OUTPUT)"
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry Cdk2CorebootEntry32 --require-fv "$(CDK2_NATIVE_COREBOOT_IMAGE)"
	@nm "$(CDK2_NATIVE_COREBOOT_IMAGE)" | grep -Eq '[[:space:]]T[[:space:]]Cdk2PlatformInitializeNativeContext$$'
	@nm "$(CDK2_NATIVE_COREBOOT_IMAGE)" | grep -Eq '[[:space:]]W[[:space:]]Cdk2PlatformLateInit$$'
native-check: $(CDK2_CONFIG_HEADER) $(CDK2_NATIVE_ELF) $(CDK2_NATIVE_OVERRIDE_ELF) $(CDK2_NATIVE_COREBOOT_ELF) $(CDK2_NATIVE_COREBOOT_ENTRY) $(CDK2_NATIVE_PACKER) $(CDK2_NATIVE_SERVICE_TEST) $(CDK2_NATIVE_COREBOOT_TEST) $(CDK2_NATIVE_FV_TEST) $(CDK2_NATIVE_FVPACK_TEST) $(CDK2_NATIVE_PE_TEST) $(CDK2_NATIVE_MODULE_TEST) $(CDK2_NATIVE_ELF_CHECK) $(CDK2_NATIVE_ELF_CHECK_TEST)
	@nm "$(CDK2_NATIVE_ELF)" | grep -Eq '[[:space:]]W[[:space:]]Cdk2PlatformInitializeNativeContext$$'
	@nm "$(CDK2_NATIVE_ELF)" | grep -Eq '[[:space:]]W[[:space:]]Cdk2PlatformLateInit$$'
	@nm "$(CDK2_NATIVE_OVERRIDE_ELF)" | grep -Eq '[[:space:]]T[[:space:]]Cdk2PlatformInitializeNativeContext$$'
	@nm "$(CDK2_NATIVE_OVERRIDE_ELF)" | grep -Eq '[[:space:]]T[[:space:]]Cdk2PlatformLateInit$$'
	@nm "$(CDK2_NATIVE_COREBOOT_ELF)" | grep -Eq '[[:space:]]T[[:space:]]Cdk2PlatformInitializeNativeContext$$'
	@nm "$(CDK2_NATIVE_COREBOOT_ELF)" | grep -Eq '[[:space:]]W[[:space:]]Cdk2PlatformLateInit$$'
	@nm "$(CDK2_NATIVE_COREBOOT_ELF)" | grep -Eq '[[:space:]]T[[:space:]]Cdk2CorebootEntry32$$'
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry Cdk2NativeStageEntry "$(CDK2_NATIVE_ELF)"
	@"$(CDK2_NATIVE_ELF_CHECK)" --entry Cdk2CorebootEntry32 "$(CDK2_NATIVE_COREBOOT_ELF)"
	@test -s "$(CDK2_NATIVE_MAP)"
	@test -s "$(CDK2_NATIVE_COREBOOT_MAP)"
	@test -s "$(CDK2_NATIVE_OVERRIDE_MAP)"
	@test -x "$(CDK2_NATIVE_PACKER)"
	@"$(CDK2_NATIVE_SERVICE_TEST)"
	@"$(CDK2_NATIVE_COREBOOT_TEST)"
	@"$(CDK2_NATIVE_FV_TEST)"
	@"$(CDK2_NATIVE_FVPACK_TEST)" "$(CDK2_NATIVE_PACKER)" "$(CDK2_NATIVE_BUILD_DIR)"
	@"$(CDK2_NATIVE_PE_TEST)"
	@"$(CDK2_NATIVE_MODULE_TEST)"
	@"$(CDK2_NATIVE_ELF_CHECK_TEST)" "$(CDK2_NATIVE_ELF_CHECK)" "$(CDK2_NATIVE_BUILD_DIR)"
	@printf '%s\n' "native cdk2 stage: $(CDK2_NATIVE_ELF)"
	@printf '%s\n' "native cdk2 FV packer: $(CDK2_NATIVE_PACKER)"
else
native-stage:
	@printf '%s\n' 'native cdk2 stage: disabled by Kconfig'

native-coreboot-stage:
	@printf '%s\n' 'native cdk2 coreboot stage: disabled by Kconfig'

native-coreboot-image:
	@printf '%s\n' 'native cdk2 coreboot image: disabled by Kconfig'

native-check: $(CDK2_CONFIG_HEADER) $(CDK2_NATIVE_PACKER) $(CDK2_NATIVE_SERVICE_TEST) $(CDK2_NATIVE_COREBOOT_TEST) $(CDK2_NATIVE_FV_TEST) $(CDK2_NATIVE_FVPACK_TEST) $(CDK2_NATIVE_PE_TEST) $(CDK2_NATIVE_MODULE_TEST) $(CDK2_NATIVE_ELF_CHECK) $(CDK2_NATIVE_ELF_CHECK_TEST)
	@"$(CDK2_NATIVE_SERVICE_TEST)"
	@"$(CDK2_NATIVE_COREBOOT_TEST)"
	@"$(CDK2_NATIVE_FV_TEST)"
	@"$(CDK2_NATIVE_FVPACK_TEST)" "$(CDK2_NATIVE_PACKER)" "$(CDK2_NATIVE_BUILD_DIR)"
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

native-pe-test: $(CDK2_NATIVE_PE_TEST)
	@"$(CDK2_NATIVE_PE_TEST)"

native-module-test: $(CDK2_NATIVE_MODULE_TEST)
	@"$(CDK2_NATIVE_MODULE_TEST)"

native-elfcheck-test: $(CDK2_NATIVE_ELF_CHECK) $(CDK2_NATIVE_ELF_CHECK_TEST)
	@"$(CDK2_NATIVE_ELF_CHECK_TEST)" "$(CDK2_NATIVE_ELF_CHECK)" "$(CDK2_NATIVE_BUILD_DIR)"

$(CDK2_NATIVE_BUILD_DIR):
	@mkdir -p "$@"

$(CDK2_NATIVE_COREBOOT_ENTRY): $(CDK2_NATIVE_ARCH_X86_DIR)/entry32.S | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) -c -ffreestanding -fno-pie -fno-stack-protector -o "$@" "$<"

$(CDK2_NATIVE_BUILD_DIR)/entry.o: $(CDK2_NATIVE_COMMON_DIR)/entry.c $(CDK2_DIR)/include/cdk2/entry.h $(CDK2_DIR)/include/cdk2/module.h $(CDK2_DIR)/include/cdk2/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/module.o: $(CDK2_NATIVE_COMMON_DIR)/module.c $(CDK2_DIR)/include/cdk2/module.h $(CDK2_DIR)/include/cdk2/context.h $(CDK2_DIR)/include/cdk2/services.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/platform.o: $(CDK2_ROOT)/UefiPayloadPkg/cdk2/Library/Cdk2PlatformLib/Cdk2PlatformLib.c $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot_backend.o: $(CDK2_NATIVE_COREBOOT_DIR)/coreboot_backend.c $(CDK2_DIR)/include/cdk2/coreboot_hobs.h $(CDK2_DIR)/include/cdk2/fv.h $(CDK2_DIR)/include/cdk2/pe.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot.o: $(CDK2_NATIVE_COREBOOT_DIR)/coreboot.c $(CDK2_DIR)/include/cdk2/coreboot.h $(CDK2_ROOT)/UefiPayloadPkg/Include/Coreboot.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/coreboot_hobs.o: $(CDK2_NATIVE_COREBOOT_DIR)/coreboot_hobs.c $(CDK2_DIR)/include/cdk2/coreboot_hobs.h $(CDK2_DIR)/include/cdk2/coreboot.h $(CDK2_ROOT)/MdePkg/Include/Pi/PiHob.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/fv.o: $(CDK2_NATIVE_COMMON_DIR)/fv.c $(CDK2_DIR)/include/cdk2/fv.h $(CDK2_ROOT)/MdePkg/Include/Pi/PiFirmwareFile.h $(CDK2_ROOT)/MdePkg/Include/Pi/PiFirmwareVolume.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/pe.o: $(CDK2_NATIVE_COMMON_DIR)/pe.c $(CDK2_DIR)/include/cdk2/pe.h $(CDK2_ROOT)/MdePkg/Include/IndustryStandard/PeImage.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/services.o: $(CDK2_NATIVE_COMMON_DIR)/services.c $(CDK2_DIR)/include/cdk2/services.h $(CDK2_DIR)/include/cdk2/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_BUILD_DIR)/override.o: $(CDK2_NATIVE_PLATFORM_DIR)/override.c $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_PACKER): $(CDK2_NATIVE_TOOLS_DIR)/fvpack.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_ELF_CHECK): $(CDK2_NATIVE_TOOLS_DIR)/elfcheck.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -o "$@" "$<"

$(CDK2_NATIVE_ELF_CHECK_TEST): $(CDK2_NATIVE_TESTS_DIR)/elfcheck_test.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/elfcheck-test.d" -MT "$@" -o "$@" "$<"

$(CDK2_NATIVE_BUILD_DIR)/payload.o: $(CDK2_NATIVE_COMMON_DIR)/payload.c $(CDK2_DIR)/include/cdk2/services.h $(CDK2_DIR)/include/cdk2/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_CFLAGS) -MMD -MP -MF "$(@:.o=.d)" -MT "$@" $(CDK2_NATIVE_INCLUDES) -c "$<" -o "$@"

$(CDK2_NATIVE_ELF): $(CDK2_NATIVE_STAGE_OBJS) $(CDK2_NATIVE_ARCH_X86_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,Cdk2NativeStageEntry -o "$@" $(CDK2_NATIVE_STAGE_LINK_INPUTS)

$(CDK2_NATIVE_OVERRIDE_ELF): $(CDK2_NATIVE_OVERRIDE_OBJS) $(CDK2_NATIVE_ARCH_X86_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_OVERRIDE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,Cdk2NativeStageEntry -o "$@" $(CDK2_NATIVE_OVERRIDE_LINK_INPUTS)

$(CDK2_NATIVE_COREBOOT_ELF): $(CDK2_NATIVE_COREBOOT_OBJS) $(CDK2_NATIVE_ARCH_X86_DIR)/cdk2.ld
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_COREBOOT_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,Cdk2CorebootEntry32 -o "$@" $(CDK2_NATIVE_COREBOOT_LINK_INPUTS)

FORCE:

$(CDK2_NATIVE_FV_BLOB_OBJ): $(CDK2_OUTPUT) FORCE | $(CDK2_NATIVE_BUILD_DIR)
	@cd "$(dir $<)" && $(CDK2_NATIVE_OBJCOPY) -I binary -O elf64-x86-64 -B i386:x86-64 --rename-section .data=.cdk2.fv,alloc,load,readonly,data,contents "$(notdir $<)" "$(abspath $@)"
	@$(CDK2_NATIVE_OBJCOPY) --redefine-sym "$(CDK2_NATIVE_FV_BLOB_SYMBOL_PREFIX)start=__cdk2_fv_start" --redefine-sym "$(CDK2_NATIVE_FV_BLOB_SYMBOL_PREFIX)end=__cdk2_fv_end" "$@"

$(CDK2_NATIVE_COREBOOT_IMAGE): $(CDK2_NATIVE_COREBOOT_ELF) $(CDK2_NATIVE_FV_BLOB_OBJ)
	@$(CDK2_NATIVE_CC) $(CDK2_NATIVE_LINK_FLAGS) -Wl,-Map,"$(CDK2_NATIVE_COREBOOT_IMAGE_MAP)" $(CDK2_NATIVE_LINK_POST_MAP_FLAGS) -Wl,-e,Cdk2CorebootEntry32 -o "$@" $(CDK2_NATIVE_COREBOOT_LINK_INPUTS) "$(CDK2_NATIVE_FV_BLOB_OBJ)"

$(CDK2_NATIVE_SERVICE_TEST): $(CDK2_NATIVE_COMMON_DIR)/payload.c $(CDK2_NATIVE_COMMON_DIR)/services.c $(CDK2_DIR)/include/cdk2/services.h $(CDK2_DIR)/include/cdk2/context.h $(CDK2_NATIVE_TESTS_DIR)/services_test.c | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/services-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_NATIVE_COMMON_DIR)/payload.c" "$(CDK2_NATIVE_COMMON_DIR)/services.c" "$(CDK2_NATIVE_TESTS_DIR)/services_test.c"

$(CDK2_NATIVE_COREBOOT_TEST): $(CDK2_NATIVE_COREBOOT_DIR)/coreboot.c $(CDK2_DIR)/include/cdk2/coreboot.h $(CDK2_NATIVE_COREBOOT_DIR)/coreboot_hobs.c $(CDK2_DIR)/include/cdk2/coreboot_hobs.h $(CDK2_NATIVE_COREBOOT_DIR)/coreboot_backend.c $(CDK2_NATIVE_COMMON_DIR)/services.c $(CDK2_DIR)/include/cdk2/services.h $(CDK2_NATIVE_TESTS_DIR)/coreboot_test.c $(CDK2_ROOT)/UefiPayloadPkg/Include/Coreboot.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -DCDK2_COREBOOT_BACKEND_TEST -ffunction-sections -fdata-sections -Wl,--gc-sections -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/coreboot-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_NATIVE_COREBOOT_DIR)/coreboot.c" "$(CDK2_NATIVE_COREBOOT_DIR)/coreboot_hobs.c" "$(CDK2_NATIVE_COREBOOT_DIR)/coreboot_backend.c" "$(CDK2_NATIVE_COMMON_DIR)/services.c" "$(CDK2_NATIVE_TESTS_DIR)/coreboot_test.c"

$(CDK2_NATIVE_FV_TEST): $(CDK2_NATIVE_COMMON_DIR)/fv.c $(CDK2_DIR)/include/cdk2/fv.h $(CDK2_NATIVE_TESTS_DIR)/fv_test.c $(CDK2_ROOT)/MdePkg/Include/Pi/PiFirmwareFile.h $(CDK2_ROOT)/MdePkg/Include/Pi/PiFirmwareVolume.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/fv-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_NATIVE_COMMON_DIR)/fv.c" "$(CDK2_NATIVE_TESTS_DIR)/fv_test.c"

$(CDK2_NATIVE_FVPACK_TEST): $(CDK2_NATIVE_TESTS_DIR)/fvpack_test.c $(CDK2_ROOT)/MdePkg/Include/IndustryStandard/PeImage.h $(CDK2_ROOT)/MdePkg/Include/Pi/PiFirmwareFile.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/fvpack-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_NATIVE_TESTS_DIR)/fvpack_test.c"

$(CDK2_NATIVE_PE_TEST): $(CDK2_NATIVE_COMMON_DIR)/pe.c $(CDK2_DIR)/include/cdk2/pe.h $(CDK2_NATIVE_TESTS_DIR)/pe_test.c $(CDK2_ROOT)/MdePkg/Include/IndustryStandard/PeImage.h | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/pe-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_NATIVE_COMMON_DIR)/pe.c" "$(CDK2_NATIVE_TESTS_DIR)/pe_test.c"

$(CDK2_NATIVE_MODULE_TEST): $(CDK2_NATIVE_COMMON_DIR)/entry.c $(CDK2_DIR)/include/cdk2/entry.h $(CDK2_DIR)/include/cdk2/module.h $(CDK2_NATIVE_TESTS_DIR)/module_test.c $(CDK2_DIR)/include/cdk2/context.h $(CDK2_CONFIG_HEADER) | $(CDK2_NATIVE_BUILD_DIR)
	@$(CC) $(CDK2_NATIVE_HOST_CFLAGS) -MMD -MP -MF "$(CDK2_NATIVE_BUILD_DIR)/module-test.d" -MT "$@" $(CDK2_NATIVE_INCLUDES) -o "$@" "$(CDK2_NATIVE_COMMON_DIR)/entry.c" "$(CDK2_NATIVE_TESTS_DIR)/module_test.c"

-include $(CDK2_NATIVE_DEPFILES)
