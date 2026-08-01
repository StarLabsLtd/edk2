## SPDX-License-Identifier: BSD-2-Clause-Patent

# EDK II backend for cdk2. This is deliberately isolated from the Kconfig,
# native-stage, and image-packaging rules so a native backend can replace it.

CDK2_BACKEND_NAME := edk2
CDK2_BACKEND_SUPPORTED_INTERFACE_VERSION := 1
CDK2_BACKEND_SOURCE_DATE_PATHS := UefiPayloadPkg/cdk2 UefiPayloadPkg/UefiPayloadPkg.dsc UefiPayloadPkg/UefiPayloadPkg.fdf
CDK2_BACKEND_METADATA_TEST := metadata-test
CDK2_BACKEND_BUILD_COMMAND ?= build
CDK2_BACKEND_TOOLCHAIN ?= GCC

# cdk2 supports the X64 payload on x86. The native entry32.S file is only the
# coreboot-to-long-mode bootstrap; it is not an IA32 payload build.
CDK2_BACKEND_ENTRY_ARCH := X64
CDK2_BACKEND_ARCHES ?= X64
CDK2_BACKEND_BUILD_ARCH ?= X64
CDK2_BACKEND_OUTPUT_DIRECTORY ?= Build/cdk2/edk2/UefiPayloadPkg$(CDK2_BACKEND_BUILD_ARCH)

ifneq ($(strip $(CDK2_BACKEND_ENTRY_ARCH)),X64)
$(error cdk2 direct EDK II backend is X64-only: CDK2_BACKEND_ENTRY_ARCH=$(CDK2_BACKEND_ENTRY_ARCH))
endif
ifneq ($(strip $(CDK2_BACKEND_ARCHES)),X64)
$(error cdk2 direct EDK II backend is X64-only: CDK2_BACKEND_ARCHES=$(CDK2_BACKEND_ARCHES))
endif
ifneq ($(strip $(CDK2_BACKEND_BUILD_ARCH)),X64)
$(error cdk2 direct EDK II backend is X64-only: CDK2_BACKEND_BUILD_ARCH=$(CDK2_BACKEND_BUILD_ARCH))
endif

include $(CDK2_DIR)/modules.mk
CDK2_TIMER_SUPPORT := $(CDK2_EFFECTIVE_TIMER_SUPPORT)

# These are EDK II build definitions, not cdk2 policy. Keep their translation
# behind the backend so a native linker can consume the same Kconfig values
# without carrying BaseTools-specific command-line names.
CDK2_DEFAULT_DEFINES := \
  -D BOOTLOADER=COREBOOT \
  -D UNIVERSAL_PAYLOAD=FALSE \
  -D UNIVERSAL_PAYLOAD_FORMAT=ELF \
  -D MEMORY_TEST=$(CDK2_EFFECTIVE_MEMORY_TEST) \
  -D NETWORK_DRIVER_ENABLE=FALSE \
  -D DISABLE_RESET_SYSTEM=FALSE \
  -D BOOTSPLASH_IMAGE=FALSE \
  -D SECURITY_STUB_ENABLE=$(if $(filter y,$(CDK2_EFFECTIVE_SECURITY_STUB)),TRUE,FALSE)

CDK2_DEFINES := $(CDK2_DEFAULT_DEFINES)
# Coreboot hands the payload CPUs that have already been initialized by the
# bootblock/romstage path.  Use INIT-SIPI-SIPI for the first EDK II wakeup;
# SIPI-only startup is not reliable after that handoff, especially under QEMU.
CDK2_PCDS := \
  --pcd gUefiCpuPkgTokenSpaceGuid.PcdFirstTimeWakeUpAPsBySipi=FALSE
CDK2_CAPSULE_FMP_DXE_MODULE := FmpDevicePkg/FmpDxe/FmpDxe.inf
CDK2_CAPSULE_MAIN_FW_GUID := $(patsubst "%",%,$(strip $(CONFIG_CDK2_CAPSULE_MAIN_FW_GUID)))
CDK2_EXTRA_DEFINES_NORMALIZED := $(subst ",,$(CDK2_EXTRA_DEFINES))
CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA := $(filter CAPSULE_MAIN_FW_GUID=% -DCAPSULE_MAIN_FW_GUID=% --define=CAPSULE_MAIN_FW_GUID=%,$(CDK2_EXTRA_DEFINES_NORMALIZED))
CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA := $(patsubst --define=CAPSULE_MAIN_FW_GUID=%,%,$(CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA))
CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA := $(patsubst -DCAPSULE_MAIN_FW_GUID=%,%,$(CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA))
CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA := $(patsubst CAPSULE_MAIN_FW_GUID=%,%,$(CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA))
CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA := $(strip $(lastword $(CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA)))
CDK2_CAPSULE_MAIN_FW_GUID_OVERRIDE := $(CDK2_CAPSULE_MAIN_FW_GUID_FROM_EXTRA)
CDK2_EFFECTIVE_CAPSULE_MAIN_FW_GUID := $(strip $(if $(CDK2_CAPSULE_MAIN_FW_GUID_OVERRIDE),$(CDK2_CAPSULE_MAIN_FW_GUID_OVERRIDE),$(CDK2_CAPSULE_MAIN_FW_GUID)))

# cdk2 owns the final outer volume and exposes the retained DXE files directly
# so the entry path does not have to discover and unwrap a nested FV image.
CDK2_DEFINES += -D CDK2_FLAT_DXE_FV=TRUE

ifeq ($(CDK2_EFFECTIVE_SHELL),y)
CDK2_DEFINES += -D SHELL_TYPE=BUILD_SHELL
else
CDK2_DEFINES += -D SHELL_TYPE=NONE
endif

CDK2_BOOL_DEFINES := \
  SMM:SMM_SUPPORT \
  CAPSULE:CAPSULE_SUPPORT \
  ESRT:ESRT_SUPPORT \
  SECURE_BOOT:SECURE_BOOT_ENABLE \
  SECURE_BOOT_CONFIG:SECURE_BOOT_CONFIG_ENABLE \
  SETUP_UI:SETUP_UI_ENABLE \
  CONNECT_ALL_DEVICES:CONNECT_ALL_DEVICES \
  TPM12:TPM1_ENABLE \
  TPM2:TPM2_ENABLE \
  TPM_CONFIG:TPM_CONFIG_ENABLE \
  PCI:PCI_ENABLE \
  STORAGE:STORAGE_ENABLE \
  NVME:NVME_ENABLE \
  USB:USB_ENABLE \
  ATA:ATA_ENABLE \
  SD:SD_ENABLE \
  GRAPHICS:GRAPHICS_ENABLE \
  CONSOLE:CONSOLE_ENABLE \
  SIO_BUS:SIO_BUS_ENABLE \
  PS2_KEYBOARD:PS2_KEYBOARD_ENABLE \
  PS2_MOUSE:PS2_MOUSE_ENABLE \
  CBMEM_CONSOLE:USE_CBMEM_FOR_CONSOLE \
  CBMEM_TIMESTAMPS:CBMEM_TIMESTAMPS \
  LVGL:LVGL_ENABLE \
  CPU_TIMER:CPU_TIMER_LIB_ENABLE \
  LATE_LINK:CDK2_LATE_LINK

define CDK2_ADD_BOOL_DEFINE
ifeq ($(CDK2_EFFECTIVE_$(word 1,$(subst :, ,$(1)))),y)
CDK2_DEFINES += -D $(word 2,$(subst :, ,$(1)))=TRUE
else
CDK2_DEFINES += -D $(word 2,$(subst :, ,$(1)))=FALSE
endif
endef

$(foreach map,$(CDK2_BOOL_DEFINES),$(eval $(call CDK2_ADD_BOOL_DEFINE,$(map))))

ifeq ($(CDK2_EFFECTIVE_SMMSTORE),y)
CDK2_DEFINES += -D VARIABLE_SUPPORT=SMMSTORE
else
CDK2_DEFINES += -D VARIABLE_SUPPORT=EMU
endif

ifeq ($(CDK2_EFFECTIVE_CAPSULE),y)
ifneq ($(strip $(CDK2_EFFECTIVE_CAPSULE_MAIN_FW_GUID)),)
CDK2_DEFINES += -D CAPSULE_MAIN_FW_GUID=$(CDK2_EFFECTIVE_CAPSULE_MAIN_FW_GUID)
endif
endif

ifneq ($(filter y,$(CDK2_EFFECTIVE_TPM12) $(CDK2_EFFECTIVE_TPM2)),)
CDK2_DEFINES += -D TPM_ENABLE=TRUE
else
CDK2_DEFINES += -D TPM_ENABLE=FALSE
endif

ifeq ($(CDK2_EFFECTIVE_SERIAL),y)
CDK2_DEFINES += -D SERIAL_DRIVER_ENABLE=TRUE -D DISABLE_SERIAL_TERMINAL=FALSE
else
CDK2_DEFINES += -D SERIAL_DRIVER_ENABLE=FALSE -D DISABLE_SERIAL_TERMINAL=TRUE
endif

CDK2_DEFINES += -D PLATFORM_BOOT_TIMEOUT=$(CONFIG_CDK2_BOOT_TIMEOUT)
CDK2_DEFINES += -D TIMER_SUPPORT=$(CDK2_TIMER_SUPPORT)

# Command-line overrides are deliberately last, so QEMU and board-specific
# test configurations can change one setting without copying defconfig.
CDK2_DEFINES += $(CDK2_EXTRA_DEFINES)

CDK2_BACKEND_DESCRIPTOR := $(CDK2_ROOT)/UefiPayloadPkg/UefiPayloadPkg.dsc
ifneq ($(filter /%,$(CDK2_BACKEND_OUTPUT_DIRECTORY)),)
CDK2_BACKEND_OUTPUT_ROOT := $(CDK2_BACKEND_OUTPUT_DIRECTORY)
else
CDK2_BACKEND_OUTPUT_ROOT := $(CDK2_ROOT)/$(CDK2_BACKEND_OUTPUT_DIRECTORY)
endif
CDK2_BACKEND_BUILD_DIR := $(CDK2_BACKEND_OUTPUT_ROOT)/$(CDK2_TARGET)_$(CDK2_BACKEND_TOOLCHAIN)
CDK2_PYTHON_STAGE_ROOT := $(CDK2_BASETOOLS_BUILD_DIR)/Python
CDK2_PYTHON_WRAPPER_ROOT := $(CDK2_PYTHON_STAGE_ROOT)/BinWrappers/PosixLike
CDK2_REJECT_WRAPPER_ROOT := $(CDK2_PYTHON_STAGE_ROOT)/BinWrappers/cdk2-denied
ifeq ($(CDK2_EFFECTIVE_LVGL),y)
CDK2_BACKEND_ENV += PACKAGES_PATH="$(CDK2_ROOT)/3rdparty$${PACKAGES_PATH:+:$$PACKAGES_PATH}"
endif
CDK2_BACKEND_ENTRY_MODULE := UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry.inf
CDK2_BACKEND_ENTRY_IMAGE := $(CDK2_BACKEND_BUILD_DIR)/$(CDK2_BACKEND_ENTRY_ARCH)/UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry/OUTPUT/PayloadEntry.efi
CDK2_BACKEND_DXE_FV := $(CDK2_BACKEND_BUILD_DIR)/FV/DXEFV.Fv
CDK2_BACKEND_DXE_FV_INF := $(CDK2_BACKEND_BUILD_DIR)/FV/DXEFV.inf
CDK2_BACKEND_DXE_FV_TEXT := $(CDK2_BACKEND_DXE_FV).txt
CDK2_BACKEND_METADATA_TOOL := $(CDK2_DIR)/module_metadata.py
CDK2_BACKEND_METADATA := $(CDK2_BUILD_DIR)/cdk2-module-metadata.json
CDK2_BACKEND_METADATA_INPUT_STATE := $(CDK2_BUILD_DIR)/cdk2-edk2-metadata-input-state.txt
CDK2_BACKEND_MODULE_GUIDS := $(CDK2_BUILD_DIR)/cdk2-module-guids.txt
CDK2_BACKEND_MANIFEST_STATE := $(CDK2_BUILD_DIR)/cdk2-edk2-manifest-state.txt
CDK2_BACKEND_FFS_LIST := $(CDK2_BUILD_DIR)/cdk2-dxe-ffs.txt
CDK2_BACKEND_METADATA_MODULES := $(CDK2_BUILD_DIR)/cdk2-metadata-modules.txt
CDK2_BACKEND_DXE_MANIFEST := $(CDK2_BUILD_DIR)/cdk2-dxe-fvpack.manifest
CDK2_BACKEND_SELECTED_MODULES := $(CDK2_BUILD_DIR)/cdk2-selected-modules.txt
CDK2_BACKEND_DXE_FV_GUIDS := $(CDK2_BUILD_DIR)/cdk2-dxe-fv-guids.txt
CDK2_BACKEND_SELECTED_DXE_GUIDS := $(CDK2_BUILD_DIR)/cdk2-selected-dxe-guids.txt
CDK2_BACKEND_SELECTED_MODULE_FILES := $(addprefix $(CDK2_ROOT)/,$(CDK2_SELECTED_MODULES))
CDK2_BACKEND_PAYLOAD_LIBRARY_FILES := $(addprefix $(CDK2_ROOT)/,$(CDK2_PAYLOAD_LIBRARIES))
CDK2_BACKEND_SELECTED_MODULE_FILES_EXISTING := $(wildcard $(CDK2_BACKEND_SELECTED_MODULE_FILES))
CDK2_BACKEND_PAYLOAD_LIBRARY_FILES_EXISTING := $(wildcard $(CDK2_BACKEND_PAYLOAD_LIBRARY_FILES))
CDK2_BACKEND_SELECTED_MODULE_FILE_STATUS = $(foreach module,$(CDK2_SELECTED_MODULES),\
  $(module)=$(if $(wildcard $(CDK2_ROOT)/$(module)),present,missing))
CDK2_BACKEND_PAYLOAD_LIBRARY_FILE_STATUS = $(foreach library,$(CDK2_PAYLOAD_LIBRARIES),\
  $(library)=$(if $(wildcard $(CDK2_ROOT)/$(library)),present,missing))
CDK2_BACKEND_BUILD_DEPS := $(CDK2_BACKEND_METADATA) $(CDK2_BACKEND_MODULE_GUIDS) \
  $(CDK2_DIR)/modules.mk $(CDK2_BACKEND_DESCRIPTOR) $(CDK2_ROOT)/UefiPayloadPkg/UefiPayloadPkg.fdf
CDK2_BACKEND_INPUTS += $(CDK2_BACKEND_MANIFEST_STATE)
CDK2_BACKEND_MANIFEST_DEPS := $(CDK2_DIR)/modules.mk $(CDK2_BACKEND_INPUTS) $(CDK2_BACKEND_CHECK_DEPS)
# FDF-owned DXE files without INF metadata must be explicit cdk2 selections.
CDK2_BACKEND_DXE_APRIORI_GUID := FC510EE7-FFDC-11D4-BD41-0080C73C8881
CDK2_BACKEND_DXE_FFS_PAD_GUID := FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF
CDK2_BACKEND_LOW_BATTERY_LOGO_GUID := BE6E1243-682C-4186-8151-448D48AFE341
CDK2_BACKEND_SECURE_BOOT_CERT_GUIDS := \
  "4E52DD60-D79E-42C5-8337-089232EA5C87 UefiPayloadPkg/UefiPayloadPkg.fdf:SecureBootDbxUpdate" \
  "73282F84-7909-4E87-ADF0-845D5DA335AB UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftUefiDb2011" \
  "9B29F606-5102-4DE1-A88A-FF6210BD8B65 UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftWindowsDb2011" \
  "C7769261-FE8D-4E15-B334-CADF4364AD92 UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftUefiDb2023" \
  "4AC66F32-6895-46FC-AD00-F1C81D06C668 UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftWindowsDb2023" \
  "73F89874-B2EC-4C28-A7E3-7D8030134E0B UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftKek2011" \
  "CCE7D8E7-AAE8-4697-B5C0-EF35A92A059F UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftKek2023" \
  "F5A81B7B-419A-4A92-8212-1C369BCBE2CB UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftOptionRomDb2023" \
  "701649DD-8739-40B9-BBDB-9CA434FDCD3B UefiPayloadPkg/UefiPayloadPkg.fdf:MicrosoftOemPk2023"
CDK2_BACKEND_SECURE_BOOT_CERT_FILES := \
  "3rdparty/secureboot_objects/PostSignedObjects/DBX/amd64/DBXUpdate.bin" \
  "3rdparty/secureboot_objects/PreSignedObjects/DB/Certificates/MicCorUEFCA2011_2011-06-27.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/DB/Certificates/MicWinProPCA2011_2011-10-19.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/DB/Certificates/microsoft uefi ca 2023.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/DB/Certificates/windows uefi ca 2023.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/KEK/Certificates/MicCorKEKCA2011_2011-06-24.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/KEK/Certificates/microsoft corporation kek 2k ca 2023.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/DB/Certificates/microsoft option rom uefi ca 2023.der" \
  "3rdparty/secureboot_objects/PreSignedObjects/PK/Certificate/WindowsOEMDevicesPK.der"
CDK2_BACKEND_REQUIRED_SUBMODULE_FILES := \
  "CryptoPkg/Library/OpensslLib/openssl/crypto/aes/aes_core.c" \
  "MdePkg/Library/BaseFdtLib/libfdt/libfdt/fdt.c"
CDK2_BACKEND_REQUIRED_SUBMODULES := \
  "CryptoPkg/Library/OpensslLib/openssl" \
  "MdePkg/Library/BaseFdtLib/libfdt"
CDK2_BACKEND_LVGL_FILES := \
  "3rdparty/LvglPkg/LvglPkg.dec" \
  "3rdparty/LvglPkg/Library/LvglLib/LvglLib.inf" \
  "3rdparty/LvglPkg/Library/LvglLib/lvgl/src/lv_init.c" \
  "3rdparty/LvglPkg/LvglDisplayEngineDxe/LvglDisplayEngineDxe.inf" \
  "3rdparty/LvglPkg/LvglSetupDxe/LvglSetupDxe.inf"

define CDK2_BACKEND_WRITE_METADATA_INPUT_STATE
$(CDK2_BACKEND_CHECK)
mkdir -p "$(dir $(CDK2_BACKEND_METADATA_INPUT_STATE))"
set -e; tmp="$(CDK2_BACKEND_METADATA_INPUT_STATE).tmp"; { \
  printf 'CDK2_SELECTED_MODULE_FILE_STATUS=%s\n' "$(CDK2_BACKEND_SELECTED_MODULE_FILE_STATUS)"; \
  printf 'CDK2_PAYLOAD_LIBRARY_FILE_STATUS=%s\n' "$(CDK2_BACKEND_PAYLOAD_LIBRARY_FILE_STATUS)"; \
} > "$$tmp"; \
if test -e "$(CDK2_BACKEND_METADATA_INPUT_STATE)" && cmp -s "$$tmp" "$(CDK2_BACKEND_METADATA_INPUT_STATE)"; then \
  rm "$$tmp"; \
else \
  mv "$$tmp" "$(CDK2_BACKEND_METADATA_INPUT_STATE)"; \
fi
endef

.PHONY: cdk2-edk2-metadata-input-state-force
cdk2-edk2-metadata-input-state-force:

$(CDK2_BACKEND_METADATA_INPUT_STATE): cdk2-edk2-metadata-input-state-force ; $(CDK2_BACKEND_WRITE_METADATA_INPUT_STATE)

$(CDK2_BACKEND_METADATA): $(CDK2_BACKEND_METADATA_INPUT_STATE) $(CDK2_MANIFEST) \
    $(CDK2_BACKEND_METADATA_TOOL) $(CDK2_BACKEND_SELECTED_MODULE_FILES_EXISTING) \
    $(CDK2_BACKEND_PAYLOAD_LIBRARY_FILES_EXISTING)
	@mkdir -p "$(dir $(CDK2_BACKEND_METADATA))"
	@$(PYTHON) "$(CDK2_BACKEND_METADATA_TOOL)" \
	  --workspace "$(CDK2_ROOT)" \
	  --arch "$(CDK2_BACKEND_BUILD_ARCH)" \
	  --module-list "$(CDK2_MANIFEST)" \
	  $(foreach library,$(CDK2_PAYLOAD_LIBRARIES),--library "$(library)") \
	  --output "$(CDK2_BACKEND_METADATA)" \
	  --guid-map "$(CDK2_BACKEND_MODULE_GUIDS)"

$(CDK2_BACKEND_MODULE_GUIDS): $(CDK2_BACKEND_METADATA)
	@test -s "$@"

.PHONY: cdk2-edk2-manifest-state-force
cdk2-edk2-manifest-state-force:

$(CDK2_BACKEND_MANIFEST_STATE): cdk2-edk2-manifest-state-force
	@mkdir -p "$(dir $@)"
	@set -e; tmp="$@.tmp"; { \
	  printf 'CONFIG_CDK2_CAPSULE=%s\n' "$(CONFIG_CDK2_CAPSULE)"; \
	  printf 'CAPSULE_MAIN_FW_GUID=%s\n' "$(CDK2_EFFECTIVE_CAPSULE_MAIN_FW_GUID)"; \
	  printf 'CDK2_SELECTED_MODULES=%s\n' "$(CDK2_SELECTED_MODULES)"; \
	} > "$$tmp"; \
	if test -e "$@" && cmp -s "$$tmp" "$@"; then rm "$$tmp"; else mv "$$tmp" "$@"; fi

define CDK2_BACKEND_BUILD
rm -rf "$(CDK2_BACKEND_BUILD_DIR)"
$(MAKE) -C "$(CDK2_ROOT)/BaseTools/cdk2" path-check \
  CDK2_BUILD_DIR="$(CDK2_BASETOOLS_BUILD_DIR)" \
  CDK2_OUTPUT_ROOT="$(CDK2_BASETOOLS_OUTPUT_ROOT)" \
  CDK2_PYTHON_STAGE_ROOT="$(CDK2_PYTHON_STAGE_ROOT)"
cd "$(CDK2_ROOT)" && \
CDK2_BACKEND_HOST_PATH="$$(printf '%s' "$$PATH" | awk -v root="$(CDK2_ROOT)/BaseTools/" 'BEGIN { RS = ":" } index($$0, root "BinWrappers/") != 1 && index($$0, root "Bin/") != 1 { printf "%s%s", sep, $$0; sep = ":" }')" && \
source edksetup.sh >/dev/null && \
$(CDK2_BACKEND_ENV) \
PATH="$(CDK2_BASETOOLS_BIN):$(CDK2_PYTHON_WRAPPER_ROOT):$(CDK2_REJECT_WRAPPER_ROOT):$$CDK2_BACKEND_HOST_PATH" \
$(CDK2_BACKEND_BUILD_COMMAND) $(foreach arch,$(CDK2_BACKEND_ARCHES),-a $(arch)) -b $(CDK2_TARGET) -t $(CDK2_BACKEND_TOOLCHAIN) \
  -p "$(CDK2_BACKEND_DESCRIPTOR)" $(CDK2_DEFINES) \
  $(CDK2_PCDS) \
  -D BUILD_ARCH=$(CDK2_BACKEND_BUILD_ARCH) \
  -D CDK2_OUTPUT_DIRECTORY=$(CDK2_BACKEND_OUTPUT_DIRECTORY)
endef

define CDK2_BACKEND_DISCOVER
awk '{ print $$2 }' "$(CDK2_BACKEND_MODULE_GUIDS)" | sort -u > "$(CDK2_BACKEND_METADATA_MODULES)" && \
printf '%s\n' $(CDK2_SELECTED_MODULES) | sort -u > "$(CDK2_BACKEND_SELECTED_MODULES)" && \
diff -u "$(CDK2_BACKEND_SELECTED_MODULES)" "$(CDK2_BACKEND_METADATA_MODULES)" || { \
  echo "cdk2 Kconfig/native metadata module closure mismatch" >&2; exit 1; \
} && \
test -s "$(CDK2_BACKEND_DXE_FV_TEXT)" && \
awk '/^0x[[:xdigit:]]+[[:space:]]+[[:xdigit:]-]+$$/ { print toupper($$2) }' \
  "$(CDK2_BACKEND_DXE_FV_TEXT)" | sort -u > "$(CDK2_BACKEND_DXE_FV_GUIDS)" && \
{ \
  awk 'NR == FNR { selected[$$0] = 1; next } \
    ($$2 in selected) && ($$2 != "$(CDK2_BACKEND_ENTRY_MODULE)") { print $$1, $$2 }' \
    "$(CDK2_BACKEND_SELECTED_MODULES)" "$(CDK2_BACKEND_MODULE_GUIDS)"; \
  printf '%s\n' \
    "$(CDK2_BACKEND_DXE_APRIORI_GUID) UefiPayloadPkg/UefiPayloadPkg.fdf:APRIORI_DXE" \
    "$(CDK2_BACKEND_LOW_BATTERY_LOGO_GUID) UefiPayloadPkg/Library/PlatformBootManagerLib/LowBatteryLogo.bmp"; \
  if [ "$(CDK2_EFFECTIVE_SECURE_BOOT)" = "y" ]; then \
    printf '%s\n' $(CDK2_BACKEND_SECURE_BOOT_CERT_GUIDS); \
  fi; \
} | sort -k2,2 > "$(CDK2_BACKEND_SELECTED_DXE_GUIDS)" && \
awk 'NR == FNR { fv[$$1] = 1; next } \
  !($$1 in fv) { print "selected cdk2 DXE GUID missing from EDK2 DXE FV: " $$1 " " $$2 > "/dev/stderr"; missing = 1 } \
  END { exit missing ? 1 : 0 }' \
  "$(CDK2_BACKEND_DXE_FV_GUIDS)" "$(CDK2_BACKEND_SELECTED_DXE_GUIDS)" || { \
  echo "cdk2 EDK2 DXE FV placement mismatch" >&2; exit 1; \
} && \
entry_guid=$$(awk -v entry="$(CDK2_BACKEND_ENTRY_MODULE)" '$$2 == entry { print toupper($$1); exit }' "$(CDK2_BACKEND_MODULE_GUIDS)") && \
awk -v entry_guid="$$entry_guid" -v pad_guid="$(CDK2_BACKEND_DXE_FFS_PAD_GUID)" 'NR == FNR { selected[$$1] = $$2; next } \
  ($$1 == entry_guid) || ($$1 == pad_guid) { next } \
  !($$1 in selected) { print "unexpected DXE FV GUID selected for cdk2 packing: " $$1 > "/dev/stderr"; unexpected = 1 } \
  END { exit unexpected ? 1 : 0 }' \
  "$(CDK2_BACKEND_SELECTED_DXE_GUIDS)" "$(CDK2_BACKEND_DXE_FV_GUIDS)" || { \
  echo "cdk2 EDK2 DXE FV contains GUIDs outside the cdk2 selected map" >&2; exit 1; \
} && \
awk '/^EFI_FILE_NAME[[:space:]]*=/ { \
  sub(/^EFI_FILE_NAME[[:space:]]*=[[:space:]]*/, ""); \
  print; \
}' "$(CDK2_BACKEND_DXE_FV_INF)" | \
awk -v entry_guid="$$entry_guid" -v pad_guid="$(CDK2_BACKEND_DXE_FFS_PAD_GUID)" '{ \
  file = $$0; base = file; sub(/^.*\//, "", base); \
  guid = toupper(substr(base, 1, 36)); \
  if ((guid != entry_guid) && (guid != pad_guid)) { print file } \
}' > "$(CDK2_BACKEND_FFS_LIST)" && \
test -s "$(CDK2_BACKEND_FFS_LIST)" && \
while IFS= read -r ffs; do \
  case "$$ffs" in \
    *.ffs|*.Ffs|*.FFS) ;; \
    *) echo "cdk2 DXE FV references non-FFS file $$ffs" >&2; exit 1 ;; \
  esac; \
  if [ ! -f "$$ffs" ]; then \
    echo "cdk2 DXE FV references missing FFS file $$ffs" >&2; \
    exit 1; \
  fi; \
done < "$(CDK2_BACKEND_FFS_LIST)" && \
dups=$$(sort "$(CDK2_BACKEND_FFS_LIST)" | uniq -d) && \
if [ -n "$$dups" ]; then \
  echo "cdk2 DXE FV references duplicate FFS files:" >&2; \
  printf '%s\n' "$$dups" >&2; \
  exit 1; \
fi && \
{ \
  printf '%s\n' '# cdk2 native fvpack manifest'; \
  printf '%s\n' '# Format: FILE <reference-dxe-fv-offset> <file-guid> <ffs-path>'; \
  printf '%s\n' 'VERSION 1'; \
  awk -v entry_guid="$$entry_guid" -v pad_guid="$(CDK2_BACKEND_DXE_FFS_PAD_GUID)" 'NR == FNR { \
    file = $$0; base = file; sub(/^.*\//, "", base); \
    guid = toupper(substr(base, 1, 36)); \
    if (guid in path) { \
      print "duplicate FFS manifest path for GUID: " guid > "/dev/stderr"; \
      failed = 1; next; \
    } \
    path[guid] = file; next; \
  } \
  /^0x[[:xdigit:]]+[[:space:]]+[[:xdigit:]-]+$$/ { \
    guid = toupper($$2); \
    if ((guid == entry_guid) || (guid == pad_guid)) { next } \
    if (!(guid in path)) { \
      print "ordered DXE FV GUID missing FFS path: " guid > "/dev/stderr"; \
      failed = 1; next; \
    } \
    found[guid] = 1; \
    print "FILE", $$1, guid, path[guid]; \
  } \
  END { \
    for (guid in path) { \
      if (!(guid in found)) { \
        print "FFS path missing from ordered DXE FV manifest: " guid > "/dev/stderr"; \
        failed = 1; \
      } \
    } \
    exit failed ? 1 : 0; \
  }' "$(CDK2_BACKEND_FFS_LIST)" "$(CDK2_BACKEND_DXE_FV_TEXT)"; \
} > "$(CDK2_BACKEND_DXE_MANIFEST)"
endef

# The generic cdk2 build only asks a backend for a completed payload. Keep
# descriptor reports, FFS discovery, and the EDK II-to-flat-FV conversion
# together so a future native backend can replace this contract as one unit.
define CDK2_BACKEND_ASSEMBLE
$(CDK2_BACKEND_DISCOVER)
test -s "$(CDK2_BACKEND_ENTRY_IMAGE)"
test -s "$(CDK2_BACKEND_DXE_FV)"
test -s "$(CDK2_BACKEND_FFS_LIST)"
test -s "$(CDK2_BACKEND_DXE_MANIFEST)"
$(CDK2_NATIVE_PACKER) --verify-dxe-manifest \
  --dxe-manifest "$(CDK2_BACKEND_DXE_MANIFEST)" \
  --reference-dxe-fv "$(CDK2_BACKEND_DXE_FV)"
$(CDK2_NATIVE_PACKER) --output "$(CDK2_OUTPUT)" \
  --entry-efi "$(CDK2_BACKEND_ENTRY_IMAGE)" \
  --dxe-manifest "$(CDK2_BACKEND_DXE_MANIFEST)" \
  --flatten-dxe \
  --size 0xa00000
endef

define CDK2_BACKEND_CHECK
if test "$(CDK2_EFFECTIVE_CAPSULE)" = "y" && test -z "$(strip $(CDK2_EFFECTIVE_CAPSULE_MAIN_FW_GUID))"; then \
  echo "CONFIG_CDK2_CAPSULE requires CONFIG_CDK2_CAPSULE_MAIN_FW_GUID or a CAPSULE_MAIN_FW_GUID override" >&2; exit 1; \
fi
if git -C "$(CDK2_ROOT)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
  for submodule in $(CDK2_BACKEND_REQUIRED_SUBMODULES); do \
    submodule_status=$$(git -C "$(CDK2_ROOT)" submodule status -- "$$submodule" 2>/dev/null || true); \
    case "$$submodule_status" in \
      -*) echo "missing required cdk2 EDK2 submodule: $$submodule" >&2; exit 1 ;; \
      +*) echo "stale required cdk2 EDK2 submodule: $$submodule" >&2; exit 1 ;; \
    esac; \
  done; \
fi
for object in $(CDK2_BACKEND_REQUIRED_SUBMODULE_FILES); do \
  test -f "$(CDK2_ROOT)/$$object" || { \
    echo "missing required cdk2 EDK2 submodule file: $$object" >&2; \
    echo "run: git submodule update --init --checkout" >&2; \
    exit 1; \
  }; \
done
if test "$(CDK2_EFFECTIVE_LVGL)" = "y"; then \
  if git -C "$(CDK2_ROOT)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
    submodule_status=$$(git -C "$(CDK2_ROOT)" submodule status -- 3rdparty/LvglPkg 2>/dev/null || true); \
    case "$$submodule_status" in \
      -*) echo "missing LVGL submodule: 3rdparty/LvglPkg" >&2; exit 1 ;; \
      +*) echo "stale LVGL submodule: 3rdparty/LvglPkg" >&2; exit 1 ;; \
    esac; \
  fi; \
  for object in $(CDK2_BACKEND_LVGL_FILES); do \
    test -f "$(CDK2_ROOT)/$$object" || { \
      echo "missing LVGL module file: $$object" >&2; \
      echo "run: git submodule update --init --checkout --recursive 3rdparty/LvglPkg" >&2; \
      exit 1; \
    }; \
  done; \
fi
if test "$(CDK2_EFFECTIVE_SECURE_BOOT)" = "y"; then \
  if git -C "$(CDK2_ROOT)" rev-parse --is-inside-work-tree >/dev/null 2>&1; then \
    submodule_status=$$(git -C "$(CDK2_ROOT)" submodule status -- 3rdparty/secureboot_objects 2>/dev/null || true); \
    case "$$submodule_status" in \
      -*) echo "missing Secure Boot default-key submodule: 3rdparty/secureboot_objects" >&2; exit 1 ;; \
      +*) echo "stale Secure Boot default-key submodule: 3rdparty/secureboot_objects" >&2; exit 1 ;; \
    esac; \
  fi; \
  for object in $(CDK2_BACKEND_SECURE_BOOT_CERT_FILES); do \
    test -f "$(CDK2_ROOT)/$$object" || { \
      echo "missing Secure Boot default-key object: $$object" >&2; \
      echo "run: git submodule update --init --checkout 3rdparty/secureboot_objects" >&2; \
      exit 1; \
    }; \
  done; \
fi
for module in $(CDK2_RETAINED_MODULES) $(CDK2_PAYLOAD_LIBRARIES); do \
  test -f "$(CDK2_ROOT)/$$module" || { echo "missing backend module: $$module" >&2; exit 1; }; \
done
for module in $(CDK2_SELECTED_MODULES); do \
  test -f "$(CDK2_ROOT)/$$module" || { echo "missing selected backend module: $$module" >&2; exit 1; }; \
  grep -Fq "$$module" "$(CDK2_BACKEND_DESCRIPTOR)" || { \
    echo "selected backend module not referenced by descriptor: $$module" >&2; exit 1; \
  }; \
done
grep -q '^CONFIG_CDK2_PAYLOAD=y' "$(CDK2_CONFIG)"
printf '%s\n' "cdk2 retained backend inventory: $(words $(CDK2_RETAINED_MODULES)) INF modules"
printf '%s\n' "cdk2 selected backend module set: $(words $(CDK2_SELECTED_MODULES)) INF modules"
endef

define CDK2_BACKEND_WRITE_MANIFEST
mkdir -p "$(dir $(CDK2_MANIFEST))"
set -e; tmp="$(CDK2_MANIFEST).tmp"; { \
  printf '%s\n' '# Resolved cdk2 backend module set'; \
  printf '%s\n' '# Generated from Kconfig; do not edit.'; \
  for module in $(CDK2_SELECTED_MODULES); do \
    if test "$$module" = "$(CDK2_CAPSULE_FMP_DXE_MODULE)" && test "$(CDK2_EFFECTIVE_CAPSULE)" = "y"; then \
      printf '%s FILE_GUID=%s\n' "$$module" "$(CDK2_EFFECTIVE_CAPSULE_MAIN_FW_GUID)"; \
    else \
      printf '%s\n' "$$module"; \
    fi; \
  done; \
} > "$$tmp"; mv "$$tmp" "$(CDK2_MANIFEST)"
printf '%s\n' "cdk2 backend module manifest: $(CDK2_MANIFEST)"
endef

define CDK2_BACKEND_PRINT_MODULES
printf '%s\n' $(CDK2_SELECTED_MODULES)
endef

define CDK2_BACKEND_WRITE_LINK_MANIFEST
{ \
  find "$(CDK2_BACKEND_BUILD_DIR)" -type f -name '*.map' -printf '%p\n'; \
  for map in $(CDK2_NATIVE_DIRECT_LINK_MAPS); do \
    test ! -s "$$map" || printf '%s\n' "$$map"; \
  done; \
} | sort > "$(CDK2_LINK_MANIFEST)"
printf '%s\n' "cdk2 link manifest: $(CDK2_LINK_MANIFEST)"
endef

define CDK2_BACKEND_CLEAN
rm -rf "$(CDK2_BACKEND_OUTPUT_ROOT)"
endef
