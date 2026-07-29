## SPDX-License-Identifier: BSD-2-Clause-Patent

# EDK II backend for cdk2. This is deliberately isolated from the Kconfig,
# native-stage, and image-packaging rules so a native backend can replace it.

CDK2_BACKEND_NAME := edk2
CDK2_BACKEND_SUPPORTED_INTERFACE_VERSION := 1
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

# These are EDK II build definitions, not cdk2 policy. Keep their translation
# behind the backend so a native linker can consume the same Kconfig values
# without carrying BaseTools-specific command-line names.
CDK2_DEFAULT_DEFINES := \
  -D BOOTLOADER=COREBOOT \
  -D UNIVERSAL_PAYLOAD=FALSE \
  -D UNIVERSAL_PAYLOAD_FORMAT=ELF \
  -D MEMORY_TEST=NULL \
  -D NETWORK_DRIVER_ENABLE=FALSE \
  -D DISABLE_RESET_SYSTEM=FALSE \
  -D BOOTSPLASH_IMAGE=FALSE \
  -D SECURITY_STUB_ENABLE=TRUE \
  -D PS2_KEYBOARD_ENABLE=FALSE \
  -D SIO_BUS_ENABLE=FALSE

CDK2_DEFINES := $(CDK2_DEFAULT_DEFINES)
CDK2_CAPSULE_MAIN_FW_GUID := $(patsubst "%",%,$(strip $(CONFIG_CDK2_CAPSULE_MAIN_FW_GUID)))
CDK2_CAPSULE_MAIN_FW_GUID_OVERRIDE := $(findstring CAPSULE_MAIN_FW_GUID,$(CDK2_EXTRA_DEFINES))

# cdk2 owns the final outer volume and exposes the retained DXE files directly
# so the entry path does not have to discover and unwrap a nested FV image.
CDK2_DEFINES += -D CDK2_FLAT_DXE_FV=TRUE

ifeq ($(CONFIG_CDK2_SHELL),y)
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
  PS2_MOUSE:PS2_MOUSE_ENABLE \
  CBMEM_CONSOLE:USE_CBMEM_FOR_CONSOLE \
  CBMEM_TIMESTAMPS:CBMEM_TIMESTAMPS \
  CPU_TIMER:CPU_TIMER_LIB_ENABLE \
  LATE_LINK:CDK2_LATE_LINK

define CDK2_ADD_BOOL_DEFINE
ifeq ($(CONFIG_CDK2_$(word 1,$(subst :, ,$(1)))),y)
CDK2_DEFINES += -D $(word 2,$(subst :, ,$(1)))=TRUE
else
CDK2_DEFINES += -D $(word 2,$(subst :, ,$(1)))=FALSE
endif
endef

$(foreach map,$(CDK2_BOOL_DEFINES),$(eval $(call CDK2_ADD_BOOL_DEFINE,$(map))))

ifeq ($(CONFIG_CDK2_SMMSTORE),y)
CDK2_DEFINES += -D VARIABLE_SUPPORT=SMMSTORE
else
CDK2_DEFINES += -D VARIABLE_SUPPORT=EMU
endif

ifeq ($(CONFIG_CDK2_CAPSULE),y)
ifneq ($(strip $(CDK2_CAPSULE_MAIN_FW_GUID)),)
CDK2_DEFINES += -D CAPSULE_MAIN_FW_GUID=$(CDK2_CAPSULE_MAIN_FW_GUID)
endif
endif

ifneq ($(filter y,$(CONFIG_CDK2_TPM12) $(CONFIG_CDK2_TPM2)),)
CDK2_DEFINES += -D TPM_ENABLE=TRUE
else
CDK2_DEFINES += -D TPM_ENABLE=FALSE
endif

ifeq ($(CONFIG_CDK2_SERIAL),y)
CDK2_DEFINES += -D SERIAL_DRIVER_ENABLE=TRUE -D DISABLE_SERIAL_TERMINAL=FALSE
else
CDK2_DEFINES += -D SERIAL_DRIVER_ENABLE=FALSE -D DISABLE_SERIAL_TERMINAL=TRUE
endif

CDK2_DEFINES += -D PLATFORM_BOOT_TIMEOUT=$(CONFIG_CDK2_BOOT_TIMEOUT)

# Command-line overrides are deliberately last, so QEMU and board-specific
# test configurations can change one setting without copying defconfig.
CDK2_DEFINES += $(CDK2_EXTRA_DEFINES)

CDK2_BACKEND_DESCRIPTOR := $(CDK2_ROOT)/UefiPayloadPkg/UefiPayloadPkg.dsc
CDK2_BACKEND_BUILD_DIR := $(CDK2_ROOT)/$(CDK2_BACKEND_OUTPUT_DIRECTORY)/$(CDK2_TARGET)_$(CDK2_BACKEND_TOOLCHAIN)
CDK2_BACKEND_REPORT := $(CDK2_BUILD_DIR)/UefiPayloadPkg.txt
CDK2_BACKEND_ENTRY_MODULE := UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry.inf
CDK2_BACKEND_ENTRY_IMAGE := $(CDK2_BACKEND_BUILD_DIR)/$(CDK2_BACKEND_ENTRY_ARCH)/UefiPayloadPkg/cdk2/backend/edk2/entry/UefiPayloadEntry/OUTPUT/PayloadEntry.efi
CDK2_BACKEND_DXE_FV := $(CDK2_BACKEND_BUILD_DIR)/FV/DXEFV.Fv
CDK2_BACKEND_DXE_FV_TEXT := $(CDK2_BACKEND_DXE_FV).txt
CDK2_BACKEND_FFS_LIST := $(CDK2_BUILD_DIR)/cdk2-dxe-ffs.txt
CDK2_BACKEND_REPORT_MODULES := $(CDK2_BUILD_DIR)/cdk2-report-modules.txt
CDK2_BACKEND_SELECTED_MODULES := $(CDK2_BUILD_DIR)/cdk2-selected-modules.txt
CDK2_BACKEND_REPORT_GUIDS := $(CDK2_BUILD_DIR)/cdk2-report-guids.txt
CDK2_BACKEND_DXE_FV_GUIDS := $(CDK2_BUILD_DIR)/cdk2-dxe-fv-guids.txt
CDK2_BACKEND_SELECTED_DXE_GUIDS := $(CDK2_BUILD_DIR)/cdk2-selected-dxe-guids.txt

define CDK2_BACKEND_BUILD
rm -rf "$(CDK2_BACKEND_BUILD_DIR)"
cd "$(CDK2_ROOT)" && \
source edksetup.sh >/dev/null && \
$(CDK2_BACKEND_BUILD_COMMAND) $(foreach arch,$(CDK2_BACKEND_ARCHES),-a $(arch)) -b $(CDK2_TARGET) -t $(CDK2_BACKEND_TOOLCHAIN) \
  -p "$(CDK2_BACKEND_DESCRIPTOR)" $(CDK2_DEFINES) \
  -D BUILD_ARCH=$(CDK2_BACKEND_BUILD_ARCH) \
  -D CDK2_OUTPUT_DIRECTORY=$(CDK2_BACKEND_OUTPUT_DIRECTORY) \
  -y "$(CDK2_BACKEND_REPORT)"
endef

define CDK2_BACKEND_DISCOVER
awk -F ':' '/^Module INF Path:/ { sub(/^[[:space:]]+/, "", $$2); print $$2 }' \
  "$(CDK2_BACKEND_REPORT)" | sort -u > "$(CDK2_BACKEND_REPORT_MODULES)" && \
printf '%s\n' $(CDK2_SELECTED_MODULES) | sort -u > "$(CDK2_BACKEND_SELECTED_MODULES)" && \
diff -u "$(CDK2_BACKEND_SELECTED_MODULES)" "$(CDK2_BACKEND_REPORT_MODULES)" || { \
  echo "cdk2 Kconfig/EDK2 module closure mismatch" >&2; exit 1; \
} && \
test -s "$(CDK2_BACKEND_DXE_FV_TEXT)" && \
awk -F ': *' '/^Module INF Path:/ { module = $$2; next } /^File GUID:/ { print toupper($$2), module }' \
  "$(CDK2_BACKEND_REPORT)" | sort -k2,2 > "$(CDK2_BACKEND_REPORT_GUIDS)" && \
awk '/^0x[[:xdigit:]]+[[:space:]]+[[:xdigit:]-]+$$/ { print toupper($$2) }' \
  "$(CDK2_BACKEND_DXE_FV_TEXT)" | sort -u > "$(CDK2_BACKEND_DXE_FV_GUIDS)" && \
awk 'NR == FNR { selected[$$0] = 1; next } \
  ($$2 in selected) && ($$2 != "$(CDK2_BACKEND_ENTRY_MODULE)") { print $$1, $$2 }' \
  "$(CDK2_BACKEND_SELECTED_MODULES)" "$(CDK2_BACKEND_REPORT_GUIDS)" | sort -k2,2 > "$(CDK2_BACKEND_SELECTED_DXE_GUIDS)" && \
awk 'NR == FNR { fv[$$1] = 1; next } \
  !($$1 in fv) { print "selected backend module missing from DXE FV: " $$2; missing = 1 } \
  END { exit missing ? 1 : 0 }' \
  "$(CDK2_BACKEND_DXE_FV_GUIDS)" "$(CDK2_BACKEND_SELECTED_DXE_GUIDS)" || { \
  echo "cdk2 EDK2 DXE FV placement mismatch" >&2; exit 1; \
} && \
find "$(CDK2_BACKEND_BUILD_DIR)/FV/Ffs" -type f -iname '*.ffs' -print | sort | \
awk 'NR == FNR { dxe[$$1] = 1; next } \
  { \
    file = $$NF; \
    sub(/^.*\//, "", file); \
    guid = toupper(substr(file, 1, 36)); \
    if (guid in dxe) { \
      if (guid in found) { \
        print "duplicate DXE FV FFS: " guid > "/dev/stderr"; \
        failed = 1; next; \
      } \
      found[guid] = 1; print $$0; \
    } \
  } \
  END { \
    for (guid in dxe) { \
      if (!(guid in found)) { \
        print "DXE FV FFS missing from build output: " guid > "/dev/stderr"; \
        failed = 1; \
      } \
    } \
    exit failed ? 1 : 0; \
  }' "$(CDK2_BACKEND_DXE_FV_GUIDS)" - > "$(CDK2_BACKEND_FFS_LIST)"
endef

# The generic cdk2 build only asks a backend for a completed payload. Keep
# descriptor reports, FFS discovery, and the EDK II-to-flat-FV conversion
# together so a future native backend can replace this contract as one unit.
define CDK2_BACKEND_ASSEMBLE
$(CDK2_BACKEND_DISCOVER)
test -s "$(CDK2_BACKEND_ENTRY_IMAGE)"
test -s "$(CDK2_BACKEND_DXE_FV)"
test -s "$(CDK2_BACKEND_FFS_LIST)"
$(CDK2_NATIVE_PACKER) --output "$(CDK2_OUTPUT)" \
  --entry-efi "$(CDK2_BACKEND_ENTRY_IMAGE)" \
  --dxe-fv "$(CDK2_BACKEND_DXE_FV)" \
  --dxe-ffs-list "$(CDK2_BACKEND_FFS_LIST)" \
  --flatten-dxe \
  --size 0xa00000
$(CDK2_BACKEND_WRITE_LINK_MANIFEST)
endef

define CDK2_BACKEND_CHECK
if test "$(CONFIG_CDK2_CAPSULE)" = "y" && test -z "$(strip $(CDK2_CAPSULE_MAIN_FW_GUID)$(CDK2_CAPSULE_MAIN_FW_GUID_OVERRIDE))"; then \
  echo "CONFIG_CDK2_CAPSULE requires CONFIG_CDK2_CAPSULE_MAIN_FW_GUID or a CAPSULE_MAIN_FW_GUID override" >&2; exit 1; \
fi
for module in $(CDK2_RETAINED_MODULES) $(CDK2_PAYLOAD_LIBRARIES); do \
  test -f "$(CDK2_ROOT)/$$module" || { echo "missing backend module: $$module" >&2; exit 1; }; \
done
for module in $(CDK2_SELECTED_MODULES); do \
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
{ \
  printf '%s\n' '# Resolved cdk2 backend module set'; \
  printf '%s\n' '# Generated from Kconfig; do not edit.'; \
  printf '%s\n' $(CDK2_SELECTED_MODULES); \
} > "$(CDK2_MANIFEST)"
printf '%s\n' "cdk2 backend module manifest: $(CDK2_MANIFEST)"
endef

define CDK2_BACKEND_PRINT_MODULES
printf '%s\n' $(CDK2_SELECTED_MODULES)
endef

define CDK2_BACKEND_WRITE_LINK_MANIFEST
find "$(CDK2_BACKEND_BUILD_DIR)" -type f -name '*.map' -printf '%p\n' | sort > "$(CDK2_LINK_MANIFEST)"
endef

define CDK2_BACKEND_CLEAN
rm -rf "$(CDK2_ROOT)/$(CDK2_BACKEND_OUTPUT_DIRECTORY)"
endef
