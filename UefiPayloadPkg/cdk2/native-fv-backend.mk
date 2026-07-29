## SPDX-License-Identifier: BSD-2-Clause-Patent

# Native cdk2 backend for a previously-built flat payload FV.  This is the
# coreboot-facing path: the EDK II backend may produce the FV elsewhere, but
# this backend only validates and embeds it with the native C/linker stage.

CDK2_BACKEND_NAME := native-fv
CDK2_BACKEND_SUPPORTED_INTERFACE_VERSION := 1
CDK2_BACKEND_CHECK_DEPS := $(CDK2_NATIVE_FV_TEST)
CDK2_BACKEND_ARCHES := X64
CDK2_BACKEND_BUILD_ARCH := X64
CDK2_BACKEND_ENTRY_ARCH := X64
CDK2_BACKEND_INPUTS :=
CDK2_BACKEND_DESCRIPTOR :=
CDK2_BACKEND_BUILD_DIR :=
CDK2_BACKEND_ENTRY_IMAGE :=
CDK2_BACKEND_DXE_FV :=
CDK2_BACKEND_FFS_LIST :=
CDK2_SELECTED_MODULES :=
CDK2_RETAINED_MODULES :=
CDK2_PAYLOAD_LIBRARIES :=

ifneq ($(strip $(CDK2_PAYLOAD_FV)),)
CDK2_PAYLOAD_FV := $(abspath $(CDK2_PAYLOAD_FV))
CDK2_BACKEND_INPUTS := $(CDK2_PAYLOAD_FV)
endif

ifeq ($(strip $(CDK2_PAYLOAD_FV)),)
$(error CDK2_BACKEND=native-fv requires CDK2_PAYLOAD_FV=/path/to/flat-payload-fv)
endif

ifneq ($(CONFIG_CDK2_NATIVE_STAGE),y)
$(error CDK2_BACKEND=native-fv requires CONFIG_CDK2_NATIVE_STAGE=y)
endif

ifneq ($(abspath $(CDK2_PAYLOAD_FV)),$(abspath $(CDK2_OUTPUT)))
else
$(error CDK2_PAYLOAD_FV must not be the same path as CDK2_OUTPUT)
endif

define CDK2_BACKEND_BUILD
test -s "$(CDK2_PAYLOAD_FV)" || { echo "missing native cdk2 payload FV: $(CDK2_PAYLOAD_FV)" >&2; exit 1; }
"$(CDK2_NATIVE_FV_TEST)" "$(CDK2_PAYLOAD_FV)"
mkdir -p "$(dir $(CDK2_OUTPUT))"
install -m 0644 "$(CDK2_PAYLOAD_FV)" "$(CDK2_OUTPUT)"
endef

define CDK2_BACKEND_ASSEMBLE
:
endef

define CDK2_BACKEND_CHECK
test -s "$(CDK2_PAYLOAD_FV)" || { echo "missing native cdk2 payload FV: $(CDK2_PAYLOAD_FV)" >&2; exit 1; }
"$(CDK2_NATIVE_FV_TEST)" "$(CDK2_PAYLOAD_FV)"
grep -q '^CONFIG_CDK2_PAYLOAD=y' "$(CDK2_CONFIG)"
endef

define CDK2_BACKEND_CLEAN
:
endef

define CDK2_BACKEND_WRITE_MANIFEST
mkdir -p "$(dir $(CDK2_MANIFEST))"
set -e; tmp="$(CDK2_MANIFEST).tmp"; { \
  printf '%s\n' '# Native cdk2 prebuilt-FV backend'; \
  printf '%s\n' '# No EDK II module or Python/BaseTools closure is used here.'; \
  printf 'payload-fv=%s\n' "$(CDK2_PAYLOAD_FV)"; \
} > "$$tmp"; mv "$$tmp" "$(CDK2_MANIFEST)"
printf '%s\n' "cdk2 native-FV manifest: $(CDK2_MANIFEST)"
endef

define CDK2_BACKEND_WRITE_LINK_MANIFEST
{ \
  for map in $(CDK2_NATIVE_DIRECT_LINK_MAPS); do \
    test ! -s "$$map" || printf '%s\n' "$$map"; \
  done; \
} | sort -u > "$(CDK2_LINK_MANIFEST)"
printf '%s\n' "cdk2 native link manifest: $(CDK2_LINK_MANIFEST)"
endef

define CDK2_BACKEND_PRINT_MODULES
printf '%s\n' '# native-fv consumes a prebuilt flat FV; no EDK II modules are built'
endef
