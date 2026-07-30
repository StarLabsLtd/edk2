## SPDX-License-Identifier: BSD-2-Clause-Patent

# Compatibility name for the original prebuilt-FV backend.  Keep existing
# callers working while the shorter native backend name becomes the canonical
# coreboot-style C/Make/linker interface.

include $(CDK2_DIR)/native-backend.mk

CDK2_BACKEND_NAME := native-fv
