/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Bounds-checked firmware-volume discovery for native cdk2.
 */

#ifndef CDK2_NATIVE_FV_H_
#define CDK2_NATIVE_FV_H_

#include <uefi.h>
#include <pi/firmware_file.h>
#include <pi/firmware_volume.h>

struct cdk2_native_dxe_core {
	const EFI_FIRMWARE_VOLUME_HEADER *volume;
	const EFI_FFS_FILE_HEADER *dxe_core_file;
	const void *pe32_image;
	UINTN pe32_size;
	UINTN volume_size;
};

EFI_STATUS
cdk2_native_find_dxe_core(const void *firmware_volume, UINTN firmware_volume_size,
			  struct cdk2_native_dxe_core *dxe_core);

#endif
