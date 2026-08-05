/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Bounded PE32+ loading for native cdk2.
 */

#ifndef CDK2_NATIVE_PE_H_
#define CDK2_NATIVE_PE_H_

#include <uefi.h>
#include <industry_standard/pe_image.h>

EFI_STATUS
cdk2_native_load_pe32_plus(const void *image, unsigned long long image_size,
			   unsigned long long destination, unsigned long long destination_size,
			   unsigned long long *loaded_base, unsigned long long *loaded_size,
			   unsigned long long *entry_point);

#endif
