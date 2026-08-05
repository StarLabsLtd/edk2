/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Freestanding HOB construction from a validated coreboot handoff.
 */

#ifndef CDK2_NATIVE_COREBOOT_HOBS_H_
#define CDK2_NATIVE_COREBOOT_HOBS_H_

#include <uefi.h>
#include <pi/boot_mode.h>
#include <pi/hob.h>

#include "coreboot.h"

#define CDK2_COREBOOT_TEMP_MAP_LIMIT (0x2000000000ULL)

EFI_STATUS
cdk2_coreboot_build_hobs(const struct cdk2_coreboot_handoff *coreboot, void *efi_memory_bottom,
			 void *efi_memory_top, void *efi_free_memory_bottom,
			 void *efi_free_memory_top, BOOLEAN capsule_support_enabled,
			 void **handoff);

EFI_STATUS
cdk2_coreboot_find_hob_memory_base(const struct cdk2_coreboot_handoff *coreboot,
				   EFI_PHYSICAL_ADDRESS payload_base, UINTN payload_size,
				   UINTN hob_region_size, UINT64 temporary_map_limit,
				   UINTN *hob_mem_base);

EFI_STATUS
cdk2_coreboot_append_fv_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
			    EFI_PHYSICAL_ADDRESS base_address, UINT64 length);

EFI_STATUS
cdk2_coreboot_append_capsule_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				 EFI_PHYSICAL_ADDRESS base_address, UINT64 length);

EFI_STATUS
cdk2_coreboot_append_guid_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff, const EFI_GUID *guid,
			      const void *data, UINTN data_length);

EFI_STATUS
cdk2_coreboot_append_memory_allocation_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
					   EFI_PHYSICAL_ADDRESS base_address, UINT64 length,
					   EFI_MEMORY_TYPE memory_type);

EFI_STATUS
cdk2_coreboot_append_stack_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
			       EFI_PHYSICAL_ADDRESS base_address, UINT64 length);

EFI_STATUS
cdk2_coreboot_append_cpu_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff, UINT8 size_of_memory_space,
			     UINT8 size_of_io_space);

EFI_STATUS
cdk2_coreboot_append_module_hob(EFI_HOB_HANDOFF_INFO_TABLE *handoff,
				const EFI_GUID *module_name, EFI_PHYSICAL_ADDRESS base_address,
				UINT64 length, EFI_PHYSICAL_ADDRESS entry_point);

#endif
