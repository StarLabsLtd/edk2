/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 entry services shared by the freestanding stage and UEFI entry.
 */

#ifndef CDK2_NATIVE_SERVICES_API_H_
#define CDK2_NATIVE_SERVICES_API_H_

#include <uefi.h>
#include <pi/boot_mode.h>
#include <pi/hob.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CDK2_NATIVE_HOB_BUFFER_SIZE 0x1000U

struct cdk2_native_context;

typedef EFI_HOB_HANDOFF_INFO_TABLE efi_hob_handoff_info_table_t;
typedef EFI_PHYSICAL_ADDRESS efi_physical_address_t;
typedef UINTN efi_uintn_t;

enum cdk2_native_image {
	cdk2_native_image_dxe_core,
	cdk2_native_image_payload_entry,
	cdk2_native_image_max
};

typedef efi_hob_handoff_info_table_t *cdk2_native_construct_hobs_fn_t(
	void *efi_memory_bottom, void *efi_memory_top, void *efi_free_memory_bottom,
	void *efi_free_memory_top);
typedef EFI_STATUS cdk2_native_context_fn_t(struct cdk2_native_context *context);
typedef EFI_STATUS cdk2_native_build_platform_hobs_fn_t(struct cdk2_native_context *context,
							void **handoff);
typedef EFI_STATUS cdk2_native_find_hob_memory_fn_t(struct cdk2_native_context *context,
						    efi_uintn_t *hob_mem_base);
typedef EFI_STATUS cdk2_native_load_dxe_core_fn_t(struct cdk2_native_context *context,
						  efi_physical_address_t *entry_point,
						  efi_physical_address_t *image_base,
						  efi_uintn_t *image_size);
typedef EFI_STATUS cdk2_native_load_image_fn_t(struct cdk2_native_context *context,
					       enum cdk2_native_image image,
					       efi_physical_address_t *entry_point);
typedef EFI_STATUS cdk2_native_initialize_context_fn_t(struct cdk2_native_context *context,
						       UINTN bootloader_parameter);

struct cdk2_native_ops {
	cdk2_native_construct_hobs_fn_t *construct_hobs;
	cdk2_native_build_platform_hobs_fn_t *build_platform_hobs;
	cdk2_native_context_fn_t *populate_hobs;
	cdk2_native_context_fn_t *build_serial_hob;
	cdk2_native_context_fn_t *apply_boot_mode;
	cdk2_native_context_fn_t *initialize_libraries;
	cdk2_native_context_fn_t *set_bootloader_parameter;
	cdk2_native_find_hob_memory_fn_t *find_hob_memory;
	cdk2_native_context_fn_t *initialize_floating_point;
	cdk2_native_context_fn_t *mask_legacy_interrupts;
	cdk2_native_load_dxe_core_fn_t *load_dxe_core;
	cdk2_native_context_fn_t *transfer;
};

struct cdk2_native_services {
	cdk2_native_context_fn_t *build_hobs;
	cdk2_native_context_fn_t *populate_hobs;
	cdk2_native_context_fn_t *build_serial_hob;
	cdk2_native_context_fn_t *apply_boot_mode;
	cdk2_native_context_fn_t *initialize_libraries;
	cdk2_native_context_fn_t *set_bootloader_parameter;
	cdk2_native_find_hob_memory_fn_t *find_hob_memory;
	cdk2_native_context_fn_t *initialize_floating_point;
	cdk2_native_context_fn_t *mask_legacy_interrupts;
	cdk2_native_load_image_fn_t *load_image;
	cdk2_native_context_fn_t *handoff;
};

struct cdk2_native_context {
	UINTN bootloader_parameter;
	EFI_PHYSICAL_ADDRESS payload_base;
	UINTN payload_size;
	void *hob_list;
	UINTN hob_list_size;
	EFI_PHYSICAL_ADDRESS image_base;
	UINTN image_size;
	EFI_PHYSICAL_ADDRESS image_entry_point;
	void *hob_memory_bottom;
	void *hob_memory_top;
	void *hob_free_memory_bottom;
	void *hob_free_memory_top;
	UINTN hob_region_size;
	EFI_PHYSICAL_ADDRESS allocation_bottom;
	EFI_PHYSICAL_ADDRESS allocation_top;
	struct cdk2_native_ops ops;
	struct cdk2_native_services services;
};

EFI_STATUS
EFIAPI
cdk2_native_initialize_services(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_initialize_stage_context(struct cdk2_native_context *context,
				     UINTN bootloader_parameter);

EFI_STATUS
EFIAPI
cdk2_native_validate_ops(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_payload_entry(UINTN bootloader_parameter,
			  cdk2_native_initialize_context_fn_t initialize_context);

EFI_STATUS
EFIAPI
cdk2_native_run_entry(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_build_hobs(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_populate_hobs(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_build_serial_hob(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_apply_boot_mode(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_initialize_libraries(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_set_bootloader_parameter(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_find_hob_memory(struct cdk2_native_context *context, UINTN *hob_mem_base);

EFI_STATUS
EFIAPI
cdk2_native_initialize_floating_point(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_mask_legacy_interrupts(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_prepare_entry(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_load_image(struct cdk2_native_context *context, enum cdk2_native_image image,
		       EFI_PHYSICAL_ADDRESS *entry_point);

EFI_STATUS
EFIAPI
cdk2_native_allocate_pages(struct cdk2_native_context *context, UINTN pages,
			   EFI_PHYSICAL_ADDRESS *base);

EFI_STATUS
EFIAPI
cdk2_native_handoff(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_transfer(struct cdk2_native_context *context);

EFI_STATUS
EFIAPI
cdk2_native_adopt_hob_list(struct cdk2_native_context *context,
			   efi_hob_handoff_info_table_t *handoff);

EFI_STATUS
EFIAPI
cdk2_native_validate_entry(struct cdk2_native_context *context,
			   efi_hob_handoff_info_table_t *handoff,
			   EFI_PHYSICAL_ADDRESS image_base,
			   UINTN image_size, EFI_PHYSICAL_ADDRESS image_entry_point);

#ifdef __cplusplus
}
#endif

#endif
