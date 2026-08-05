/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Native cdk2 HOB, image-range, and handoff services.
 *
 * These services deliberately stop short of transferring control. They make
 * the native boundary validate the same invariants before the existing UEFI
 * entry path is replaced.
 */

#include <uefi.h>
#include <pi/boot_mode.h>
#include <pi/hob.h>
#include <library/cdk2_platform_lib.h>

#include "services.h"

static UINT8 m_cdk2_native_hob_storage[CDK2_NATIVE_HOB_BUFFER_SIZE] __aligned(8);

static BOOLEAN cdk2_native_range_contains(EFI_PHYSICAL_ADDRESS base, UINTN size,
					  EFI_PHYSICAL_ADDRESS address)
{
	EFI_PHYSICAL_ADDRESS end;

	if (size == 0 || base > MAX_UINT64 - size) {
		return FALSE;
	}

	end = base + size;
	return address >= base && address < end;
}

static void cdk2_native_clear_image_state(struct cdk2_native_context *context)
{
	context->image_base = 0;
	context->image_size = 0;
	context->image_entry_point = 0;
}

EFI_STATUS
EFIAPI
cdk2_native_initialize_services(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	context->services.build_hobs = cdk2_native_build_hobs;
	context->services.populate_hobs = cdk2_native_populate_hobs;
	context->services.build_serial_hob = cdk2_native_build_serial_hob;
	context->services.apply_boot_mode = cdk2_native_apply_boot_mode;
	context->services.initialize_libraries = cdk2_native_initialize_libraries;
	context->services.set_bootloader_parameter = cdk2_native_set_bootloader_parameter;
	context->services.find_hob_memory = cdk2_native_find_hob_memory;
	context->services.initialize_floating_point = cdk2_native_initialize_floating_point;
	context->services.mask_legacy_interrupts = cdk2_native_mask_legacy_interrupts;
	context->services.load_image = cdk2_native_load_image;
	context->services.handoff = cdk2_native_handoff;
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_initialize_stage_context(struct cdk2_native_context *context,
				     UINTN bootloader_parameter)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*context = (struct cdk2_native_context){0};
	context->bootloader_parameter = bootloader_parameter;
	return cdk2_native_initialize_services(context);
}

EFI_STATUS
EFIAPI
cdk2_native_validate_ops(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if ((context->ops.build_platform_hobs == NULL) &&
	    (context->ops.construct_hobs == NULL)) {
		return EFI_UNSUPPORTED;
	}

	if (context->ops.find_hob_memory == NULL ||
	    context->ops.initialize_floating_point == NULL ||
	    context->ops.load_dxe_core == NULL || context->ops.transfer == NULL) {
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_build_hobs(struct cdk2_native_context *context)
{
	EFI_HOB_HANDOFF_INFO_TABLE *handoff;
	EFI_HOB_GENERIC_HEADER *end;
	EFI_STATUS status;

	if (context == NULL || context->payload_base == 0 || context->payload_size == 0 ||
	    context->payload_base > MAX_UINT64 - context->payload_size ||
	    sizeof(*handoff) + sizeof(*end) > CDK2_NATIVE_HOB_BUFFER_SIZE) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.build_platform_hobs != NULL) {
		status = context->ops.build_platform_hobs(context, (void **)&handoff);
		if (EFI_ERROR(status)) {
			return status;
		}

		return cdk2_native_adopt_hob_list(context, handoff);
	}

	if (context->ops.construct_hobs != NULL) {
		handoff = context->ops.construct_hobs(context->hob_memory_bottom,
							  context->hob_memory_top,
							  context->hob_free_memory_bottom,
							  context->hob_free_memory_top);
		if (handoff == NULL) {
			return EFI_OUT_OF_RESOURCES;
		}

		return cdk2_native_adopt_hob_list(context, handoff);
	}

	handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)(void *)m_cdk2_native_hob_storage;
	end = (EFI_HOB_GENERIC_HEADER *)(void *)(m_cdk2_native_hob_storage + sizeof(*handoff));

	handoff->header.hob_type = EFI_HOB_TYPE_HANDOFF;
	handoff->header.hob_length = sizeof(*handoff);
	handoff->header.reserved = 0;
	handoff->version = EFI_HOB_HANDOFF_TABLE_VERSION;
	handoff->boot_mode = BOOT_WITH_FULL_CONFIGURATION;
	handoff->efi_memory_bottom = context->payload_base;
	handoff->efi_memory_top = context->payload_base + context->payload_size;
	handoff->efi_free_memory_bottom = context->payload_base;
	handoff->efi_free_memory_top = handoff->efi_memory_top;

	end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	end->hob_length = sizeof(*end);
	end->reserved = 0;

	context->hob_list = handoff;
	context->hob_list_size = sizeof(*handoff) + sizeof(*end);
	handoff->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_populate_hobs(struct cdk2_native_context *context)
{
	EFI_STATUS status;

	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.populate_hobs == NULL) {
		return EFI_SUCCESS;
	}

	if (context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	status = context->ops.populate_hobs(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	return cdk2_native_adopt_hob_list(
		context, (EFI_HOB_HANDOFF_INFO_TABLE *)(void *)context->hob_list);
}

EFI_STATUS
EFIAPI
cdk2_native_build_serial_hob(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.build_serial_hob == NULL) {
		return EFI_SUCCESS;
	}

	if (context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	return context->ops.build_serial_hob(context);
}

EFI_STATUS
EFIAPI
cdk2_native_apply_boot_mode(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.apply_boot_mode == NULL) {
		return EFI_SUCCESS;
	}

	if (context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	return context->ops.apply_boot_mode(context);
}

EFI_STATUS
EFIAPI
cdk2_native_initialize_libraries(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.initialize_libraries == NULL) {
		return EFI_SUCCESS;
	}

	return context->ops.initialize_libraries(context);
}

EFI_STATUS
EFIAPI
cdk2_native_set_bootloader_parameter(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.set_bootloader_parameter == NULL) {
		return EFI_SUCCESS;
	}

	return context->ops.set_bootloader_parameter(context);
}

EFI_STATUS
EFIAPI
cdk2_native_find_hob_memory(struct cdk2_native_context *context, UINTN *hob_mem_base)
{
	if (context == NULL || context->ops.find_hob_memory == NULL ||
	    hob_mem_base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	return context->ops.find_hob_memory(context, hob_mem_base);
}

EFI_STATUS
EFIAPI
cdk2_native_initialize_floating_point(struct cdk2_native_context *context)
{
	if (context == NULL || context->ops.initialize_floating_point == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	return context->ops.initialize_floating_point(context);
}

EFI_STATUS
EFIAPI
cdk2_native_mask_legacy_interrupts(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	if (context->ops.mask_legacy_interrupts == NULL) {
		return EFI_SUCCESS;
	}

	return context->ops.mask_legacy_interrupts(context);
}

EFI_STATUS
EFIAPI
cdk2_native_prepare_entry(struct cdk2_native_context *context)
{
	EFI_STATUS status;
	EFI_PHYSICAL_ADDRESS dxe_core_entry_point;
	EFI_PHYSICAL_ADDRESS hob_mem_top;
	EFI_PHYSICAL_ADDRESS memory_bottom;
	EFI_PHYSICAL_ADDRESS memory_top;
	EFI_PHYSICAL_ADDRESS payload_end;
	UINTN hob_mem_base;

	if (context == NULL || context->payload_base == 0 || context->payload_size == 0 ||
	    context->payload_base > MAX_UINT64 - context->payload_size ||
	    context->hob_region_size == 0) {
		return EFI_INVALID_PARAMETER;
	}

	payload_end = context->payload_base + context->payload_size;
	if (payload_end > MAX_UINTN) {
		return EFI_INVALID_PARAMETER;
	}

	status = cdk2_native_set_bootloader_parameter(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_initialize_floating_point(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	hob_mem_base = 0;
	status = cdk2_native_find_hob_memory(context, &hob_mem_base);
	if (EFI_ERROR(status) && status != EFI_NOT_FOUND) {
		return status;
	}

	if (hob_mem_base == 0) {
		if (payload_end > (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - (SIZE_1MB - 1U))) {
			return EFI_INVALID_PARAMETER;
		}

		hob_mem_base = ALIGN_VALUE((UINTN)payload_end, SIZE_1MB);
	}

	if (hob_mem_base > MAX_UINTN - context->hob_region_size) {
		return EFI_INVALID_PARAMETER;
	}

	hob_mem_top = hob_mem_base + context->hob_region_size;
	memory_bottom = context->payload_base;
	memory_top = payload_end;
	if (hob_mem_base < memory_bottom) {
		memory_bottom = hob_mem_base;
	}

	if (hob_mem_top > memory_top) {
		memory_top = hob_mem_top;
	}

	context->hob_memory_bottom = (void *)(UINTN)memory_bottom;
	context->hob_memory_top = (void *)(UINTN)memory_top;
	context->hob_free_memory_bottom = (void *)(UINTN)hob_mem_base;
	context->hob_free_memory_top = (void *)(UINTN)hob_mem_top;
	status = cdk2_native_build_hobs(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_build_serial_hob(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	/*
	 * The library constructors might depend on the serial port, so call them
	 * after serial port HOB construction.
	 */
	status = cdk2_native_initialize_libraries(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_populate_hobs(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	status =
		cdk2_native_load_image(context, cdk2_native_image_dxe_core, &dxe_core_entry_point);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_validate_entry(context,
					    (EFI_HOB_HANDOFF_INFO_TABLE *)context->hob_list,
					    context->image_base, context->image_size,
					    dxe_core_entry_point);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_apply_boot_mode(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	status = cdk2_native_mask_legacy_interrupts(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_load_image(struct cdk2_native_context *context, enum cdk2_native_image image,
		       EFI_PHYSICAL_ADDRESS *entry_point)
{
	EFI_PHYSICAL_ADDRESS image_base;
	EFI_PHYSICAL_ADDRESS image_entry_point;
	UINTN image_size;
	EFI_STATUS status;

	if (context == NULL || entry_point == NULL || image >= cdk2_native_image_max) {
		return EFI_INVALID_PARAMETER;
	}

	image_base = 0;
	image_size = 0;
	image_entry_point = 0;
	if (image == cdk2_native_image_dxe_core) {
		if (context->ops.load_dxe_core == NULL) {
			status = EFI_UNSUPPORTED;
			goto failed;
		}

		status = context->ops.load_dxe_core(context, &image_entry_point,
							&image_base, &image_size);
		if (EFI_ERROR(status)) {
			goto failed;
		}
	} else if (image == cdk2_native_image_payload_entry) {
		if (context->payload_base == 0 || context->payload_size == 0 ||
		    context->payload_base > MAX_UINT64 - context->payload_size) {
			status = EFI_INVALID_PARAMETER;
			goto failed;
		}

		image_base = context->payload_base;
		image_size = context->payload_size;
		image_entry_point = context->image_entry_point;
		if (image_entry_point == 0) {
			image_entry_point = image_base;
		}
	} else {
		return EFI_INVALID_PARAMETER;
	}

	if (!cdk2_native_range_contains(image_base, image_size, image_entry_point)) {
		status = EFI_SECURITY_VIOLATION;
		goto failed;
	}

	context->image_base = image_base;
	context->image_size = image_size;
	context->image_entry_point = image_entry_point;
	*entry_point = image_entry_point;
	return EFI_SUCCESS;

failed:
	cdk2_native_clear_image_state(context);
	*entry_point = 0;
	return status;
}

EFI_STATUS
EFIAPI
cdk2_native_allocate_pages(struct cdk2_native_context *context, UINTN pages,
			   EFI_PHYSICAL_ADDRESS *base)
{
	EFI_HOB_HANDOFF_INFO_TABLE *handoff;
	EFI_PHYSICAL_ADDRESS bottom;
	EFI_PHYSICAL_ADDRESS top;
	UINTN size;

	if (context == NULL || pages == 0 || base == NULL ||
	    pages > MAX_UINTN / EFI_PAGE_SIZE) {
		return EFI_INVALID_PARAMETER;
	}

	handoff = NULL;
	size = pages * EFI_PAGE_SIZE;
	bottom = context->allocation_bottom;
	top = context->allocation_top & ~(EFI_PHYSICAL_ADDRESS)(EFI_PAGE_SIZE - 1);
	if (context->hob_list != NULL) {
		handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)context->hob_list;
		if (handoff->header.hob_type != EFI_HOB_TYPE_HANDOFF ||
		    handoff->header.hob_length != sizeof(*handoff)) {
			return EFI_COMPROMISED_DATA;
		}

		if (handoff->efi_free_memory_top != context->allocation_top ||
		    handoff->efi_free_memory_bottom < context->allocation_bottom ||
		    handoff->efi_free_memory_bottom > handoff->efi_free_memory_top) {
			return EFI_COMPROMISED_DATA;
		}

		bottom = handoff->efi_free_memory_bottom;
	}

	if (top < bottom || size > top - bottom) {
		return EFI_OUT_OF_RESOURCES;
	}

	top -= size;
	if (handoff != NULL) {
		handoff->efi_free_memory_top = top;
	}

	context->allocation_bottom = bottom;
	context->allocation_top = top;
	*base = top;
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_handoff(struct cdk2_native_context *context)
{
	if (context == NULL || context->hob_list == NULL || context->hob_list_size == 0 ||
	    context->image_base == 0 || context->image_size == 0 ||
	    !cdk2_native_range_contains(context->image_base, context->image_size,
					context->image_entry_point)) {
		return EFI_NOT_READY;
	}

	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_transfer(struct cdk2_native_context *context)
{
	EFI_STATUS status;

	if (context == NULL || context->ops.transfer == NULL) {
		return EFI_UNSUPPORTED;
	}

	status = cdk2_native_handoff(context);
	if (EFI_ERROR(status)) {
		return status;
	}

	/*
	 * Run the platform hook after handoff validation and immediately before
	 * transferring control to DXE.
	 */
	cdk2_platform_late_init();
	return context->ops.transfer(context);
}

EFI_STATUS
EFIAPI
cdk2_native_adopt_hob_list(struct cdk2_native_context *context,
			   EFI_HOB_HANDOFF_INFO_TABLE *handoff)
{
	EFI_HOB_GENERIC_HEADER *hob;
	EFI_HOB_GENERIC_HEADER *end;
	EFI_PHYSICAL_ADDRESS hob_list_bottom;
	EFI_PHYSICAL_ADDRESS hob_list_top;
	UINTN hob_list_size;
	UINTN hob_length;

	if (context == NULL || handoff == NULL ||
	    handoff->header.hob_type != EFI_HOB_TYPE_HANDOFF ||
	    handoff->header.hob_length != sizeof(*handoff) || handoff->efi_end_of_hob_list == 0) {
		return EFI_INVALID_PARAMETER;
	}

	if (handoff->efi_memory_bottom > handoff->efi_memory_top ||
	    handoff->efi_free_memory_bottom > handoff->efi_free_memory_top ||
	    handoff->efi_free_memory_bottom < handoff->efi_memory_bottom ||
	    handoff->efi_free_memory_top > handoff->efi_memory_top) {
		return EFI_COMPROMISED_DATA;
	}

	end = (EFI_HOB_GENERIC_HEADER *)(UINTN)handoff->efi_end_of_hob_list;
	if ((UINTN)end <= (UINTN)handoff || (UINTN)end > MAX_UINTN - sizeof(*end)) {
		return EFI_COMPROMISED_DATA;
	}

	hob_list_size = ((UINTN)end - (UINTN)handoff) + sizeof(*end);
	hob_list_bottom = (EFI_PHYSICAL_ADDRESS)(UINTN)handoff;
	hob_list_top = hob_list_bottom + hob_list_size;
	if (handoff->efi_free_memory_bottom < hob_list_top &&
	    handoff->efi_free_memory_top > hob_list_bottom) {
		return EFI_COMPROMISED_DATA;
	}

	hob = (EFI_HOB_GENERIC_HEADER *)(void *)handoff;
	while ((UINTN)hob < (UINTN)end) {
		if ((UINTN)end - (UINTN)hob < sizeof(*hob)) {
			return EFI_COMPROMISED_DATA;
		}

		hob_length = hob->hob_length;
		if (hob_length < sizeof(*hob) || hob_length > (UINTN)end - (UINTN)hob ||
		    (hob_length & 7U) != 0 || hob->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST) {
			return EFI_COMPROMISED_DATA;
		}

		hob = (EFI_HOB_GENERIC_HEADER *)(void *)((UINT8 *)hob + hob_length);
	}

	if (hob != end || end->hob_type != EFI_HOB_TYPE_END_OF_HOB_LIST ||
	    end->hob_length != sizeof(*end)) {
		return EFI_COMPROMISED_DATA;
	}

	if (handoff->efi_free_memory_bottom > handoff->efi_free_memory_top) {
		return EFI_COMPROMISED_DATA;
	}

	context->hob_list = handoff;
	context->hob_list_size = hob_list_size;
	context->allocation_bottom = handoff->efi_free_memory_bottom;
	context->allocation_top = handoff->efi_free_memory_top;
	return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
cdk2_native_validate_entry(struct cdk2_native_context *context,
			   EFI_HOB_HANDOFF_INFO_TABLE *handoff, EFI_PHYSICAL_ADDRESS image_base,
			   UINTN image_size, EFI_PHYSICAL_ADDRESS image_entry_point)
{
	EFI_STATUS status;

	if (context == NULL || image_base == 0 || image_size == 0) {
		return EFI_INVALID_PARAMETER;
	}

	cdk2_native_clear_image_state(context);
	status = cdk2_native_adopt_hob_list(context, handoff);
	if (EFI_ERROR(status)) {
		return status;
	}

	if (context->services.handoff == NULL) {
		return EFI_NOT_READY;
	}

	context->image_base = image_base;
	context->image_size = image_size;
	context->image_entry_point = image_entry_point;
	status = context->services.handoff(context);
	if (EFI_ERROR(status)) {
		cdk2_native_clear_image_state(context);
	}

	return status;
}
