/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Host checks for the native cdk2 service boundary.
 */

#include "services.h"

#include <stdio.h>

static UINT8 m_test_hob_storage[CDK2_NATIVE_HOB_BUFFER_SIZE];
static UINTN m_construct_hobs_calls;
static UINTN m_populate_hobs_calls;
static UINTN m_build_serial_hob_calls;
static UINTN m_apply_boot_mode_calls;
static UINTN m_initialize_libraries_calls;
static UINTN m_set_bootloader_parameter_calls;
static UINTN m_find_hob_memory_calls;
static UINTN m_initialize_floating_point_calls;
static UINTN m_mask_legacy_interrupts_calls;
static UINTN m_transfer_calls;
static UINTN m_late_init_calls;
static BOOLEAN m_fail_set_bootloader_parameter;
static BOOLEAN m_fail_find_hob_memory;

void EFIAPI cdk2_platform_late_init(void)
{
	m_late_init_calls++;
}

static EFI_STATUS EFIAPI test_build_serial_hob(struct cdk2_native_context *context)
{
	if (context == NULL || context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_build_serial_hob_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_apply_boot_mode(struct cdk2_native_context *context)
{
	if (context == NULL || context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_apply_boot_mode_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_initialize_libraries(struct cdk2_native_context *context)
{
	if (context == NULL || context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_initialize_libraries_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_set_bootloader_parameter(struct cdk2_native_context *context)
{
	if (m_fail_set_bootloader_parameter) {
		return EFI_DEVICE_ERROR;
	}

	if (context == NULL || context->bootloader_parameter != 0x12345678) {
		return EFI_INVALID_PARAMETER;
	}

	m_set_bootloader_parameter_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_find_hob_memory(struct cdk2_native_context *context,
					   UINTN *hob_mem_base)
{
	if (m_fail_find_hob_memory) {
		return EFI_DEVICE_ERROR;
	}

	if (context == NULL || hob_mem_base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*hob_mem_base = 0x00200000;
	m_find_hob_memory_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_find_no_hob_memory(struct cdk2_native_context *context,
					     UINTN *hob_mem_base)
{
	if (context == NULL || hob_mem_base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*hob_mem_base = 0;
	m_find_hob_memory_calls++;
	return EFI_NOT_FOUND;
}

static EFI_STATUS EFIAPI test_find_below_payload_hob_memory(struct cdk2_native_context *context,
						       UINTN *hob_mem_base)
{
	if (context == NULL || hob_mem_base == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*hob_mem_base = 0x00200000;
	m_find_hob_memory_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_initialize_floating_point(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_initialize_floating_point_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_mask_legacy_interrupts(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_mask_legacy_interrupts_calls++;
	return EFI_SUCCESS;
}

static EFI_HOB_HANDOFF_INFO_TABLE *EFIAPI test_construct_hobs(void *efi_memory_bottom,
							    void *efi_memory_top,
							    void *efi_free_memory_bottom,
							    void *efi_free_memory_top)
{
	EFI_HOB_HANDOFF_INFO_TABLE *handoff;
	EFI_HOB_GENERIC_HEADER *end;

	if (efi_memory_bottom == NULL || efi_memory_top == NULL ||
	    efi_free_memory_bottom == NULL || efi_free_memory_top == NULL) {
		return NULL;
	}

	m_construct_hobs_calls++;
	handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)(void *)m_test_hob_storage;
	end = (EFI_HOB_GENERIC_HEADER *)(void *)(m_test_hob_storage + sizeof(*handoff));

	handoff->header.hob_type = EFI_HOB_TYPE_HANDOFF;
	handoff->header.hob_length = sizeof(*handoff);
	handoff->header.reserved = 0;
	handoff->version = EFI_HOB_HANDOFF_TABLE_VERSION;
	handoff->boot_mode = BOOT_WITH_FULL_CONFIGURATION;
	handoff->efi_memory_bottom = (EFI_PHYSICAL_ADDRESS)(UINTN)efi_memory_bottom;
	handoff->efi_memory_top = (EFI_PHYSICAL_ADDRESS)(UINTN)efi_memory_top;
	handoff->efi_free_memory_bottom = (EFI_PHYSICAL_ADDRESS)(UINTN)efi_free_memory_bottom;
	handoff->efi_free_memory_top = (EFI_PHYSICAL_ADDRESS)(UINTN)efi_free_memory_top;
	handoff->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;

	end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	end->hob_length = sizeof(*end);
	end->reserved = 0;
	return handoff;
}

static EFI_STATUS EFIAPI test_populate_hobs(struct cdk2_native_context *context)
{
	EFI_HOB_HANDOFF_INFO_TABLE *handoff;
	EFI_HOB_GENERIC_HEADER *hob;
	EFI_HOB_GENERIC_HEADER *end;

	if (context == NULL || context->hob_list == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_populate_hobs_calls++;
	handoff = (EFI_HOB_HANDOFF_INFO_TABLE *)context->hob_list;
	hob = (EFI_HOB_GENERIC_HEADER *)(void *)(m_test_hob_storage + sizeof(*handoff));
	end = (EFI_HOB_GENERIC_HEADER *)(void *)((UINT8 *)hob + sizeof(*hob));

	hob->hob_type = EFI_HOB_TYPE_UNUSED;
	hob->hob_length = sizeof(*hob);
	hob->reserved = 0;
	end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	end->hob_length = sizeof(*end);
	end->reserved = 0;
	handoff->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 service test: %s\n", message);
		return 1;
	}

	return 0;
}

static EFI_STATUS EFIAPI test_load_dxe_core(struct cdk2_native_context *context,
					    unsigned long long *entry_point,
					    unsigned long long *image_base,
					    unsigned long long *image_size)
{
	if (context == NULL || entry_point == NULL || image_base == NULL ||
	    image_size == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*image_base = 0x00400000;
	*image_size = 0x00020000;
	*entry_point = 0x00401000;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_load_dxe_core_fails_after_output(
	struct cdk2_native_context *context, unsigned long long *entry_point,
	unsigned long long *image_base, unsigned long long *image_size)
{
	if (context == NULL || entry_point == NULL || image_base == NULL ||
	    image_size == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	*image_base = 0x00400000;
	*image_size = 0x00020000;
	*entry_point = 0x00401000;
	return EFI_DEVICE_ERROR;
}

static EFI_STATUS EFIAPI test_transfer(struct cdk2_native_context *context)
{
	if (context == NULL) {
		return EFI_INVALID_PARAMETER;
	}

	m_transfer_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI test_initialize_context(struct cdk2_native_context *context,
					       UINTN bootloader_parameter)
{
	if (context == NULL || bootloader_parameter != 0x12345678) {
		return EFI_INVALID_PARAMETER;
	}

	*context = (struct cdk2_native_context){0};
	context->bootloader_parameter = bootloader_parameter;
	context->payload_base = 0x00100000;
	context->payload_size = 0x00200000;
	context->hob_region_size = 0x00100000;
	context->ops.construct_hobs = test_construct_hobs;
	context->ops.populate_hobs = test_populate_hobs;
	context->ops.build_serial_hob = test_build_serial_hob;
	context->ops.apply_boot_mode = test_apply_boot_mode;
	context->ops.initialize_libraries = test_initialize_libraries;
	context->ops.set_bootloader_parameter = test_set_bootloader_parameter;
	context->ops.find_hob_memory = test_find_hob_memory;
	context->ops.initialize_floating_point = test_initialize_floating_point;
	context->ops.mask_legacy_interrupts = test_mask_legacy_interrupts;
	context->ops.load_dxe_core = test_load_dxe_core;
	context->ops.transfer = test_transfer;
	return cdk2_native_initialize_services(context);
}

int main(void)
{
	struct cdk2_native_context context = {0};
	struct cdk2_native_context stage = {0};
	struct cdk2_native_context prepared = {0};
	struct cdk2_native_context below_payload = {0};
	struct cdk2_native_context fallback_overflow = {0};
	struct cdk2_native_context optional = {0};
	struct cdk2_native_context incomplete = {0};
	struct cdk2_native_context failed = {0};
	struct cdk2_native_context allocator = {0};
	EFI_HOB_HANDOFF_INFO_TABLE *allocator_hob;
	EFI_HOB_HANDOFF_INFO_TABLE *below_payload_hob;
	EFI_HOB_HANDOFF_INFO_TABLE rejected_hob;
	EFI_HOB_GENERIC_HEADER *end;
	EFI_HOB_GENERIC_HEADER *malformed_hob;
	EFI_HOB_GENERIC_HEADER rejected_end;
	EFI_PHYSICAL_ADDRESS hob_list_top;
	EFI_PHYSICAL_ADDRESS entry_point;
	EFI_PHYSICAL_ADDRESS allocation_base;
	UINTN hob_mem_base;
	UINTN late_init_before;
	UINTN transfer_before;
	UINTN optional_populate_hobs_calls;
	UINTN optional_build_serial_hob_calls;
	UINTN optional_apply_boot_mode_calls;
	UINTN optional_initialize_libraries_calls;
	UINTN optional_set_bootloader_parameter_calls;
	UINTN optional_mask_legacy_interrupts_calls;
	int failures;

	context.payload_base = 0x00100000;
	context.payload_size = 0x00200000;
	context.image_entry_point = 0x00110000;
	failures = 0;
	failures += expect(cdk2_native_initialize_services(&context) == EFI_SUCCESS,
			   "service initialization");
	failures += expect(context.services.build_hobs != NULL, "HOB service installed");
	failures += expect(context.services.populate_hobs != NULL,
			   "HOB population service installed");
	failures += expect(context.services.build_serial_hob != NULL,
			   "serial HOB service installed");
	failures +=
		expect(context.services.apply_boot_mode != NULL, "boot-mode service installed");
	failures += expect(context.services.initialize_libraries != NULL,
			   "library service installed");
	failures += expect(context.services.set_bootloader_parameter != NULL,
			   "bootloader parameter service installed");
	failures += expect(context.services.find_hob_memory != NULL,
			   "HOB memory service installed");
	failures += expect(context.services.initialize_floating_point != NULL,
			   "floating-point service installed");
	failures += expect(context.services.mask_legacy_interrupts != NULL,
			   "interrupt service installed");
	failures += expect(context.services.load_image != NULL, "image service installed");
	failures += expect(context.services.handoff != NULL, "handoff service installed");

	stage.image_base = 0x00400000;
	failures +=
		expect(cdk2_native_initialize_stage_context(&stage, 0xCAFEBABE) == EFI_SUCCESS,
		       "native stage context initialization");
	failures +=
		expect(stage.bootloader_parameter == 0xCAFEBABE, "stage bootloader parameter");
	failures += expect(stage.image_base == 0, "stage context reset");
	failures += expect(stage.services.build_hobs != NULL, "stage services installed");
	failures += expect(cdk2_native_validate_ops(&context) == EFI_UNSUPPORTED,
			   "incomplete handoff rejected");
	failures += expect(cdk2_native_transfer(&context) == EFI_UNSUPPORTED,
			   "transfer requires architecture hook");
	failures += expect(cdk2_native_build_hobs(&context) == EFI_SUCCESS, "HOB build");
	context.hob_memory_bottom = (void *)(UINTN)0x00100000;
	context.hob_memory_top = (void *)(UINTN)0x00400000;
	context.hob_free_memory_bottom = (void *)(UINTN)0x00200000;
	context.hob_free_memory_top = (void *)(UINTN)0x00300000;
	context.ops.construct_hobs = test_construct_hobs;
	failures +=
		expect(cdk2_native_build_hobs(&context) == EFI_SUCCESS, "callback HOB build");
	failures += expect(m_construct_hobs_calls == 1, "HOB constructor callback");
	failures += expect(context.hob_list == (void *)m_test_hob_storage, "callback HOB list");
	context.ops.populate_hobs = test_populate_hobs;
	failures +=
		expect(cdk2_native_populate_hobs(&context) == EFI_SUCCESS, "HOB population");
	failures += expect(m_populate_hobs_calls == 1, "HOB population callback");
	failures += expect(context.hob_list_size == sizeof(EFI_HOB_HANDOFF_INFO_TABLE) +
							    2 * sizeof(EFI_HOB_GENERIC_HEADER),
			   "expanded HOB list");
	context.ops.build_serial_hob = test_build_serial_hob;
	failures += expect(cdk2_native_build_serial_hob(&context) == EFI_SUCCESS,
			   "serial HOB service");
	failures += expect(m_build_serial_hob_calls == 1, "serial HOB callback");
	context.ops.apply_boot_mode = test_apply_boot_mode;
	failures += expect(cdk2_native_apply_boot_mode(&context) == EFI_SUCCESS,
			   "boot-mode service");
	failures += expect(m_apply_boot_mode_calls == 1, "boot-mode callback");
	context.ops.initialize_libraries = test_initialize_libraries;
	failures += expect(cdk2_native_initialize_libraries(&context) == EFI_SUCCESS,
			   "library service");
	failures += expect(m_initialize_libraries_calls == 1, "library callback");
	context.bootloader_parameter = 0x12345678;
	context.ops.set_bootloader_parameter = test_set_bootloader_parameter;
	failures += expect(cdk2_native_set_bootloader_parameter(&context) == EFI_SUCCESS,
			   "bootloader parameter service");
	failures += expect(m_set_bootloader_parameter_calls == 1,
			   "bootloader parameter callback");
	context.ops.find_hob_memory = test_find_hob_memory;
	hob_mem_base = 0;
	failures += expect(cdk2_native_find_hob_memory(&context, &hob_mem_base) == EFI_SUCCESS,
			   "HOB memory service");
	failures += expect(hob_mem_base == 0x00200000, "HOB memory callback");
	failures += expect(m_find_hob_memory_calls == 1, "HOB memory callback count");
	context.ops.initialize_floating_point = test_initialize_floating_point;
	failures += expect(cdk2_native_initialize_floating_point(&context) == EFI_SUCCESS,
			   "floating-point service");
	failures += expect(m_initialize_floating_point_calls == 1, "floating-point callback");
	context.ops.mask_legacy_interrupts = test_mask_legacy_interrupts;
	failures += expect(cdk2_native_mask_legacy_interrupts(&context) == EFI_SUCCESS,
			   "interrupt service");
	failures += expect(m_mask_legacy_interrupts_calls == 1, "interrupt callback");
	failures += expect(cdk2_native_load_image(&context, cdk2_native_image_payload_entry,
						  &entry_point) == EFI_SUCCESS,
			   "image load");
	failures += expect(entry_point == context.image_entry_point, "entry point");
	failures += expect(cdk2_native_handoff(&context) == EFI_SUCCESS, "handoff validation");

	context.ops.load_dxe_core = test_load_dxe_core;
	failures += expect(cdk2_native_load_image(&context, cdk2_native_image_dxe_core,
						  &entry_point) == EFI_SUCCESS,
			   "DXE core load");
	failures += expect(m_late_init_calls == 0, "late-init deferred until transfer");
	failures += expect(entry_point == 0x00401000, "DXE core entry point");
	failures += expect(context.image_base == 0x00400000, "DXE core image base");
	failures += expect(context.image_size == 0x00020000, "DXE core image size");
	context.ops.transfer = test_transfer;
	failures += expect(cdk2_native_transfer(&context) == EFI_SUCCESS, "transfer service");
	failures += expect(m_late_init_calls == 1, "late-init hook");
	failures += expect(m_transfer_calls == 1, "transfer callback");
	context.ops.load_dxe_core = test_load_dxe_core_fails_after_output;
	late_init_before = m_late_init_calls;
	transfer_before = m_transfer_calls;
	failures += expect(cdk2_native_load_image(&context, cdk2_native_image_dxe_core,
						  &entry_point) == EFI_DEVICE_ERROR,
			   "failed DXE core load status");
	failures += expect(context.image_base == 0, "failed DXE core load clears image base");
	failures += expect(context.image_size == 0, "failed DXE core load clears image size");
	failures += expect(context.image_entry_point == 0,
			   "failed DXE core load clears entry point");
	failures +=
		expect(entry_point == 0, "failed DXE core load clears returned entry point");
	failures += expect(cdk2_native_transfer(&context) == EFI_NOT_READY,
			   "failed DXE core load blocks transfer");
	failures += expect(m_late_init_calls == late_init_before,
			   "late-init skipped after failed DXE core load");
	failures += expect(m_transfer_calls == transfer_before,
			   "transfer skipped after failed DXE core load");
	context.ops.load_dxe_core = NULL;
	failures += expect(cdk2_native_load_image(&context, cdk2_native_image_dxe_core,
						  &entry_point) == EFI_UNSUPPORTED,
			   "DXE core callback required");

	context.image_entry_point = context.payload_base + context.payload_size;
	failures += expect(cdk2_native_load_image(&context, cdk2_native_image_payload_entry,
						  &entry_point) == EFI_SECURITY_VIOLATION,
			   "range rejection");

	context.image_entry_point = 0x00110000;
	failures += expect(cdk2_native_load_image(&context, cdk2_native_image_max,
						  &entry_point) == EFI_INVALID_PARAMETER,
			   "image selector rejection");

	context.image_base = 0x00400000;
	context.image_size = 0x00020000;
	context.image_entry_point = 0x00401000;
	failures += expect(cdk2_native_validate_entry(
				   &context, (EFI_HOB_HANDOFF_INFO_TABLE *)context.hob_list,
				   context.image_base, context.image_size,
				   context.image_entry_point) == EFI_SUCCESS,
			   "existing HOB handoff validation");

	rejected_hob = (EFI_HOB_HANDOFF_INFO_TABLE){0};
	rejected_end = (EFI_HOB_GENERIC_HEADER){0};
	rejected_hob.header.hob_type = EFI_HOB_TYPE_HANDOFF;
	rejected_hob.header.hob_length = sizeof(rejected_hob);
	rejected_hob.efi_memory_bottom = 0x00100000;
	rejected_hob.efi_memory_top = 0x00400000;
	rejected_hob.efi_free_memory_bottom = 0x00300000;
	rejected_hob.efi_free_memory_top = 0x00200000;
	rejected_hob.efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)&rejected_end;
	rejected_end.hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	rejected_end.hob_length = sizeof(rejected_end);
	late_init_before = m_late_init_calls;
	transfer_before = m_transfer_calls;
	failures += expect(cdk2_native_validate_entry(&context, &rejected_hob, 0x00500000,
						      0x00010000,
						      0x00501000) == EFI_COMPROMISED_DATA,
			   "rejected HOB validation status");
	failures +=
		expect(context.image_base == 0, "rejected HOB validation clears image base");
	failures +=
		expect(context.image_size == 0, "rejected HOB validation clears image size");
	failures += expect(context.image_entry_point == 0,
			   "rejected HOB validation clears entry point");
	failures += expect(cdk2_native_transfer(&context) == EFI_NOT_READY,
			   "rejected HOB validation blocks transfer");
	failures += expect(m_late_init_calls == late_init_before,
			   "late-init skipped after rejected HOB validation");
	failures += expect(m_transfer_calls == transfer_before,
			   "transfer skipped after rejected HOB validation");

	failures += expect(cdk2_native_adopt_hob_list(&context, NULL) == EFI_INVALID_PARAMETER,
			   "null HOB rejection");
	allocator_hob = test_construct_hobs((void *)(UINTN)0x00100000, (void *)(UINTN)0x00400000,
					 (void *)(UINTN)0x00200000, (void *)(UINTN)0x00300000);
	allocator_hob->efi_free_memory_top = MAX_UINT64;
	failures += expect(cdk2_native_adopt_hob_list(&context, allocator_hob) ==
				   EFI_COMPROMISED_DATA,
			   "out-of-range HOB free top rejection");

	allocator_hob = test_construct_hobs(m_test_hob_storage,
					 m_test_hob_storage + sizeof(m_test_hob_storage),
					 m_test_hob_storage + sizeof(*allocator_hob),
					 m_test_hob_storage + sizeof(m_test_hob_storage));
	end = (EFI_HOB_GENERIC_HEADER *)(void *)(m_test_hob_storage + sizeof(*allocator_hob));
	hob_list_top = (EFI_PHYSICAL_ADDRESS)(UINTN)end + sizeof(*end);
	allocator = (struct cdk2_native_context){0};
	failures += expect(cdk2_native_adopt_hob_list(&allocator, allocator_hob) ==
				   EFI_COMPROMISED_DATA,
			   "overlapping adopted HOB free range accepted");
	allocator_hob->efi_free_memory_bottom = hob_list_top;
	failures += expect(cdk2_native_adopt_hob_list(&allocator, allocator_hob) == EFI_SUCCESS,
			   "non-overlapping adopted HOB free range rejected");

	allocator_hob = test_construct_hobs((void *)(UINTN)0x00100000, (void *)(UINTN)0x00400000,
					 (void *)(UINTN)0x00200000, (void *)(UINTN)0x00300000);
	malformed_hob =
		(EFI_HOB_GENERIC_HEADER *)(void *)(m_test_hob_storage + sizeof(*allocator_hob));
	end = (EFI_HOB_GENERIC_HEADER *)(void *)((UINT8 *)(void *)malformed_hob + 16);
	malformed_hob->hob_type = EFI_HOB_TYPE_UNUSED;
	malformed_hob->hob_length = sizeof(*malformed_hob) + 1;
	malformed_hob->reserved = 0;
	end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	end->hob_length = sizeof(*end);
	end->reserved = 0;
	allocator_hob->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;
	failures += expect(cdk2_native_adopt_hob_list(&context, allocator_hob) ==
				   EFI_COMPROMISED_DATA,
			   "unaligned adopted HOB length rejection");

	allocator_hob = test_construct_hobs((void *)(UINTN)0x00100000, (void *)(UINTN)0x00400000,
					 (void *)(UINTN)0x00200000, (void *)(UINTN)0x00300000);
	malformed_hob =
		(EFI_HOB_GENERIC_HEADER *)(void *)(m_test_hob_storage + sizeof(*allocator_hob));
	end = (EFI_HOB_GENERIC_HEADER *)(void *)((UINT8 *)(void *)malformed_hob +
						 sizeof(*malformed_hob));
	malformed_hob->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	malformed_hob->hob_length = sizeof(*malformed_hob);
	malformed_hob->reserved = 0;
	end->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	end->hob_length = sizeof(*end);
	end->reserved = 0;
	allocator_hob->efi_end_of_hob_list = (EFI_PHYSICAL_ADDRESS)(UINTN)end;
	failures += expect(cdk2_native_adopt_hob_list(&context, allocator_hob) ==
				   EFI_COMPROMISED_DATA,
			   "early adopted HOB end marker rejection");

	allocator = (struct cdk2_native_context){0};
	allocator.allocation_bottom = 0x00200000;
	allocator.allocation_top = 0x00210000;
	failures += expect(cdk2_native_allocate_pages(&allocator, 1, &allocation_base) ==
				   EFI_SUCCESS,
			   "page allocation");
	failures += expect(allocation_base == 0x0020f000, "top-down page placement");
	failures += expect(allocator.allocation_top == allocation_base, "allocator top update");
	failures += expect(cdk2_native_allocate_pages(&allocator, 15, &allocation_base) ==
				   EFI_SUCCESS,
			   "allocator exact exhaustion");
	failures += expect(allocator.allocation_top == allocator.allocation_bottom,
			   "allocator exhaustion boundary");
	failures += expect(cdk2_native_allocate_pages(&allocator, 1, &allocation_base) ==
				   EFI_OUT_OF_RESOURCES,
			   "allocator exhaustion rejection");
	allocator_hob = (EFI_HOB_HANDOFF_INFO_TABLE *)(void *)m_test_hob_storage;
	*allocator_hob = (EFI_HOB_HANDOFF_INFO_TABLE){0};
	allocator_hob->header.hob_type = EFI_HOB_TYPE_HANDOFF;
	allocator_hob->header.hob_length = sizeof(*allocator_hob);
	allocator_hob->efi_memory_bottom = 0x00200000;
	allocator_hob->efi_memory_top = 0x00210000;
	allocator_hob->efi_free_memory_bottom = 0x00200000;
	allocator_hob->efi_free_memory_top = 0x00210000;
	allocator = (struct cdk2_native_context){0};
	allocator.hob_list = allocator_hob;
	allocator.allocation_bottom = 0x00200000;
	allocator.allocation_top = 0x00210000;
	failures += expect(cdk2_native_allocate_pages(&allocator, 1, &allocation_base) ==
				   EFI_SUCCESS,
			   "HOB-backed page allocation");
	failures += expect(allocator.allocation_top == allocation_base,
			   "HOB-backed allocator top update");
	failures += expect(allocator_hob->efi_free_memory_top == allocation_base,
			   "PHIT free memory top update");
	allocator.hob_list = NULL;
	allocator.allocation_bottom = 0x00300000;
	allocator.allocation_top = 0x00200000;
	failures += expect(cdk2_native_allocate_pages(&allocator, 1, &allocation_base) ==
				   EFI_OUT_OF_RESOURCES,
			   "inverted allocator range rejection");
	allocator_hob = test_construct_hobs((void *)(UINTN)0x00200000, (void *)(UINTN)0x00203000,
					 (void *)(UINTN)0x00200000, (void *)(UINTN)0x00203000);
	allocator = (struct cdk2_native_context){0};
	failures += expect(cdk2_native_adopt_hob_list(&allocator, allocator_hob) == EFI_SUCCESS,
			   "allocator HOB adoption");
	allocator_hob->efi_free_memory_bottom = 0x00202000;
	failures += expect(cdk2_native_allocate_pages(&allocator, 2, &allocation_base) ==
				   EFI_OUT_OF_RESOURCES,
			   "allocator stale PHIT free bottom rejection");
	failures += expect(allocator_hob->efi_free_memory_top == 0x00203000,
			   "failed allocator preserves PHIT free top");

	prepared.bootloader_parameter = 0x12345678;
	prepared.payload_base = 0x00100000;
	prepared.payload_size = 0x00200000;
	prepared.hob_region_size = 0x00100000;
	prepared.ops.construct_hobs = test_construct_hobs;
	prepared.ops.populate_hobs = test_populate_hobs;
	prepared.ops.build_serial_hob = test_build_serial_hob;
	prepared.ops.apply_boot_mode = test_apply_boot_mode;
	prepared.ops.initialize_libraries = test_initialize_libraries;
	prepared.ops.set_bootloader_parameter = test_set_bootloader_parameter;
	prepared.ops.find_hob_memory = test_find_hob_memory;
	prepared.ops.initialize_floating_point = test_initialize_floating_point;
	prepared.ops.mask_legacy_interrupts = test_mask_legacy_interrupts;
	prepared.ops.load_dxe_core = test_load_dxe_core;
	failures += expect(cdk2_native_initialize_services(&prepared) == EFI_SUCCESS,
			   "prepare service initialization");

	optional = prepared;
	optional.ops.populate_hobs = NULL;
	optional.ops.build_serial_hob = NULL;
	optional.ops.apply_boot_mode = NULL;
	optional.ops.initialize_libraries = NULL;
	optional.ops.set_bootloader_parameter = NULL;
	optional.ops.mask_legacy_interrupts = NULL;
	optional.ops.transfer = test_transfer;
	failures += expect(cdk2_native_validate_ops(&optional) == EFI_SUCCESS,
			   "optional callbacks omitted");
	optional_populate_hobs_calls = m_populate_hobs_calls;
	optional_build_serial_hob_calls = m_build_serial_hob_calls;
	optional_apply_boot_mode_calls = m_apply_boot_mode_calls;
	optional_initialize_libraries_calls = m_initialize_libraries_calls;
	optional_set_bootloader_parameter_calls = m_set_bootloader_parameter_calls;
	optional_mask_legacy_interrupts_calls = m_mask_legacy_interrupts_calls;
	failures += expect(cdk2_native_prepare_entry(&optional) == EFI_SUCCESS,
			   "prepare entry with optional callbacks omitted");
	failures += expect(m_populate_hobs_calls == optional_populate_hobs_calls,
			   "optional HOB population skipped");
	failures += expect(m_build_serial_hob_calls == optional_build_serial_hob_calls,
			   "optional serial HOB skipped");
	failures += expect(m_apply_boot_mode_calls == optional_apply_boot_mode_calls,
			   "optional boot mode skipped");
	failures += expect(m_initialize_libraries_calls == optional_initialize_libraries_calls,
			   "optional library init skipped");
	failures += expect(m_set_bootloader_parameter_calls == optional_set_bootloader_parameter_calls,
			   "optional bootloader parameter skipped");
	failures += expect(m_mask_legacy_interrupts_calls == optional_mask_legacy_interrupts_calls,
			   "optional interrupt mask skipped");

	failed = prepared;
	m_fail_set_bootloader_parameter = TRUE;
	failures += expect(cdk2_native_prepare_entry(&failed) == EFI_DEVICE_ERROR,
			   "bootloader parameter failure");
	m_fail_set_bootloader_parameter = FALSE;

	failed = prepared;
	m_fail_find_hob_memory = TRUE;
	failures += expect(cdk2_native_prepare_entry(&failed) == EFI_DEVICE_ERROR,
			   "HOB memory discovery failure");
	m_fail_find_hob_memory = FALSE;

	fallback_overflow = prepared;
	fallback_overflow.payload_base = (EFI_PHYSICAL_ADDRESS)(MAX_UINTN - (SIZE_1MB / 2U));
	fallback_overflow.payload_size = EFI_PAGE_SIZE;
	fallback_overflow.ops.find_hob_memory = test_find_no_hob_memory;
	failures +=
		expect(cdk2_native_prepare_entry(&fallback_overflow) == EFI_INVALID_PARAMETER,
		       "fallback HOB memory alignment overflow accepted");

	below_payload = prepared;
	below_payload.payload_base = 0x00400000;
	below_payload.payload_size = 0x00200000;
	below_payload.ops.find_hob_memory = test_find_below_payload_hob_memory;
	failures += expect(cdk2_native_prepare_entry(&below_payload) == EFI_SUCCESS,
			   "below-payload HOB prepare entry");
	below_payload_hob = (EFI_HOB_HANDOFF_INFO_TABLE *)below_payload.hob_list;
	failures += expect(below_payload_hob != NULL, "below-payload prepared HOB list");
	failures += expect(below_payload_hob != NULL &&
				   below_payload_hob->efi_memory_bottom == 0x00200000,
			   "below-payload PHIT memory bottom");
	failures +=
		expect(below_payload_hob != NULL && below_payload_hob->efi_memory_top == 0x00600000,
		       "below-payload PHIT memory top");
	failures += expect(below_payload_hob != NULL &&
				   below_payload_hob->efi_free_memory_bottom == 0x00200000,
			   "below-payload PHIT free bottom");
	failures += expect(below_payload_hob != NULL &&
				   below_payload_hob->efi_free_memory_top == 0x00300000,
			   "below-payload PHIT free top");

	failures +=
		expect(cdk2_native_prepare_entry(&prepared) == EFI_SUCCESS, "prepare entry");
	failures += expect(prepared.hob_list != NULL, "prepared HOB list");
	failures +=
		expect(prepared.image_entry_point == 0x00401000, "prepared DXE entry point");
	failures += expect(m_late_init_calls == 1, "prepare entry defers late-init");

	incomplete = prepared;
	incomplete.ops.transfer = NULL;
	failures += expect(cdk2_native_validate_ops(&incomplete) == EFI_UNSUPPORTED,
			   "missing transfer rejected");

	m_late_init_calls = 0;
	m_transfer_calls = 0;
	failures += expect(cdk2_native_payload_entry(0x12345678, test_initialize_context) ==
				   EFI_SUCCESS,
			   "native payload entry flow");
	failures += expect(m_late_init_calls == 1, "native payload late-init hook");
	failures += expect(m_transfer_calls == 1, "native payload transfer");

	return failures == 0 ? 0 : 1;
}
