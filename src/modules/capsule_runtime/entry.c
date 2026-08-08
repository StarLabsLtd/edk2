/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/capsule_runtime.h>
#include <cdk2/capsule_runtime_entry.h>
#include <cdk2/config.h>

#define EVT_NOTIFY_SIGNAL 0x200U
#define TPL_NOTIFY 16U

typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI locate_handles_fn(UINT32, const EFI_GUID *, void *,
	UINTN *, void ***);
typedef EFI_STATUS CDK2_MS_ABI handle_protocol_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI create_event_ex_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI convert_pointer_fn(UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI set_variable_fn(CHAR16 *, EFI_GUID *, UINT32,
	UINTN, void *);
typedef void CDK2_MS_ABI reset_system_fn(UINT32, EFI_STATUS, UINTN, void *);

static const EFI_GUID capsule_arch_guid = { 0x5053697e, 0x2cbc, 0x4819,
	{ 0x90, 0xd9, 0x05, 0x80, 0xde, 0xee, 0x57, 0x54 } };
static const EFI_GUID va_change_guid = { 0x13fa7698, 0xc831, 0x49c7,
	{ 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 } };
static const EFI_GUID ebs_guid = { 0x27abf055, 0xb1b8, 0x4c26,
	{ 0x80, 0x48, 0x74, 0x8f, 0x37, 0xba, 0xa2, 0xdf } };
static const EFI_GUID capsule_vendor_guid = { 0x711c703f, 0xc285, 0x4b10,
	{ 0xa3, 0xb0, 0x36, 0xec, 0xbd, 0x3c, 0x8b, 0xe2 } };
static const EFI_GUID fmp_capsule_guid = { 0x6dcbd5ed, 0xe82d, 0x4c44,
	{ 0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a } };
static const EFI_GUID fmp_protocol_guid = { 0x86c77a67, 0x0b97, 0x4633,
	{ 0xa1, 0x87, 0x49, 0x10, 0x4d, 0x06, 0x85, 0xc7 } };
static struct cdk2_runtime_services_view *runtime_services;
static struct cdk2_capsule_runtime runtime;
static void *capsule_handle;
static void *va_event;
static void *ebs_event;
static BOOLEAN runtime_active;

struct fmp_capsule_header { UINT32 version; UINT16 embedded_count, payload_count; }
	__packed;
struct fmp_image_header {
	UINT32 version;
	EFI_GUID image_type;
	UINT8 image_index, reserved[3];
	UINT32 image_size, vendor_size;
	UINT64 hardware_instance, capsule_support;
} __packed;
struct fmp_image_descriptor {
	UINT8 image_index;
	EFI_GUID image_type;
	UINT64 image_id;
	CHAR16 *image_id_name;
	UINT32 version;
	CHAR16 *version_name;
	UINTN size;
	UINT64 attributes_supported, attributes_setting;
	UINT32 compatibilities, lowest_supported_version, last_attempt_version,
		last_attempt_status;
	UINT64 hardware_instance;
	void *dependencies;
};
struct fmp_protocol {
	EFI_STATUS(CDK2_MS_ABI *get_image_info)(void *, UINTN *, void *, UINT32 *,
		UINT8 *, UINTN *, UINT32 *, CHAR16 **);
	void *get_image;
	EFI_STATUS(CDK2_MS_ABI *set_image)(void *, UINT8, const void *, UINTN,
		const void *, void *, CHAR16 **);
	EFI_STATUS(CDK2_MS_ABI *check_image)(void *, UINT8, const void *, UINTN,
		UINT32 *);
	void *get_package_info, *set_package_info;
};

static void *boot_slot(UINTN offset)
{
	struct cdk2_system_table_view *system = runtime.context;

	return system == NULL ? NULL : system->boot->slots_before_locate_protocol[
		(offset - 24U) / sizeof(void *)];
}

static BOOLEAN guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	const UINT8 *left = (const void *)a, *right = (const void *)b;
	UINTN index;
	for (index = 0; index < sizeof(*a); index++)
		if (left[index] != right[index])
			return FALSE;
	return TRUE;
}

static UINT64 read_u64(const void *source)
{
	const UINT8 *bytes = source;
	UINT64 value = 0;
	UINTN index;
	for (index = 0; index < sizeof(value); index++)
		value |= (UINT64)bytes[index] << (index * 8U);
	return value;
}

EFI_STATUS __weak cdk2_capsule_cache_writeback_range_all_cpus(UINT64 address,
	UINT64 length)
{
	UINT64 line, end;
	if (length == 0U || address > MAX_UINT64 - length)
		return EFI_INVALID_PARAMETER;
	line = address & ~63ULL;
	end = address + length;
	for (;;) {
		__asm__ volatile("clflush (%0)" : : "r"((UINTN)line) : "memory");
		if (end - line <= 64U)
			break;
		line += 64U;
	}
	__asm__ volatile("mfence" : : : "memory");
	return EFI_SUCCESS;
}

#ifdef CDK2_CAPSULE_ENTRY_TEST
static const struct cdk2_capsule_policy policy = {
	.max_nonpopulate = 0x123400U,
	.max_populate = 0x567800U,
	.in_ram = TRUE,
	.persist = TRUE,
	.process_at_runtime = FALSE,
};
#else
static const struct cdk2_capsule_policy policy = {
	.max_nonpopulate = CONFIG_CDK2_CAPSULE_MAX_NONPOPULATE_SIZE,
	.max_populate = CONFIG_CDK2_CAPSULE_MAX_POPULATE_SIZE,
	.in_ram = CONFIG_CDK2_CAPSULE_IN_RAM,
	.persist = CONFIG_CDK2_CAPSULE,
	.process_at_runtime = CONFIG_CDK2_CAPSULE_PROCESS_AT_RUNTIME,
};
#endif

static EFI_STATUS fmp_payload(const struct fmp_image_header *image, UINTN available,
	BOOLEAN apply)
{
	locate_handles_fn *locate_handles = (void *)boot_slot(312U);
	handle_protocol_fn *handle_protocol = (void *)boot_slot(152U);
	allocate_pool_fn *allocate_pool = (void *)boot_slot(64U);
	free_pool_fn *free_pool = (void *)boot_slot(72U);
	void **handles = NULL;
	UINTN count = 0, handle_index;
	EFI_STATUS result = EFI_UNSUPPORTED;
	UINTN header_size = image->version >= 3U ? sizeof(*image) :
		image->version == 2U ? offsetof(struct fmp_image_header, capsule_support) :
		offsetof(struct fmp_image_header, hardware_instance);
	if (image->version < 1U || image->version > 3U || available < header_size ||
	    image->reserved[0] != 0U || image->reserved[1] != 0U ||
	    image->reserved[2] != 0U ||
	    (image->version >= 3U && (image->capsule_support & ~3ULL) != 0U) ||
	    image->image_size > available - header_size ||
	    image->vendor_size > available - header_size - image->image_size ||
	    !locate_handles || !handle_protocol || !allocate_pool || !free_pool)
		return EFI_INVALID_PARAMETER;
	result = locate_handles(2U, &fmp_protocol_guid, NULL, &count, &handles);
	if (EFI_ERROR(result))
		return result;
	result = EFI_UNSUPPORTED;
	for (handle_index = 0; handle_index < count; handle_index++) {
		struct fmp_protocol *fmp;
		struct fmp_image_descriptor *descriptors = NULL;
		UINTN info_size = 0, descriptor_size = 0, descriptor_index;
		UINT32 descriptor_version = 0, package_version = 0;
		UINT8 descriptor_count = 0;
		CHAR16 *package_name = NULL;
		EFI_STATUS status = handle_protocol(handles[handle_index], &fmp_protocol_guid,
			(void **)&fmp);
		if (EFI_ERROR(status) || fmp == NULL || fmp->get_image_info == NULL)
			continue;
		status = fmp->get_image_info(fmp, &info_size, NULL, &descriptor_version,
			&descriptor_count, &descriptor_size, &package_version, &package_name);
		if (status != EFI_BUFFER_TOO_SMALL || !info_size ||
		    descriptor_size < offsetof(struct fmp_image_descriptor, image_id) ||
		    descriptor_count > info_size / descriptor_size)
			continue;
		status = allocate_pool(4U, info_size, (void **)&descriptors);
		if (EFI_ERROR(status)) {
			result = status;
			break;
		}
		status = fmp->get_image_info(fmp, &info_size, descriptors, &descriptor_version,
			&descriptor_count, &descriptor_size, &package_version, &package_name);
		if (!EFI_ERROR(status)) {
			for (descriptor_index = 0; descriptor_index < descriptor_count;
			     descriptor_index++) {
				struct fmp_image_descriptor *descriptor = (void *)
					((UINT8 *)descriptors + descriptor_index * descriptor_size);
				const EFI_GUID *image_type = (const void *)((const UINT8 *)image +
					offsetof(struct fmp_image_header, image_type));
				UINT64 hardware = descriptor_version >= 3U &&
					descriptor_size >= offsetof(struct fmp_image_descriptor,
					hardware_instance) + sizeof(descriptor->hardware_instance) ?
					descriptor->hardware_instance : 0;
				UINT32 updatable = 0;
				if (descriptor->image_index != image->image_index ||
			    !guid_equal(&descriptor->image_type, image_type) ||
			    (image->version >= 2U && image->hardware_instance != 0U &&
			     hardware != image->hardware_instance))
					continue;
				if (fmp->check_image != NULL)
					status = fmp->check_image(fmp, image->image_index,
						(const UINT8 *)image + header_size, image->image_size,
						&updatable);
				else
					status = EFI_SUCCESS;
				if (EFI_ERROR(status) ||
				    (fmp->check_image != NULL && updatable != 1U)) {
					result = EFI_UNSUPPORTED;
					continue;
				}
				result = EFI_SUCCESS;
				if (apply) {
					CHAR16 *abort_reason = NULL;

					if (fmp->set_image == NULL)
						result = EFI_UNSUPPORTED;
					else
						result = fmp->set_image(fmp, image->image_index,
					(const UINT8 *)image + header_size, image->image_size,
					(const UINT8 *)image + header_size + image->image_size,
					NULL, &abort_reason);
					if (abort_reason != NULL)
						(void)free_pool(abort_reason);
				}
				break;
			}
		}
		if (package_name != NULL)
			(void)free_pool(package_name);
		(void)free_pool(descriptors);
		if (!EFI_ERROR(result))
			break;
	}
	if (handles != NULL)
		(void)free_pool(handles);
	return result;
}

static EFI_STATUS fmp_capsule(const struct cdk2_capsule_header *capsule, BOOLEAN apply)
{
	const UINT8 *base = (const UINT8 *)capsule + capsule->header_size;
	const struct fmp_capsule_header *header = (const void *)base;
	const UINT8 *offsets;
	UINTN body_size, items, index;
	EFI_STATUS status;

	if (!guid_equal(&capsule->guid, &fmp_capsule_guid))
		return EFI_UNSUPPORTED;
	if (capsule->image_size < capsule->header_size + sizeof(*header))
		return EFI_INVALID_PARAMETER;
	body_size = capsule->image_size - capsule->header_size;
	items = (UINTN)header->embedded_count + header->payload_count;
	if (header->version != 1U || !header->payload_count ||
	    header->embedded_count != 0U || items > (body_size - sizeof(*header)) / sizeof(UINT64))
		return EFI_UNSUPPORTED;
	offsets = (const void *)(header + 1);
	for (index = 0; index < items; index++)
		if (read_u64(offsets + index * sizeof(UINT64)) <
		    sizeof(*header) + items * sizeof(UINT64) ||
		    read_u64(offsets + index * sizeof(UINT64)) > body_size ||
		    (index != 0U && read_u64(offsets + index * sizeof(UINT64)) <=
		     read_u64(offsets + (index - 1U) * sizeof(UINT64))))
			return EFI_INVALID_PARAMETER;
	for (index = header->embedded_count; index < items; index++) {
		UINTN offset = (UINTN)read_u64(offsets + index * sizeof(UINT64));
		UINTN end = index + 1U < items ? (UINTN)read_u64(offsets +
			(index + 1U) * sizeof(UINT64)) : body_size;
		if (end - offset < offsetof(struct fmp_image_header, hardware_instance))
			return EFI_INVALID_PARAMETER;
		status = fmp_payload((const void *)(base + offset), end - offset, apply);
		if (EFI_ERROR(status))
			return status;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS support(const struct cdk2_capsule_header *capsule, void *context)
{
	(void)context;
	return fmp_capsule(capsule, FALSE);
}

static EFI_STATUS process(const struct cdk2_capsule_header *capsule, void *context)
{
	(void)context;
	return fmp_capsule(capsule, TRUE);
}

static EFI_STATUS persist(UINTN sequence, UINT64 scatter_gather, void *context)
{
	set_variable_fn *set_variable = (void *)runtime_services->set_variable;
	CHAR16 name[32] = L"CapsuleUpdateData";
	UINTN value = sequence, digits = 0, index = 17;

	(void)context;
	if (set_variable == NULL)
		return EFI_OUT_OF_RESOURCES;
	if (sequence != 0U) {
		do {
			digits++;
			value /= 10U;
		} while (value != 0U);
		if (index + digits >= ARRAY_SIZE(name))
			return EFI_OUT_OF_RESOURCES;
		value = sequence;
		index += digits;
		name[index] = 0;
		while (digits-- != 0U) {
			name[--index] = (CHAR16)(L'0' + value % 10U);
			value /= 10U;
		}
	}
	return set_variable(name, (EFI_GUID *)&capsule_vendor_guid, 7U,
		sizeof(scatter_gather), &scatter_gather);
}

static EFI_STATUS writeback(UINT64 scatter_gather, void *context)
{
	struct capsule_block { UINT64 length, address; };
	const struct capsule_block *block = (const void *)(UINTN)scatter_gather;
	UINTN walked = 0;
	EFI_STATUS status;
	(void)context;
	while (block != NULL && walked++ < SIZE_1MB / sizeof(*block)) {
		status = cdk2_capsule_cache_writeback_range_all_cpus((UINT64)(UINTN)block,
			sizeof(*block));
		if (EFI_ERROR(status))
			return status;
		if (block->length == 0U) {
			if (block->address == 0U)
				return EFI_SUCCESS;
			block = (const void *)(UINTN)block->address;
			continue;
		}
		if (block->address > MAX_UINT64 - block->length)
			return EFI_INVALID_PARAMETER;
		status = cdk2_capsule_cache_writeback_range_all_cpus(block->address,
			block->length);
		if (EFI_ERROR(status))
			return status;
		block++;
	}
	return EFI_INVALID_PARAMETER;
}

static void warm_reset(void *context)
{
	reset_system_fn *reset = (void *)runtime_services->reset_system;

	(void)context;
	if (reset != NULL)
		reset(1U, EFI_SUCCESS, 0, NULL);
}

static EFI_STATUS CDK2_MS_ABI update_capsule(
	const struct cdk2_capsule_header *const *capsules, UINTN count, UINT64 scatter_gather)
{
	return cdk2_capsule_update(&runtime, capsules, count, scatter_gather, &policy, support);
}

static EFI_STATUS CDK2_MS_ABI query_capsule(
	const struct cdk2_capsule_header *const *capsules, UINTN count,
	cdk2_uint64_ptr maximum_size, cdk2_uint32_ptr reset_type)
{
	return cdk2_capsule_query(capsules, count, &policy, support, NULL,
		maximum_size, reset_type);
}

static EFI_STATUS convert(void **pointer, void *context)
{
	convert_pointer_fn *convert_pointer = (void *)runtime_services->convert_pointer;

	(void)context;
	return convert_pointer == NULL ? EFI_UNSUPPORTED : convert_pointer(0, pointer);
}

static void CDK2_MS_ABI virtual_address_change(void *event, void *context)
{
	EFI_STATUS status;
	(void)event;
	(void)context;
	if (!runtime_active)
		return;
	status = convert((void **)&runtime_services, NULL);
	if (!EFI_ERROR(status))
		(void)cdk2_capsule_convert_runtime(&runtime, convert, NULL);
}

static void CDK2_MS_ABI exit_boot_services(void *event, void *context)
{
	(void)event;
	(void)context;
	if (!runtime_active)
		return;
	runtime.exited_boot_services = TRUE;
}

static void restore_slots(struct cdk2_runtime_services_view *rt, void *old_update,
	void *old_query, UINT32 old_crc)
{
	rt->update_capsule = old_update;
	rt->query_capsule = old_query;
	rt->header.crc32 = old_crc;
}

EFI_STATUS CDK2_MS_ABI cdk2_capsule_runtime_entry(void *image,
	struct cdk2_system_table_view *system)
{
	create_event_ex_fn *create_event_ex;
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
	void *old_update, *old_query;
	UINT32 old_crc;
	EFI_STATUS status, uninstall_status;

	(void)image;
	if (system == NULL || system->boot == NULL || system->runtime == NULL)
		return EFI_INVALID_PARAMETER;
	runtime_services = system->runtime;
	runtime_active = TRUE;
	old_update = system->runtime->update_capsule;
	old_query = system->runtime->query_capsule;
	old_crc = system->runtime->header.crc32;
	runtime = (struct cdk2_capsule_runtime) {
		.context = system,
		.process = process,
		.persist = persist,
		.writeback = writeback,
		.warm_reset = warm_reset,
	};
	status = cdk2_capsule_install_runtime_slots(system->runtime, system->boot,
		update_capsule, query_capsule);
	if (EFI_ERROR(status))
		return status;
	install_multiple = system->boot->install_multiple;
	if (install_multiple == NULL) {
		status = EFI_UNSUPPORTED;
		goto restore;
	}
	capsule_handle = NULL;
	status = install_multiple(&capsule_handle, &capsule_arch_guid, NULL, NULL);
	if (EFI_ERROR(status))
		goto restore;
	create_event_ex = (void *)system->boot->create_event_ex;
	if (create_event_ex == NULL) {
		status = EFI_UNSUPPORTED;
		goto uninstall;
	}
	va_event = NULL;
	status = create_event_ex(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, virtual_address_change,
		NULL, &va_change_guid, &va_event);
	if (EFI_ERROR(status))
		goto uninstall;
	ebs_event = NULL;
	status = create_event_ex(EVT_NOTIFY_SIGNAL, TPL_NOTIFY, exit_boot_services,
		NULL, &ebs_guid, &ebs_event);
	if (!EFI_ERROR(status))
		return EFI_SUCCESS;
uninstall:
	uninstall_multiple = system->boot->uninstall_multiple;
	if (uninstall_multiple == NULL)
		return EFI_UNSUPPORTED;
	uninstall_status = uninstall_multiple(capsule_handle, &capsule_arch_guid, NULL, NULL);
	if (EFI_ERROR(uninstall_status))
		return uninstall_status;
	runtime_active = FALSE;
	{
		close_event_fn *close_event = (void *)boot_slot(112U);
		if (close_event != NULL && va_event != NULL)
			(void)close_event(va_event);
		if (close_event != NULL && ebs_event != NULL)
			(void)close_event(ebs_event);
		va_event = NULL;
		ebs_event = NULL;
	}
	capsule_handle = NULL;
restore:
	runtime_active = FALSE;
	restore_slots(system->runtime, old_update, old_query, old_crc);
	return status;
}
