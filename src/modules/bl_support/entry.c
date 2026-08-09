/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/bl_support.h>
#include <cdk2/pcd.h>
#include <pi/hob.h>

#define MAX_HOB_LIST_SIZE (1024U * 1024U)

typedef EFI_STATUS CDK2_MS_ABI locate_protocol_fn(const EFI_GUID *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI set32_fn(size_t, uint32_t);
typedef EFI_STATUS CDK2_MS_ABI set64_fn(size_t, uint64_t);
typedef EFI_STATUS CDK2_MS_ABI set_ptr_fn(size_t, size_t *, void *);

struct table_header { uint64_t signature; uint32_t revision, size, crc, reserved; };
struct configuration_table { EFI_GUID guid; void *table; };
struct system_table_view {
	struct table_header header;
	uint16_t *vendor;
	uint32_t revision, pad;
	void *console[6], *runtime;
	struct cdk2_pcd_boot_services *boot;
	size_t table_count;
	struct configuration_table *tables;
};

static const EFI_GUID pcd_protocol_guid = {
	0x11b34006, 0xd85b, 0x4d0a, { 0xa2, 0x90, 0xd5, 0xa5, 0x71, 0x31, 0x0e, 0xf7 }
};
static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};

static EFI_STATUS set32(void *context, uint32_t token, uint32_t value)
{
	struct cdk2_pcd_protocol *pcd = context;
	return ((set32_fn *)pcd->set32)(token, value);
}

static EFI_STATUS set64(void *context, uint32_t token, uint64_t value)
{
	struct cdk2_pcd_protocol *pcd = context;
	return ((set64_fn *)pcd->set64)(token, value);
}

static EFI_STATUS set_ptr(void *context, uint32_t token, const void *value, size_t size)
{
	struct cdk2_pcd_protocol *pcd = context;
	return ((set_ptr_fn *)pcd->set_ptr)(token, &size, (void *)value);
}

static EFI_STATUS hob_extent(const void *list, size_t *size)
{
	const uint8_t *bytes = list;
	size_t walked = 0;

	if (list == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	while (walked + sizeof(EFI_HOB_GENERIC_HEADER) <= MAX_HOB_LIST_SIZE) {
		const EFI_HOB_GENERIC_HEADER *header = (const void *)(bytes + walked);

		if (header->hob_type == EFI_HOB_TYPE_END_OF_HOB_LIST) {
			*size = walked + sizeof(*header);
			return EFI_SUCCESS;
		}
		if (header->hob_length < sizeof(*header) ||
		    header->hob_length > MAX_HOB_LIST_SIZE - walked)
			return EFI_COMPROMISED_DATA;
		walked += header->hob_length;
	}
	return EFI_COMPROMISED_DATA;
}

EFI_STATUS CDK2_MS_ABI cdk2_bl_support_entry(void *image_handle, void *system_table)
{
	static const struct cdk2_bl_support_policy policy = { 0 };
	struct system_table_view *system = system_table;
	struct cdk2_pcd_protocol *pcd;
	struct cdk2_bl_support_ops ops;
	locate_protocol_fn *locate;
	void *hob_list = NULL;
	size_t hob_size, index;
	EFI_STATUS status;

	(void)image_handle;
	if (system == NULL || system->boot == NULL || system->tables == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < system->table_count; index++) {
		const uint8_t *a = (const uint8_t *)&system->tables[index].guid;
		const uint8_t *b = (const uint8_t *)&hob_list_guid;
		size_t byte;

		for (byte = 0; byte < sizeof(EFI_GUID) && a[byte] == b[byte]; byte++) { }
		if (byte == sizeof(EFI_GUID)) {
			hob_list = system->tables[index].table;
			break;
		}
	}
	if (hob_list == NULL)
		return EFI_NOT_FOUND;
	status = hob_extent(hob_list, &hob_size);
	if (EFI_ERROR(status))
		return status;
	locate = (void *)system->boot->locate_protocol;
	if (locate == NULL)
		return EFI_UNSUPPORTED;
	status = locate(&pcd_protocol_guid, NULL, (void **)&pcd);
	if (EFI_ERROR(status))
		return status;
	if (pcd == NULL || pcd->set32 == NULL || pcd->set64 == NULL || pcd->set_ptr == NULL)
		return EFI_UNSUPPORTED;
	ops = (struct cdk2_bl_support_ops){ set32, set64, set_ptr, pcd };
	return cdk2_bl_support_apply(hob_list, hob_size, &policy, &ops);
}
