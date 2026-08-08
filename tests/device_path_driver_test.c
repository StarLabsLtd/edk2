/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/device_path.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef EFI_STATUS CDK2_MS_ABI allocate_pool_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_pool_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_multiple_fn(void *, ...);
struct boot_services_view {
	UINT8 header[24];
	void *slots_before_allocate[5];
	allocate_pool_fn *allocate_pool;
	free_pool_fn *free_pool;
	void *slots_before_install_multiple[34];
	install_multiple_fn *install_multiple;
	uninstall_multiple_fn *uninstall_multiple;
};
struct system_table_view {
	UINT8 before_boot_services[96];
	struct boot_services_view *boot;
};
EFI_STATUS CDK2_MS_ABI cdk2_device_path_entry(void *, struct system_table_view *);

static UINTN installs, uninstalls, frees;

static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{
	(void)type;
	*buffer = malloc(size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{
	free(buffer);
	frees++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	if (handle == NULL || installs >= 3)
		return EFI_INVALID_PARAMETER;
	installs++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle, ...)
{
	(void)handle;
	uninstalls++;
	return EFI_SUCCESS;
}

struct fault_context {
	UINTN calls;
	UINTN fail_at;
	UINTN rolled_back;
	const EFI_GUID * rollback[3];
	const EFI_GUID * attempted[3];
};

static EFI_STATUS fault_install(void *context, void **handle, const EFI_GUID * guid,
	void *interface)
{
	struct fault_context *fault = context;
	(void)interface;
	*handle = (void *)0x55;
	fault->attempted[fault->calls] = guid;
	return fault->calls++ == fault->fail_at ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS fault_uninstall(void *context, void *handle, const EFI_GUID * guid,
	void *interface)
{
	struct fault_context *fault = context;
	(void)handle;
	(void)interface;
	fault->rollback[fault->rolled_back++] = guid;
	return EFI_DEVICE_ERROR;
}

static int guid_equal(const EFI_GUID *a, const EFI_GUID *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "device-path driver test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct boot_services_view boot_services = {0};
	struct system_table_view system = {{0}, &boot_services};
	struct cdk2_device_path_publication_ops ops;
	struct fault_context fault;
	const struct cdk2_device_path_utilities_protocol *utilities;
	const struct cdk2_device_path_to_text_protocol *to_text;
	const struct cdk2_device_path_from_text_protocol *from_text;
	struct cdk2_device_path *path;
	CHAR16 source[] = {'P', 'c', 'i', '(', '0', 'x', '1', ',',
		'0', 'x', '2', ')', 0};
	CHAR16 *text;
	void *handle = NULL;
	EFI_STATUS entry_status;
	int failures = 0;

	boot_services.allocate_pool = allocate_pool;
	boot_services.free_pool = free_pool;
	boot_services.install_multiple = install_multiple;
	boot_services.uninstall_multiple = uninstall_multiple;
	entry_status = cdk2_device_path_entry((void *)1, &system);
	if (entry_status != EFI_SUCCESS)
		fprintf(stderr, "device-path entry status: 0x%llx installs=%llu\n",
			(unsigned long long)entry_status, (unsigned long long)installs);
	failures += expect(entry_status == EFI_SUCCESS &&
		installs == 3 && uninstalls == 0, "entry did not publish exactly three protocols");
	utilities = cdk2_device_path_utilities();
	to_text = cdk2_device_path_text_converter();
	from_text = cdk2_device_path_text_parser();
	path = from_text->path_from_text(source);
	failures += expect(path != NULL && utilities->get_size(path) == 10,
		"published parser/utilities are not callable");
	text = to_text->path_to_text(path, FALSE, TRUE);
	failures += expect(text != NULL && text[0] == 'P' && text[9] == 'x',
		"published formatter is not callable");
	(void)free_pool(text);
	(void)free_pool(path);
	path = utilities->append_path(NULL, NULL);
	failures += expect(path != NULL && utilities->get_size(path) == 4,
		"NULL append did not create an end path");
	(void)free_pool(path);

	ops.context = &fault;
	ops.install = fault_install;
	ops.uninstall = fault_uninstall;
	memset(&fault, 0, sizeof(fault));
	fault.fail_at = 2;
	failures += expect(cdk2_device_path_publish(&ops, &handle) == EFI_DEVICE_ERROR &&
		fault.calls == 3 && fault.rolled_back == 2 &&
		guid_equal(fault.attempted[0], &cdk2_device_path_utilities_protocol_guid) &&
		guid_equal(fault.attempted[1], &cdk2_device_path_to_text_protocol_guid) &&
		guid_equal(fault.attempted[2], &cdk2_device_path_from_text_protocol_guid) &&
		guid_equal(fault.rollback[0], &cdk2_device_path_to_text_protocol_guid) &&
		guid_equal(fault.rollback[1], &cdk2_device_path_utilities_protocol_guid),
		"publication failure was not rolled back in reverse order");
	memset(&fault, 0, sizeof(fault));
	fault.fail_at = 0;
	failures += expect(cdk2_device_path_publish(&ops, &handle) == EFI_DEVICE_ERROR &&
		fault.rolled_back == 0, "first publication failure attempted rollback");
	failures += expect(cdk2_device_path_entry(NULL, NULL) == EFI_INVALID_PARAMETER,
		"invalid entry context accepted");
	failures += expect(frees == 3, "protocol wrapper allocation leaked");
	return failures == 0 ? 0 : 1;
}
