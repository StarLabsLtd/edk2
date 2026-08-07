/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/status_code_router/status_code_router.c"

#include <stdio.h>
#include <string.h>

static unsigned int calls;
static uint32_t seen_value;
static unsigned int conversions;
static event_notify_fn *address_change;

static uint64_t CDK2_MS_ABI callback(uint32_t type, uint32_t value,
	uint32_t instance, struct cdk2_guid *caller, struct cdk2_status_code_data *data)
{
	(void)type;
	(void)instance;
	(void)caller;
	(void)data;
	calls++;
	seen_value = value;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI recursive_callback(uint32_t type, uint32_t value,
	uint32_t instance, struct cdk2_guid *caller, struct cdk2_status_code_data *data)
{
	return report_status_code(type, value, instance, caller, data);
}

static uint64_t CDK2_MS_ABI mock_install(void **handle,
	const struct cdk2_guid *guid, void *interface, ...)
{
	(void)guid;
	(void)interface;
	*handle = (void *)1;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_create_event_ex(uint32_t type, uint64_t tpl,
	event_notify_fn notify, void *context, const struct cdk2_guid *group, void **event)
{
	if (type != EVT_NOTIFY_SIGNAL || tpl != TPL_NOTIFY || context != NULL ||
	    group != &virtual_address_change_guid)
		return EFI_INVALID_PARAMETER;
	address_change = notify;
	*event = (void *)2;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_convert(uint64_t disposition, void **address)
{
	(void)disposition;
	(void)address;
	conversions++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 status-code router test: %s\n", message);
		return 1;
	}
	return 0;
}

int main(void)
{
	struct boot_services_view boot;
	struct runtime_services_view runtime;
	struct system_table system_table;
	int failures = 0;

	memset(&boot, 0, sizeof(boot));
	memset(&runtime, 0, sizeof(runtime));
	memset(&system_table, 0, sizeof(system_table));
	boot.install_multiple_protocols = mock_install;
	boot.create_event_ex = mock_create_event_ex;
	runtime.convert_pointer = mock_convert;
	system_table.boot_services = &boot;
	system_table.runtime_services = &runtime;
	failures += expect(cdk2_status_code_router_entry(NULL, &system_table) == EFI_SUCCESS,
		"entry succeeds");
	failures += expect(register_handler(NULL, TPL_HIGH_LEVEL) == EFI_INVALID_PARAMETER,
		"null callback rejected");
	failures += expect(register_handler(callback, TPL_NOTIFY) == RSC_UNSUPPORTED,
		"unsafe callback TPL rejected");
	failures += expect(register_handler(callback, TPL_HIGH_LEVEL) == EFI_SUCCESS,
		"callback registered");
	failures += expect(register_handler(callback, TPL_HIGH_LEVEL) ==
		RSC_ALREADY_STARTED, "duplicate callback rejected");
	failures += expect(report_status_code(1, 0x1234, 2, NULL, NULL) == EFI_SUCCESS &&
		calls == 1 && seen_value == 0x1234, "status dispatched");
	failures += expect(register_handler(recursive_callback, TPL_HIGH_LEVEL) == EFI_SUCCESS,
		"recursive callback registered");
	failures += expect(report_status_code(1, 2, 3, NULL, NULL) == EFI_SUCCESS,
		"outer recursive report completes");
	address_change(NULL, NULL);
	failures += expect(conversions == 2, "runtime callbacks converted");
	failures += expect(unregister_handler(callback) == EFI_SUCCESS &&
		unregister_handler(callback) == EFI_NOT_FOUND, "callback unregistered");
	return failures == 0 ? 0 : 1;
}
