/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/status_code_handler/status_code_handler.c"

#include <stdio.h>
#include <string.h>

static struct cdk2_rsc_handler_protocol protocol;
static const struct cdk2_guid *located_guid;
static const struct cdk2_guid *event_guid;
static event_notify_fn *event_notify;

static uint64_t CDK2_MS_ABI mock_locate(const struct cdk2_guid *guid,
	void *registration, void **interface)
{
	if (registration != NULL)
		return EFI_INVALID_PARAMETER;
	located_guid = guid;
	*interface = &protocol;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_create_event_ex(uint32_t type, uint64_t tpl,
	event_notify_fn notify, void *context, const struct cdk2_guid *group, void **event)
{
	if (type != EVT_NOTIFY_SIGNAL || tpl != TPL_NOTIFY || context != NULL)
		return EFI_INVALID_PARAMETER;
	event_guid = group;
	event_notify = notify;
	*event = (void *)1;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 status-code handler test: %s\n", message);
		return 1;
	}
	return 0;
}

int main(void)
{
	struct boot_services_view boot;
	struct system_table system_table;
	int failures = 0;

	memset(&boot, 0, sizeof(boot));
	memset(&system_table, 0, sizeof(system_table));
	boot.locate_protocol = mock_locate;
	boot.create_event_ex = mock_create_event_ex;
	system_table.boot_services = &boot;
	failures += expect(cdk2_status_code_handler_entry(NULL, NULL) ==
		EFI_INVALID_PARAMETER, "null system table rejected");
	failures += expect(cdk2_status_code_handler_entry(NULL, &system_table) == EFI_SUCCESS,
		"release handler initialized");
	failures += expect(located_guid == &rsc_handler_guid && rsc_handler == &protocol,
		"native router located");
	failures += expect(event_guid == &virtual_address_change_guid &&
		event_notify != NULL, "virtual-address event registered");
	event_notify(NULL, NULL);
	return failures == 0 ? 0 : 1;
}
