/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/watchdog/watchdog.c"

#include <stdio.h>
#include <string.h>

static uint32_t timer_type;
static uint64_t timer_period;
static uint64_t notified_period;
static uint32_t reset_type;
static uint64_t reset_status;
static event_notify_fn *observed_event_notify;
static const struct guid *installed_guid;
static void *installed_interface;

static uint64_t CDK2_MS_ABI mock_create_event(uint32_t type, uint64_t tpl,
	event_notify_fn notify, void *context, void **event)
{
	if (type != (EVT_TIMER | EVT_NOTIFY_SIGNAL) || tpl != TPL_NOTIFY || context != NULL)
		return EFI_INVALID_PARAMETER;
	observed_event_notify = notify;
	*event = (void *)1;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_set_timer(void *event, uint32_t type,
	uint64_t period)
{
	if (event != (void *)1)
		return EFI_INVALID_PARAMETER;
	timer_type = type;
	timer_period = period;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI mock_install(void **handle,
	const struct guid *guid, void *interface, ...)
{
	*handle = (void *)2;
	installed_guid = guid;
	installed_interface = interface;
	return EFI_SUCCESS;
}

static void CDK2_MS_ABI mock_reset(uint32_t type, uint64_t status,
	size_t size, const void *data)
{
	(void)size;
	(void)data;
	reset_type = type;
	reset_status = status;
}

static void CDK2_MS_ABI mock_notify(uint64_t period)
{
	notified_period = period;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 watchdog test: %s\n", message);
		return 1;
	}
	return 0;
}

int main(void)
{
	struct boot_services_view boot;
	struct runtime_services_view runtime;
	struct system_table system_table;
	uint64_t period = 0;
	int failures = 0;

	memset(&boot, 0, sizeof(boot));
	memset(&runtime, 0, sizeof(runtime));
	memset(&system_table, 0, sizeof(system_table));
	boot.create_event = mock_create_event;
	boot.set_timer = mock_set_timer;
	boot.install_multiple_protocols = mock_install;
	runtime.reset_system = mock_reset;
	system_table.boot_services = &boot;
	system_table.runtime_services = &runtime;

	failures += expect(cdk2_watchdog_entry(NULL, &system_table) == EFI_SUCCESS,
		"entry succeeds");
	failures += expect(installed_guid == &watchdog_protocol_guid &&
		installed_interface == &watchdog, "architectural protocol installed");
	failures += expect(watchdog.get_timer_period(&watchdog, NULL) ==
		EFI_INVALID_PARAMETER, "null output rejected");
	failures += expect(watchdog.register_handler(&watchdog, NULL) ==
		EFI_INVALID_PARAMETER, "missing handler cannot be removed");
	failures += expect(watchdog.register_handler(&watchdog, mock_notify) == EFI_SUCCESS,
		"handler registered");
	failures += expect(watchdog.register_handler(&watchdog, mock_notify) ==
		WATCHDOG_ALREADY_STARTED, "duplicate handler rejected");
	failures += expect(watchdog.set_timer_period(&watchdog, 500) == EFI_SUCCESS &&
		timer_type == TIMER_RELATIVE && timer_period == 500, "timer armed");
	failures += expect(watchdog.get_timer_period(&watchdog, &period) == EFI_SUCCESS &&
		period == 500, "period returned");
	observed_event_notify(NULL, NULL);
	failures += expect(notified_period == 500 && reset_type == RESET_COLD &&
		reset_status == WATCHDOG_TIMEOUT, "expiry notifies then resets");
	failures += expect(watchdog.register_handler(&watchdog, NULL) == EFI_SUCCESS,
		"handler unregistered");
	failures += expect(watchdog.set_timer_period(&watchdog, 0) == EFI_SUCCESS &&
		timer_type == TIMER_CANCEL, "timer cancelled");
	return failures == 0 ? 0 : 1;
}
