/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * Native form of the admitted watchdog timer implementation.  The original
 * source is Copyright (c) 2006-2018, Intel Corporation.
 */

#include <cdk2/watchdog.h>

#include <stddef.h>
#include <stdint.h>

#define WATCHDOG_ALREADY_STARTED ((1ULL << 63) | 20ULL)
#define WATCHDOG_TIMEOUT ((1ULL << 63) | 18ULL)
#define EVT_TIMER 0x80000000U
#define EVT_NOTIFY_SIGNAL 0x00000200U
#define TPL_NOTIFY 16U
#define TIMER_CANCEL 0U
#define TIMER_RELATIVE 2U
#define RESET_COLD 0U

struct guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

struct table_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t header_size;
	uint32_t crc32;
	uint32_t reserved;
};

typedef void CDK2_MS_ABI event_notify_fn(void *event, void *context);
typedef uint64_t CDK2_MS_ABI create_event_fn(uint32_t type,
	uint64_t notify_tpl, event_notify_fn notify, void *context, void **event);
typedef uint64_t CDK2_MS_ABI set_timer_fn(void *event,
	uint32_t type, uint64_t trigger_time);
typedef uint64_t CDK2_MS_ABI install_multiple_protocols_fn(
	void **handle, const struct guid *protocol, void *interface, ...);
typedef void CDK2_MS_ABI reset_system_fn(uint32_t reset_type,
	uint64_t status, size_t data_size, const void *reset_data);

struct boot_services_view {
	uint8_t before_create_event[80];
	create_event_fn *create_event;
	set_timer_fn *set_timer;
	uint8_t before_install_multiple[232];
	install_multiple_protocols_fn *install_multiple_protocols;
};

struct runtime_services_view {
	uint8_t before_reset_system[104];
	reset_system_fn *reset_system;
};

struct system_table {
	struct table_header header;
	uint16_t *firmware_vendor;
	uint32_t firmware_revision;
	uint32_t pad;
	void *console_in_handle;
	void *console_in;
	void *console_out_handle;
	void *console_out;
	void *standard_error_handle;
	void *standard_error;
	struct runtime_services_view *runtime_services;
	struct boot_services_view *boot_services;
};

static const struct guid watchdog_protocol_guid = {
	0x665e3ff5, 0x46cc, 0x11d4, { 0x9a, 0x38, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};

static struct boot_services_view *boot_services;
static struct runtime_services_view *runtime_services;
static void *watchdog_handle;
static void *watchdog_event;
static uint64_t watchdog_period;
static cdk2_watchdog_notify_fn *watchdog_notify;

static uint64_t CDK2_MS_ABI
register_handler(struct cdk2_watchdog *watchdog, cdk2_watchdog_notify_fn notify)
{
	(void)watchdog;
	if (notify == NULL && watchdog_notify == NULL)
		return EFI_INVALID_PARAMETER;
	if (notify != NULL && watchdog_notify != NULL)
		return WATCHDOG_ALREADY_STARTED;
	watchdog_notify = notify;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI
set_timer_period(struct cdk2_watchdog *watchdog, uint64_t period)
{
	(void)watchdog;
	watchdog_period = period;
	return boot_services->set_timer(watchdog_event,
		period == 0 ? TIMER_CANCEL : TIMER_RELATIVE, period);
}

static uint64_t CDK2_MS_ABI
get_timer_period(struct cdk2_watchdog *watchdog, uint64_t *period)
{
	(void)watchdog;
	if (period == NULL)
		return EFI_INVALID_PARAMETER;
	*period = watchdog_period;
	return EFI_SUCCESS;
}

static struct cdk2_watchdog watchdog = {
	.register_handler = register_handler,
	.set_timer_period = set_timer_period,
	.get_timer_period = get_timer_period,
};

static void CDK2_MS_ABI watchdog_expires(void *event, void *context)
{
	(void)event;
	(void)context;
	if (watchdog_notify != NULL)
		watchdog_notify(watchdog_period);
	runtime_services->reset_system(RESET_COLD, WATCHDOG_TIMEOUT, 0, NULL);
}

uint64_t CDK2_MS_ABI
cdk2_watchdog_entry(void *image_handle, struct system_table *system_table)
{
	uint64_t status;

	(void)image_handle;
	boot_services = system_table->boot_services;
	runtime_services = system_table->runtime_services;
	status = boot_services->create_event(EVT_TIMER | EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
		watchdog_expires, NULL, &watchdog_event);
	if (status != EFI_SUCCESS)
		return status;
	return boot_services->install_multiple_protocols(&watchdog_handle,
		&watchdog_protocol_guid, &watchdog, NULL);
}
