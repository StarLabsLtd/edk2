/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * Native form of the pre-standalone report-status-code router.
 * The original source is Copyright (c) 2009-2018, Intel Corporation, and
 * Copyright (c) Microsoft Corporation.
 */

#include <cdk2/status_code_router.h>

#include <stddef.h>
#include <stdint.h>

#define RSC_MAX_CALLBACKS 16U
#define TPL_HIGH_LEVEL 31U
#define EVT_NOTIFY_SIGNAL 0x00000200U
#define TPL_NOTIFY 16U
#define RSC_UNSUPPORTED ((1ULL << 63) | 3ULL)
#define RSC_OUT_OF_RESOURCES ((1ULL << 63) | 9ULL)
#define RSC_ALREADY_STARTED ((1ULL << 63) | 20ULL)
#define RSC_DEVICE_ERROR ((1ULL << 63) | 7ULL)

struct table_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t header_size;
	uint32_t crc32;
	uint32_t reserved;
};

typedef void CDK2_MS_ABI event_notify_fn(void *event, void *context);
typedef uint64_t CDK2_MS_ABI install_multiple_protocols_fn(void **handle,
	const struct cdk2_guid *protocol, void *interface, ...);
typedef uint64_t CDK2_MS_ABI create_event_ex_fn(uint32_t type, uint64_t tpl,
	event_notify_fn notify, void *context, const struct cdk2_guid *event_group,
	void **event);
typedef uint64_t CDK2_MS_ABI convert_pointer_fn(uint64_t disposition,
	void **address);

struct boot_services_view {
	uint8_t before_install_multiple[328];
	install_multiple_protocols_fn *install_multiple_protocols;
	uint8_t before_create_event_ex[32];
	create_event_ex_fn *create_event_ex;
};

struct runtime_services_view {
	uint8_t before_convert_pointer[64];
	convert_pointer_fn *convert_pointer;
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

static const struct cdk2_guid rsc_handler_guid = {
	0x86212936, 0x0e76, 0x41c8, { 0xa0, 0x3a, 0x2a, 0xf2, 0xfc, 0x1c, 0x39, 0xe2 }
};
static const struct cdk2_guid status_code_guid = {
	0xd2b2b828, 0x0826, 0x48a7, { 0xb3, 0xdf, 0x98, 0x3c, 0x00, 0x60, 0x24, 0xf0 }
};
static const struct cdk2_guid virtual_address_change_guid = {
	0x13fa7698, 0xc831, 0x49c7, { 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 }
};

static cdk2_status_code_callback *callbacks[RSC_MAX_CALLBACKS];
static struct runtime_services_view *runtime_services;
static uint32_t reporting;
static void *router_handle;
static void *virtual_address_event;

static uint64_t CDK2_MS_ABI register_handler(cdk2_status_code_callback callback,
	uint64_t tpl)
{
	size_t index;
	size_t empty = RSC_MAX_CALLBACKS;

	if (callback == NULL)
		return EFI_INVALID_PARAMETER;
	if (tpl != TPL_HIGH_LEVEL)
		return RSC_UNSUPPORTED;
	for (index = 0; index < RSC_MAX_CALLBACKS; index++) {
		if (callbacks[index] == callback)
			return RSC_ALREADY_STARTED;
		if (callbacks[index] == NULL && empty == RSC_MAX_CALLBACKS)
			empty = index;
	}
	if (empty == RSC_MAX_CALLBACKS)
		return RSC_OUT_OF_RESOURCES;
	callbacks[empty] = callback;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI unregister_handler(cdk2_status_code_callback callback)
{
	size_t index;

	if (callback == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < RSC_MAX_CALLBACKS; index++) {
		if (callbacks[index] == callback) {
			callbacks[index] = NULL;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

static uint64_t CDK2_MS_ABI report_status_code(uint32_t code_type,
	uint32_t value, uint32_t instance, struct cdk2_guid *caller_id,
	struct cdk2_status_code_data *data)
{
	size_t index;

	if (__atomic_exchange_n(&reporting, 1, __ATOMIC_ACQUIRE) != 0)
		return RSC_DEVICE_ERROR;
	for (index = 0; index < RSC_MAX_CALLBACKS; index++) {
		cdk2_status_code_callback *callback = callbacks[index];

		if (callback != NULL)
			callback(code_type, value, instance, caller_id, data);
	}
	__atomic_store_n(&reporting, 0, __ATOMIC_RELEASE);
	return EFI_SUCCESS;
}

static struct cdk2_rsc_handler_protocol rsc_handler = {
	.register_handler = register_handler,
	.unregister_handler = unregister_handler,
};
static struct cdk2_status_code_protocol status_code = {
	.report_status_code = report_status_code,
};

static void CDK2_MS_ABI virtual_address_change(void *event, void *context)
{
	size_t index;

	(void)event;
	(void)context;
	for (index = 0; index < RSC_MAX_CALLBACKS; index++) {
		if (callbacks[index] != NULL)
			runtime_services->convert_pointer(0, (void **)&callbacks[index]);
	}
}

uint64_t CDK2_MS_ABI
cdk2_status_code_router_entry(void *image_handle, struct system_table *system_table)
{
	uint64_t status;

	(void)image_handle;
	runtime_services = system_table->runtime_services;
	status = system_table->boot_services->install_multiple_protocols(&router_handle,
		&rsc_handler_guid, &rsc_handler, &status_code_guid, &status_code, NULL);
	if (status != EFI_SUCCESS)
		return status;
	return system_table->boot_services->create_event_ex(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
		virtual_address_change, NULL, &virtual_address_change_guid,
		&virtual_address_event);
}
