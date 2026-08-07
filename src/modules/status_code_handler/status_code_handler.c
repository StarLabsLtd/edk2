/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * Native release-profile form of the pre-standalone status-code handler.
 * The original source is Copyright (c) 2006-2020, Intel Corporation, and
 * Copyright (c) 2016, Hewlett Packard Enterprise Development LP.
 */

#include <cdk2/status_code_router.h>

#include <stddef.h>
#include <stdint.h>

#define EVT_NOTIFY_SIGNAL 0x00000200U
#define TPL_NOTIFY 16U

typedef void CDK2_MS_ABI event_notify_fn(void *event, void *context);
typedef uint64_t CDK2_MS_ABI locate_protocol_fn(const struct cdk2_guid *protocol,
	void *registration, void **interface);
typedef uint64_t CDK2_MS_ABI create_event_ex_fn(uint32_t type, uint64_t tpl,
	event_notify_fn notify, void *context, const struct cdk2_guid *event_group,
	void **event);

struct table_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t header_size;
	uint32_t crc32;
	uint32_t reserved;
};

struct boot_services_view {
	uint8_t before_locate_protocol[320];
	locate_protocol_fn *locate_protocol;
	uint8_t before_create_event_ex[40];
	create_event_ex_fn *create_event_ex;
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
	void *runtime_services;
	struct boot_services_view *boot_services;
};

static const struct cdk2_guid rsc_handler_guid = {
	0x86212936, 0x0e76, 0x41c8, { 0xa0, 0x3a, 0x2a, 0xf2, 0xfc, 0x1c, 0x39, 0xe2 }
};
static const struct cdk2_guid virtual_address_change_guid = {
	0x13fa7698, 0xc831, 0x49c7, { 0x87, 0xea, 0x8f, 0x43, 0xfc, 0xc2, 0x51, 0x96 }
};

static struct cdk2_rsc_handler_protocol *rsc_handler;
static void *virtual_address_event;

static void CDK2_MS_ABI virtual_address_change(void *event, void *context)
{
	(void)event;
	(void)context;
}

uint64_t CDK2_MS_ABI
cdk2_status_code_handler_entry(void *image_handle, struct system_table *system_table)
{
	uint64_t status;

	(void)image_handle;
	if (system_table == NULL || system_table->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	status = system_table->boot_services->locate_protocol(&rsc_handler_guid, NULL,
		(void **)&rsc_handler);
	if (status != EFI_SUCCESS)
		return status;
	return system_table->boot_services->create_event_ex(EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
		virtual_address_change, NULL, &virtual_address_change_guid,
		&virtual_address_event);
}
