/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * Derived from SecurityStubDxe in the pre-standalone cdk2 history.
 * Copyright (c) 2006-2018 Intel Corporation.
 */

#include <stddef.h>
#include <stdint.h>
#include <cdk2/security_router.h>
#include <uefi.h>

#define EFI_SUCCESS 0
#define EFI_ALREADY_STARTED EFIERR(20)

typedef uint64_t efi_status_t;
typedef void *efi_handle_t;

struct efi_guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

struct efi_table_header {
	uint64_t signature;
	uint32_t revision;
	uint32_t header_size;
	uint32_t crc32;
	uint32_t reserved;
};

struct efi_system_table {
	struct efi_table_header header;
	uint16_t *firmware_vendor;
	uint32_t firmware_revision;
	uint32_t padding;
	void *console_in_handle, *console_in, *console_out_handle, *console_out;
	void *standard_error_handle, *standard_error, *runtime_services;
	void *boot_services;
};

typedef efi_status_t (CDK2_MS_ABI * install_multiple_t)(efi_handle_t *,
						  const struct efi_guid *, void *, ...);
typedef efi_status_t (CDK2_MS_ABI * security_authenticate_t)(const void *, uint32_t,
						       const void *);
typedef efi_status_t (CDK2_MS_ABI * security2_authenticate_t)(const void *, const void *,
							void *, size_t, uint8_t);

struct security_protocol { security_authenticate_t file_authentication_state; };
struct security2_protocol { security2_authenticate_t file_authentication; };
struct boot_services_install_view {
	uint8_t unused[328];
	install_multiple_t install_multiple;
};

static const struct efi_guid security_guid = {
	0xa46423e3, 0x4617, 0x49f1,
	{ 0xb9, 0xff, 0xd1, 0xbf, 0xa9, 0x11, 0x58, 0x39 }
};
static const struct efi_guid security2_guid = {
	0x94ab2f58, 0x1438, 0x4ef1,
	{ 0x91, 0x52, 0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68 }
};

const EFI_GUID cdk2_security_router_guid = {
	0x3159cc63, 0x8e41, 0x4cb8,
	{ 0x86, 0x02, 0x9e, 0x3c, 0x63, 0x22, 0x44, 0x31 }
};

struct handler_slot {
	cdk2_security2_handler_fn *handler;
	void *context;
};

static struct handler_slot handlers[CDK2_SECURITY_ROUTER_MAX_HANDLERS];

static EFI_STATUS CDK2_MS_ABI register_handler(
	cdk2_security2_handler_fn *handler, void *context)
{
	UINTN index;

	if (handler == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < CDK2_SECURITY_ROUTER_MAX_HANDLERS; index++) {
		if (handlers[index].handler == handler && handlers[index].context == context)
			return EFI_ALREADY_STARTED;
		if (handlers[index].handler == NULL) {
			handlers[index] = (struct handler_slot){ handler, context };
			return EFI_SUCCESS;
		}
	}
	return EFI_OUT_OF_RESOURCES;
}

static EFI_STATUS CDK2_MS_ABI unregister_handler(
	cdk2_security2_handler_fn *handler, void *context)
{
	UINTN index;

	if (handler == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < CDK2_SECURITY_ROUTER_MAX_HANDLERS; index++)
		if (handlers[index].handler == handler && handlers[index].context == context) {
			handlers[index] = (struct handler_slot){0};
			return EFI_SUCCESS;
		}
	return EFI_NOT_FOUND;
}

static struct cdk2_security_router router = {
	register_handler, unregister_handler
};

static efi_status_t CDK2_MS_ABI authenticate(const void *protocol,
					uint32_t authentication_status,
					const void *file)
{
	(void)protocol;
	(void)authentication_status;
	(void)file;
	return EFI_SUCCESS;
}

static efi_status_t CDK2_MS_ABI authenticate2(const void *protocol, const void *file,
					 void *file_buffer, size_t file_size,
					 uint8_t boot_policy)
{
	EFI_STATUS status;
	UINTN index;

	(void)protocol;
	for (index = 0; index < CDK2_SECURITY_ROUTER_MAX_HANDLERS; index++) {
		if (handlers[index].handler == NULL)
			continue;
		status = handlers[index].handler(file, file_buffer, file_size,
			boot_policy, handlers[index].context);
		if (EFI_ERROR(status))
			return status;
	}
	return EFI_SUCCESS;
}

static struct security_protocol security = { authenticate };
static struct security2_protocol security2 = { authenticate2 };

efi_status_t CDK2_MS_ABI security_stub_initialize(efi_handle_t image_handle,
					     struct efi_system_table *system_table)
{
	efi_handle_t handle = NULL;
	struct boot_services_install_view *boot_services;

	(void)image_handle;
	if (system_table == NULL || system_table->boot_services == NULL)
		return 2; /* EFI_INVALID_PARAMETER */
	boot_services = system_table->boot_services;
	if (boot_services->install_multiple == NULL)
		return 3; /* EFI_UNSUPPORTED */
	return boot_services->install_multiple(&handle, &security2_guid, &security2,
				&security_guid, &security,
				(const struct efi_guid *)&cdk2_security_router_guid, &router, NULL);
}
