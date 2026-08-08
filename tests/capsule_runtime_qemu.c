/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/capsule_runtime.h>
#include <cdk2/capsule_runtime_entry.h>

typedef EFI_STATUS CDK2_MS_ABI query_capsule_fn(
	const struct cdk2_capsule_header *const *capsules, UINTN count,
	cdk2_uint64_ptr maximum_size, cdk2_uint32_ptr reset_type);
typedef EFI_STATUS CDK2_MS_ABI update_capsule_fn(
	const struct cdk2_capsule_header *const *capsules, UINTN count,
	UINT64 scatter_gather);

static UINT8 port_read(UINT16 port)
{
	UINT8 value;

	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}

static void port_write(UINT16 port, UINT8 value)
{
	__asm__ volatile("outb %0, %w1" : : "a"(value), "Nd"(port));
}

static void serial_write(const char *text)
{
	while (*text != '\0') {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		port_write(0x3f8, (UINT8)*text++);
	}
}

EFI_STATUS CDK2_MS_ABI capsule_runtime_qemu_entry(void *image,
	struct cdk2_system_table_view *system)
{
	query_capsule_fn *query;
	update_capsule_fn *update;
	UINT64 maximum_size = 0;
	UINT32 reset_type = 0;
	EFI_STATUS query_status, update_status;

	(void)image;
	if (system == NULL || system->runtime == NULL) {
		serial_write("CDK2_CAPSULE_ORACLE_BAD_TABLE\r\n");
		return EFI_INVALID_PARAMETER;
	}
	query = system->runtime->query_capsule;
	update = system->runtime->update_capsule;
	if (query == NULL || update == NULL) {
		serial_write("CDK2_CAPSULE_ORACLE_MISSING\r\n");
		return EFI_UNSUPPORTED;
	}
	query_status = query(NULL, 0, &maximum_size, &reset_type);
	update_status = update(NULL, 0, 0);
	if (query_status != EFI_INVALID_PARAMETER ||
	    update_status != EFI_INVALID_PARAMETER) {
		serial_write("CDK2_CAPSULE_ORACLE_BAD_STATUS\r\n");
		return EFI_DEVICE_ERROR;
	}
	serial_write("CDK2_CAPSULE_QUERY_INVALID_OK\r\n");
	serial_write("CDK2_CAPSULE_UPDATE_INVALID_OK\r\n");
	return EFI_SUCCESS;
}
