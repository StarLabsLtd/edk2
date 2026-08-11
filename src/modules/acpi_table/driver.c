/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/acpi_table.h>

#define ACPI_TABLE_CAPACITY 64U
#define PAGE_SIZE 4096U
#define ALLOCATE_MAX_ADDRESS 1U
#define BOOT_SERVICES_DATA 4U

typedef EFI_STATUS CDK2_MS_ABI allocate_pages_fn(UINT32 type,
						 UINT32 memory_type,
						 UINTN pages,
						 EFI_PHYSICAL_ADDRESS * address);
typedef EFI_STATUS CDK2_MS_ABI free_pages_fn(EFI_PHYSICAL_ADDRESS address,
					     UINTN pages);
typedef EFI_STATUS CDK2_MS_ABI
install_configuration_table_fn(const EFI_GUID * guid, void *table);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **handle, ...);

struct boot_services_view {
	UINT8 before_allocate_pages[40];
	allocate_pages_fn *allocate_pages;
	free_pages_fn *free_pages;
	UINT8 before_install_configuration_table[136];
	install_configuration_table_fn *install_configuration_table;
	UINT8 before_install_multiple[128];
	install_multiple_fn *install_multiple;
};

struct system_table_view {
	UINT8 before_boot_services[96];
	struct boot_services_view *boot_services;
};

struct allocation {
	void *address;
	UINTN pages;
};

struct acpi_table_protocol;
typedef EFI_STATUS CDK2_MS_ABI install_acpi_table_fn(
	struct acpi_table_protocol *, const void *, UINTN, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI
uninstall_acpi_table_fn(struct acpi_table_protocol *, UINTN);
struct acpi_table_protocol {
	install_acpi_table_fn *install;
	uninstall_acpi_table_fn *uninstall;
};

static const EFI_GUID acpi_table_protocol_guid = {
	0xffe06bddU,
	0x6107U,
	0x46a6U,
	{0x7bU, 0xb2U, 0x5aU, 0x9cU, 0x7eU, 0xc5U, 0x27U, 0x5cU}};
static const EFI_GUID acpi_10_table_guid = {
	0xeb9d2d30U,
	0x2d88U,
	0x11d3U,
	{0x9aU, 0x16U, 0x00U, 0x90U, 0x27U, 0x3fU, 0xc1U, 0x4dU}};
static const EFI_GUID acpi_20_table_guid = {
	0x8868e871U,
	0xe4f1U,
	0x11d3U,
	{0xbcU, 0x22U, 0x00U, 0x80U, 0xc7U, 0x3cU, 0x88U, 0x81U}};

static struct boot_services_view *boot_services;
static struct allocation allocations[ACPI_TABLE_CAPACITY + 3U];
static struct cdk2_acpi_record records[ACPI_TABLE_CAPACITY];
static struct cdk2_acpi_tables tables;
static void *driver_handle;

static EFI_STATUS allocate(void *context, UINTN size, UINTN alignment,
			   void **buffer)
{
	EFI_PHYSICAL_ADDRESS address = MAX_UINT32;
	UINTN pages;
	UINTN index;
	EFI_STATUS status;

	(void)context;
	if (size == 0 || alignment > PAGE_SIZE)
		return EFI_UNSUPPORTED;
	pages = (size + PAGE_SIZE - 1U) / PAGE_SIZE;
	if (pages == 0)
		return EFI_OUT_OF_RESOURCES;
	for (index = 0; index < ARRAY_SIZE(allocations); index++)
		if (allocations[index].address == NULL)
			break;
	if (index == ARRAY_SIZE(allocations))
		return EFI_OUT_OF_RESOURCES;
	status = boot_services->allocate_pages(
		ALLOCATE_MAX_ADDRESS, BOOT_SERVICES_DATA, pages, &address);
	if (EFI_ERROR(status))
		return status;
	if (address > MAX_UINT32) {
		(void)boot_services->free_pages(address, pages);
		return EFI_UNSUPPORTED;
	}
	allocations[index].address = (void *)(UINTN)address;
	allocations[index].pages = pages;
	*buffer = allocations[index].address;
	return EFI_SUCCESS;
}

static void release(void *context, void *buffer)
{
	UINTN index;

	(void)context;
	for (index = 0; index < ARRAY_SIZE(allocations); index++)
		if (allocations[index].address == buffer) {
			(void)boot_services->free_pages(
				(UINTN)buffer, allocations[index].pages);
			allocations[index].address = NULL;
			allocations[index].pages = 0;
			return;
		}
}

static EFI_STATUS CDK2_MS_ABI
install_table(struct acpi_table_protocol *protocol, const void *table,
	      UINTN size, UINTN *key)
{
	(void)protocol;
	return cdk2_acpi_install(&tables, table, size, key);
}

static EFI_STATUS CDK2_MS_ABI
uninstall_table(struct acpi_table_protocol *protocol, UINTN key)
{
	(void)protocol;
	return cdk2_acpi_uninstall(&tables, key);
}

static struct acpi_table_protocol protocol = {install_table, uninstall_table};

EFI_STATUS CDK2_MS_ABI cdk2_acpi_table_entry(void *image,
					     struct system_table_view *system)
{
	const struct cdk2_acpi_allocator allocator = {NULL, allocate, release};
	EFI_STATUS status;

	(void)image;
	if (system == NULL || system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	boot_services = system->boot_services;
	status = cdk2_acpi_tables_initialize(&tables, &allocator, records,
					     ACPI_TABLE_CAPACITY);
	if (EFI_ERROR(status))
		return status;
	status = boot_services->install_configuration_table(&acpi_20_table_guid,
							    tables.rsdp);
	if (!EFI_ERROR(status))
		status = boot_services->install_configuration_table(
			&acpi_10_table_guid, tables.rsdp);
	if (!EFI_ERROR(status))
		status = boot_services->install_multiple(
			&driver_handle, &acpi_table_protocol_guid, &protocol,
			NULL);
	if (EFI_ERROR(status)) {
		(void)boot_services->install_configuration_table(
			&acpi_10_table_guid, NULL);
		(void)boot_services->install_configuration_table(
			&acpi_20_table_guid, NULL);
		cdk2_acpi_tables_destroy(&tables);
		return status;
	}
	return EFI_SUCCESS;
}

const void *cdk2_acpi_table_protocol(void)
{
	return &protocol;
}

const struct cdk2_acpi_tables *cdk2_acpi_active_tables(void)
{
	return &tables;
}
