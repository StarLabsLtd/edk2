/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#define _GNU_SOURCE
#include <cdk2/acpi_table.h>

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096U

struct system_table_view;
struct acpi_table_protocol;
typedef EFI_STATUS CDK2_MS_ABI install_acpi_table_fn(
	struct acpi_table_protocol *, const void *, UINTN, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI
uninstall_acpi_table_fn(struct acpi_table_protocol *, UINTN);
struct acpi_table_protocol {
	install_acpi_table_fn *install;
	uninstall_acpi_table_fn *uninstall;
};
typedef EFI_STATUS CDK2_MS_ABI allocate_pages_fn(UINT32, UINT32, UINTN,
						 EFI_PHYSICAL_ADDRESS *);
typedef EFI_STATUS CDK2_MS_ABI free_pages_fn(EFI_PHYSICAL_ADDRESS, UINTN);
typedef EFI_STATUS CDK2_MS_ABI install_configuration_table_fn(const EFI_GUID *,
							      void *);
typedef EFI_STATUS CDK2_MS_ABI install_multiple_fn(void **, ...);
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

EFI_STATUS CDK2_MS_ABI cdk2_acpi_table_entry(void *,
					     struct system_table_view *);
const void *cdk2_acpi_table_protocol(void);
const struct cdk2_acpi_tables *cdk2_acpi_active_tables(void);

struct allocation {
	void *address;
	UINTN size;
};
static struct allocation allocations[16];
static UINTN allocation_calls;
static UINTN free_calls;
static UINTN config_calls;
static UINTN protocol_calls;
static UINTN fail_allocation;
static UINTN fail_config;
static BOOLEAN fail_protocol;
static void *published_rsdp;

static EFI_STATUS CDK2_MS_ABI allocate_pages(UINT32 type, UINT32 memory_type,
					     UINTN pages,
						     EFI_PHYSICAL_ADDRESS * address)
{
	void *allocation;

	(void)type;
	(void)memory_type;
	allocation_calls++;
	if (allocation_calls == fail_allocation)
		return EFI_OUT_OF_RESOURCES;
	allocation = mmap(NULL, pages * PAGE_SIZE, PROT_READ | PROT_WRITE,
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (allocation == MAP_FAILED)
		return EFI_OUT_OF_RESOURCES;
	allocations[allocation_calls - 1U] =
		(struct allocation){allocation, pages * PAGE_SIZE};
	*address = (UINTN)allocation;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI free_pages(EFI_PHYSICAL_ADDRESS address,
					 UINTN pages)
{
	(void)munmap((void *)(UINTN)address, pages * PAGE_SIZE);
	free_calls++;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI install_configuration_table(const EFI_GUID * guid,
							  void *table)
{
	(void)guid;
	config_calls++;
	if (table != NULL && config_calls == fail_config)
		return EFI_DEVICE_ERROR;
	if (table != NULL)
		published_rsdp = table;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle, ...)
{
	protocol_calls++;
	*handle = (void *)0x1234;
	return fail_protocol ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static void reset_faults(void)
{
	memset(allocations, 0, sizeof(allocations));
	allocation_calls = 0;
	free_calls = 0;
	config_calls = 0;
	protocol_calls = 0;
	fail_allocation = 0;
	fail_config = 0;
	fail_protocol = FALSE;
	published_rsdp = NULL;
}

static void make_table(UINT8 *table)
{
	memset(table, 0, 36U);
	memcpy(table, "SSDT", 4U);
	table[4] = 36U;
}

static int expect(BOOLEAN condition, const char *expression, int line)
{
	if (condition)
		return 0;
	fprintf(stderr, "%s:%d: %s\n", __FILE__, line, expression);
	return 1;
}

#define EXPECT(condition)                                                      \
	(failures += expect((condition), #condition, __LINE__))

int main(void)
{
	struct boot_services_view boot = {0};
	struct system_table_view system = {{0}, &boot};
	struct acpi_table_protocol *protocol;
	const struct cdk2_acpi_tables *active;
	UINT8 table[36];
	UINTN key;
	int failures = 0;

	boot.allocate_pages = allocate_pages;
	boot.free_pages = free_pages;
	boot.install_configuration_table = install_configuration_table;
	boot.install_multiple = install_multiple;
	reset_faults();
	fail_allocation = 2U;
	EXPECT(cdk2_acpi_table_entry((void *)1, &system) ==
		       EFI_OUT_OF_RESOURCES &&
	       free_calls == 1U);
	reset_faults();
	fail_config = 2U;
	EXPECT(cdk2_acpi_table_entry((void *)1, &system) == EFI_DEVICE_ERROR &&
	       free_calls == 3U && config_calls == 4U);
	reset_faults();
	fail_protocol = TRUE;
	EXPECT(cdk2_acpi_table_entry((void *)1, &system) == EFI_DEVICE_ERROR &&
	       free_calls == 3U && protocol_calls == 1U);
	reset_faults();
	EXPECT(cdk2_acpi_table_entry((void *)1, &system) == EFI_SUCCESS);
	EXPECT(published_rsdp != NULL && config_calls == 2U &&
	       protocol_calls == 1U);
	protocol = (struct acpi_table_protocol *)cdk2_acpi_table_protocol();
	active = cdk2_acpi_active_tables();
	make_table(table);
	EXPECT(protocol->install(protocol, table, sizeof(table), &key) ==
		       EFI_SUCCESS &&
	       active->count == 1U);
	EXPECT(protocol->uninstall(protocol, key) == EFI_SUCCESS &&
	       active->count == 0);
	if (failures == 0)
		puts("ACPI table driver tests: PASS");
	return failures != 0;
}
