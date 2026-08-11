/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#define _GNU_SOURCE
#include <cdk2/acpi_table.h>

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#define CAPACITY 4U
#define PAGE_SIZE 4096U

struct allocation {
	void *address;
	UINTN size;
};

struct fixture {
	struct allocation allocations[16];
	UINTN allocation_count;
	UINTN frees;
	UINTN fail_at;
};

static UINT32 read32(const UINT8 *bytes)
{
	return (UINT32)bytes[0] | (UINT32)bytes[1] << 8 |
	       (UINT32)bytes[2] << 16 | (UINT32)bytes[3] << 24;
}

static void write32(UINT8 *bytes, UINT32 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
	bytes[2] = (UINT8)(value >> 16);
	bytes[3] = (UINT8)(value >> 24);
}

static EFI_STATUS allocate(void *context, UINTN size, UINTN alignment,
			   void **buffer)
{
	struct fixture *fixture = context;
	UINTN mapped = (size + PAGE_SIZE - 1U) & ~(PAGE_SIZE - 1U);
	void *address;

	(void)alignment;
	fixture->allocation_count++;
	if (fixture->allocation_count == fixture->fail_at)
		return EFI_OUT_OF_RESOURCES;
	address = mmap(NULL, mapped, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
	if (address == MAP_FAILED)
		return EFI_OUT_OF_RESOURCES;
	fixture->allocations[fixture->allocation_count - 1U] =
		(struct allocation){address, mapped};
	*buffer = address;
	return EFI_SUCCESS;
}

static void release(void *context, void *buffer)
{
	struct fixture *fixture = context;
	UINTN index;

	for (index = 0; index < fixture->allocation_count; index++)
		if (fixture->allocations[index].address == buffer) {
			(void)munmap(buffer, fixture->allocations[index].size);
			fixture->allocations[index].address = NULL;
			fixture->frees++;
			return;
		}
}

static void table(UINT8 *buffer, const char signature[4], UINT32 length)
{
	memset(buffer, 0, length);
	memcpy(buffer, signature, 4U);
	write32(buffer + 4, length);
	buffer[8] = 2U;
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
	struct fixture fixture = {0};
	struct cdk2_acpi_allocator allocator = {&fixture, allocate, release};
	struct cdk2_acpi_record records[CAPACITY];
	struct cdk2_acpi_tables tables;
	UINT8 source[64];
	UINT8 fadt[148];
	const UINT8 *rsdp;
	UINTN ssdt_key;
	UINTN dsdt_key;
	UINTN facs_key;
	UINTN fadt_key;
	UINTN key;
	int failures = 0;

	EXPECT(cdk2_acpi_tables_initialize(&tables, &allocator, records,
					   CAPACITY) == EFI_SUCCESS);
	rsdp = cdk2_acpi_rsdp(&tables);
	EXPECT(memcmp(rsdp, "RSD PTR ", 8U) == 0 && rsdp[15] == 2U);
	EXPECT(cdk2_acpi_checksum(rsdp, 20U) == 0 &&
	       cdk2_acpi_checksum(rsdp, CDK2_ACPI_RSDP_SIZE) == 0);
	table(source, "SSDT", sizeof(source));
	EXPECT(cdk2_acpi_install(&tables, source, sizeof(source), &ssdt_key) ==
	       EFI_SUCCESS);
	EXPECT(ssdt_key != 0 && tables.count == 1U &&
	       cdk2_acpi_checksum(records[0].table, sizeof(source)) == 0);
	EXPECT(read32(tables.rsdt + 4) == CDK2_ACPI_HEADER_SIZE + 4U &&
	       read32(tables.rsdt + CDK2_ACPI_HEADER_SIZE) ==
		       (UINT32)(UINTN)records[0].table);
	EXPECT(cdk2_acpi_checksum(tables.rsdt, read32(tables.rsdt + 4)) == 0);
	table(source, "DSDT", sizeof(source));
	EXPECT(cdk2_acpi_install(&tables, source, sizeof(source), &dsdt_key) ==
		       EFI_SUCCESS &&
	       read32(tables.rsdt + 4) == CDK2_ACPI_HEADER_SIZE + 4U);
	table(source, "FACS", sizeof(source));
	EXPECT(cdk2_acpi_install(&tables, source, sizeof(source), &facs_key) ==
		       EFI_SUCCESS &&
	       records[2].root_entry == FALSE);
	memset(fadt, 0, sizeof(fadt));
	memcpy(fadt, "FACP", 4U);
	write32(fadt + 4, sizeof(fadt));
	memcpy(fadt + 10, "OEM123", 6U);
	memcpy(fadt + 16, "OEMTABLE", 8U);
	EXPECT(cdk2_acpi_install(&tables, fadt, sizeof(fadt), &fadt_key) ==
	       EFI_SUCCESS);
	EXPECT(read32(records[3].table + 36) ==
		       (UINT32)(UINTN)records[2].table &&
	       read32(records[3].table + 40) ==
		       (UINT32)(UINTN)records[1].table &&
	       read32(records[3].table + 132) ==
		       (UINT32)(UINTN)records[2].table &&
	       read32(records[3].table + 140) ==
		       (UINT32)(UINTN)records[1].table &&
	       memcmp(tables.rsdt + 10, "OEM123OEMTABLE", 14U) == 0 &&
	       memcmp(tables.xsdt + 10, "OEM123OEMTABLE", 14U) == 0 &&
	       cdk2_acpi_checksum(records[3].table, sizeof(fadt)) == 0);
	EXPECT(cdk2_acpi_install(&tables, fadt, sizeof(fadt), &key) ==
	       EFI_INVALID_PARAMETER);
	EXPECT(cdk2_acpi_uninstall(&tables, dsdt_key) == EFI_SUCCESS &&
	       tables.count == 3U);
	EXPECT(read32(records[2].table + 40) == 0 &&
	       read32(records[2].table + 140) == 0 &&
	       cdk2_acpi_checksum(records[2].table, sizeof(fadt)) == 0);
	EXPECT(cdk2_acpi_uninstall(&tables, dsdt_key) == EFI_NOT_FOUND);
	table(source, "RSDT", sizeof(source));
	EXPECT(cdk2_acpi_install(&tables, source, sizeof(source), &key) ==
	       EFI_COMPROMISED_DATA);
	table(source, "SSDT", sizeof(source));
	write32(source + 4, sizeof(source) + 1U);
	EXPECT(cdk2_acpi_install(&tables, source, sizeof(source), &key) ==
	       EFI_COMPROMISED_DATA);
	fixture.fail_at = fixture.allocation_count + 1U;
	table(source, "SSDT", sizeof(source));
	EXPECT(cdk2_acpi_install(&tables, source, sizeof(source), &key) ==
		       EFI_OUT_OF_RESOURCES &&
	       tables.count == 3U);
	fixture.fail_at = 0;
	EXPECT(cdk2_acpi_uninstall(&tables, ssdt_key) == EFI_SUCCESS);
	EXPECT(cdk2_acpi_uninstall(&tables, facs_key) == EFI_SUCCESS);
	EXPECT(cdk2_acpi_uninstall(&tables, fadt_key) == EFI_SUCCESS);
	cdk2_acpi_tables_destroy(&tables);
	EXPECT(fixture.frees == fixture.allocation_count - 1U);
	if (failures == 0)
		puts("ACPI table ownership tests: PASS");
	return failures != 0;
}
