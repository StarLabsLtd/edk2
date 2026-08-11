/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_ACPI_TABLE_H_
#define CDK2_ACPI_TABLE_H_

#include <uefi.h>

#define CDK2_ACPI_HEADER_SIZE 36U
#define CDK2_ACPI_RSDP_SIZE 36U
#define CDK2_ACPI_MAX_TABLE_SIZE SIZE_1MB

typedef EFI_STATUS cdk2_acpi_allocate_fn(void *context, UINTN size,
					 UINTN alignment, void **buffer);
typedef void cdk2_acpi_free_fn(void *context, void *buffer);

struct cdk2_acpi_allocator {
	void *context;
	cdk2_acpi_allocate_fn *allocate;
	cdk2_acpi_free_fn *free;
};

struct cdk2_acpi_record {
	void *table;
	UINT32 length;
	UINTN key;
	BOOLEAN root_entry;
};

struct cdk2_acpi_tables {
	struct cdk2_acpi_allocator allocator;
	struct cdk2_acpi_record *records;
	UINTN capacity;
	UINTN count;
	UINTN next_key;
	UINT8 *rsdp;
	UINT8 *rsdt;
	UINT8 *xsdt;
};

EFI_STATUS
cdk2_acpi_tables_initialize(struct cdk2_acpi_tables *tables,
			    const struct cdk2_acpi_allocator *allocator,
			    struct cdk2_acpi_record *records, UINTN capacity);
void cdk2_acpi_tables_destroy(struct cdk2_acpi_tables *tables);
EFI_STATUS cdk2_acpi_install(struct cdk2_acpi_tables *tables, const void *table,
			     UINTN table_size, UINTN *key);
EFI_STATUS cdk2_acpi_uninstall(struct cdk2_acpi_tables *tables, UINTN key);
const void *cdk2_acpi_rsdp(const struct cdk2_acpi_tables *tables);
UINT8 cdk2_acpi_checksum(const void *buffer, UINTN size);

#endif
