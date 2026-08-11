/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/acpi_table.h>

#define RSDT_SIGNATURE 0x54445352U
#define XSDT_SIGNATURE 0x54445358U
#define DSDT_SIGNATURE 0x54445344U
#define FACS_SIGNATURE 0x53434146U
#define FADT_SIGNATURE 0x50434146U
#define RSDP_REVISION 2U
#define ACPI_REVISION 1U

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

static void write64(UINT8 *bytes, UINT64 value)
{
	write32(bytes, (UINT32)value);
	write32(bytes + 4, (UINT32)(value >> 32));
}

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;

	while (size-- != 0)
		*out++ = *in++;
}

static void fill(UINT8 *bytes, UINT8 value, UINTN size)
{
	while (size-- != 0)
		*bytes++ = value;
}

UINT8 cdk2_acpi_checksum(const void *buffer, UINTN size)
{
	const UINT8 *bytes = buffer;
	UINT8 sum = 0;

	while (size-- != 0)
		sum = (UINT8)(sum + *bytes++);
	return sum;
}

static void checksum_table(UINT8 *table, UINT32 length)
{
	table[9] = 0;
	table[9] = (UINT8)(0U - cdk2_acpi_checksum(table, length));
}

static void header(UINT8 *table, UINT32 signature)
{
	static const UINT8 oem_id[6] = {'C', 'D', 'K', '2', ' ', ' '};
	static const UINT8 oem_table[8] = {'C', 'D', 'K', '2',
					   'T', 'A', 'B', 'L'};

	fill(table, 0, CDK2_ACPI_HEADER_SIZE);
	write32(table, signature);
	table[8] = ACPI_REVISION;
	copy_bytes(table + 10, oem_id, sizeof(oem_id));
	copy_bytes(table + 16, oem_table, sizeof(oem_table));
	write32(table + 24, 1U);
	write32(table + 28, 0x324b4443U);
	write32(table + 32, 1U);
}

static struct cdk2_acpi_record *find_record(struct cdk2_acpi_tables *tables,
					    UINT32 signature)
{
	UINTN index;

	for (index = 0; index < tables->count; index++)
		if (read32(tables->records[index].table) == signature)
			return &tables->records[index];
	return NULL;
}

static EFI_STATUS synchronize_fadt(struct cdk2_acpi_tables *tables)
{
	struct cdk2_acpi_record *fadt = find_record(tables, FADT_SIGNATURE);
	struct cdk2_acpi_record *dsdt = find_record(tables, DSDT_SIGNATURE);
	struct cdk2_acpi_record *facs = find_record(tables, FACS_SIGNATURE);
	UINTN dsdt_address = dsdt == NULL ? 0 : (UINTN)dsdt->table;
	UINTN facs_address = facs == NULL ? 0 : (UINTN)facs->table;
	UINT8 *bytes;
	UINTN index;

	if (fadt == NULL) {
		static const UINT8 default_identity[26] = {
			'C', 'D', 'K', '2', ' ', ' ', 'C', 'D', 'K',
			'2', 'T', 'A', 'B', 'L', 1U,  0,   0,	0,
			'C', 'D', 'K', '2', 1U,	 0,   0,   0};

		copy_bytes(tables->rsdt + 10, default_identity,
			   sizeof(default_identity));
		copy_bytes(tables->xsdt + 10, default_identity,
			   sizeof(default_identity));
		return EFI_SUCCESS;
	}
	if (fadt->length < 44U || dsdt_address > MAX_UINT32 ||
	    facs_address > MAX_UINT32)
		return EFI_UNSUPPORTED;
	bytes = fadt->table;
	for (index = 10U; index < CDK2_ACPI_HEADER_SIZE; index++) {
		tables->rsdt[index] = bytes[index];
		tables->xsdt[index] = bytes[index];
	}
	write32(bytes + 36, (UINT32)facs_address);
	write32(bytes + 40, (UINT32)dsdt_address);
	if (fadt->length >= 148U) {
		write64(bytes + 132, facs_address);
		write64(bytes + 140, dsdt_address);
	}
	checksum_table(bytes, fadt->length);
	return EFI_SUCCESS;
}

static EFI_STATUS rebuild_roots(struct cdk2_acpi_tables *tables)
{
	UINT32 rsdt_length = CDK2_ACPI_HEADER_SIZE;
	UINT32 xsdt_length = CDK2_ACPI_HEADER_SIZE;
	UINTN index;

	for (index = 0; index < tables->count; index++) {
		UINTN address;

		if (!tables->records[index].root_entry)
			continue;
		address = (UINTN)tables->records[index].table;
		if (address > MAX_UINT32)
			return EFI_UNSUPPORTED;
		write32(tables->rsdt + rsdt_length, (UINT32)address);
		write64(tables->xsdt + xsdt_length, address);
		rsdt_length += 4U;
		xsdt_length += 8U;
	}
	write32(tables->rsdt + 4, rsdt_length);
	write32(tables->xsdt + 4, xsdt_length);
	checksum_table(tables->rsdt, rsdt_length);
	checksum_table(tables->xsdt, xsdt_length);
	tables->rsdp[8] = 0;
	tables->rsdp[32] = 0;
	tables->rsdp[8] = (UINT8)(0U - cdk2_acpi_checksum(tables->rsdp, 20U));
	tables->rsdp[32] =
		(UINT8)(0U -
			cdk2_acpi_checksum(tables->rsdp, CDK2_ACPI_RSDP_SIZE));
	return EFI_SUCCESS;
}

EFI_STATUS
cdk2_acpi_tables_initialize(struct cdk2_acpi_tables *tables,
			    const struct cdk2_acpi_allocator *allocator,
			    struct cdk2_acpi_record *records, UINTN capacity)
{
	UINTN rsdt_size;
	UINTN xsdt_size;
	EFI_STATUS status;

	if (tables == NULL || allocator == NULL ||
	    allocator->allocate == NULL || allocator->free == NULL ||
	    records == NULL || capacity == 0 ||
	    capacity > (MAX_UINT32 - CDK2_ACPI_HEADER_SIZE) / 8U)
		return EFI_INVALID_PARAMETER;
	fill((UINT8 *)tables, 0, sizeof(*tables));
	tables->allocator = *allocator;
	tables->records = records;
	tables->capacity = capacity;
	tables->next_key = 1U;
	rsdt_size = CDK2_ACPI_HEADER_SIZE + capacity * 4U;
	xsdt_size = CDK2_ACPI_HEADER_SIZE + capacity * 8U;
	status = allocator->allocate(allocator->context, CDK2_ACPI_RSDP_SIZE,
				     16U, (void **)&tables->rsdp);
	if (!EFI_ERROR(status))
		status = allocator->allocate(allocator->context, rsdt_size, 16U,
					     (void **)&tables->rsdt);
	if (!EFI_ERROR(status))
		status = allocator->allocate(allocator->context, xsdt_size, 16U,
					     (void **)&tables->xsdt);
	if (EFI_ERROR(status)) {
		cdk2_acpi_tables_destroy(tables);
		return status;
	}
	fill(tables->rsdp, 0, CDK2_ACPI_RSDP_SIZE);
	fill(tables->rsdt, 0, rsdt_size);
	fill(tables->xsdt, 0, xsdt_size);
	copy_bytes(tables->rsdp, "RSD PTR ", 8U);
	copy_bytes(tables->rsdp + 9, "CDK2  ", 6U);
	tables->rsdp[15] = RSDP_REVISION;
	write32(tables->rsdp + 16, (UINT32)(UINTN)tables->rsdt);
	write32(tables->rsdp + 20, CDK2_ACPI_RSDP_SIZE);
	write64(tables->rsdp + 24, (UINTN)tables->xsdt);
	if ((UINTN)tables->rsdp > MAX_UINT32 ||
	    (UINTN)tables->rsdt > MAX_UINT32) {
		cdk2_acpi_tables_destroy(tables);
		return EFI_UNSUPPORTED;
	}
	header(tables->rsdt, RSDT_SIGNATURE);
	header(tables->xsdt, XSDT_SIGNATURE);
	return rebuild_roots(tables);
}

void cdk2_acpi_tables_destroy(struct cdk2_acpi_tables *tables)
{
	UINTN index;

	if (tables == NULL || tables->allocator.free == NULL)
		return;
	for (index = 0; index < tables->count; index++)
		tables->allocator.free(tables->allocator.context,
				       tables->records[index].table);
	if (tables->xsdt != NULL)
		tables->allocator.free(tables->allocator.context, tables->xsdt);
	if (tables->rsdt != NULL)
		tables->allocator.free(tables->allocator.context, tables->rsdt);
	if (tables->rsdp != NULL)
		tables->allocator.free(tables->allocator.context, tables->rsdp);
	tables->count = 0;
	tables->rsdp = NULL;
	tables->rsdt = NULL;
	tables->xsdt = NULL;
}

EFI_STATUS cdk2_acpi_install(struct cdk2_acpi_tables *tables,
			     const void *source, UINTN table_size, UINTN *key)
{
	const UINT8 *source_bytes = source;
	struct cdk2_acpi_record *record;
	UINT32 signature;
	UINT32 length;
	EFI_STATUS status;

	if (tables == NULL || source == NULL || key == NULL ||
	    table_size < 8U || table_size > CDK2_ACPI_MAX_TABLE_SIZE ||
	    tables->count == tables->capacity)
		return EFI_INVALID_PARAMETER;
	signature = read32(source_bytes);
	length = read32(source_bytes + 4);
	if (length > table_size || length > CDK2_ACPI_MAX_TABLE_SIZE ||
	    (signature == FACS_SIGNATURE ? length < 64U
					 : length < CDK2_ACPI_HEADER_SIZE) ||
	    signature == RSDT_SIGNATURE || signature == XSDT_SIGNATURE)
		return EFI_COMPROMISED_DATA;
	if ((signature == FADT_SIGNATURE || signature == DSDT_SIGNATURE ||
	     signature == FACS_SIGNATURE) &&
	    find_record(tables, signature) != NULL)
		return EFI_INVALID_PARAMETER;
	record = &tables->records[tables->count];
	status = tables->allocator.allocate(tables->allocator.context, length,
					    16U, &record->table);
	if (EFI_ERROR(status))
		return status;
	copy_bytes(record->table, source, length);
	if (signature != FACS_SIGNATURE)
		checksum_table(record->table, length);
	record->length = length;
	record->key = tables->next_key++;
	if (tables->next_key == 0)
		tables->next_key = 1U;
	record->root_entry =
		signature != DSDT_SIGNATURE && signature != FACS_SIGNATURE;
	tables->count++;
	status = synchronize_fadt(tables);
	if (!EFI_ERROR(status))
		status = rebuild_roots(tables);
	if (EFI_ERROR(status)) {
		tables->count--;
		tables->allocator.free(tables->allocator.context,
				       record->table);
		return status;
	}
	*key = record->key;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_acpi_uninstall(struct cdk2_acpi_tables *tables, UINTN key)
{
	UINTN index;
	EFI_STATUS status;

	if (tables == NULL || key == 0)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < tables->count; index++)
		if (tables->records[index].key == key)
			break;
	if (index == tables->count)
		return EFI_NOT_FOUND;
	tables->allocator.free(tables->allocator.context,
			       tables->records[index].table);
	for (; index + 1U < tables->count; index++)
		tables->records[index] = tables->records[index + 1U];
	tables->count--;
	status = synchronize_fadt(tables);
	if (!EFI_ERROR(status))
		status = rebuild_roots(tables);
	return status;
}

const void *cdk2_acpi_rsdp(const struct cdk2_acpi_tables *tables)
{
	return tables == NULL ? NULL : tables->rsdp;
}
