/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/*
 * A source-built Generic Memory Test Protocol implementation.  Coreboot has
 * already initialized DRAM, so this driver promotes PI GCD ranges marked
 * present and initialized and reports completion without destructive testing.
 */

#include <cdk2/null_memory_test.h>

#include <stddef.h>
#include <stdint.h>

#define EFI_SUCCESS 0ULL
#define EFI_INVALID_PARAMETER (1ULL << 63 | 2ULL)
#define EFI_NOT_FOUND (1ULL << 63 | 14ULL)
#define EFI_MEMORY_PRESENT 0x0100000000000000ULL
#define EFI_MEMORY_INITIALIZED 0x0200000000000000ULL
#define EFI_MEMORY_TESTED 0x0400000000000000ULL
#define EFI_MEMORY_RUNTIME 0x8000000000000000ULL
#define EFI_MEMORY_MORE_RELIABLE 0x0000000000010000ULL
#define SIXTEEN_MIB 0x01000000ULL

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

struct configuration_table {
	struct guid vendor_guid;
	void *vendor_table;
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
	void *boot_services;
	size_t configuration_table_count;
	struct configuration_table *configuration_table;
};

enum gcd_memory_type {
	gcd_memory_nonexistent,
	gcd_memory_reserved,
	gcd_memory_system,
	gcd_memory_mmio,
	gcd_memory_persistent,
	gcd_memory_more_reliable,
};

struct gcd_memory_descriptor {
	uint64_t base;
	uint64_t length;
	uint64_t capabilities;
	uint64_t attributes;
	enum gcd_memory_type type;
	uint32_t pad;
	void *image_handle;
	void *device_handle;
};

typedef uint64_t (__attribute__((ms_abi)) *add_memory_space_fn)(
	enum gcd_memory_type type, uint64_t base, uint64_t length, uint64_t capabilities);
typedef uint64_t (__attribute__((ms_abi)) *remove_memory_space_fn)(uint64_t base,
	uint64_t length);
typedef uint64_t (__attribute__((ms_abi)) *get_memory_descriptor_fn)(
	uint64_t base, struct gcd_memory_descriptor *descriptor);
typedef uint64_t (__attribute__((ms_abi)) *get_memory_map_fn)(
	size_t *count, struct gcd_memory_descriptor **map);
typedef uint64_t (__attribute__((ms_abi)) *free_pool_fn)(void *buffer);
typedef uint64_t (__attribute__((ms_abi)) *install_protocol_fn)(
	void **handle, const struct guid *protocol, uint32_t interface_type, void *interface);

struct dxe_services {
	struct table_header header;
	add_memory_space_fn add_memory_space;
	void *allocate_memory_space;
	void *free_memory_space;
	remove_memory_space_fn remove_memory_space;
	get_memory_descriptor_fn get_memory_descriptor;
	void *set_memory_attributes;
	get_memory_map_fn get_memory_map;
};

struct boot_services_view {
	uint8_t unused_before_free_pool[72];
	free_pool_fn free_pool;
	uint8_t unused_before_install_protocol[48];
	install_protocol_fn install_protocol;
};

static const struct guid dxe_services_guid = {
	0x05ad34ba, 0x6f02, 0x4214, { 0x95, 0x2e, 0x4d, 0xa0, 0x39, 0x8e, 0x2b, 0xb9 }
};
static const struct guid generic_memory_test_guid = {
	0x309de7f1, 0x7f5e, 0x4ace, { 0xb4, 0x9c, 0x53, 0x1b, 0xe5, 0xaa, 0x95, 0xef }
};

static struct dxe_services *dxe_services;
static struct boot_services_view *boot_services;
static uint64_t tested_memory;
static uint64_t total_memory;
static void *protocol_handle;

static int guid_equal(const struct guid *left, const struct guid *right)
{
	const uint8_t *a = (const uint8_t *)left;
	const uint8_t *b = (const uint8_t *)right;
	size_t index;

	for (index = 0; index < sizeof(*left); index++) {
		if (a[index] != b[index])
			return 0;
	}
	return 1;
}

static uint64_t promote_memory(const struct gcd_memory_descriptor *descriptor,
	uint64_t base, uint64_t length)
{
	enum gcd_memory_type type =
		(descriptor->capabilities & EFI_MEMORY_MORE_RELIABLE) != 0 ?
		gcd_memory_more_reliable : gcd_memory_system;
	uint64_t status;

	status = dxe_services->remove_memory_space(base, length);
	if (status != EFI_SUCCESS)
		return status;
	return dxe_services->add_memory_space(type, base, length,
		descriptor->capabilities & ~(EFI_MEMORY_PRESENT | EFI_MEMORY_INITIALIZED |
			EFI_MEMORY_TESTED | EFI_MEMORY_RUNTIME));
}

static uint64_t __attribute__((ms_abi)) initialize_memory_test(
	struct cdk2_generic_memory_test *unused, uint32_t level, uint8_t *soft_ecc)
{
	struct gcd_memory_descriptor *map;
	size_t count;
	size_t index;
	uint64_t status;

	(void)unused;
	(void)level;
	if (soft_ecc == NULL)
		return EFI_INVALID_PARAMETER;
	tested_memory = 0;
	total_memory = 0;
	status = dxe_services->get_memory_map(&count, &map);
	if (status != EFI_SUCCESS)
		return status;
	for (index = 0; index < count; index++) {
		uint64_t state = map[index].capabilities &
			(EFI_MEMORY_PRESENT | EFI_MEMORY_INITIALIZED | EFI_MEMORY_TESTED);

		if (map[index].type == gcd_memory_reserved &&
		    state == (EFI_MEMORY_PRESENT | EFI_MEMORY_INITIALIZED)) {
			status = promote_memory(&map[index], map[index].base, map[index].length);
			if (status != EFI_SUCCESS)
				break;
			tested_memory += map[index].length;
			total_memory += map[index].length;
		} else if (map[index].type == gcd_memory_system ||
			   map[index].type == gcd_memory_more_reliable) {
			total_memory += map[index].length;
		}
	}
	boot_services->free_pool(map);
	*soft_ecc = 0;
	return status;
}

static uint64_t __attribute__((ms_abi)) perform_memory_test(
	struct cdk2_generic_memory_test *unused, uint64_t *tested, uint64_t *total,
	uint8_t *error, uint8_t abort)
{
	(void)unused;
	(void)abort;
	if (tested == NULL || total == NULL || error == NULL)
		return EFI_INVALID_PARAMETER;
	*tested = tested_memory;
	*total = total_memory;
	*error = 0;
	return EFI_NOT_FOUND;
}

static uint64_t __attribute__((ms_abi)) finish_memory_test(
	struct cdk2_generic_memory_test *unused)
{
	(void)unused;
	return EFI_SUCCESS;
}

static uint64_t __attribute__((ms_abi)) test_compatible_range(
	struct cdk2_generic_memory_test *unused, uint64_t start, uint64_t length)
{
	uint64_t end;
	uint64_t current;

	(void)unused;
	if (length > SIXTEEN_MIB || start > SIXTEEN_MIB - length)
		return EFI_INVALID_PARAMETER;
	end = start + length;
	current = start;
	while (current < end) {
		struct gcd_memory_descriptor descriptor;
		uint64_t descriptor_end;
		uint64_t chunk;
		uint64_t status = dxe_services->get_memory_descriptor(current, &descriptor);

		if (status != EFI_SUCCESS)
			return status;
		if (descriptor.length > UINT64_MAX - descriptor.base)
			return EFI_INVALID_PARAMETER;
		descriptor_end = descriptor.base + descriptor.length;
		if (descriptor_end <= current)
			return EFI_INVALID_PARAMETER;
		chunk = descriptor_end < end ? descriptor_end - current : end - current;
		if (descriptor.type == gcd_memory_reserved &&
		    (descriptor.capabilities & (EFI_MEMORY_PRESENT | EFI_MEMORY_INITIALIZED |
					EFI_MEMORY_TESTED)) ==
		    (EFI_MEMORY_PRESENT | EFI_MEMORY_INITIALIZED)) {
			status = promote_memory(&descriptor, current, chunk);
			if (status != EFI_SUCCESS)
				return status;
		}
		current += chunk;
	}
	return EFI_SUCCESS;
}

static struct cdk2_generic_memory_test memory_test = {
	.initialize = initialize_memory_test,
	.perform = perform_memory_test,
	.finished = finish_memory_test,
	.test_compatible_range = test_compatible_range,
};

uint64_t __attribute__((ms_abi))
cdk2_null_memory_test_entry(void *image_handle, struct system_table *system_table)
{
	size_t index;

	(void)image_handle;
	if (system_table == NULL || system_table->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	dxe_services = NULL;
	for (index = 0; index < system_table->configuration_table_count; index++) {
		if (guid_equal(&system_table->configuration_table[index].vendor_guid,
			       &dxe_services_guid)) {
			dxe_services = system_table->configuration_table[index].vendor_table;
			break;
		}
	}
	if (dxe_services == NULL)
		return EFI_NOT_FOUND;
	boot_services = system_table->boot_services;
	return boot_services->install_protocol(&protocol_handle, &generic_memory_test_guid,
		0, &memory_test);
}
