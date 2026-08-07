/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/null_memory_test/null_memory_test.c"

#include <stdio.h>
#include <string.h>

static struct gcd_memory_descriptor descriptors[3];
static const struct guid *installed_guid;
static void *installed_interface;
static unsigned int add_calls;
static unsigned int remove_calls;
static unsigned int free_calls;

static uint64_t __attribute__((ms_abi)) mock_add(enum gcd_memory_type type,
	uint64_t base, uint64_t length, uint64_t capabilities)
{
	(void)capabilities;
	if (type != gcd_memory_system || base != 0x100000 || length != 0x200000)
		return EFI_INVALID_PARAMETER;
	add_calls++;
	return EFI_SUCCESS;
}

static uint64_t __attribute__((ms_abi)) mock_remove(uint64_t base, uint64_t length)
{
	if (base != 0x100000 || length != 0x200000)
		return EFI_INVALID_PARAMETER;
	remove_calls++;
	return EFI_SUCCESS;
}

static uint64_t __attribute__((ms_abi)) mock_get_descriptor(
	uint64_t base, struct gcd_memory_descriptor *descriptor)
{
	if (base >= 0x300000)
		return EFI_NOT_FOUND;
	*descriptor = descriptors[0];
	return EFI_SUCCESS;
}

static uint64_t __attribute__((ms_abi)) mock_get_map(
	size_t *count, struct gcd_memory_descriptor **map)
{
	*count = 3;
	*map = descriptors;
	return EFI_SUCCESS;
}

static uint64_t __attribute__((ms_abi)) mock_free(void *buffer)
{
	if (buffer != descriptors)
		return EFI_INVALID_PARAMETER;
	free_calls++;
	return EFI_SUCCESS;
}

static uint64_t __attribute__((ms_abi)) mock_install(void **handle,
	const struct guid *guid, uint32_t interface_type, void *interface)
{
	if (interface_type != 0)
		return EFI_INVALID_PARAMETER;
	*handle = (void *)1;
	installed_guid = guid;
	installed_interface = interface;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 null memory test: %s\n", message);
		return 1;
	}
	return 0;
}

int main(void)
{
	struct dxe_services dxe;
	struct boot_services_view boot;
	struct configuration_table configuration;
	struct system_table system;
	uint64_t tested;
	uint64_t total;
	uint8_t error;
	uint8_t soft_ecc;
	int failures = 0;

	memset(&dxe, 0, sizeof(dxe));
	memset(&boot, 0, sizeof(boot));
	memset(&system, 0, sizeof(system));
	memset(descriptors, 0, sizeof(descriptors));
	dxe.add_memory_space = mock_add;
	dxe.remove_memory_space = mock_remove;
	dxe.get_memory_descriptor = mock_get_descriptor;
	dxe.get_memory_map = mock_get_map;
	boot.free_pool = mock_free;
	boot.install_protocol = mock_install;
	configuration.vendor_guid = dxe_services_guid;
	configuration.vendor_table = &dxe;
	system.boot_services = &boot;
	system.configuration_table_count = 1;
	system.configuration_table = &configuration;
	descriptors[0].base = 0x100000;
	descriptors[0].length = 0x200000;
	descriptors[0].capabilities = EFI_MEMORY_PRESENT | EFI_MEMORY_INITIALIZED;
	descriptors[0].type = gcd_memory_reserved;
	descriptors[1].base = 0x300000;
	descriptors[1].length = 0x400000;
	descriptors[1].type = gcd_memory_system;
	descriptors[2].base = 0x700000;
	descriptors[2].length = 0x100000;
	descriptors[2].type = gcd_memory_mmio;

	failures += expect(cdk2_null_memory_test_entry(NULL, &system) == EFI_SUCCESS,
		"entry installs protocol");
	failures += expect(guid_equal(installed_guid, &generic_memory_test_guid),
		"generic memory test protocol GUID installed");
	failures += expect(installed_interface == &memory_test, "protocol interface installed");
	failures += expect(memory_test.initialize(&memory_test, 0, &soft_ecc) == EFI_SUCCESS,
		"initialization succeeds");
	failures += expect(soft_ecc == 0, "software ECC initialization not required");
	failures += expect(add_calls == 1 && remove_calls == 1 && free_calls == 1,
		"untested reserved memory promoted and map released");
	failures += expect(memory_test.perform(&memory_test, &tested, &total, &error, 0) ==
		EFI_NOT_FOUND, "memory test reports completion");
	failures += expect(tested == 0x200000 && total == 0x600000 && error == 0,
		"memory totals reported");
	failures += expect(memory_test.finished(&memory_test) == EFI_SUCCESS,
		"finish succeeds");
	failures += expect(memory_test.test_compatible_range(&memory_test, SIXTEEN_MIB, 1) ==
		EFI_INVALID_PARAMETER, "range above 16 MiB rejected without overflow");
	return failures == 0 ? 0 : 1;
}
