/* SPDX-License-Identifier: GPL-2.0-only */

#define CDK2_CPU_IO2_SMM_TEST
#include "../src/modules/cpu_io2_smm/cpu_io2_smm.c"

#include <stdio.h>

struct operation {
	int mmio;
	unsigned int width;
	uint64_t address;
	uint64_t value;
};

static struct operation operations[8];
static size_t operation_count;
static struct smm_system_table_view mock_smst;
static struct smm_base2_protocol mock_base;
static const struct guid *installed_guid;

uint64_t cpu_io2_smm_test_read(int mmio, unsigned int width, uint64_t address)
{
	operations[operation_count++] = (struct operation){ mmio, width, address,
		0x8877665544332211ULL + address };
	return operations[operation_count - 1].value;
}

void cpu_io2_smm_test_write(int mmio, unsigned int width, uint64_t address,
	uint64_t value)
{
	operations[operation_count++] = (struct operation){ mmio, width, address, value };
}

static uint64_t CDK2_MS_ABI locate(const struct guid *guid, void *registration,
	void **interface)
{
	(void)registration;
	if (guid != &smm_base2_guid)
		return EFI_NOT_FOUND;
	*interface = &mock_base;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI get_smst(const void *base, void **smst)
{
	if (base != &mock_base)
		return EFI_INVALID_PARAMETER;
	*smst = &mock_smst;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI install(void **handle, const struct guid *guid,
	uint32_t type, void *interface)
{
	*handle = (void *)1;
	installed_guid = guid;
	return type == EFI_NATIVE_INTERFACE && interface == &cpu_io2 ?
		EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "cpu-io2-smm test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct boot_services_view boot = { 0 };
	struct system_table system = { 0 };
	uint32_t values[2] = { 0x11223344, 0x55667788 };
	uint64_t aligned = 0;
	int failures = 0;

	mock_base.get_smst = get_smst;
	mock_smst.install_protocol = install;
	boot.locate_protocol = locate;
	system.boot_services = &boot;
	failures += expect(cdk2_cpu_io2_smm_entry(NULL, &system) == EFI_SUCCESS &&
		installed_guid == &smm_cpu_io2_guid &&
		mock_smst.io.mem.read == memory_read,
		"entry publishes protocol and SMST I/O services");
	failures += expect(memory_write(&cpu_io2, CDK2_CPU_IO_UINT32, 0x1000,
		2, values) == EFI_SUCCESS && operation_count == 2 &&
		operations[1].address == 0x1004 && operations[1].value == 0x55667788,
		"MMIO write preserves width and stride");
	operation_count = 0;
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_UINT16, 0x80, 2,
		values) == EFI_SUCCESS && operation_count == 2 && operations[1].address == 0x82,
		"port read preserves width and stride");
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_UINT64, 0, 1, &aligned) ==
		EFI_INVALID_PARAMETER, "64-bit port access rejected");
	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_FIFO_UINT8, 0, 1,
		&aligned) == EFI_INVALID_PARAMETER, "DXE-only FIFO width rejected");
	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_UINT32, 2, 1,
		&aligned) == EFI_UNSUPPORTED, "misaligned MMIO rejected");
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_UINT16, 0xfffe, 2,
		&aligned) == EFI_UNSUPPORTED, "port range overflow rejected");
	return failures == 0 ? 0 : 1;
}
