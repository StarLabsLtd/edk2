/* SPDX-License-Identifier: GPL-2.0-only */

#define CDK2_CPU_IO2_TEST
#include "../src/modules/cpu_io2/cpu_io2.c"

#include <stdio.h>
#include <string.h>

struct operation {
	int mmio;
	unsigned int width;
	uint64_t address;
	uint64_t value;
};

static struct operation operations[16];
static size_t operation_count;
static const struct guid *installed_guid;
static void *installed_interface;

uint64_t cpu_io2_test_read(int mmio, unsigned int width, uint64_t address)
{
	uint64_t value = 0x8877665544332211ULL + address;
	operations[operation_count++] = (struct operation){ mmio, width, address, value };
	return value;
}

void cpu_io2_test_write(int mmio, unsigned int width, uint64_t address,
	uint64_t value)
{
	operations[operation_count++] = (struct operation){ mmio, width, address, value };
}

static uint64_t CDK2_MS_ABI mock_install(void **handle, const struct guid *guid,
	void *interface, ...)
{
	*handle = (void *)1;
	installed_guid = guid;
	installed_interface = interface;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) {
		fprintf(stderr, "cdk2 cpu-io2 test: %s\n", message);
		return 1;
	}
	return 0;
}

static int test_widths(void)
{
	uint64_t buffer[3] = { 0x11, 0x2233, 0x44556677 };
	unsigned int width;
	int failures = 0;

	for (width = 0; width != 4; ++width) {
		operation_count = 0;
		failures += expect(memory_write(&cpu_io2, width, 0x1000, 2, buffer) ==
			EFI_SUCCESS, "MMIO write width accepted");
		failures += expect(operation_count == 2 && operations[0].mmio == 1 &&
			operations[0].width == width &&
			operations[1].address == 0x1000 + (1U << width),
			"MMIO normal write strides address");
		operation_count = 0;
		memset(buffer, 0, sizeof(buffer));
		failures += expect(memory_read(&cpu_io2, width, 0x2000, 2, buffer) ==
			EFI_SUCCESS && operation_count == 2,
			"MMIO read width accepted");
	}
	for (width = 0; width != 3; ++width) {
		operation_count = 0;
		failures += expect(io_write(&cpu_io2, width, 0x80, 2, buffer) == EFI_SUCCESS &&
			operation_count == 2 && operations[1].address == 0x80 + (1U << width),
			"port normal write width and stride");
	}
	return failures;
}

static int test_modes(void)
{
	uint32_t values[3] = { 1, 2, 3 };
	uint32_t reads[3] = { 0 };
	int failures = 0;

	operation_count = 0;
	failures += expect(memory_write(&cpu_io2, CDK2_CPU_IO_FIFO_UINT32,
		0x3000, 3, values) == EFI_SUCCESS, "FIFO write succeeds");
	failures += expect(operation_count == 3 && operations[0].address == 0x3000 &&
		operations[2].address == 0x3000 && operations[0].value == 1 &&
		operations[2].value == 3, "FIFO fixes address and advances buffer");
	operation_count = 0;
	failures += expect(memory_write(&cpu_io2, CDK2_CPU_IO_FILL_UINT32,
		0x4000, 3, values) == EFI_SUCCESS, "fill write succeeds");
	failures += expect(operation_count == 3 && operations[2].address == 0x4008 &&
		operations[0].value == 1 && operations[2].value == 1,
		"fill advances address and fixes buffer");
	operation_count = 0;
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_FIFO_UINT16,
		0x80, 3, reads) == EFI_SUCCESS && operations[2].address == 0x80,
		"port FIFO read supported");
	operation_count = 0;
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_FILL_UINT16,
		0x80, 3, reads) == EFI_SUCCESS && operations[2].address == 0x84,
		"port fill read supported");
	return failures;
}

static int test_validation(void)
{
	uint64_t aligned = 0;
	uint8_t bytes[16];
	int failures = 0;

	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_UINT8, 0, 1, NULL) ==
		EFI_INVALID_PARAMETER, "null buffer rejected");
	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_WIDTH_MAX, 0, 1,
		&aligned) == EFI_INVALID_PARAMETER, "invalid width rejected");
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_UINT64, 0, 1, &aligned) ==
		EFI_INVALID_PARAMETER, "64-bit port access rejected");
	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_UINT32, 2, 1,
		&aligned) == EFI_UNSUPPORTED, "misaligned address rejected");
	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_UINT32, 4, 1,
		bytes + 1) == EFI_UNSUPPORTED, "misaligned buffer rejected");
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_UINT16, 0xfffe, 2,
		&aligned) == EFI_UNSUPPORTED, "port range overflow rejected");
	failures += expect(memory_read(&cpu_io2, CDK2_CPU_IO_UINT64,
		UINT64_MAX - 7, 2, &aligned) == EFI_UNSUPPORTED,
		"MMIO range overflow rejected");
	failures += expect(check_request(1, CDK2_CPU_IO_FIFO_UINT32,
		UINT64_MAX - 3, SIZE_MAX, &aligned) == EFI_SUCCESS,
		"FIFO count cannot overflow address");
	failures += expect(io_read(&cpu_io2, CDK2_CPU_IO_UINT8, 0x10000, 0,
		&aligned) == EFI_UNSUPPORTED, "zero-count address still validated");
	return failures;
}

int main(void)
{
	struct boot_services_view boot = { 0 };
	struct system_table system = { 0 };
	int failures = 0;

	boot.install_multiple_protocols = mock_install;
	system.boot_services = &boot;
	failures += expect(cdk2_cpu_io2_entry(NULL, &system) == EFI_SUCCESS &&
		installed_guid == &cpu_io2_protocol_guid && installed_interface == &cpu_io2,
		"entry installs exactly the CPU I/O 2 protocol");
	failures += test_widths();
	failures += test_modes();
	failures += test_validation();
	return failures == 0 ? 0 : 1;
}
