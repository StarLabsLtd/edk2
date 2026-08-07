/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native form of UefiCpuPkg/CpuIo2Dxe. */

#include <cdk2/cpu_io2.h>

#define IO_PORT_MAX 0xffffU

struct guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

typedef uint64_t CDK2_MS_ABI install_multiple_protocols_fn(
	void **handle, const struct guid *protocol, void *interface, ...);

struct boot_services_view {
	uint8_t before_install_multiple[328];
	install_multiple_protocols_fn *install_multiple_protocols;
};

struct system_table {
	uint8_t before_boot_services[96];
	struct boot_services_view *boot_services;
};

static const struct guid cpu_io2_protocol_guid = {
	0xad61f191, 0xae5f, 0x4c0e, { 0xb9, 0xfa, 0xe8, 0x69, 0xd2, 0x88, 0xc6, 0x4f }
};

#ifdef CDK2_CPU_IO2_TEST
extern uint64_t cpu_io2_test_read(int mmio, unsigned int width, uint64_t address);
extern void cpu_io2_test_write(int mmio, unsigned int width, uint64_t address,
	uint64_t value);
#endif

static uint64_t read_unit(int mmio, unsigned int width, uint64_t address)
{
#ifdef CDK2_CPU_IO2_TEST
	return cpu_io2_test_read(mmio, width, address);
#else
	if (mmio) {
		if (width == 0)
			return *(volatile uint8_t *)(uintptr_t)address;
		if (width == 1)
			return *(volatile uint16_t *)(uintptr_t)address;
		if (width == 2)
			return *(volatile uint32_t *)(uintptr_t)address;
		return *(volatile uint64_t *)(uintptr_t)address;
	}
	if (width == 0) {
		uint8_t value; __asm__ volatile("inb %w1, %b0" : "=a"(value) : "d"((uint16_t)address)); return value;
	}
	if (width == 1) {
		uint16_t value; __asm__ volatile("inw %w1, %w0" : "=a"(value) : "d"((uint16_t)address)); return value;
	}
	{
		uint32_t value; __asm__ volatile("inl %w1, %0" : "=a"(value) : "d"((uint16_t)address)); return value;
	}
#endif
}

static void write_unit(int mmio, unsigned int width, uint64_t address,
	uint64_t value)
{
#ifdef CDK2_CPU_IO2_TEST
	cpu_io2_test_write(mmio, width, address, value);
#else
	if (mmio) {
		if (width == 0)
			*(volatile uint8_t *)(uintptr_t)address = (uint8_t)value;
		else if (width == 1)
			*(volatile uint16_t *)(uintptr_t)address = (uint16_t)value;
		else if (width == 2)
			*(volatile uint32_t *)(uintptr_t)address = (uint32_t)value;
		else
			*(volatile uint64_t *)(uintptr_t)address = value;
	} else if (width == 0) {
		__asm__ volatile("outb %b0, %w1" : : "a"((uint8_t)value), "d"((uint16_t)address));
	} else if (width == 1) {
		__asm__ volatile("outw %w0, %w1" : : "a"((uint16_t)value), "d"((uint16_t)address));
	} else {
		__asm__ volatile("outl %0, %w1" : : "a"((uint32_t)value), "d"((uint16_t)address));
	}
#endif
}

static uint64_t check_request(int mmio, enum cdk2_cpu_io_width width,
	uint64_t address, size_t count, const void *buffer)
{
	unsigned int unit;
	uint64_t limit = mmio ? UINT64_MAX : IO_PORT_MAX;
	uint64_t transfers = count;

	if (buffer == NULL || width >= CDK2_CPU_IO_WIDTH_MAX)
		return EFI_INVALID_PARAMETER;
	unit = (unsigned int)width & 3U;
	if (!mmio && unit == 3U)
		return EFI_INVALID_PARAMETER;
	if ((address & ((1ULL << unit) - 1U)) != 0 ||
	    ((uintptr_t)buffer & ((1ULL << unit) - 1U)) != 0)
		return EFI_UNSUPPORTED;
	if (width >= CDK2_CPU_IO_FIFO_UINT8 && width <= CDK2_CPU_IO_FIFO_UINT64)
		transfers = count == 0 ? 0 : 1;
	if (transfers == 0)
		return address <= limit ? EFI_SUCCESS : EFI_UNSUPPORTED;
	if (address > limit || transfers - 1U > ((limit - address) >> unit))
		return EFI_UNSUPPORTED;
	return EFI_SUCCESS;
}

static uint64_t access_units(int mmio, int write, enum cdk2_cpu_io_width width,
	uint64_t address, size_t count, void *buffer)
{
	uint64_t status = check_request(mmio, width, address, count, buffer);
	unsigned int unit = (unsigned int)width & 3U;
	size_t size = (size_t)1U << unit;
	size_t address_stride = size;
	size_t buffer_stride = size;
	uint8_t *bytes = buffer;

	if (status != EFI_SUCCESS)
		return status;
	if (width >= CDK2_CPU_IO_FIFO_UINT8 && width <= CDK2_CPU_IO_FIFO_UINT64)
		address_stride = 0;
	else if (width >= CDK2_CPU_IO_FILL_UINT8)
		buffer_stride = 0;
	while (count-- != 0) {
		uint64_t value = 0;
		if (write) {
			__builtin_memcpy(&value, bytes, size);
			write_unit(mmio, unit, address, value);
		} else {
			value = read_unit(mmio, unit, address);
			__builtin_memcpy(bytes, &value, size);
		}
		address += address_stride;
		bytes += buffer_stride;
	}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI memory_read(struct cdk2_cpu_io2 *cpu_io,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)cpu_io;
	return access_units(1, 0, width, address, count, buffer);
}

static uint64_t CDK2_MS_ABI memory_write(struct cdk2_cpu_io2 *cpu_io,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)cpu_io;
	return access_units(1, 1, width, address, count, buffer);
}

static uint64_t CDK2_MS_ABI io_read(struct cdk2_cpu_io2 *cpu_io,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)cpu_io;
	return access_units(0, 0, width, address, count, buffer);
}

static uint64_t CDK2_MS_ABI io_write(struct cdk2_cpu_io2 *cpu_io,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)cpu_io;
	return access_units(0, 1, width, address, count, buffer);
}

static struct cdk2_cpu_io2 cpu_io2 = {
	.mem = { memory_read, memory_write },
	.io = { io_read, io_write },
};
static void *cpu_io2_handle;

uint64_t CDK2_MS_ABI cdk2_cpu_io2_entry(void *image_handle,
	struct system_table *system_table)
{
	(void)image_handle;
	return system_table->boot_services->install_multiple_protocols(
		&cpu_io2_handle, &cpu_io2_protocol_guid, &cpu_io2, NULL);
}
