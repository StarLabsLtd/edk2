/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native form of UefiCpuPkg/CpuIo2Smm. */

#include <cdk2/cpu_io2.h>

#define IO_PORT_MAX 0xffffU
#define EFI_NATIVE_INTERFACE 0U

struct guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

typedef uint64_t CDK2_MS_ABI locate_protocol_fn(const struct guid *protocol,
	void *registration, void **interface);
typedef uint64_t CDK2_MS_ABI get_smst_fn(const void *base, void **smst);
typedef uint64_t CDK2_MS_ABI install_protocol_fn(void **handle,
	const struct guid *protocol, uint32_t interface_type, void *interface);

struct boot_services_view {
	uint8_t before_locate_protocol[320];
	locate_protocol_fn *locate_protocol;
};

struct system_table {
	uint8_t before_boot_services[96];
	struct boot_services_view *boot_services;
};

struct smm_base2_protocol {
	void *in_smm;
	get_smst_fn *get_smst;
};

struct smm_system_table_view {
	uint8_t before_io[48];
	struct cdk2_cpu_io2 io;
	uint8_t before_install_protocol[88];
	install_protocol_fn *install_protocol;
};

static const struct guid smm_base2_guid = {
	0xf4ccbfb7, 0xf6e0, 0x47fd, { 0x9d, 0xd4, 0x10, 0xa8, 0xf1, 0x50, 0xc1, 0x91 }
};
static const struct guid smm_cpu_io2_guid = {
	0x3242a9d8, 0xce70, 0x4aa0, { 0x95, 0x5d, 0x5e, 0x7b, 0x14, 0x0d, 0xe4, 0xd2 }
};

#ifdef CDK2_CPU_IO2_SMM_TEST
extern uint64_t cpu_io2_smm_test_read(int mmio, unsigned int width,
	uint64_t address);
extern void cpu_io2_smm_test_write(int mmio, unsigned int width,
	uint64_t address, uint64_t value);
#endif

static uint64_t read_unit(int mmio, unsigned int width, uint64_t address)
{
#ifdef CDK2_CPU_IO2_SMM_TEST
	return cpu_io2_smm_test_read(mmio, width, address);
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
		uint8_t value;
		__asm__ volatile("inb %w1, %b0" : "=a"(value) : "d"((uint16_t)address));
		return value;
	}
	if (width == 1) {
		uint16_t value;
		__asm__ volatile("inw %w1, %w0" : "=a"(value) : "d"((uint16_t)address));
		return value;
	}
	{
		uint32_t value;
		__asm__ volatile("inl %w1, %0" : "=a"(value) : "d"((uint16_t)address));
		return value;
	}
#endif
}

static void write_unit(int mmio, unsigned int width, uint64_t address,
	uint64_t value)
{
#ifdef CDK2_CPU_IO2_SMM_TEST
	cpu_io2_smm_test_write(mmio, width, address, value);
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
		__asm__ volatile("outb %b0, %w1" : : "a"((uint8_t)value),
			"d"((uint16_t)address));
	} else if (width == 1) {
		__asm__ volatile("outw %w0, %w1" : : "a"((uint16_t)value),
			"d"((uint16_t)address));
	} else {
		__asm__ volatile("outl %0, %w1" : : "a"((uint32_t)value),
			"d"((uint16_t)address));
	}
#endif
}

static uint64_t check_request(int mmio, enum cdk2_cpu_io_width width,
	uint64_t address, size_t count, const void *buffer)
{
	uint64_t limit = mmio ? UINT64_MAX : IO_PORT_MAX;
	unsigned int unit;

	if (buffer == NULL || width > CDK2_CPU_IO_UINT64)
		return EFI_INVALID_PARAMETER;
	unit = (unsigned int)width;
	if (!mmio && unit == CDK2_CPU_IO_UINT64)
		return EFI_INVALID_PARAMETER;
	if (count == 0)
		return address <= limit ? EFI_SUCCESS : EFI_UNSUPPORTED;
	if (address > limit || count - 1U > ((limit - address) >> unit))
		return EFI_UNSUPPORTED;
	if ((address & ((1ULL << unit) - 1U)) != 0)
		return EFI_UNSUPPORTED;
	return EFI_SUCCESS;
}

static uint64_t access_units(int mmio, int write, enum cdk2_cpu_io_width width,
	uint64_t address, size_t count, void *buffer)
{
	uint64_t status = check_request(mmio, width, address, count, buffer);
	size_t size = (size_t)1U << (unsigned int)width;
	uint8_t *bytes = buffer;

	if (status != EFI_SUCCESS)
		return status;
	while (count-- != 0) {
		uint64_t value = 0;
		if (write) {
			__builtin_memcpy(&value, bytes, size);
			write_unit(mmio, (unsigned int)width, address, value);
		} else {
			value = read_unit(mmio, (unsigned int)width, address);
			__builtin_memcpy(bytes, &value, size);
		}
		address += size;
		bytes += size;
	}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI memory_read(struct cdk2_cpu_io2 *protocol,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)protocol;
	return access_units(1, 0, width, address, count, buffer);
}

static uint64_t CDK2_MS_ABI memory_write(struct cdk2_cpu_io2 *protocol,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)protocol;
	return access_units(1, 1, width, address, count, buffer);
}

static uint64_t CDK2_MS_ABI io_read(struct cdk2_cpu_io2 *protocol,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)protocol;
	return access_units(0, 0, width, address, count, buffer);
}

static uint64_t CDK2_MS_ABI io_write(struct cdk2_cpu_io2 *protocol,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer)
{
	(void)protocol;
	return access_units(0, 1, width, address, count, buffer);
}

static struct cdk2_cpu_io2 cpu_io2 = {
	.mem = { memory_read, memory_write },
	.io = { io_read, io_write },
};
static void *cpu_io2_handle;

uint64_t CDK2_MS_ABI cdk2_cpu_io2_smm_entry(void *image_handle,
	struct system_table *system_table)
{
	struct smm_base2_protocol *base;
	struct smm_system_table_view *smst;
	uint64_t status;

	(void)image_handle;
	if (system_table == NULL || system_table->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	status = system_table->boot_services->locate_protocol(&smm_base2_guid,
		NULL, (void **)&base);
	if (status != EFI_SUCCESS)
		return status;
	status = base->get_smst(base, (void **)&smst);
	if (status != EFI_SUCCESS)
		return status;
	smst->io = cpu_io2;
	return smst->install_protocol(&cpu_io2_handle, &smm_cpu_io2_guid,
		EFI_NATIVE_INTERFACE, &cpu_io2);
}
