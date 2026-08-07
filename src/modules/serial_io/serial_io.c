/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Native PI serial I/O driver. */

#include <cdk2/hob_payload.h>
#include <cdk2/serial_io.h>
#include <pi/hob.h>

#include <stddef.h>
#include <stdint.h>

#define TPL_NOTIFY 16U
#define UART_CLOCK_HZ 1843200U
#define UART_DEFAULT_BAUD 115200U
#define UART_DEFAULT_TIMEOUT 1000000U
#define UART_DEFAULT_FIFO_DEPTH 16U

#define UART_RBR 0U
#define UART_THR 0U
#define UART_DLL 0U
#define UART_IER 1U
#define UART_DLM 1U
#define UART_FCR 2U
#define UART_LCR 3U
#define UART_MCR 4U
#define UART_LSR 5U
#define UART_MSR 6U
#define UART_LCR_DLAB 0x80U
#define UART_LSR_DATA_READY 0x01U
#define UART_LSR_THR_EMPTY 0x20U
#define UART_LSR_TX_EMPTY 0x40U

struct guid {
	uint32_t data1;
	uint16_t data2;
	uint16_t data3;
	uint8_t data4[8];
};

struct config_table {
	struct guid guid;
	void *table;
};

typedef uint64_t CDK2_MS_ABI install_multiple_fn(void **handle, ...);
typedef uint64_t CDK2_MS_ABI reinstall_fn(void *handle, const struct guid *guid,
	void *old_interface, void *new_interface);
typedef uint64_t CDK2_MS_ABI stall_fn(size_t microseconds);
typedef uint64_t CDK2_MS_ABI raise_tpl_fn(uint64_t tpl);
typedef void CDK2_MS_ABI restore_tpl_fn(uint64_t tpl);

struct boot_services_view {
	uint8_t header[24];
	raise_tpl_fn *raise_tpl;
	restore_tpl_fn *restore_tpl;
	uint8_t before_reinstall[96];
	reinstall_fn *reinstall;
	uint8_t before_stall[104];
	stall_fn *stall;
	uint8_t before_install_multiple[72];
	install_multiple_fn *install_multiple;
};

struct system_table {
	uint8_t before_boot_services[96];
	struct boot_services_view *boot_services;
	size_t config_count;
	struct config_table *config_tables;
};

typedef char reinstall_offset_must_match[
	offsetof(struct boot_services_view, reinstall) == 136 ? 1 : -1];
typedef char stall_offset_must_match[
	offsetof(struct boot_services_view, stall) == 248 ? 1 : -1];
typedef char install_multiple_offset_must_match[
	offsetof(struct boot_services_view, install_multiple) == 328 ? 1 : -1];
typedef char config_count_offset_must_match[
	offsetof(struct system_table, config_count) == 104 ? 1 : -1];

struct vendor_device_path {
	uint8_t type;
	uint8_t subtype;
	uint8_t length[2];
	struct guid guid;
} __packed;

struct uart_device_path {
	uint8_t type;
	uint8_t subtype;
	uint8_t length[2];
	uint32_t reserved;
	uint64_t baud_rate;
	uint8_t data_bits;
	uint8_t parity;
	uint8_t stop_bits;
} __packed;

struct end_device_path {
	uint8_t type;
	uint8_t subtype;
	uint8_t length[2];
} __packed;

struct serial_device_path {
	struct vendor_device_path vendor;
	struct uart_device_path uart;
	struct end_device_path end;
} __packed;

static const struct guid hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const struct guid serial_hob_guid = {
	0xaa7e190d, 0xbe21, 0x4409, { 0x8e, 0x67, 0xa2, 0xcd, 0x0f, 0x61, 0xe1, 0x70 }
};
static const struct guid serial_io_guid = {
	0xbb25cf6f, 0xf1d4, 0x11d2, { 0x9a, 0x0c, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0xfd }
};
static const struct guid device_path_guid = {
	0x09576e91, 0x6d3f, 0x11d2, { 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b }
};
static const struct guid serial_vendor_guid = {
	0xd3987d4b, 0x971a, 0x435f, { 0x8c, 0xaf, 0x49, 0x67, 0xeb, 0x62, 0x72, 0x41 }
};

static struct boot_services_view *boot_services;
static const CDK2_SERIAL_PORT_HOB *port;
static void *serial_handle;

static int guid_equal(const struct guid *left, const void *right)
{
	const uint8_t *a = (const uint8_t *)left;
	const uint8_t *b = right;
	size_t index;

	for (index = 0; index < sizeof(*left); index++)
		if (a[index] != b[index])
			return 0;
	return 1;
}

static const CDK2_SERIAL_PORT_HOB *find_serial_hob(struct system_table *system)
{
	EFI_HOB_GENERIC_HEADER *hob = NULL;
	size_t index;

	for (index = 0; index < system->config_count; index++)
		if (guid_equal(&hob_list_guid, &system->config_tables[index].guid))
			hob = system->config_tables[index].table;
	while (hob != NULL && hob->hob_type != EFI_HOB_TYPE_END_OF_HOB_LIST) {
		if (hob->hob_length < sizeof(*hob))
			return NULL;
		if (hob->hob_type == EFI_HOB_TYPE_GUID_EXTENSION &&
		    hob->hob_length >= sizeof(EFI_HOB_GUID_TYPE) + sizeof(CDK2_SERIAL_PORT_HOB)) {
			EFI_HOB_GUID_TYPE *guid_hob = (EFI_HOB_GUID_TYPE *)hob;
			if (guid_equal(&serial_hob_guid, &guid_hob->name))
				return (const CDK2_SERIAL_PORT_HOB *)(guid_hob + 1);
		}
		hob = (EFI_HOB_GENERIC_HEADER *)((uint8_t *)hob + hob->hob_length);
	}
	return NULL;
}

#ifdef CDK2_SERIAL_IO_TEST
extern uint8_t serial_io_test_read(uint64_t address);
extern void serial_io_test_write(uint64_t address, uint8_t value);
#endif

static uint64_t register_address(unsigned int reg)
{
	return port->register_base + (uint64_t)reg * port->register_stride;
}

static uint8_t register_read(unsigned int reg)
{
	uint64_t address = register_address(reg);
#ifdef CDK2_SERIAL_IO_TEST
	return serial_io_test_read(address);
#else
	if (port->use_mmio)
		return *(volatile uint8_t *)(uintptr_t)address;
	{
		uint8_t value;
		__asm__ volatile("inb %w1, %b0" : "=a"(value) : "d"((uint16_t)address));
		return value;
	}
#endif
}

static void register_write(unsigned int reg, uint8_t value)
{
	uint64_t address = register_address(reg);
#ifdef CDK2_SERIAL_IO_TEST
	serial_io_test_write(address, value);
#else
	if (port->use_mmio)
		*(volatile uint8_t *)(uintptr_t)address = value;
	else
		__asm__ volatile("outb %b0, %w1" : : "a"(value), "d"((uint16_t)address));
#endif
}

static uint8_t line_control(uint8_t data_bits, enum cdk2_serial_parity parity,
	 enum cdk2_serial_stop_bits stop_bits)
{
	uint8_t value = (uint8_t)(data_bits - 5U);
	if (stop_bits == CDK2_TWO_STOP_BITS || stop_bits == CDK2_ONE_FIVE_STOP_BITS)
		value |= 0x04U;
	if (parity != CDK2_NO_PARITY) {
		value |= 0x08U;
		if (parity == CDK2_EVEN_PARITY || parity == CDK2_SPACE_PARITY)
			value |= 0x10U;
		if (parity == CDK2_MARK_PARITY || parity == CDK2_SPACE_PARITY)
			value |= 0x20U;
	}
	return value;
}

static uint64_t configure(uint64_t baud, uint32_t fifo, enum cdk2_serial_parity parity,
	uint8_t data_bits, enum cdk2_serial_stop_bits stop_bits)
{
	uint32_t divisor;
	uint8_t lcr;

	if (baud == 0)
		baud = port->baud_rate != 0 ? port->baud_rate : UART_DEFAULT_BAUD;
	if (fifo == 0)
		fifo = UART_DEFAULT_FIFO_DEPTH;
	if (parity == CDK2_DEFAULT_PARITY)
		parity = CDK2_NO_PARITY;
	if (data_bits == 0)
		data_bits = 8;
	if (stop_bits == CDK2_DEFAULT_STOP_BITS)
		stop_bits = CDK2_ONE_STOP_BIT;
	if (baud > UART_CLOCK_HZ / 16U || data_bits < 5 || data_bits > 8 ||
	    parity > CDK2_SPACE_PARITY || stop_bits > CDK2_TWO_STOP_BITS ||
	    (data_bits == 5 && stop_bits == CDK2_TWO_STOP_BITS) ||
	    (data_bits != 5 && stop_bits == CDK2_ONE_FIVE_STOP_BITS))
		return EFI_INVALID_PARAMETER;
	divisor = (uint32_t)((UART_CLOCK_HZ + baud * 8U) / (baud * 16U));
	if (divisor == 0 || divisor > 0xffffU)
		return EFI_INVALID_PARAMETER;
	lcr = line_control(data_bits, parity, stop_bits);
	register_write(UART_IER, 0);
	register_write(UART_LCR, (uint8_t)(lcr | UART_LCR_DLAB));
	register_write(UART_DLL, (uint8_t)divisor);
	register_write(UART_DLM, (uint8_t)(divisor >> 8));
	register_write(UART_LCR, lcr);
	register_write(UART_FCR, fifo > 1 ? 0x07U : 0U);
	return EFI_SUCCESS;
}

static struct cdk2_serial_io_mode serial_mode = {
	.control_mask = CDK2_SERIAL_REQUEST_TO_SEND | CDK2_SERIAL_DATA_TERMINAL_READY |
		CDK2_SERIAL_HARDWARE_LOOPBACK,
	.timeout = UART_DEFAULT_TIMEOUT,
	.baud_rate = UART_DEFAULT_BAUD,
	.receive_fifo_depth = UART_DEFAULT_FIFO_DEPTH,
	.data_bits = 8,
	.parity = CDK2_NO_PARITY,
	.stop_bits = CDK2_ONE_STOP_BIT,
};

static struct serial_device_path serial_path = {
	.vendor = { 1, 4, { 20, 0 }, { 0 } },
	.uart = { 3, 14, { 19, 0 }, 0, UART_DEFAULT_BAUD, 8,
		 CDK2_NO_PARITY, CDK2_ONE_STOP_BIT },
	.end = { 0x7f, 0xff, { 4, 0 } },
};

static uint64_t CDK2_MS_ABI serial_set_attributes(struct cdk2_serial_io *serial,
	uint64_t baud, uint32_t fifo, uint32_t timeout, enum cdk2_serial_parity parity,
	uint8_t data_bits, enum cdk2_serial_stop_bits stop_bits)
{
	uint64_t old_tpl;
	uint64_t status;

	if (serial == NULL)
		return EFI_INVALID_PARAMETER;
	if (baud == 0)
		baud = port->baud_rate != 0 ? port->baud_rate : UART_DEFAULT_BAUD;
	if (fifo == 0)
		fifo = UART_DEFAULT_FIFO_DEPTH;
	if (timeout == 0)
		timeout = UART_DEFAULT_TIMEOUT;
	if (parity == CDK2_DEFAULT_PARITY)
		parity = CDK2_NO_PARITY;
	if (data_bits == 0)
		data_bits = 8;
	if (stop_bits == CDK2_DEFAULT_STOP_BITS)
		stop_bits = CDK2_ONE_STOP_BIT;
	old_tpl = boot_services->raise_tpl(TPL_NOTIFY);
	if (serial_path.uart.baud_rate == baud && serial_path.uart.parity == parity &&
	    serial_path.uart.data_bits == data_bits &&
	    serial_path.uart.stop_bits == stop_bits) {
		serial_mode.receive_fifo_depth = fifo;
		serial_mode.timeout = timeout;
		boot_services->restore_tpl(old_tpl);
		return EFI_SUCCESS;
	}
	status = configure(baud, fifo, parity, data_bits, stop_bits);
	if (status != EFI_SUCCESS) {
		boot_services->restore_tpl(old_tpl);
		return status;
	}
	serial_mode.baud_rate = baud;
	serial_mode.receive_fifo_depth = fifo;
	serial_mode.timeout = timeout;
	serial_mode.parity = parity;
	serial_mode.data_bits = data_bits;
	serial_mode.stop_bits = stop_bits;
	serial_path.uart.baud_rate = baud;
	serial_path.uart.parity = parity;
	serial_path.uart.data_bits = data_bits;
	serial_path.uart.stop_bits = stop_bits;
	status = serial_handle == NULL ? EFI_SUCCESS : boot_services->reinstall(serial_handle,
		&device_path_guid, &serial_path, &serial_path);
	boot_services->restore_tpl(old_tpl);
	return status;
}

static uint64_t CDK2_MS_ABI serial_reset(struct cdk2_serial_io *serial)
{
	return serial_set_attributes(serial, serial_mode.baud_rate,
		serial_mode.receive_fifo_depth, serial_mode.timeout, serial_mode.parity,
		(uint8_t)serial_mode.data_bits, serial_mode.stop_bits);
}

static uint64_t CDK2_MS_ABI serial_set_control(struct cdk2_serial_io *serial,
	uint32_t control)
{
	uint8_t mcr = 0;
	(void)serial;
	if ((control & ~serial_mode.control_mask) != 0)
		return EFI_UNSUPPORTED;
	if (control & CDK2_SERIAL_DATA_TERMINAL_READY)
		mcr |= 0x01U;
	if (control & CDK2_SERIAL_REQUEST_TO_SEND)
		mcr |= 0x02U;
	if (control & CDK2_SERIAL_HARDWARE_LOOPBACK)
		mcr |= 0x10U;
	register_write(UART_MCR, mcr);
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI serial_get_control(struct cdk2_serial_io *serial,
	uint32_t *control)
{
	uint8_t lsr;
	uint8_t mcr;
	uint8_t msr;
	(void)serial;
	if (control == NULL)
		return EFI_INVALID_PARAMETER;
	lsr = register_read(UART_LSR);
	mcr = register_read(UART_MCR);
	msr = register_read(UART_MSR);
	*control = (lsr & UART_LSR_DATA_READY) ? 0 : CDK2_SERIAL_INPUT_BUFFER_EMPTY;
	if (lsr & UART_LSR_TX_EMPTY)
		*control |= CDK2_SERIAL_OUTPUT_BUFFER_EMPTY;
	if (mcr & 0x01U)
		*control |= CDK2_SERIAL_DATA_TERMINAL_READY;
	if (mcr & 0x02U)
		*control |= CDK2_SERIAL_REQUEST_TO_SEND;
	if (mcr & 0x10U)
		*control |= CDK2_SERIAL_HARDWARE_LOOPBACK;
	*control |= (uint32_t)(msr & 0xf0U);
	return EFI_SUCCESS;
}

static int wait_for_lsr(uint8_t mask)
{
	uint32_t elapsed;
	for (elapsed = 0; elapsed < serial_mode.timeout; elapsed += 10U) {
		if ((register_read(UART_LSR) & mask) != 0)
			return 1;
		boot_services->stall(10);
	}
	return 0;
}

static uint64_t CDK2_MS_ABI serial_write(struct cdk2_serial_io *serial, size_t *size,
	void *buffer)
{
	uint8_t *bytes = buffer;
	size_t count;
	(void)serial;
	if (size == NULL || (*size != 0 && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	for (count = 0; count < *size; count++) {
		if (!wait_for_lsr(UART_LSR_THR_EMPTY)) {
			*size = count;
			return EFIERR(18);
		}
		register_write(UART_THR, bytes[count]);
	}
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI serial_read(struct cdk2_serial_io *serial, size_t *size,
	void *buffer)
{
	uint8_t *bytes = buffer;
	size_t count;
	(void)serial;
	if (size == NULL || (*size != 0 && buffer == NULL))
		return EFI_INVALID_PARAMETER;
	for (count = 0; count < *size; count++) {
		if (!wait_for_lsr(UART_LSR_DATA_READY)) {
			*size = count;
			return EFIERR(18);
		}
		bytes[count] = register_read(UART_RBR);
	}
	return EFI_SUCCESS;
}

static struct cdk2_serial_io serial_io = {
	CDK2_SERIAL_IO_REVISION, serial_reset, serial_set_attributes,
	serial_set_control, serial_get_control, serial_write, serial_read, &serial_mode
};

uint64_t CDK2_MS_ABI cdk2_serial_io_entry(void *image_handle,
	struct system_table *system)
{
	(void)image_handle;
	if (system == NULL || system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	boot_services = system->boot_services;
	port = find_serial_hob(system);
	if (port == NULL || port->header.revision != CDK2_SERIAL_PORT_HOB_REVISION ||
	    port->header.length < sizeof(*port) || port->register_stride == 0)
		return EFI_NOT_FOUND;
	serial_path.vendor.guid = serial_vendor_guid;
	serial_mode.baud_rate = port->baud_rate != 0 ? port->baud_rate : UART_DEFAULT_BAUD;
	serial_path.uart.baud_rate = serial_mode.baud_rate;
	return boot_services->install_multiple(&serial_handle, &serial_io_guid, &serial_io,
		&device_path_guid, &serial_path, NULL);
}
