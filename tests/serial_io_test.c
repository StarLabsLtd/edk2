/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <stdio.h>
#include <string.h>

#define CDK2_SERIAL_IO_TEST
#include "../src/modules/serial_io/serial_io.c"

static uint8_t registers[8];
static unsigned int writes;

uint8_t serial_io_test_read(uint64_t address)
{
	return registers[(address - port->register_base) / port->register_stride];
}

void serial_io_test_write(uint64_t address, uint8_t value)
{
	registers[(address - port->register_base) / port->register_stride] = value;
	writes++;
}

static uint64_t CDK2_MS_ABI test_stall(size_t microseconds)
{
	(void)microseconds;
	return EFI_SUCCESS;
}

static uint64_t CDK2_MS_ABI test_raise(uint64_t tpl)
{
	return tpl;
}

static void CDK2_MS_ABI test_restore(uint64_t tpl)
{
	(void)tpl;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "serial io test failed: %s\n", message);
	return !condition;
}

int main(void)
{
	CDK2_SERIAL_PORT_HOB test_port = {
		.header = { CDK2_SERIAL_PORT_HOB_REVISION, 0, sizeof(test_port) },
		.use_mmio = 0, .register_stride = 1, .baud_rate = 115200,
		.register_base = 0x3f8,
	};
	struct boot_services_view services = { 0 };
	uint8_t output[] = { 'o', 'k' };
	size_t size = sizeof(output);
	uint32_t control;
	int failures = 0;

	port = &test_port;
	boot_services = &services;
	services.stall = test_stall;
	services.raise_tpl = test_raise;
	services.restore_tpl = test_restore;
	failures += expect(configure(115200, 16, CDK2_NO_PARITY, 8,
		CDK2_ONE_STOP_BIT) == EFI_SUCCESS, "configure 8N1");
	failures += expect(registers[UART_LCR] == 3, "8N1 line control");
	failures += expect(writes >= 6, "UART programmed");
	failures += expect(configure(0xffffffffU, 16, CDK2_NO_PARITY, 8,
		CDK2_ONE_STOP_BIT) == EFI_INVALID_PARAMETER, "reject impossible baud");
	registers[UART_LSR] = UART_LSR_THR_EMPTY | UART_LSR_TX_EMPTY;
	failures += expect(serial_write(&serial_io, &size, output) == EFI_SUCCESS,
		"write succeeds");
	failures += expect(size == sizeof(output) && registers[UART_THR] == 'k',
		"write consumes all bytes");
	failures += expect(serial_set_control(&serial_io,
		CDK2_SERIAL_DATA_TERMINAL_READY | CDK2_SERIAL_REQUEST_TO_SEND) == EFI_SUCCESS,
		"set modem control");
	failures += expect(serial_get_control(&serial_io, &control) == EFI_SUCCESS,
		"get modem control");
	failures += expect((control & CDK2_SERIAL_OUTPUT_BUFFER_EMPTY) != 0,
		"reports empty output buffer");
	failures += expect(serial_get_control(&serial_io, NULL) == EFI_INVALID_PARAMETER,
		"reject NULL control");
	return failures != 0;
}
