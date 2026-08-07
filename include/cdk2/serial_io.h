/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SERIAL_IO_H
#define CDK2_SERIAL_IO_H

#include <uefi.h>

enum cdk2_serial_parity {
	CDK2_DEFAULT_PARITY,
	CDK2_NO_PARITY,
	CDK2_EVEN_PARITY,
	CDK2_ODD_PARITY,
	CDK2_MARK_PARITY,
	CDK2_SPACE_PARITY
};

enum cdk2_serial_stop_bits {
	CDK2_DEFAULT_STOP_BITS,
	CDK2_ONE_STOP_BIT,
	CDK2_ONE_FIVE_STOP_BITS,
	CDK2_TWO_STOP_BITS
};

struct cdk2_serial_io;

typedef uint64_t CDK2_MS_ABI cdk2_serial_reset_fn(struct cdk2_serial_io *serial);
typedef uint64_t CDK2_MS_ABI cdk2_serial_attributes_fn(struct cdk2_serial_io *serial,
	uint64_t baud_rate, uint32_t receive_fifo_depth, uint32_t timeout,
	enum cdk2_serial_parity parity, uint8_t data_bits,
	enum cdk2_serial_stop_bits stop_bits);
typedef uint64_t CDK2_MS_ABI cdk2_serial_set_control_fn(struct cdk2_serial_io *serial,
	uint32_t control);
typedef uint64_t CDK2_MS_ABI cdk2_serial_get_control_fn(struct cdk2_serial_io *serial,
	uint32_t *control);
typedef uint64_t CDK2_MS_ABI cdk2_serial_transfer_fn(struct cdk2_serial_io *serial,
	size_t *size, void *buffer);

struct cdk2_serial_io_mode {
	uint32_t control_mask;
	uint32_t timeout;
	uint64_t baud_rate;
	uint32_t receive_fifo_depth;
	uint32_t data_bits;
	uint32_t parity;
	uint32_t stop_bits;
};

struct cdk2_serial_io {
	uint32_t revision;
	cdk2_serial_reset_fn *reset;
	cdk2_serial_attributes_fn *set_attributes;
	cdk2_serial_set_control_fn *set_control;
	cdk2_serial_get_control_fn *get_control;
	cdk2_serial_transfer_fn *write;
	cdk2_serial_transfer_fn *read;
	struct cdk2_serial_io_mode *mode;
};

#define CDK2_SERIAL_IO_REVISION 0x00010000U

#define CDK2_SERIAL_CLEAR_TO_SEND        (1U << 4)
#define CDK2_SERIAL_DATA_SET_READY       (1U << 5)
#define CDK2_SERIAL_RING_INDICATE        (1U << 6)
#define CDK2_SERIAL_CARRIER_DETECT       (1U << 7)
#define CDK2_SERIAL_REQUEST_TO_SEND      (1U << 1)
#define CDK2_SERIAL_DATA_TERMINAL_READY  (1U << 0)
#define CDK2_SERIAL_INPUT_BUFFER_EMPTY   (1U << 8)
#define CDK2_SERIAL_OUTPUT_BUFFER_EMPTY  (1U << 9)
#define CDK2_SERIAL_HARDWARE_LOOPBACK    (1U << 12)

#endif
