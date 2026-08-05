/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_SERIAL_PORT_INFO_GUID_H_
#define CDK2_ABI_SERIAL_PORT_INFO_GUID_H_

#include <uefi.h>

#define PLD_SERIAL_TYPE_IO_MAPPED     1U
#define PLD_SERIAL_TYPE_MEMORY_MAPPED 2U

typedef struct {
	UINT8 revision;
	UINT8 reserved0[3];
	UINT32 type;
	UINT32 base_addr;
	UINT32 baud;
	UINT32 reg_width;
	UINT32 input_hertz;
	UINT32 uart_pci_addr;
} SERIAL_PORT_INFO;

#endif
