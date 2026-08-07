/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CPU_IO2_H_
#define CDK2_CPU_IO2_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

enum cdk2_cpu_io_width {
	CDK2_CPU_IO_UINT8,
	CDK2_CPU_IO_UINT16,
	CDK2_CPU_IO_UINT32,
	CDK2_CPU_IO_UINT64,
	CDK2_CPU_IO_FIFO_UINT8,
	CDK2_CPU_IO_FIFO_UINT16,
	CDK2_CPU_IO_FIFO_UINT32,
	CDK2_CPU_IO_FIFO_UINT64,
	CDK2_CPU_IO_FILL_UINT8,
	CDK2_CPU_IO_FILL_UINT16,
	CDK2_CPU_IO_FILL_UINT32,
	CDK2_CPU_IO_FILL_UINT64,
	CDK2_CPU_IO_WIDTH_MAX,
};

struct cdk2_cpu_io2;
typedef uint64_t CDK2_MS_ABI cdk2_cpu_io_access_fn(struct cdk2_cpu_io2 *cpu_io,
	enum cdk2_cpu_io_width width, uint64_t address, size_t count, void *buffer);

struct cdk2_cpu_io_access {
	cdk2_cpu_io_access_fn *read;
	cdk2_cpu_io_access_fn *write;
};

struct cdk2_cpu_io2 {
	struct cdk2_cpu_io_access mem;
	struct cdk2_cpu_io_access io;
};

#endif
