/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef CDK2_ABI_MEMORY_ALLOCATION_HOB_H_
#define CDK2_ABI_MEMORY_ALLOCATION_HOB_H_

#include <uefi.h>

#define EFI_HOB_MEMORY_ALLOC_STACK_GUID                                            \
	{ 0x4ed4bf27U, 0x4092U, 0x42e9U, { 0x80U, 0x7dU, 0x52U, 0x7bU, 0x1dU, 0x00U, 0xc9U, 0xbdU } }

#define EFI_HOB_MEMORY_ALLOC_MODULE_GUID                                           \
	{ 0xf8e21975U, 0x0899U, 0x4f58U, { 0xa4U, 0xbeU, 0x55U, 0x25U, 0xa9U, 0xc6U, 0xd7U, 0x7aU } }

#endif
