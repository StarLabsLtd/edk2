/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_SIO_BUS_H_
#define CDK2_SIO_BUS_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

#define CDK2_SIO_ACCESS_DENIED ((1ULL << 63) | 15ULL)

struct cdk2_sio_resource { uint8_t descriptor; uint16_t base; uint8_t length;
	uint8_t end_tag, checksum; };
struct cdk2_sio_modify { uint8_t register_number, and_mask, or_mask; };
struct cdk2_sio;
typedef uint64_t CDK2_MS_ABI cdk2_sio_access_fn(const struct cdk2_sio *, uint8_t,
	uint8_t, uint8_t, uint8_t *);
typedef uint64_t CDK2_MS_ABI cdk2_sio_get_fn(const struct cdk2_sio *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_sio_set_fn(const struct cdk2_sio *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_sio_modify_fn(const struct cdk2_sio *,
	const struct cdk2_sio_modify *, size_t);
struct cdk2_sio {
	cdk2_sio_access_fn *register_access;
	cdk2_sio_get_fn *get_resources;
	cdk2_sio_set_fn *set_resources;
	cdk2_sio_get_fn *possible_resources;
	cdk2_sio_modify_fn *modify;
	size_t device_index;
};
struct cdk2_sio_device_info { uint32_t hid, uid; uint16_t io_base;
	uint8_t io_length; };

extern const struct cdk2_sio_device_info cdk2_sio_devices[3];
void cdk2_sio_init(struct cdk2_sio *sio, size_t device_index);

#endif
