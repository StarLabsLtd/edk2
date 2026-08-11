/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/sio_bus.h>

const struct cdk2_sio_device_info cdk2_sio_devices[3] = {
	{ 0x0105d041, 0, 0x3f8, 8 },
	{ 0x0105d041, 1, 0x2f8, 8 },
	{ 0x0303d041, 0, 0x60, 5 },
};
static struct cdk2_sio_resource resources[3];

static uint64_t CDK2_MS_ABI access(const struct cdk2_sio *sio, uint8_t write,
	uint8_t exit, uint8_t reg, uint8_t *value)
{ (void)sio; (void)write; (void)exit; (void)reg;
	return value == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS; }
static uint64_t CDK2_MS_ABI get(const struct cdk2_sio *sio, void **resource)
{
	if (sio == NULL || resource == NULL || sio->device_index >= 3)
		return EFI_INVALID_PARAMETER;
	*resource = &resources[sio->device_index];
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI set(const struct cdk2_sio *sio, void *resource)
{
	if (sio == NULL || resource == NULL || sio->device_index >= 3)
		return EFI_INVALID_PARAMETER;
	{
		const struct cdk2_sio_resource *value = resource;
		const struct cdk2_sio_resource *fixed = &resources[sio->device_index];

		return value->descriptor == fixed->descriptor &&
			value->base == fixed->base && value->length == fixed->length &&
			value->end_tag == fixed->end_tag && value->checksum == fixed->checksum ?
			EFI_SUCCESS : CDK2_SIO_ACCESS_DENIED;
	}
}
static uint64_t CDK2_MS_ABI modify(const struct cdk2_sio *sio,
	const struct cdk2_sio_modify *commands, size_t count)
{ (void)sio; return commands == NULL && count != 0 ? EFI_INVALID_PARAMETER : EFI_SUCCESS; }

void cdk2_sio_init(struct cdk2_sio *sio, size_t device_index)
{
	const struct cdk2_sio_device_info *info = &cdk2_sio_devices[device_index];
	resources[device_index] = (struct cdk2_sio_resource){ 0x4b, info->io_base,
		info->io_length, 0x79, 0 };
	*sio = (struct cdk2_sio){ access, get, set, get, modify, device_index };
}
