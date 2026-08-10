/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_bus.h>

#include <stddef.h>
#include <string.h>

static struct cdk2_usb_io_device *owner(struct cdk2_usb_io_protocol *protocol)
{
	return (void *)((UINT8 *)protocol -
		offsetof(struct cdk2_usb_io_device, protocol));
}

static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb_io_protocol *protocol,
	struct cdk2_usb_request *request, UINTN direction, UINT32 timeout, void *data,
	UINTN * length, UINT32 * result)
{
	struct cdk2_usb_io_device *device;

	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	return device->host->control_transfer(device->host, device->address,
		device->speed, device->maximum_packet, request, direction, data, length,
		timeout, NULL, result);
}

static EFI_STATUS CDK2_MS_ABI bulk(struct cdk2_usb_io_protocol *protocol,
	UINT8 endpoint, void *data, UINTN * length, UINTN timeout, UINT32 * result)
{
	struct cdk2_usb_io_device *device;
	void *buffers[1] = { data };
	UINT8 dci;

	if (protocol == NULL || (endpoint & 0xfU) == 0U)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	dci = (endpoint & 0xfU) * 2U + ((endpoint & 0x80U) != 0U ? 1U : 0U);
	return device->host->bulk_transfer(device->host, device->address, endpoint,
		device->speed, device->maximum_packet, 1U, buffers, length,
		&device->toggle[dci], timeout, NULL, result);
}

static EFI_STATUS CDK2_MS_ABI async_interrupt(
	struct cdk2_usb_io_protocol *protocol, UINT8 endpoint, BOOLEAN new_transfer,
	UINTN interval, UINTN length, cdk2_usb2_async_callback_fn * callback,
	void *context)
{
	struct cdk2_usb_io_device *device;
	UINT8 dci;

	if (protocol == NULL || (endpoint & 0xfU) == 0U)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	dci = (endpoint & 0xfU) * 2U + ((endpoint & 0x80U) != 0U ? 1U : 0U);
	return device->host->async_interrupt_transfer(device->host, device->address,
		endpoint, device->speed, device->maximum_packet, new_transfer,
		&device->toggle[dci], interval, length, NULL, callback, context);
}

static EFI_STATUS CDK2_MS_ABI sync_interrupt(struct cdk2_usb_io_protocol *protocol,
	UINT8 endpoint, void *data, UINTN * length, UINTN timeout, UINT32 * result)
{
	struct cdk2_usb_io_device *device;
	void *buffers[1] = { data };
	UINT8 dci;

	if (protocol == NULL || (endpoint & 0xfU) == 0U)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	dci = (endpoint & 0xfU) * 2U + ((endpoint & 0x80U) != 0U ? 1U : 0U);
	return device->host->sync_interrupt_transfer(device->host, device->address,
		endpoint, device->speed, device->maximum_packet, 1U, buffers, length,
		&device->toggle[dci], timeout, NULL, result);
}

static EFI_STATUS CDK2_MS_ABI unsupported(void) { return EFI_UNSUPPORTED; }

static EFI_STATUS CDK2_MS_ABI device_descriptor(
	struct cdk2_usb_io_protocol *protocol, void *descriptor)
{
	if (protocol == NULL || descriptor == NULL)
		return EFI_INVALID_PARAMETER;
	memcpy(descriptor, owner(protocol)->device_descriptor, 18U);
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI config_descriptor(
	struct cdk2_usb_io_protocol *protocol, void *descriptor)
{
	struct cdk2_usb_configuration *configuration;
	UINT8 *bytes = descriptor;

	if (protocol == NULL || descriptor == NULL)
		return EFI_INVALID_PARAMETER;
	configuration = &owner(protocol)->configuration;
	memset(bytes, 0, 9U);
	bytes[0] = 9U; bytes[1] = 2U;
	bytes[2] = (UINT8)configuration->total_length;
	bytes[3] = (UINT8)(configuration->total_length >> 8);
	bytes[4] = configuration->number_interfaces;
	bytes[5] = configuration->value; bytes[7] = configuration->attributes;
	bytes[8] = configuration->maximum_power;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI interface_descriptor(
	struct cdk2_usb_io_protocol *protocol, void *descriptor)
{
	const struct cdk2_usb_interface *interface;
	UINT8 *bytes = descriptor;

	if (protocol == NULL || descriptor == NULL)
		return EFI_INVALID_PARAMETER;
	interface = owner(protocol)->interface;
	memset(bytes, 0, 9U);
	bytes[0] = 9U; bytes[1] = 4U; bytes[2] = interface->number;
	bytes[3] = interface->alternate; bytes[4] = interface->endpoint_count;
	bytes[5] = interface->class_code; bytes[6] = interface->subclass;
	bytes[7] = interface->protocol;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI endpoint_descriptor(
	struct cdk2_usb_io_protocol *protocol, UINT8 index, void *descriptor)
{
	const struct cdk2_usb_interface *interface;
	const struct cdk2_usb_endpoint *endpoint;
	UINT8 *bytes = descriptor;

	if (protocol == NULL || descriptor == NULL)
		return EFI_INVALID_PARAMETER;
	interface = owner(protocol)->interface;
	if (index >= interface->endpoint_count)
		return EFI_NOT_FOUND;
	endpoint = &interface->endpoints[index];
	bytes[0] = 7U; bytes[1] = 5U; bytes[2] = endpoint->address;
	bytes[3] = endpoint->attributes; bytes[4] = endpoint->maximum_packet;
	bytes[5] = endpoint->maximum_packet >> 8; bytes[6] = endpoint->interval;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI string_descriptor(
	struct cdk2_usb_io_protocol *protocol, UINT16 language, UINT8 index,
	CHAR16 * *result)
{
	struct cdk2_usb_io_device *device;
	struct cdk2_usb_request request = { 0x80U, 6U,
		(UINT16)(3U << 8 | index), language, 254U };
	UINT8 bytes[254];
	UINTN length = sizeof(bytes);
	UINT32 transfer_result;
	EFI_STATUS status;

	if (protocol == NULL || result == NULL || index == 0U)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	status = control(protocol, &request, 0U, 1000U, bytes, &length,
		&transfer_result);
	if (EFI_ERROR(status) || length < 2U || bytes[1] != 3U || bytes[0] > length ||
	    (bytes[0] & 1U) != 0U)
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	memcpy(device->string, bytes + 2U, bytes[0] - 2U);
	device->string[(bytes[0] - 2U) / 2U] = 0U;
	if (device->allocate == NULL)
		*result = device->string;
	else {
		UINTN size = bytes[0];

		status = device->allocate(device->allocate_context, size,
			(void **)result);
		if (EFI_ERROR(status))
			return status;
		memcpy(*result, device->string, size);
	}
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI languages(struct cdk2_usb_io_protocol *protocol,
	UINT16 * *values, UINT16 * count)
{
	struct cdk2_usb_io_device *device;

	if (protocol == NULL || values == NULL || count == NULL)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	if (device->language_count == 0U) {
		struct cdk2_usb_request request = { 0x80U, 6U, 3U << 8, 0U, 66U };
		UINT8 bytes[66];
		UINTN length = sizeof(bytes);
		UINT32 transfer_result;
		EFI_STATUS status = control(protocol, &request, 0U, 1000U, bytes,
			&length, &transfer_result);

		if (EFI_ERROR(status) || length < 4U || bytes[1] != 3U ||
		    bytes[0] > length || (bytes[0] & 1U) != 0U)
			return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
		device->language_count = (bytes[0] - 2U) / 2U;
		memcpy(device->languages, bytes + 2U,
			device->language_count * sizeof(UINT16));
	}
	if (device->allocate == NULL)
		*values = device->languages;
	else {
		EFI_STATUS status = device->allocate(device->allocate_context,
			device->language_count * sizeof(UINT16), (void **)values);

		if (EFI_ERROR(status))
			return status;
		memcpy(*values, device->languages,
			device->language_count * sizeof(UINT16));
	}
	*count = device->language_count;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI port_reset(struct cdk2_usb_io_protocol *protocol)
{
	struct cdk2_usb_io_device *device;

	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	device = owner(protocol);
	return device->host->set_root_hub_port_feature(device->host, device->port, 4U);
}

EFI_STATUS cdk2_usb_io_init(struct cdk2_usb_io_device *device,
	struct cdk2_usb2_hc_protocol *host, UINT8 address, UINT8 port, UINT8 speed,
	UINT16 maximum_packet, const UINT8 descriptor[18],
	const struct cdk2_usb_configuration *configuration, UINT8 interface_number,
	UINT8 alternate)
{
	EFI_STATUS status;

	if (device == NULL || host == NULL || address == 0U || maximum_packet == 0U ||
	    descriptor == NULL || configuration == NULL)
		return EFI_INVALID_PARAMETER;
	memset(device, 0, sizeof(*device));
	device->host = host; device->address = address; device->port = port;
	device->speed = speed; device->maximum_packet = maximum_packet;
	memcpy(device->device_descriptor, descriptor, 18U);
	device->configuration = *configuration;
	status = cdk2_usb_find_interface(&device->configuration, interface_number,
		alternate, &device->interface);
	if (EFI_ERROR(status))
		return status;
	device->protocol = (struct cdk2_usb_io_protocol) { control, bulk,
		async_interrupt, sync_interrupt, unsupported, unsupported,
		device_descriptor, config_descriptor, interface_descriptor,
		endpoint_descriptor, string_descriptor, languages, port_reset };
	return EFI_SUCCESS;
}
