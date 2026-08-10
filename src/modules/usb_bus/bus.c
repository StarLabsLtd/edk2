/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_bus.h>

#include <string.h>

static void move_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *to = destination;
	const UINT8 *from = source;

	if (to < from)
		for (UINTN index = 0U; index < size; index++)
			to[index] = from[index];
	else
		for (UINTN index = size; index > 0U; index--)
			to[index - 1U] = from[index - 1U];
}

static EFI_STATUS request(struct cdk2_usb_bus *bus, UINT8 address, UINT8 speed,
	UINT16 packet, struct cdk2_usb_request *usb_request, UINTN direction,
	void *data, UINTN *length)
{
	UINT32 result;
	EFI_STATUS status = bus->host->control_transfer(bus->host, address, speed,
		packet, usb_request, direction, data, length, 3000U, NULL, &result);

	return EFI_ERROR(status) || result != 0U ?
		(EFI_ERROR(status) ? status : EFI_DEVICE_ERROR) : EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_bus_init(struct cdk2_usb_bus *bus,
	struct cdk2_usb2_hc_protocol *host, void *delay_context,
	cdk2_usb_delay_fn *delay)
{
	if (bus == NULL || host == NULL || delay == NULL ||
	    host->get_root_hub_port_status == NULL ||
	    host->set_root_hub_port_feature == NULL || host->control_transfer == NULL)
		return EFI_INVALID_PARAMETER;
	memset(bus, 0, sizeof(*bus));
	bus->host = host;
	bus->delay_context = delay_context;
	bus->delay = delay;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_bus_enumerate_port(struct cdk2_usb_bus *bus, UINT8 port)
{
	struct cdk2_usb_configuration configuration;
	struct cdk2_usb_port_status port_status;
	struct cdk2_usb_request usb_request;
	UINT8 configuration_bytes[CDK2_USB_MAX_CONFIG_LENGTH];
	UINT8 descriptor[18];
	UINT8 address;
	UINT8 speed;
	UINT16 packet;
	UINTN length;
	UINTN first_child;
	EFI_STATUS status;

	if (bus == NULL || bus->host == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < bus->child_count; index++)
		if (bus->children[index].active && bus->children[index].port == port)
			return EFI_ALREADY_STARTED;
	status = bus->host->get_root_hub_port_status(bus->host, port, &port_status);
	if (EFI_ERROR(status) || (port_status.status & 1U) == 0U)
		return EFI_ERROR(status) ? status : EFI_NOT_FOUND;
	status = bus->host->set_root_hub_port_feature(bus->host, port, 8U);
	if (!EFI_ERROR(status))
		status = bus->host->set_root_hub_port_feature(bus->host, port, 4U);
	if (EFI_ERROR(status))
		return status;
	speed = (port_status.status & 1U << 11) != 0U ? 3U :
		(port_status.status & 1U << 10) != 0U ? 2U :
		(port_status.status & 1U << 9) != 0U ? 1U : 0U;
	packet = speed == 3U ? 512U : 8U;
	usb_request = (struct cdk2_usb_request) { 0x80U, 6U, 1U << 8, 0U, 8U };
	length = 8U;
	status = request(bus, 0U, speed, packet, &usb_request, 0U, descriptor, &length);
	if (EFI_ERROR(status) || length != 8U || descriptor[0] != 18U ||
	    descriptor[1] != 1U)
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	packet = descriptor[7];
	if (speed == 3U)
		packet = (UINT16)1U << packet;
	if (packet == 0U)
		return EFI_COMPROMISED_DATA;
	status = cdk2_usb_allocate_address(&bus->addresses, &address);
	if (EFI_ERROR(status))
		return status;
	usb_request = (struct cdk2_usb_request) { 0U, 5U, address, 0U, 0U };
	length = 0U;
	status = request(bus, 0U, speed, packet, &usb_request, 2U, NULL, &length);
	if (EFI_ERROR(status))
		goto release_address;
	bus->delay(bus->delay_context, 2000U);
	usb_request = (struct cdk2_usb_request) { 0x80U, 6U, 1U << 8, 0U, 18U };
	length = sizeof(descriptor);
	status = request(bus, address, speed, packet, &usb_request, 0U, descriptor,
		&length);
	if (EFI_ERROR(status) || length != sizeof(descriptor)) {
		status = EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
		goto release_address;
	}
	usb_request = (struct cdk2_usb_request) { 0x80U, 6U, 2U << 8, 0U, 9U };
	length = 9U;
	status = request(bus, address, speed, packet, &usb_request, 0U,
		configuration_bytes, &length);
	if (EFI_ERROR(status) || length != 9U || configuration_bytes[1] != 2U) {
		status = EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
		goto release_address;
	}
	length = configuration_bytes[2] | (UINTN)configuration_bytes[3] << 8;
	if (length < 9U || length > sizeof(configuration_bytes)) {
		status = EFI_BAD_BUFFER_SIZE;
		goto release_address;
	}
	usb_request.length = length;
	status = request(bus, address, speed, packet, &usb_request, 0U,
		configuration_bytes, &length);
	if (!EFI_ERROR(status))
		status = cdk2_usb_parse_configuration(configuration_bytes, length,
			&configuration);
	if (EFI_ERROR(status))
		goto release_address;
	usb_request = (struct cdk2_usb_request) { 0U, 9U, configuration.value,
		0U, 0U };
	length = 0U;
	status = request(bus, address, speed, packet, &usb_request, 2U, NULL, &length);
	if (EFI_ERROR(status))
		goto release_address;
	first_child = bus->child_count;
	for (UINTN index = 0U; index < configuration.interface_count; index++) {
		struct cdk2_usb_interface *interface = &configuration.interfaces[index];
		struct cdk2_usb_child *child;

		if (interface->alternate != 0U)
			continue;
		if (bus->child_count == CDK2_USB_MAX_CHILDREN) {
			status = EFI_OUT_OF_RESOURCES;
			goto rollback_children;
		}
		child = &bus->children[bus->child_count];
		status = cdk2_usb_io_init(&child->io, bus->host, address, port, speed,
			packet, descriptor, &configuration, interface->number, 0U);
		if (!EFI_ERROR(status))
			status = cdk2_usb_build_path(port, interface->number, &child->path);
		if (EFI_ERROR(status))
			goto rollback_children;
		child->io.allocate_context = bus->allocate_context;
		child->io.allocate = bus->allocate;
		child->port = port; child->address = address;
		child->interface = interface->number; child->active = TRUE;
		bus->child_count++;
	}
	if (bus->child_count != first_child)
		return EFI_SUCCESS;
	status = EFI_NOT_FOUND;
rollback_children:
	while (bus->child_count > first_child)
		memset(&bus->children[--bus->child_count], 0,
			sizeof(bus->children[0]));
release_address:
	(void)cdk2_usb_release_address(&bus->addresses, address);
	return status;
}

EFI_STATUS cdk2_usb_bus_remove_port(struct cdk2_usb_bus *bus, UINT8 port)
{
	UINT8 address = 0U;
	BOOLEAN found = FALSE;

	if (bus == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = bus->child_count; index > 0U; index--)
		if (bus->children[index - 1U].active &&
		    bus->children[index - 1U].port == port) {
			address = bus->children[index - 1U].address;
			move_bytes(&bus->children[index - 1U], &bus->children[index],
				(bus->child_count - index) * sizeof(bus->children[0]));
			memset(&bus->children[--bus->child_count], 0,
				sizeof(bus->children[0]));
			found = TRUE;
		}
	return !found ? EFI_NOT_FOUND :
		cdk2_usb_release_address(&bus->addresses, address);
}
