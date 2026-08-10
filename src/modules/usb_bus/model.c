/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_bus.h>

#include <string.h>

EFI_STATUS cdk2_usb_parse_configuration(const void *data, UINTN length,
	struct cdk2_usb_configuration *configuration)
{
	const UINT8 *bytes = data;
	struct cdk2_usb_interface *interface = NULL;
	UINTN offset = 0U;

	if (data == NULL || configuration == NULL || length < 9U || bytes[0] != 9U ||
	    bytes[1] != 2U || ((UINTN)bytes[2] | (UINTN)bytes[3] << 8) != length)
		return EFI_COMPROMISED_DATA;
	memset(configuration, 0, sizeof(*configuration));
	configuration->value = bytes[5];
	configuration->attributes = bytes[7];
	configuration->maximum_power = bytes[8];
	offset = bytes[0];
	while (offset < length) {
		UINT8 descriptor_length;
		UINT8 descriptor_type;

		if (length - offset < 2U)
			return EFI_COMPROMISED_DATA;
		descriptor_length = bytes[offset];
		descriptor_type = bytes[offset + 1U];
		if (descriptor_length < 2U || descriptor_length > length - offset)
			return EFI_COMPROMISED_DATA;
		if (descriptor_type == 4U) {
			if (descriptor_length < 9U ||
			    configuration->interface_count == CDK2_USB_MAX_INTERFACES)
				return EFI_OUT_OF_RESOURCES;
			interface = &configuration->interfaces[
				configuration->interface_count++];
			*interface = (struct cdk2_usb_interface) {
				.number = bytes[offset + 2U],
				.alternate = bytes[offset + 3U],
				.class_code = bytes[offset + 5U],
				.subclass = bytes[offset + 6U],
				.protocol = bytes[offset + 7U],
			};
		} else if (descriptor_type == 5U) {
			struct cdk2_usb_endpoint *endpoint;

			if (descriptor_length < 7U || interface == NULL ||
			    interface->endpoint_count == CDK2_USB_MAX_ENDPOINTS)
				return EFI_COMPROMISED_DATA;
			endpoint = &interface->endpoints[interface->endpoint_count++];
			*endpoint = (struct cdk2_usb_endpoint) {
				.address = bytes[offset + 2U],
				.attributes = bytes[offset + 3U],
				.maximum_packet = bytes[offset + 4U] |
					(UINT16)bytes[offset + 5U] << 8,
				.interval = bytes[offset + 6U],
			};
			if ((endpoint->address & 0xfU) == 0U ||
			    endpoint->maximum_packet == 0U)
				return EFI_COMPROMISED_DATA;
		}
		offset += descriptor_length;
	}
	return configuration->interface_count == 0U ?
		EFI_COMPROMISED_DATA : EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_find_interface(const struct cdk2_usb_configuration *configuration,
	UINT8 number, UINT8 alternate, const struct cdk2_usb_interface **interface)
{
	if (configuration == NULL || interface == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0U; index < configuration->interface_count; index++)
		if (configuration->interfaces[index].number == number &&
		    configuration->interfaces[index].alternate == alternate) {
			*interface = &configuration->interfaces[index];
			return EFI_SUCCESS;
		}
	return EFI_NOT_FOUND;
}

EFI_STATUS cdk2_usb_build_path(UINT8 parent_port, UINT8 interface,
	struct cdk2_usb_device_path_node *node)
{
	if (node == NULL)
		return EFI_INVALID_PARAMETER;
	*node = (struct cdk2_usb_device_path_node) { 3U, 5U, sizeof(*node),
		parent_port, interface };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_parse_path(const void *node, UINTN available,
	UINT8 *parent_port, UINT8 *interface)
{
	const struct cdk2_usb_device_path_node *path = node;

	if (node == NULL || parent_port == NULL || interface == NULL ||
	    available < sizeof(*path) || path->type != 3U || path->subtype != 5U ||
	    path->length != sizeof(*path))
		return EFI_UNSUPPORTED;
	*parent_port = path->parent_port;
	*interface = path->interface;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_allocate_address(struct cdk2_usb_address_pool *pool,
	UINT8 *address)
{
	if (pool == NULL || address == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINT8 value = 1U; value < 128U; value++) {
		UINT64 bit = 1ULL << (value & 63U);

		if ((pool->used[value >> 6] & bit) == 0U) {
			pool->used[value >> 6] |= bit;
			*address = value;
			return EFI_SUCCESS;
		}
	}
	return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS cdk2_usb_release_address(struct cdk2_usb_address_pool *pool,
	UINT8 address)
{
	UINT64 bit;

	if (pool == NULL || address == 0U || address >= 128U)
		return EFI_INVALID_PARAMETER;
	bit = 1ULL << (address & 63U);
	if ((pool->used[address >> 6] & bit) == 0U)
		return EFI_NOT_FOUND;
	pool->used[address >> 6] &= ~bit;
	return EFI_SUCCESS;
}
