/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_bus.h>

#include <string.h>

static UINT16 get16(const UINT8 *value)
{
	return (UINT16)value[0] | ((UINT16)value[1] << 8);
}

static UINT32 get32(const UINT8 *value)
{
	return get16(value) | ((UINT32)get16(value + 2) << 16);
}

static UINT64 get64(const UINT8 *value)
{
	return get32(value) | ((UINT64)get32(value + 4) << 32);
}

EFI_STATUS cdk2_ata_bus_parse_identify(const UINT8 identify[512],
	struct cdk2_ata_bus_media *media)
{
	UINT16 word49, word83, word106, word209;
	UINT64 blocks;
	UINT32 block_size = 512U;

	if (identify == NULL || media == NULL)
		return EFI_INVALID_PARAMETER;
	word49 = get16(identify + 49U * 2U);
	word83 = get16(identify + 83U * 2U);
	word106 = get16(identify + 106U * 2U);
	word209 = get16(identify + 209U * 2U);
	if ((word49 & (1U << 9)) == 0U || (word83 & 0xc000U) != 0x4000U)
		return EFI_UNSUPPORTED;
	if ((word106 & 0xc000U) == 0x4000U && (word106 & (1U << 12)) != 0U) {
		UINT32 words = get32(identify + 117U * 2U);
		if (words == 0U || words > UINT32_MAX / 2U)
			return EFI_COMPROMISED_DATA;
		block_size = words * 2U;
	}
	blocks = (word83 & (1U << 10)) != 0U ? get64(identify + 100U * 2U) :
		get32(identify + 60U * 2U);
	if (blocks == 0U)
		return CDK2_EFI_NO_MEDIA;
	memset(media, 0, sizeof(*media));
	media->blocks = blocks; media->block_size = block_size;
	media->lba48 = (word83 & (1U << 10)) != 0U;
	media->removable = (get16(identify) & (1U << 7)) != 0U;
	media->write_caching = (get16(identify + 85U * 2U) & (1U << 5)) != 0U;
	media->trusted = (get16(identify + 48U * 2U) & 1U) != 0U;
	media->logical_blocks_per_physical_block = (word106 & (1U << 13)) != 0U ?
		1U << (word106 & 0xfU) : 1U;
	if ((word209 & 0xc000U) == 0x4000U) {
		UINT32 alignment = word209 & 0x3fffU;
		if (alignment >= media->logical_blocks_per_physical_block &&
		    alignment != 0U)
			return EFI_COMPROMISED_DATA;
		media->lowest_aligned_lba = alignment == 0U ? 0U :
			media->logical_blocks_per_physical_block - alignment;
	}
	return EFI_SUCCESS;
}

static EFI_STATUS identify_device(struct cdk2_ata_pass_thru_protocol *protocol,
	UINT16 port, UINT16 multiplier, struct cdk2_ata_bus_child *child,
	void (*release_path)(void *))
{
	struct cdk2_ata_command_block acb = { .command = 0xecU };
	struct cdk2_ata_status_block asb;
	struct cdk2_ata_command_packet packet = { .asb = &asb, .acb = &acb,
		.timeout = 300000000U, .in_data = child->identify, .in_length = 512U,
		.protocol = 4U, .length = 0xa0U };
	void *path = NULL;
	EFI_STATUS status;

	status = protocol->pass_thru(protocol, port, multiplier, &packet, NULL);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_ata_bus_parse_identify(child->identify, &child->geometry);
	if (EFI_ERROR(status))
		return status;
	status = protocol->build_device_path(protocol, port, multiplier, &path);
	if (EFI_ERROR(status) || path == NULL)
		return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
	child->device_path_size = ((UINT8 *)path)[2] | ((UINTN)((UINT8 *)path)[3] << 8);
	if (child->device_path_size > sizeof(child->device_path) ||
	    child->device_path_size < 4U) {
		release_path(path);
		return EFI_COMPROMISED_DATA;
	}
	memcpy(child->device_path, path, child->device_path_size);
	release_path(path);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_add_controller(struct cdk2_ata_bus *bus,
	void *handle, struct cdk2_ata_pass_thru_protocol *pass_thru,
	void (*release_path)(void *))
{
	struct cdk2_ata_bus staged;
	struct cdk2_ata_bus_controller *controller;
	UINT16 port = 0xffffU;
	EFI_STATUS status;

	if (bus == NULL || handle == NULL || pass_thru == NULL || release_path == NULL ||
	    pass_thru->get_next_port == NULL || pass_thru->get_next_device == NULL ||
	    pass_thru->pass_thru == NULL || pass_thru->build_device_path == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN index = 0; index < bus->controller_count; index++)
		if (bus->controllers[index].handle == handle)
			return EFI_ALREADY_STARTED;
	if (bus->controller_count == CDK2_ATA_BUS_MAX_CONTROLLERS)
		return EFI_OUT_OF_RESOURCES;
	staged = *bus; controller = &staged.controllers[staged.controller_count];
	memset(controller, 0, sizeof(*controller)); controller->handle = handle;
	controller->pass_thru = pass_thru; controller->first_child = staged.child_count;
	while (!EFI_ERROR(status = pass_thru->get_next_port(pass_thru, &port))) {
		UINT16 multiplier = 0xffffU;
		while (!EFI_ERROR(status = pass_thru->get_next_device(pass_thru, port,
			&multiplier))) {
			struct cdk2_ata_bus_child *child;
			if (staged.child_count == CDK2_ATA_BUS_MAX_CHILDREN)
				return EFI_OUT_OF_RESOURCES;
			child = &staged.children[staged.child_count]; memset(child, 0,
				sizeof(*child)); child->controller = handle; child->port = port;
			child->multiplier = multiplier; child->type = CDK2_ATA_DISK;
			status = identify_device(pass_thru, port, multiplier, child,
				release_path);
			if (EFI_ERROR(status))
				return status;
			staged.child_count++; controller->child_count++;
		}
		if (status != EFI_NOT_FOUND)
			return status;
	}
	if (status != EFI_NOT_FOUND || controller->child_count == 0U)
		return status == EFI_NOT_FOUND ? EFI_NOT_FOUND : status;
	staged.controller_count++; *bus = staged;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_bus_remove_controller(struct cdk2_ata_bus *bus, void *handle)
{
	UINTN index;
	if (bus == NULL || handle == NULL)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < bus->controller_count; index++)
		if (bus->controllers[index].handle == handle)
			break;
	if (index == bus->controller_count)
		return EFI_NOT_FOUND;
	{
		UINTN first = bus->controllers[index].first_child;
		UINTN count = bus->controllers[index].child_count;
		memmove(&bus->children[first], &bus->children[first + count],
			(bus->child_count - first - count) * sizeof(bus->children[0]));
		bus->child_count -= count;
		memmove(&bus->controllers[index], &bus->controllers[index + 1],
			(bus->controller_count - index - 1U) * sizeof(bus->controllers[0]));
		bus->controller_count--;
		for (UINTN next = index; next < bus->controller_count; next++)
			bus->controllers[next].first_child -= count;
	}
	return EFI_SUCCESS;
}
