/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_pass_thru.h>

#include <string.h>

#define MESSAGING_DEVICE_PATH 3U
#define MSG_ATAPI_DP 1U
#define MSG_SATA_DP 18U

static int disk_exists(const struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 multiplier)
{
	for (size_t i = 0; i < topology->count; i++)
		if (topology->devices[i].type == CDK2_ATA_DISK &&
		    topology->devices[i].port == port &&
		    topology->devices[i].multiplier == multiplier)
			return 1;
	return 0;
}

EFI_STATUS cdk2_ata_topology_init(struct cdk2_ata_topology *topology,
	enum cdk2_ata_mode mode)
{
	if (topology == NULL || (mode != CDK2_ATA_IDE && mode != CDK2_ATA_AHCI))
		return EFI_INVALID_PARAMETER;
	memset(topology, 0, sizeof(*topology));
	topology->mode = mode;
	topology->previous_port = topology->previous_multiplier = 0xffffU;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_add_device(struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 multiplier, enum cdk2_ata_device_type type)
{
	size_t position;
	if (topology == NULL || type > CDK2_PORT_MULTIPLIER)
		return EFI_INVALID_PARAMETER;
	for (size_t i = 0; i < topology->count; i++) {
		struct cdk2_ata_device *device = &topology->devices[i];
		if (device->port == port && device->multiplier == multiplier)
			return device->type == type ? EFI_ALREADY_STARTED : EFI_INVALID_PARAMETER;
	}
	if (topology->count == CDK2_ATA_MAX_DEVICES)
		return EFI_OUT_OF_RESOURCES;
	for (position = 0; position < topology->count; position++)
		if (topology->devices[position].port > port ||
		    (topology->devices[position].port == port &&
		    topology->devices[position].multiplier > multiplier))
			break;
	for (size_t i = topology->count; i > position; i--)
		topology->devices[i] = topology->devices[i - 1U];
	topology->devices[position] = (struct cdk2_ata_device) {
		.port = port, .multiplier = multiplier, .type = type };
	topology->count++;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_get_next_port(struct cdk2_ata_topology *topology, UINT16 *port)
{
	if (topology == NULL || port == NULL)
		return EFI_INVALID_PARAMETER;
	if (*port != 0xffffU && *port != topology->previous_port)
		return EFI_INVALID_PARAMETER;
	for (size_t i = 0; i < topology->count; i++)
		if (topology->devices[i].type == CDK2_ATA_DISK &&
		    (*port == 0xffffU || topology->devices[i].port > *port)) {
			*port = topology->previous_port = topology->devices[i].port;
			return EFI_SUCCESS;
		}
	topology->previous_port = 0xffffU;
	return EFI_NOT_FOUND;
}

EFI_STATUS cdk2_ata_get_next_device(struct cdk2_ata_topology *topology, UINT16 port,
	UINT16 *multiplier)
{
	if (topology == NULL || multiplier == NULL)
		return EFI_INVALID_PARAMETER;
	if (*multiplier != 0xffffU && *multiplier != topology->previous_multiplier)
		return EFI_INVALID_PARAMETER;
	for (size_t i = 0; i < topology->count; i++)
		if (topology->devices[i].type == CDK2_ATA_DISK &&
		    topology->devices[i].port == port && (*multiplier == 0xffffU ||
		    topology->devices[i].multiplier > *multiplier)) {
			*multiplier = topology->previous_multiplier =
				topology->devices[i].multiplier;
			return EFI_SUCCESS;
		}
	topology->previous_multiplier = 0xffffU;
	return EFI_NOT_FOUND;
}

EFI_STATUS cdk2_ata_build_device_path(const struct cdk2_ata_topology *topology,
	UINT16 port, UINT16 multiplier, void *path, size_t *path_size)
{
	size_t required;
	if (topology == NULL || path_size == NULL)
		return EFI_INVALID_PARAMETER;
	if (!disk_exists(topology, port, multiplier))
		return EFI_NOT_FOUND;
	required = topology->mode == CDK2_ATA_IDE ?
		sizeof(struct cdk2_atapi_device_path) : sizeof(struct cdk2_sata_device_path);
	if (path == NULL || *path_size < required) {
		*path_size = required;
		return path == NULL ? EFI_INVALID_PARAMETER : EFI_BUFFER_TOO_SMALL;
	}
	memset(path, 0, required);
	((struct cdk2_device_path_header *)path)->type = MESSAGING_DEVICE_PATH;
	((struct cdk2_device_path_header *)path)->subtype =
		topology->mode == CDK2_ATA_IDE ? MSG_ATAPI_DP : MSG_SATA_DP;
	((struct cdk2_device_path_header *)path)->length[0] = (UINT8)required;
	if (topology->mode == CDK2_ATA_IDE) {
		struct cdk2_atapi_device_path *node = path;
		node->primary_secondary = (UINT8)port; node->slave_master = (UINT8)multiplier;
	} else {
		struct cdk2_sata_device_path *node = path;
		node->hba_port = port; node->multiplier = multiplier;
	}
	*path_size = required;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_get_device(const struct cdk2_ata_topology *topology,
	const void *path, size_t path_size, UINT16 *port, UINT16 *multiplier)
{
	const struct cdk2_device_path_header *header = path;
	if (topology == NULL || path == NULL || port == NULL || multiplier == NULL)
		return EFI_INVALID_PARAMETER;
	if (header->type != MESSAGING_DEVICE_PATH || header->length[1] != 0U ||
	    header->length[0] != path_size)
		return EFI_UNSUPPORTED;
	if (topology->mode == CDK2_ATA_IDE && header->subtype == MSG_ATAPI_DP &&
	    path_size == sizeof(struct cdk2_atapi_device_path)) {
		const struct cdk2_atapi_device_path *node = path;
		*port = node->primary_secondary; *multiplier = node->slave_master;
	} else if (topology->mode == CDK2_ATA_AHCI && header->subtype == MSG_SATA_DP &&
	    path_size == sizeof(struct cdk2_sata_device_path)) {
		const struct cdk2_sata_device_path *node = path;
		*port = node->hba_port; *multiplier = node->multiplier;
	} else
		return EFI_UNSUPPORTED;
	return disk_exists(topology, *port, *multiplier) ? EFI_SUCCESS : EFI_NOT_FOUND;
}

EFI_STATUS cdk2_ata_validate_transfer(UINT8 protocol, UINT8 length,
	const void *in_buffer, UINT32 in_length, const void *out_buffer,
	UINT32 out_length, UINT32 io_align)
{
	UINT8 kind = length & 0x70U;
	if (protocol != 2U && protocol != 4U && protocol != 5U && protocol != 6U &&
	    protocol != 0x0aU && protocol != 0x0bU && protocol != 0xffU)
		return EFI_INVALID_PARAMETER;
	if (kind != 0U && kind != 0x10U && kind != 0x20U && kind != 0x30U)
		return EFI_INVALID_PARAMETER;
	if ((in_length != 0U && in_buffer == NULL) ||
	    (out_length != 0U && out_buffer == NULL))
		return EFI_INVALID_PARAMETER;
	if (io_align > 1U && ((in_buffer != NULL && (uintptr_t)in_buffer % io_align != 0U) ||
	    (out_buffer != NULL && (uintptr_t)out_buffer % io_align != 0U)))
		return EFI_INVALID_PARAMETER;
	if ((protocol == 4U || protocol == 0x0aU) && out_length != 0U)
		return EFI_INVALID_PARAMETER;
	if ((protocol == 5U || protocol == 0x0bU) && in_length != 0U)
		return EFI_INVALID_PARAMETER;
	if (protocol == 2U && (in_length != 0U || out_length != 0U))
		return EFI_INVALID_PARAMETER;
	return EFI_SUCCESS;
}
