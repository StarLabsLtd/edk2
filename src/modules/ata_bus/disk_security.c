/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_bus.h>

#include <stddef.h>
#include <string.h>

typedef UINT32 cdk2_uint32;
typedef UINT8 cdk2_uint8;
typedef UINTN cdk2_uintn;

static const EFI_GUID ide_interface = { 0x5e948fe3, 0x26d3, 0x42b5,
	{ 0xaf, 0x17, 0x61, 0x02, 0x87, 0x18, 0x8d, 0xec } };
static const EFI_GUID ahci_interface = { 0x9e498932, 0x4abc, 0x45af,
	{ 0xa3, 0x4d, 0x02, 0x47, 0x78, 0x7b, 0xe7, 0xc6 } };

static struct cdk2_ata_bus_bound_child *from_disk(struct cdk2_ata_bus_disk_info *disk)
{
	return (struct cdk2_ata_bus_bound_child *)((UINT8 *)disk -
		offsetof(struct cdk2_ata_bus_bound_child, disk_info));
}

static struct cdk2_ata_bus_bound_child *from_security(
	struct cdk2_ata_bus_security *security)
{
	return (struct cdk2_ata_bus_bound_child *)((UINT8 *)security -
		offsetof(struct cdk2_ata_bus_bound_child, security));
}

static EFI_STATUS CDK2_MS_ABI unsupported_inquiry(struct cdk2_ata_bus_disk_info *disk,
	void *buffer,
	cdk2_uint32 * size)
{
	(void)disk; (void)buffer; (void)size;
	return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI identify(struct cdk2_ata_bus_disk_info *disk,
	void *buffer,
	cdk2_uint32 * size)
{
	struct cdk2_ata_bus_bound_child *child;

	if (disk == NULL || size == NULL)
		return EFI_INVALID_PARAMETER;
	if (*size < 512U || buffer == NULL) {
		*size = 512U;
		return EFI_BUFFER_TOO_SMALL;
	}
	child = from_disk(disk);
	memcpy(buffer, child->model.identify, 512U);
	*size = 512U;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI sense(struct cdk2_ata_bus_disk_info *disk,
	void *buffer,
	cdk2_uint32 * size,
	cdk2_uint8 * number)
{
	(void)disk; (void)buffer; (void)size; (void)number;
	return EFI_NOT_FOUND;
}

static EFI_STATUS CDK2_MS_ABI which_ide(struct cdk2_ata_bus_disk_info *disk,
	cdk2_uint32 * channel,
	cdk2_uint32 * device)
{
	struct cdk2_ata_bus_bound_child *child;

	if (disk == NULL || channel == NULL || device == NULL)
		return EFI_INVALID_PARAMETER;
	child = from_disk(disk);
	*channel = child->model.port;
	*device = child->model.multiplier;
	return EFI_SUCCESS;
}

static EFI_STATUS security_common(struct cdk2_ata_bus_bound_child *child,
	UINT32 media_id, UINT64 timeout, UINT8 protocol_id, UINT16 protocol_data,
	UINTN size, void *buffer,
	cdk2_uintn * transferred, BOOLEAN receive)
{
	struct cdk2_ata_command_block acb = { 0 };
	struct cdk2_ata_status_block asb = { 0 };
	struct cdk2_ata_command_packet packet = { 0 };
	UINT8 *raw = NULL, *bounce = NULL;
	EFI_STATUS status;

	if (!child->model.geometry.trusted)
		return EFI_UNSUPPORTED;
	if (!child->block.media.media_present)
		return CDK2_EFI_NO_MEDIA;
	if (media_id != child->block.media.media_id)
		return CDK2_EFI_MEDIA_CHANGED;
	if (size > UINT32_MAX || size / 512U > UINT16_MAX ||
	    (size != 0U && (buffer == NULL || size % 512U != 0U)) ||
	    (receive && size != 0U && transferred == NULL))
		return EFI_INVALID_PARAMETER;
	if (receive && transferred != NULL)
		*transferred = 0;
	if (size != 0U) {
		UINTN align = child->model.geometry.io_align;

		if (align == 0U)
			align = 1U;
		if ((align & (align - 1U)) != 0U || size > (UINTN)-1 - (align - 1U))
			return EFI_INVALID_PARAMETER;
		status = child->allocate(child->service_context, size + align - 1U,
			(void **)&raw);
		if (EFI_ERROR(status))
			return status;
		bounce = (UINT8 *)(((UINTN)raw + align - 1U) & ~(align - 1U));
		if (!receive)
			memcpy(bounce, buffer, size);
	}
	acb.command = size == 0U ? 0x5bU : (receive ? 0x5cU : 0x5eU);
	acb.features = protocol_id;
	acb.sector_count = (UINT8)(size / 512U);
	acb.sector_number = (UINT8)(size / 512U >> 8);
	acb.cylinder_low = (UINT8)(protocol_data >> 8);
	acb.cylinder_high = (UINT8)protocol_data;
	packet.acb = &acb; packet.asb = &asb; packet.timeout = timeout;
	packet.protocol = size == 0U ? 2U : (receive ? 4U : 5U);
	packet.length = size == 0U ? 0U : 0x20U;
	packet.in_data = receive ? bounce : NULL;
	packet.in_length = receive ? (UINT32)size : 0U;
	packet.out_data = receive ? NULL : bounce;
	packet.out_length = receive ? 0U : (UINT32)size;
	status = child->transport.execute(child->transport.context, &child->model, &packet);
	if (!EFI_ERROR(status) && (asb.status & 1U) != 0U)
		status = EFI_DEVICE_ERROR;
	if (!EFI_ERROR(status) && receive && packet.in_length > size)
		status = EFI_DEVICE_ERROR;
	if (!EFI_ERROR(status) && receive && size != 0U) {
		memcpy(buffer, bounce, packet.in_length);
		*transferred = packet.in_length;
	}
	if (raw != NULL)
		child->release(child->service_context, raw);
	return status;
}

static EFI_STATUS CDK2_MS_ABI receive_data(struct cdk2_ata_bus_security *security,
	UINT32 media_id, UINT64 timeout, UINT8 protocol_id, UINT16 protocol_data,
	UINTN size, void *buffer, UINTN *transferred)
{
	if (security == NULL)
		return EFI_INVALID_PARAMETER;
	return security_common(from_security(security), media_id, timeout, protocol_id,
		protocol_data, size, buffer, transferred, 1);
}

static EFI_STATUS CDK2_MS_ABI send_data(struct cdk2_ata_bus_security *security,
	UINT32 media_id, UINT64 timeout, UINT8 protocol_id, UINT16 protocol_data,
	UINTN size, const void *buffer)
{
	if (security == NULL)
		return EFI_INVALID_PARAMETER;
	return security_common(from_security(security), media_id, timeout, protocol_id,
		protocol_data, size, (void *)buffer, NULL, 0);
}

EFI_STATUS cdk2_ata_bus_disk_security_init(struct cdk2_ata_bus_bound_child *child,
	const struct cdk2_ata_bus_binding_services *services)
{
	if (child == NULL || services == NULL || services->allocate == NULL ||
	    services->release == NULL)
		return EFI_INVALID_PARAMETER;
	child->disk_info = (struct cdk2_ata_bus_disk_info) {
		child->model.device_path[1] == 1U ? ide_interface : ahci_interface,
		unsupported_inquiry, identify, sense, which_ide };
	child->security = (struct cdk2_ata_bus_security) { receive_data, send_data };
	child->transport = services->transport;
	child->service_context = services->context;
	child->allocate = services->allocate;
	child->release = services->release;
	return EFI_SUCCESS;
}
