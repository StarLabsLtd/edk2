/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>

typedef EFI_STATUS CDK2_MS_ABI create_fn(UINT32, UINTN, void *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI wait_fn(UINTN, void **, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI close_event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI locate_fn(const EFI_GUID *, void *, void **);
struct boot_view {
	UINT8 prefix[64];
	allocate_fn *allocate_pool;
	free_fn *free_pool;
	create_fn *create_event;
	void *set_timer;
	wait_fn *wait_for_event;
	void *signal_event;
	close_event_fn *close_event;
	UINT8 before_locate[200];
	locate_fn *locate_protocol;
};
struct system_view { UINT8 prefix[96]; struct boot_view *boot; };
static const EFI_GUID scsi_io_guid = { 0x932f47e6, 0x2362, 0x4002,
	{ 0x80, 0x3e, 0x3c, 0xd5, 0x4b, 0x13, 0x8f, 0x85 } };

static UINT8 port_read(UINT16 port)
{
	UINT8 value;
	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}

static void serial(const char *text)
{
	while (*text != '\0') {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++),
			"Nd"((UINT16)0x3f8));
	}
}

EFI_STATUS CDK2_MS_ABI scsi_bus_qemu_entry(void *image, void *table)
{
	struct system_view *system = table;
	struct cdk2_scsi_io *io = NULL;
	struct cdk2_scsi_request packet;
	UINT8 *inquiry;
	UINT8 *sense;
	UINT8 cdb[6] = { 0x12, 0, 0, 0, 36, 0 };
	UINT8 target_storage[CDK2_SCSI_TARGET_MAX];
	UINT8 *target = target_storage;
	UINT64 lun;
	UINT8 type;
	void *event = NULL;
	void *allocation = NULL;
	UINTN alignment;
	UINTN address;
	UINTN index = ~0U;
	EFI_STATUS status;
	(void)image;

	serial("CDK2_SCSI_BUS_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL ||
	    system->boot->locate_protocol == NULL ||
	    system->boot->allocate_pool == NULL || system->boot->free_pool == NULL ||
	    system->boot->create_event == NULL || system->boot->wait_for_event == NULL ||
	    system->boot->close_event == NULL ||
	    EFI_ERROR(system->boot->locate_protocol(&scsi_io_guid, NULL,
	    (void **)&io)) || io == NULL)
		goto bad;
	serial("SCSI_BUS_STAGE_LOCATE_OK\r\n");
	if (io->get_device_type == NULL || io->get_device_location == NULL ||
	    io->execute_scsi_command == NULL || io->reset_device == NULL ||
	    EFI_ERROR(io->get_device_type(io, &type)) || type != 5U ||
	    EFI_ERROR(io->get_device_location(io, &target, &lun)) || lun != 0U)
		goto bad;
	serial("SCSI_BUS_STAGE_DEVICE_OK\r\n");
	alignment = io->io_align == 0U ? 1U : io->io_align;
	if ((alignment & (alignment - 1U)) != 0U || alignment > 0x10000U ||
	    EFI_ERROR(system->boot->allocate_pool(4U,
	    36U + 18U + 2U * (alignment - 1U), &allocation)))
		goto bad;
	address = ((UINTN)allocation + alignment - 1U) & ~(alignment - 1U);
	inquiry = (UINT8 *)address;
	address = ((UINTN)(inquiry + 36U) + alignment - 1U) & ~(alignment - 1U);
	sense = (UINT8 *)address;
	for (UINTN offset = 0; offset < 36U; offset++)
		inquiry[offset] = 0;
	for (UINTN offset = 0; offset < 18U; offset++)
		sense[offset] = 0;
	status = system->boot->create_event(0, 0, NULL, NULL, &event);
	if (EFI_ERROR(status) || event == NULL) {
		serial("SCSI_BUS_STAGE_CREATE_BAD\r\n");
		goto bad;
	}
	serial("SCSI_BUS_STAGE_CREATE_OK\r\n");
	packet = (struct cdk2_scsi_request) {
		.timeout = 30000000ULL, .in_data = inquiry, .sense_data = sense,
		.cdb = cdb, .in_length = 36U, .cdb_length = sizeof(cdb),
		.data_direction = 0, .sense_length = 18U,
	};
	status = io->execute_scsi_command(io, &packet, event);
	if (EFI_ERROR(status)) {
		serial(status == EFI_UNSUPPORTED ? "SCSI_BUS_STAGE_EXEC_UNSUPPORTED\r\n" :
			status == EFI_TIMEOUT ? "SCSI_BUS_STAGE_EXEC_TIMEOUT\r\n" :
			status == EFI_INVALID_PARAMETER ? "SCSI_BUS_STAGE_EXEC_INVALID\r\n" :
			status == EFI_DEVICE_ERROR ? "SCSI_BUS_STAGE_EXEC_DEVICE\r\n" :
			status == EFI_NOT_READY ? "SCSI_BUS_STAGE_EXEC_NOT_READY\r\n" :
			"SCSI_BUS_STAGE_EXEC_BAD\r\n");
		goto bad;
	}
	serial("SCSI_BUS_STAGE_SUBMIT_OK\r\n");
	if (EFI_ERROR(system->boot->wait_for_event(1, &event, &index)) || index != 0U ||
	    packet.host_status != 0U || packet.target_status != 0U ||
	    packet.in_length == 0U || (inquiry[0] & 0x1fU) != 5U)
		goto bad;
	serial("SCSI_BUS_STAGE_INQUIRY_OK\r\n");
	if (EFI_ERROR(io->reset_device(io)))
		goto bad;
	serial("SCSI_BUS_STAGE_RESET_OK\r\n");
	if (EFI_ERROR(system->boot->close_event(event)))
		goto bad;
	event = NULL;
	if (EFI_ERROR(system->boot->free_pool(allocation)))
		goto bad;
	allocation = NULL;
	serial("CDK2_SCSI_BUS_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	if (event != NULL)
		(void)system->boot->close_event(event);
	if (allocation != NULL)
		(void)system->boot->free_pool(allocation);
	serial("CDK2_SCSI_BUS_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
