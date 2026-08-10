/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINT64 now;
	unsigned int allocations, releases, resets, atapi, submits, cancels;
	void *submitted_event;
};
static EFI_STATUS allocate(void *opaque, size_t size, void **buffer)
{ struct fixture *fixture = opaque; fixture->allocations++; *buffer = malloc(size);
	return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *opaque, void *buffer)
{ struct fixture *fixture = opaque; fixture->releases++; free(buffer); }
static UINT8 read8(void *opaque, UINT16 port)
{ struct fixture *fixture = opaque;
	if ((port & 7U) == 7U && fixture->atapi == 1U) {
		fixture->atapi = 2U;
		return 0x08U;
	}
	(void)port;
	return 0; }
static UINT16 read16(void *opaque, UINT16 port)
{ (void)opaque; (void)port; return 0; }
static EFI_STATUS write8(void *opaque, UINT16 port, UINT8 value)
{ struct fixture *fixture = opaque; (void)value;
	if ((port & 7U) == 7U && value == 0xa0U)
		fixture->atapi = 1U;
	if ((port & 7U) == 6U)
		fixture->resets++;
	return EFI_SUCCESS; }
static EFI_STATUS write16(void *opaque, UINT16 port, UINT16 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS write32(void *opaque, UINT16 port, UINT32 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS map(void *opaque, enum cdk2_ahci_dma_operation operation,
	void *host, size_t *size, UINT64 *device, void **mapping)
{ (void)opaque; (void)operation; (void)size; *device = 0x1000; *mapping = host;
	return EFI_SUCCESS; }
static EFI_STATUS unmap(void *opaque, void *mapping)
{ (void)opaque; (void)mapping; return EFI_SUCCESS; }
static EFI_STATUS flush(void *opaque)
{ (void)opaque; return EFI_SUCCESS; }
static EFI_STATUS timing(void *opaque, UINT8 channel, UINT8 device)
{ (void)opaque; (void)channel; (void)device; return EFI_SUCCESS; }
static UINT64 get_time(void *opaque)
{ struct fixture *fixture = opaque; return fixture->now++; }
static void delay(void *opaque, UINTN microseconds)
{ struct fixture *fixture = opaque; (void)microseconds; fixture->now++; }
static EFI_STATUS submit(void *opaque, struct cdk2_ata_controller *controller,
	UINT16 port, UINT16 multiplier, struct cdk2_ata_command_packet *packet,
	void *event)
{
	struct fixture *fixture = opaque;
	(void)controller; (void)port; (void)multiplier; (void)packet;
	fixture->submits++; fixture->submitted_event = event;
	return EFI_SUCCESS;
}
static EFI_STATUS cancel(void *opaque, struct cdk2_ata_controller *controller)
{ struct fixture *fixture = opaque; (void)controller; fixture->cancels++;
	return EFI_SUCCESS; }

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_ide_channel channel = { 0x1f0, 0x3f6, 0 };
	struct cdk2_ide_services ide_services = { &fixture, read8, read16,
		write8, write16, write32, map, unmap, flush, timing, get_time, delay };
	struct cdk2_ata_protocol_services services = {
		&fixture, allocate, release, NULL, NULL };
	struct cdk2_ata_controller controller = { 0 };
	struct cdk2_ata_protocol_instance instance;
	struct cdk2_ext_scsi_instance scsi;
	struct cdk2_ide_engine engine;
	struct cdk2_ata_command_block acb = { .command = 0xe7 };
	struct cdk2_ata_command_packet packet = { .acb = &acb, .timeout = 100,
		.protocol = 2 };
	UINT16 port = 0xffff, device = 0xffff, parsed_port, parsed_device;
	void *path = NULL;
	UINT8 first[CDK2_EXT_SCSI_TARGET_BYTES], *target = first;
	UINT8 cdb[12] = { 0 };
	UINT64 lun = 0;
	struct cdk2_ext_scsi_packet scsi_packet = { .cdb = cdb,
		.cdb_length = 6, .direction = CDK2_EXT_SCSI_DIRECTION_READ,
		.timeout = 100 };

	CHECK(sizeof(struct cdk2_ata_pass_thru_protocol) == 8 * sizeof(void *));
	CHECK(offsetof(struct cdk2_ata_pass_thru_protocol, pass_thru) == sizeof(void *));
	CHECK(cdk2_ata_topology_init(&controller.topology, CDK2_ATA_IDE) == EFI_SUCCESS);
	CHECK(cdk2_ata_add_device(&controller.topology, 0, 0, CDK2_ATA_DISK) == EFI_SUCCESS);
	CHECK(cdk2_ata_add_device(&controller.topology, 0, 1, CDK2_ATAPI_DEVICE) == EFI_SUCCESS);
	controller.topology.devices[0].block_size = 512;
	{
		UINT8 transfer[1024];
		struct cdk2_ata_command_packet sectors = { .in_data = transfer,
			.in_length = 2, .length = 0x20 };
		CHECK(cdk2_ata_normalize_transfer(&controller.topology.devices[0],
			&sectors) == EFI_SUCCESS && sectors.in_length == sizeof(transfer));
		sectors.in_length = UINT32_MAX; sectors.out_length = 0;
		CHECK(cdk2_ata_normalize_transfer(&controller.topology.devices[0],
			&sectors) == EFI_BAD_BUFFER_SIZE && sectors.in_length == UINT32_MAX);
		sectors.in_length = 7; sectors.length = 0xa0;
		CHECK(cdk2_ata_normalize_transfer(&controller.topology.devices[0],
			&sectors) == EFI_SUCCESS && sectors.in_length == 7);
	}
	CHECK(cdk2_ide_engine_init(&engine, &ide_services, &channel, 1) == EFI_SUCCESS);
	controller.ide_engine = &engine; controller.started = 1;
	CHECK(cdk2_ata_protocol_init(&instance, &controller, &services, 4) == EFI_SUCCESS);
	CHECK(instance.mode.attributes == (CDK2_ATA_PASS_THRU_ATTRIBUTES_PHYSICAL |
		CDK2_ATA_PASS_THRU_ATTRIBUTES_LOGICAL));
	CHECK(instance.protocol.get_next_port(&instance.protocol, &port) == EFI_SUCCESS);
	CHECK(port == 0);
	CHECK(instance.protocol.get_next_device(&instance.protocol, port, &device) ==
		EFI_SUCCESS && device == 0);
	CHECK(instance.protocol.build_device_path(&instance.protocol, port, device,
		&path) == EFI_SUCCESS && path != NULL);
	CHECK(instance.protocol.get_device(&instance.protocol, path, &parsed_port,
		&parsed_device) == EFI_SUCCESS);
	CHECK(parsed_port == port && parsed_device == device);
	release(&fixture, path);
	CHECK(instance.protocol.pass_thru(&instance.protocol, 0, 0, &packet,
		&fixture) == EFI_UNSUPPORTED && fixture.submits == 0);
	services.submit = submit;
	CHECK(cdk2_ata_protocol_init(&instance, &controller, &services, 4) == EFI_SUCCESS &&
		(instance.mode.attributes & CDK2_ATA_PASS_THRU_ATTRIBUTES_NONBLOCKIO) != 0U);
	CHECK(instance.protocol.pass_thru(&instance.protocol, 0, 0, &packet,
		&fixture) == EFI_SUCCESS && fixture.submits == 1 &&
		fixture.submitted_event == &fixture);
	CHECK(instance.protocol.pass_thru(&instance.protocol, 1, 0, &packet,
		NULL) == EFI_NOT_FOUND);
	CHECK(instance.protocol.pass_thru(&instance.protocol, 0, 0, &packet,
		NULL) == EFI_SUCCESS);
	instance.services.cancel = cancel;
	CHECK(instance.protocol.reset_device(&instance.protocol, 0, 0) == EFI_SUCCESS &&
		fixture.cancels == 1);
	CHECK(instance.protocol.reset_device(&instance.protocol, 0, 2) == EFI_NOT_FOUND);
	CHECK(fixture.allocations == fixture.releases && fixture.resets != 0U);
	CHECK(sizeof(struct cdk2_ext_scsi_mode) == 12);
	CHECK(sizeof(struct cdk2_ext_scsi_protocol) == 8 * sizeof(void *));
	CHECK(cdk2_ext_scsi_init(&scsi, &controller, &services, 4) == EFI_SUCCESS);
	CHECK(scsi.mode.adapter_id == 0 && scsi.mode.attributes ==
		(CDK2_ATA_PASS_THRU_ATTRIBUTES_PHYSICAL |
		 CDK2_ATA_PASS_THRU_ATTRIBUTES_LOGICAL));
	memset(first, 0xff, sizeof(first));
	CHECK(scsi.protocol.get_next_target_lun(&scsi.protocol, &target, &lun) ==
		EFI_SUCCESS);
	CHECK(target[0] == 0 && target[1] == 1 && lun == 0);
	CHECK(scsi.protocol.pass_thru(&scsi.protocol, target, lun, &scsi_packet,
		&fixture) == EFI_SUCCESS);
	CHECK(scsi_packet.host_status == 0 && scsi_packet.target_status == 0);
	path = NULL;
	CHECK(scsi.protocol.build_device_path(&scsi.protocol, target, lun, NULL) ==
		EFI_INVALID_PARAMETER);
	CHECK(scsi.protocol.build_device_path(&scsi.protocol, target, lun, &path) ==
		EFI_SUCCESS);
	target = NULL;
	CHECK(scsi.protocol.get_target_lun(&scsi.protocol, path, &target, &lun) ==
		EFI_SUCCESS && target[0] == 0 && target[1] == 1 && lun == 0);
	release(&fixture, path);
	puts("ata pass thru protocol tests: PASS");
	return 0;
}
