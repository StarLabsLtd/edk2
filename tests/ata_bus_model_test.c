/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_bus.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	struct cdk2_ata_pass_thru_protocol protocol;
	struct cdk2_ata_pass_thru_mode mode;
	UINTN port_call, device_call, identify_call, releases;
	UINTN devices, fail_identify, bad_path, atapi_device, timeout_device;
};
static struct fixture *active;

static void put16(UINT8 *p, UINT16 value)
{ p[0] = (UINT8)value; p[1] = (UINT8)(value >> 8); }
static void put32(UINT8 *p, UINT32 value)
{ put16(p, (UINT16)value); put16(p + 2, (UINT16)(value >> 16)); }
static void put64(UINT8 *p, UINT64 value)
{ put32(p, (UINT32)value); put32(p + 4, (UINT32)(value >> 32)); }

static EFI_STATUS CDK2_MS_ABI next_port(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 *port)
{
	(void)p;
	if (active->port_call++ == 0U) {
		*port = 3;
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}
static EFI_STATUS CDK2_MS_ABI next_device(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 port, UINT16 *device)
{
	(void)p; (void)port;
	if (active->device_call < active->devices) {
		*device = (UINT16)active->device_call++;
		return EFI_SUCCESS;
	}
	return EFI_NOT_FOUND;
}
static EFI_STATUS CDK2_MS_ABI pass(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 port, UINT16 device, struct cdk2_ata_command_packet *packet, void *event)
{
	UINT8 *id = packet->in_data; (void)p; (void)port; (void)device; (void)event;
	active->identify_call++;
	if (device == active->timeout_device)
		return EFI_TIMEOUT;
	if (active->identify_call == active->fail_identify)
		return EFI_DEVICE_ERROR;
	memset(id, 0, 512);
	if (device == active->atapi_device)
		return EFI_SUCCESS;
	put16(id + 49 * 2, 1U << 9);
	put16(id + 53 * 2, 1U << 2); put16(id + 83 * 2, 0x4400);
	put16(id + 85 * 2, 1U << 5); put16(id + 88 * 2, 1);
	put16(id + 106 * 2, 0x7003); put32(id + 117 * 2, 2048);
	put64(id + 100 * 2, 0x123456789ULL); put16(id + 209 * 2, 0x4002);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI build_path(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 port, UINT16 device, void **path)
{
	UINT8 *node = malloc(10); (void)p;
	if (node == NULL)
		return EFI_OUT_OF_RESOURCES;
	memset(node, 0, 10); node[0] = 3; node[1] = 18;
	node[2] = active->bad_path ? 17 : 10; node[4] = (UINT8)port;
	node[6] = (UINT8)device; *path = node; return EFI_SUCCESS;
}
static void release_path(void *context, void *path)
{ struct fixture *fixture = context; fixture->releases++; free(path); }
static void init(struct fixture *fixture, UINTN devices)
{
	memset(fixture, 0, sizeof(*fixture)); active = fixture; fixture->devices = devices;
	fixture->atapi_device = (UINTN)-1; fixture->timeout_device = (UINTN)-1;
	fixture->protocol.pass_thru = pass; fixture->protocol.get_next_port = next_port;
	fixture->protocol.get_next_device = next_device;
	fixture->protocol.build_device_path = build_path;
	fixture->mode.io_align = 64; fixture->mode.attributes =
		CDK2_ATA_PASS_THRU_ATTRIBUTES_LOGICAL |
		CDK2_ATA_PASS_THRU_ATTRIBUTES_NONBLOCKIO;
	fixture->protocol.mode = &fixture->mode;
}

int main(void)
{
	struct cdk2_ata_bus bus = { 0 }, before;
	struct cdk2_ata_bus_media media;
	struct fixture first, second;
	UINT8 identify[512] = { 0 };

	CHECK(sizeof(struct cdk2_block_io) == 48);
	CHECK(sizeof(struct cdk2_block_io2) == 40);
	CHECK(sizeof(struct cdk2_block_media) == 48);
	CHECK(sizeof(struct cdk2_ata_bus_disk_info) == 40);
	CHECK(sizeof(struct cdk2_ata_bus_security) == 16);
	CHECK(offsetof(struct cdk2_block_media, lowest_aligned_lba) == 32);
	put16(identify + 49 * 2, 1U << 9); put16(identify + 83 * 2, 0x4400);
	put16(identify + 106 * 2, 0x7003); put32(identify + 117 * 2, 2048);
	put64(identify + 100 * 2, 0x123456789ULL); put16(identify + 209 * 2, 0x4002);
	CHECK(cdk2_ata_bus_parse_identify(identify, &media) == EFI_SUCCESS);
	CHECK(media.blocks == 0x123456789ULL && media.block_size == 4096 &&
		media.logical_blocks_per_physical_block == 8 &&
		media.lowest_aligned_lba == 6 && media.lba48);
	memset(identify, 0, sizeof(identify)); put16(identify + 49 * 2, 1U << 9);
	put16(identify + 60 * 2, 1234); put16(identify + 83 * 2, 0xffff);
	CHECK(cdk2_ata_bus_parse_identify(identify, &media) == EFI_SUCCESS &&
		media.blocks == 1234 && !media.lba48);
	put16(identify + 83 * 2, 0x4400); put64(identify + 100 * 2, 0x123456789ULL);
	put16(identify + 106 * 2, 0x7003); put32(identify + 117 * 2, 2048);
	put16(identify + 209 * 2, 0x4008);
	CHECK(cdk2_ata_bus_parse_identify(identify, &media) == EFI_COMPROMISED_DATA);
	put16(identify + 209 * 2, 0x4002);
	put64(identify + 100 * 2, 0); CHECK(cdk2_ata_bus_parse_identify(identify,
		&media) == CDK2_EFI_NO_MEDIA);

	init(&first, 2);
	CHECK(cdk2_ata_bus_add_controller(&bus, (void *)1, &first.protocol,
		release_path, &first) == EFI_SUCCESS);
	CHECK(bus.controller_count == 1 && bus.child_count == 2 && first.releases == 2 &&
		bus.children[0].port == 3 && bus.children[1].multiplier == 1 &&
		bus.children[0].geometry.io_align == 64 && bus.children[0].geometry.udma);
	CHECK(cdk2_ata_bus_add_controller(&bus, (void *)1, &first.protocol,
		release_path, &first) == EFI_ALREADY_STARTED);
	before = bus; init(&second, 2); second.fail_identify = 2;
	CHECK(cdk2_ata_bus_add_controller(&bus, (void *)2, &second.protocol,
		release_path, &second) == EFI_SUCCESS && bus.controller_count == 2 &&
		bus.child_count == 4);
	CHECK(cdk2_ata_bus_remove_controller(&bus, (void *)2) == EFI_SUCCESS);
	init(&second, 3); second.atapi_device = 1; second.timeout_device = 2;
	CHECK(cdk2_ata_bus_add_controller(&bus, (void *)2, &second.protocol,
		release_path, &second) == EFI_SUCCESS && bus.controller_count == 2 &&
		bus.controllers[1].child_count == 1);
	CHECK(cdk2_ata_bus_remove_controller(&bus, (void *)2) == EFI_SUCCESS);
	init(&second, 1); second.bad_path = 1;
	CHECK(cdk2_ata_bus_add_controller(&bus, (void *)2, &second.protocol,
		release_path, &second) == EFI_NOT_FOUND);
	CHECK(second.releases == 1 && bus.controller_count == before.controller_count &&
		bus.child_count == before.child_count);
	CHECK(cdk2_ata_bus_remove_controller(&bus, (void *)1) == EFI_SUCCESS &&
		bus.controller_count == 0 && bus.child_count == 0);
	CHECK(cdk2_ata_bus_remove_controller(&bus, (void *)1) == EFI_NOT_FOUND);
	puts("ata bus model tests: PASS");
	return 0;
}
