/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINT8 status, bm_status; UINT16 data;
	unsigned int writes8, writes16, writes32, maps, unmaps, flushes, timings;
	unsigned int data_reads;
	unsigned int fail_map, hold_busy, bm_reads;
	UINT64 now; enum cdk2_ahci_dma_operation operations[8];
};
static UINT8 read8(void *opaque, UINT16 port)
{ struct fixture *f = opaque;
	if ((port & 7U) == 7U)
		return f->hold_busy ? 0x80U : f->status;
	if ((port & 7U) == 2U) {
		UINT8 status = f->bm_reads++ == 0U ? 0U : f->bm_status;
		if ((status & 0x04U) != 0U)
			f->status = 0;
		return status;
	}
	return 0; }
static UINT16 read16(void *opaque, UINT16 port)
{ struct fixture *f = opaque; (void)port; UINT16 value = f->data++; f->data_reads++;
	if (f->data_reads == 256U)
		f->status = 0;
	return value; }
static EFI_STATUS write8(void *opaque, UINT16 port, UINT8 value)
{ struct fixture *f = opaque; (void)value; f->writes8++;
	if (port == 0x1f7U || port == 0x177U)
		f->status = 0x08;
	return EFI_SUCCESS; }
static EFI_STATUS write16(void *opaque, UINT16 port, UINT16 value)
{ struct fixture *f = opaque; (void)port; (void)value; f->writes16++;
	if (f->writes16 == 256U)
		f->status = 0;
	return EFI_SUCCESS; }
static EFI_STATUS write32(void *opaque, UINT16 port, UINT32 value)
{ struct fixture *f = opaque; (void)port; (void)value; f->writes32++; return EFI_SUCCESS; }
static EFI_STATUS map(void *opaque, enum cdk2_ahci_dma_operation operation,
	void *host, size_t *size, UINT64 *device, void **mapping)
{ struct fixture *f = opaque; (void)host; f->maps++;
	if (f->maps <= 8U)
		f->operations[f->maps - 1U] = operation;
	if (f->maps == f->fail_map)
		return EFI_DEVICE_ERROR;
	if (*size > 0x18000U)
		*size = 0x18000U;
	*device = 0x10ff00U; *mapping = host; return EFI_SUCCESS; }
static EFI_STATUS unmap(void *opaque, void *mapping)
{ struct fixture *f = opaque; (void)mapping; f->unmaps++; return EFI_SUCCESS; }
static EFI_STATUS flush(void *opaque)
{ struct fixture *f = opaque; f->flushes++; return EFI_SUCCESS; }
static EFI_STATUS timing(void *opaque, UINT8 channel, UINT8 device)
{ struct fixture *f = opaque; CHECK(channel < 2 && device < 2); f->timings++;
	return EFI_SUCCESS; }
static UINT64 get_time(void *opaque)
{ struct fixture *f = opaque; return f->now++; }
static void delay(void *opaque, UINTN microseconds)
{ struct fixture *f = opaque; (void)microseconds; f->now++; }
static void initialize(struct fixture *fixture, struct cdk2_ide_engine *engine)
{
	struct cdk2_ide_services services; struct cdk2_ide_channel channels[2] = {
		{ .command = 0x1f0, .control = 0x3f6, .bus_master = 0xc000 },
		{ .command = 0x170, .control = 0x376, .bus_master = 0xc008 } };
	memset(fixture, 0, sizeof(*fixture)); fixture->status = 0;
	fixture->bm_status = 0x04; fixture->data = 0x1234;
	services = (struct cdk2_ide_services) { .context = fixture, .read8 = read8,
		.read16 = read16, .write8 = write8, .write16 = write16,
		.write32 = write32, .map = map, .unmap = unmap, .flush = flush,
		.set_timing = timing, .time = get_time, .delay = delay };
	CHECK(cdk2_ide_engine_init(engine, &services, channels, 2) == EFI_SUCCESS);
}

int main(void)
{
	struct fixture fixture; struct cdk2_ide_engine engine;
	struct cdk2_ata_status_block asb;
	struct cdk2_ata_command_block acb = { .command = 0x20, .sector_count = 1 };
	UINT8 data[0x20000]; struct cdk2_ata_command_packet packet = {
		.asb = &asb, .acb = &acb, .in_data = data, .in_length = 512,
		.protocol = 4 };
	initialize(&fixture, &engine);
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_SUCCESS);
	CHECK(fixture.timings == 1 && fixture.writes16 == 0 && data[0] == 0x34 &&
		data[1] == 0x12);
	CHECK(asb.status == 0 && asb.error == 0);
	packet.in_data = NULL; packet.in_length = 0; packet.out_data = data;
	packet.out_length = 512; packet.protocol = 5; fixture.status = 0;
	CHECK(cdk2_ide_execute(&engine, 1, 1, &packet, 100) == EFI_SUCCESS);
	CHECK(fixture.writes16 == 256);
	packet.out_data = NULL; packet.out_length = 0; packet.in_data = data;
	packet.in_length = sizeof(data); packet.protocol = 0x0a; fixture.status = 0;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_SUCCESS);
	CHECK(fixture.operations[0] == CDK2_AHCI_BUS_MASTER_WRITE && fixture.maps == 3 &&
		fixture.unmaps == 3 && fixture.writes32 == 1 && engine.prd[4].end == 0x8000);
	fixture.fail_map = fixture.maps + 1;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_DEVICE_ERROR);
	CHECK(fixture.unmaps == 3);
	fixture.fail_map = 0; fixture.hold_busy = 1; fixture.now = 0;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 2) == EFI_TIMEOUT);
	fixture.hold_busy = 0; fixture.status = 0;
	CHECK(cdk2_ide_reset(&engine, 0, 100) == EFI_SUCCESS);
	puts("ata atapi IDE tests: PASS");
	return 0;
}
