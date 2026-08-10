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
	unsigned int data_reads, clear_after_reads;
	unsigned int fail_map, hold_busy, bm_reads;
	unsigned int atapi, resets, prdt_ready, packet_issued, bm_starts, cdb_words;
	unsigned int ordering_bad, fail_cdb;
	unsigned int phase_bytes;
	unsigned int phase_write;
	unsigned int phase_words;
	UINT16 written[50];
	UINT64 now; enum cdk2_ahci_dma_operation operations[8];
};
static UINT8 read8(void *opaque, UINT16 port)
{ struct fixture *f = opaque;
	if (f->atapi == 2U && port < 0x400U) {
		if ((port & 7U) == 7U)
			return (f->phase_write ? f->phase_words : f->data_reads) * 2U <
				(f->phase_bytes != 0U ?
				f->phase_bytes : 3U) ? 0x08U : 0U;
		if ((port & 7U) == 2U)
			return f->cdb_words != 0U ? 1U : (f->phase_write ? 0U : 2U);
		if ((port & 7U) == 4U)
			return (UINT8)(f->phase_bytes != 0U ? f->phase_bytes : 3U);
		if ((port & 7U) == 5U)
			return (UINT8)(f->phase_bytes >> 8);
	}
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
	if (f->data_reads == f->clear_after_reads)
		f->status = 0;
	return value; }
static EFI_STATUS write8(void *opaque, UINT16 port, UINT8 value)
{ struct fixture *f = opaque; (void)value; f->writes8++;
	if ((port & 7U) == 7U && value == 0xa0U) {
		if (!f->prdt_ready || f->bm_starts != 0U)
			f->ordering_bad++;
		f->packet_issued++;
		f->atapi = 2;
		f->cdb_words = 6U;
	}
	if (port >= 0xc000U && (port & 7U) == 0U && (value & 1U) != 0U) {
		if (f->atapi != 0U && !f->packet_issued)
			f->ordering_bad++;
		if (f->atapi != 0U)
			f->bm_starts++;
	}
	if ((port == 0x3f6U || port == 0x376U) && value == 0x04U)
		f->resets++;
	if (port == 0x1f7U || port == 0x177U)
		f->status = 0x08;
	return EFI_SUCCESS; }
static EFI_STATUS write16(void *opaque, UINT16 port, UINT16 value)
{ struct fixture *f = opaque; (void)port; f->writes16++;
	if (f->atapi == 2U && f->cdb_words != 0U)
		f->cdb_words--;
	else if (f->atapi == 2U && f->phase_write) {
		if (f->phase_words < 50U)
			f->written[f->phase_words] = value;
		f->phase_words++;
	}
	if (f->atapi == 2U && f->fail_cdb)
		return EFI_DEVICE_ERROR;
	if (f->writes16 == 256U)
		f->status = 0;
	return EFI_SUCCESS; }
static EFI_STATUS write32(void *opaque, UINT16 port, UINT32 value)
{ struct fixture *f = opaque; (void)value; f->writes32++;
	if (port >= 0xc000U && (port & 7U) == 4U)
		f->prdt_ready++;
	return EFI_SUCCESS; }
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
	fixture->clear_after_reads = 256U;
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
	{
		UINT8 odd[3] = { 0 };

		packet.in_data = odd; packet.in_length = sizeof(odd);
		packet.protocol = 4U; fixture.status = 0U;
		fixture.clear_after_reads = fixture.data_reads + 2U;
		CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_SUCCESS &&
			packet.in_length == sizeof(odd));
		CHECK(odd[0] != 0U || odd[1] != 0U || odd[2] != 0U);
		fixture.clear_after_reads = fixture.data_reads + 256U;
	}
	packet.in_data = NULL; packet.in_length = 0; packet.out_data = data;
	packet.out_length = 512; packet.protocol = 5; fixture.status = 0;
	CHECK(cdk2_ide_execute(&engine, 1, 1, &packet, 100) == EFI_SUCCESS);
	CHECK(fixture.writes16 == 256);
	packet.out_data = NULL; packet.out_length = 0; packet.in_data = data;
	packet.in_length = sizeof(data); packet.protocol = 0x0a; fixture.status = 0;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_SUCCESS);
	CHECK(fixture.operations[0] == CDK2_AHCI_BUS_MASTER_WRITE && fixture.maps == 3 &&
		fixture.unmaps == 3 && fixture.writes32 == 1 && engine.prd[4].end == 0x8000);
	{
		struct cdk2_ide_async_request request;
		BOOLEAN complete = 0;
		unsigned int steps = 0, before_unmaps = fixture.unmaps;

		fixture.bm_reads = 0; fixture.bm_status = 0x04U;
		CHECK(cdk2_ide_async_prepare(&request, &engine, 1, 1, &packet, 100) ==
			EFI_SUCCESS);
		while (!complete && steps++ < 64U)
			CHECK(cdk2_ide_async_step(&request, &complete) == EFI_SUCCESS);
		CHECK(complete && steps > 16U && request.cleaned &&
			fixture.unmaps > before_unmaps);
		fixture.bm_reads = 0; fixture.bm_status = 0U;
		CHECK(cdk2_ide_async_prepare(&request, &engine, 0, 0, &packet, 100) ==
			EFI_SUCCESS);
		CHECK(cdk2_ide_async_step(&request, &complete) == EFI_SUCCESS);
		complete = 0;
		while (!complete)
			(void)cdk2_ide_async_abort(&request, &complete);
		CHECK(request.cleaned && request.terminal_status == EFIERR(21));
	}
	{
		unsigned int before_unmaps = fixture.unmaps;
	fixture.fail_map = fixture.maps + 1;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_DEVICE_ERROR);
	CHECK(fixture.unmaps == before_unmaps);
	}
	fixture.fail_map = 0; fixture.hold_busy = 1; fixture.now = 0;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 2) == EFI_TIMEOUT);
	fixture.hold_busy = 0; fixture.status = 0;
	fixture.bm_status = 0x02U; fixture.bm_reads = 0; fixture.now = 0;
	CHECK(cdk2_ide_execute(&engine, 0, 0, &packet, 100) == EFI_DEVICE_ERROR);
	fixture.bm_status = 0x04U; fixture.bm_reads = 0; fixture.status = 0;
	CHECK(cdk2_ide_reset(&engine, 0, 100) == EFI_SUCCESS);
	{
		UINT8 cdb[12] = { 0x12 }, odd[3] = { 0 };
		struct cdk2_ata_status_block packet_asb;
		struct cdk2_ata_command_packet atapi_packet = { .asb = &packet_asb,
			.in_data = odd, .in_length = sizeof(odd), .protocol = 4 };

		fixture.atapi = 1; fixture.data_reads = 0; fixture.data = 0x1234;
		CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
			sizeof(cdb), 100) == EFI_SUCCESS);
		CHECK(atapi_packet.in_length == 3 && odd[0] == 0x34 &&
			odd[1] == 0x12 && odd[2] == 0x35);
		CHECK(fixture.writes16 >= 6U && packet_asb.status == 0);
		{
			UINT8 short_read[102] = { 0 };

			short_read[100] = 0xa5U; short_read[101] = 0x5aU;
			fixture.atapi = 1; fixture.data_reads = 0; fixture.data = 0x2000;
			fixture.phase_bytes = 512U; fixture.status = 0U;
			atapi_packet.in_data = short_read; atapi_packet.in_length = 100U;
			CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
				sizeof(cdb), 100000U) == EFI_SUCCESS);
			CHECK(atapi_packet.in_length == 100U && short_read[0] == 0U &&
				short_read[1] == 0x20U && short_read[98] == 49U &&
				short_read[99] == 0x20U && short_read[100] == 0xa5U &&
				short_read[101] == 0x5aU && fixture.data_reads == 256U);
			fixture.phase_bytes = 0U;
		}
		{
			UINT8 guarded[5] = { 0x11U, 0x22U, 0x33U, 0xa5U, 0x5aU };

			fixture.atapi = 1; fixture.phase_bytes = 3U; fixture.phase_write = 1U;
			fixture.phase_words = 0U; fixture.status = 0U;
			atapi_packet.in_data = guarded; atapi_packet.in_length = 3U;
			CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
				sizeof(cdb), 1000U) == EFI_DEVICE_ERROR);
			CHECK(guarded[0] == 0x11U && guarded[1] == 0x22U &&
				guarded[2] == 0x33U && guarded[3] == 0xa5U &&
				guarded[4] == 0x5aU && fixture.phase_words == 0U);
			fixture.phase_bytes = 0U; fixture.phase_write = 0U;
		}
		{
			UINT8 odd_phase[102] = { 0 };

			odd_phase[100] = 0xa5U; odd_phase[101] = 0x5aU;
			fixture.atapi = 1; fixture.phase_bytes = 513U; fixture.status = 0U;
			fixture.data_reads = 0U; fixture.data = 0x3000U;
			atapi_packet.in_data = odd_phase; atapi_packet.in_length = 100U;
			CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
				sizeof(cdb), 100000U) == EFI_SUCCESS);
			CHECK(atapi_packet.in_length == 100U && fixture.data_reads == 257U &&
				odd_phase[100] == 0xa5U && odd_phase[101] == 0x5aU);
			fixture.phase_bytes = 0U;
		}
		{
			UINT8 short_write[102];

			for (unsigned int index = 0; index < 100U; index++)
				short_write[index] = (UINT8)index;
			short_write[100] = 0xa5U; short_write[101] = 0x5aU;
			fixture.atapi = 1; fixture.phase_bytes = 512U; fixture.phase_write = 1U;
			fixture.phase_words = 0U; fixture.status = 0U;
			atapi_packet.in_data = NULL; atapi_packet.in_length = 0U;
			atapi_packet.out_data = short_write; atapi_packet.out_length = 100U;
			CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
				sizeof(cdb), 100000U) == EFI_SUCCESS);
			CHECK(atapi_packet.out_length == 100U && fixture.phase_words == 256U &&
				fixture.written[0] == 0x0100U && fixture.written[49] == 0x6362U &&
				short_write[100] == 0xa5U && short_write[101] == 0x5aU);
			fixture.phase_bytes = 0U; fixture.phase_write = 0U;
			atapi_packet.out_data = NULL; atapi_packet.out_length = 0U;
		}
		fixture.atapi = 1; fixture.data_reads = 0; fixture.bm_reads = 0;
		fixture.prdt_ready = 0; fixture.packet_issued = 0;
		fixture.bm_starts = 0; fixture.ordering_bad = 0;
		fixture.status = 0; fixture.bm_status = 0x04;
		atapi_packet.in_data = data; atapi_packet.in_length = 512;
		atapi_packet.protocol = 0x0a;
		CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
			sizeof(cdb), 100) == EFI_SUCCESS);
		CHECK(fixture.maps >= 2U && fixture.unmaps >= 2U);
		CHECK(fixture.prdt_ready != 0U && fixture.packet_issued != 0U &&
			fixture.bm_starts == 1U && fixture.ordering_bad == 0U);
		fixture.atapi = 1; fixture.packet_issued = 0; fixture.bm_starts = 0;
		fixture.fail_cdb = 1; fixture.bm_reads = 0;
		{
			unsigned int maps = fixture.maps, unmaps = fixture.unmaps;
			CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
				sizeof(cdb), 100) == EFI_DEVICE_ERROR);
			CHECK(fixture.maps > maps && fixture.unmaps > unmaps &&
				fixture.bm_starts == 0U);
		}
		fixture.fail_cdb = 0;
		fixture.atapi = 1; fixture.bm_reads = 0;
		fixture.fail_map = fixture.maps + 1U;
		{
			unsigned int resets = fixture.resets;
		CHECK(cdk2_ide_atapi_execute(&engine, 0, 0, &atapi_packet, cdb,
			sizeof(cdb), 100) == EFI_DEVICE_ERROR);
		CHECK(fixture.resets == resets);
		}
	}
	puts("ata atapi IDE tests: PASS");
	return 0;
}
