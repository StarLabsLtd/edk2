/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)
#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))

struct fixture {
	unsigned int allocations, releases, maps, unmaps, flushes, fail_allocate;
	unsigned int fail_map, fail_unmap, fail_flush, writes, ci_reads;
	unsigned int fail_write; UINT16 write_offsets[128], write_ports[128];
	UINT32 write_values[128];
	unsigned int hold_ci, ghc_reads; UINT32 hold_command;
	size_t map_limit;
	UINT64 now; UINT32 registers[64]; enum cdk2_ahci_dma_operation operation;
};
static EFI_STATUS allocate(void *opaque, size_t size, size_t alignment,
	void **host, UINT64 *device)
{ struct fixture *f = opaque; f->allocations++;
	if (f->allocations == f->fail_allocate)
		return EFI_OUT_OF_RESOURCES;
	*host = aligned_alloc(alignment, size);
	if (*host == NULL)
		return EFI_OUT_OF_RESOURCES;
	*device = (UINT64)(uintptr_t)*host; return EFI_SUCCESS; }
static EFI_STATUS release(void *opaque, void *host, size_t size)
{ struct fixture *f = opaque; (void)size; f->releases++; free(host); return EFI_SUCCESS; }
static EFI_STATUS map(void *opaque, enum cdk2_ahci_dma_operation operation,
	void *host, size_t *size, UINT64 *device, void **mapping)
{ struct fixture *f = opaque; f->maps++; f->operation = operation;
	if (f->maps == f->fail_map)
		return EFI_DEVICE_ERROR;
	if (f->map_limit != 0U && *size > f->map_limit)
		*size = f->map_limit;
	else if (f->map_limit == 0U && *size > 0x500000U)
		*size = 0x500000U;
	*device = (UINT64)(uintptr_t)host; *mapping = host; return EFI_SUCCESS; }
static EFI_STATUS unmap(void *opaque, void *mapping)
{ struct fixture *f = opaque; (void)mapping; f->unmaps++;
	return f->unmaps == f->fail_unmap ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS flush(void *opaque)
{ struct fixture *f = opaque; f->flushes++;
	return f->flushes == f->fail_flush ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static UINT32 read_register(void *opaque, UINT16 port, UINT16 offset)
{ struct fixture *f = opaque; (void)port;
	if (offset == 0x38U && !f->hold_ci && f->ci_reads++ != 0U)
		f->registers[offset / 4U] = 0;
	if (offset == 0x04U && f->ghc_reads++ != 0U)
		f->registers[offset / 4U] = 0;
	return f->registers[offset / 4U] |
		(offset == 0x18U ? f->hold_command : 0U); }
static EFI_STATUS write_register(void *opaque, UINT16 port, UINT16 offset, UINT32 value)
{ struct fixture *f = opaque; f->write_offsets[f->writes] = offset;
	f->write_ports[f->writes] = port; f->write_values[f->writes] = value;
	f->writes++; if (f->writes == f->fail_write) return EFI_DEVICE_ERROR;
	f->registers[offset / 4U] = value; return EFI_SUCCESS; }
static UINT64 get_time(void *opaque)
{ struct fixture *f = opaque; return f->now++; }
static void delay(void *opaque, UINTN microseconds)
{ struct fixture *f = opaque; (void)microseconds; f->now++; }
static void initialize(struct fixture *fixture, struct cdk2_ahci_dma_services *services)
{
	memset(fixture, 0, sizeof(*fixture));
	*services = (struct cdk2_ahci_dma_services) {
		.context = fixture, .allocate = allocate, .release = release, .map = map,
		.unmap = unmap, .flush = flush, .read = read_register,
		.write = write_register, .time = get_time, .delay = delay };
}
static UINT32 get32(const UINT8 *value)
{ return value[0] | ((UINT32)value[1] << 8) | ((UINT32)value[2] << 16) |
	((UINT32)value[3] << 24); }

int main(void)
{
	struct fixture fixture; struct cdk2_ahci_dma_services services;
	struct cdk2_ahci_engine engine; struct cdk2_ata_command_block acb = {0};
	struct cdk2_ata_status_block asb;
	struct cdk2_ata_command_packet packet = { .asb = &asb, .acb = &acb };
	struct cdk2_ahci_command command; UINT8 atapi[12] = { 0x28 };
	void *large = malloc(0x600000U);
	CHECK(large != NULL);
	initialize(&fixture, &services);
	CHECK(cdk2_ahci_engine_init(&engine, &services, 3U << 8, 5) == EFI_SUCCESS);
	CHECK(engine.slots == 4 && fixture.allocations == 6);
	((UINT8 *)engine.received_fis.host)[0x42] = 0x50;
	((UINT8 *)engine.received_fis.host)[0x43] = 0x04;
	acb.command = 0x25; acb.features = CDK2_ATAPI_FEATURE_DMA;
	acb.sector_number = 4; acb.sector_count = 8;
	packet.in_data = large; packet.in_length = 0x600000U; packet.protocol = 0x0a;
	CHECK(cdk2_ahci_build_command(&packet, 3, atapi, sizeof(atapi), &command) ==
		EFI_SUCCESS);
	CHECK(command.fis[0] == 0x27 && command.fis[1] == 0x83 &&
		command.fis[2] == 0x25 && command.fis[3] == CDK2_ATAPI_FEATURE_DMA &&
		command.atapi_command);
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, atapi, sizeof(atapi), 100) ==
		EFI_SUCCESS);
	CHECK(asb.status == 0x50 && asb.error == 0x04);
	CHECK(engine.active_port == 0 && fixture.registers[0] ==
		(UINT32)engine.command_list.device);
	{
		unsigned int sequence = 0;
		static const UINT16 offsets[] = { 0x18, 0x18, 0x00, 0x04, 0x08,
			0x0c, 0x10, 0x30, 0x18, 0x18 };
		for (unsigned int index = 0; index < fixture.writes; index++) {
			if (sequence < ARRAY_SIZE(offsets) &&
			    fixture.write_offsets[index] == offsets[sequence])
				sequence++;
		}
		CHECK(sequence == ARRAY_SIZE(offsets));
		CHECK(fixture.write_values[8] == 0x10U &&
			fixture.write_values[9] == 0x11U);
	}
	CHECK(fixture.operation == CDK2_AHCI_BUS_MASTER_WRITE && fixture.maps == 2 &&
		fixture.unmaps == 2 && engine.active_slots == 0);
	CHECK((get32(engine.command_list.host) >> 16) == 3);
	CHECK((get32((UINT8 *)engine.command_tables[0].host + 0x80U + 12U) &
		0x3fffffU) == CDK2_AHCI_PRDT_MAX_BYTES - 1U);
	{
		unsigned int before = fixture.writes, restored = 0, configured = 0;

		fixture.ci_reads = 0;
		CHECK(cdk2_ahci_execute(&engine, 2, &packet, NULL, 0, 1000) ==
			EFI_SUCCESS);
		for (unsigned int index = before; index < fixture.writes; index++) {
			if (fixture.write_ports[index] == 0 &&
			    fixture.write_offsets[index] == 0x00U)
				restored = 1;
			if (restored && fixture.write_ports[index] == 2 &&
			    fixture.write_offsets[index] == 0x00U)
				configured = 1;
		}
		CHECK(restored && configured && engine.active_port == 2 &&
			engine.configured_ports == (1U << 2));
	}
	fixture.ci_reads = 0; packet.in_length = 0x600000U;
	fixture.fail_map = fixture.maps + 1;
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, NULL, 0, 100) == EFI_DEVICE_ERROR);
	CHECK(engine.active_slots == 0);
	fixture.fail_map = 0; fixture.hold_ci = 1; fixture.now = 0;
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, NULL, 0, 2) == EFI_TIMEOUT);
	CHECK(engine.active_slots == 0);
	fixture.hold_ci = 0; fixture.ci_reads = 0; fixture.registers[0x20 / 4] = 0;
	CHECK(cdk2_ahci_reset_port(&engine, 0, 100) == EFI_SUCCESS);
	fixture.registers[0x04 / 4] = 0;
	CHECK(cdk2_ahci_reset_controller(&engine, 100) == EFI_SUCCESS);
	{
		struct cdk2_ahci_async_request request;
		BOOLEAN complete = 0;
		unsigned int before_unmaps = fixture.unmaps;

		fixture.ci_reads = 0; fixture.now = 0; packet.in_length = 512;
		CHECK(cdk2_ahci_async_prepare(&request, &engine, 0, &packet, 100) ==
			EFI_SUCCESS && request.mapping_count == 0 && engine.active_slots == 0);
		for (unsigned int tick = 0; tick < 512 && !complete; tick++)
			CHECK(cdk2_ahci_async_step(&request, &complete) == EFI_SUCCESS);
		CHECK(complete && request.cleaned && engine.active_slots == 0 &&
			fixture.unmaps == before_unmaps + 1U);
		fixture.map_limit = 512U; packet.in_length = 32768U; fixture.ci_reads = 0;
		complete = 0;
		CHECK(cdk2_ahci_async_prepare(&request, &engine, 0, &packet, 1000U) ==
			EFI_SUCCESS);
		for (unsigned int tick = 0; tick < 1024U && !complete; tick++) {
			unsigned int maps = fixture.maps, unmaps = fixture.unmaps;

			CHECK(cdk2_ahci_async_step(&request, &complete) == EFI_SUCCESS);
			CHECK(fixture.maps - maps <= 1U && fixture.unmaps - unmaps <= 1U);
		}
		CHECK(complete && request.cleaned && request.command.prdt_count == 64U);
		fixture.map_limit = 0U; packet.in_length = 512U;
		fixture.hold_ci = 1; fixture.now = 0;
		CHECK(cdk2_ahci_async_prepare(&request, &engine, 0, &packet, 100) == EFI_SUCCESS);
		while (request.phase != CDK2_AHCI_ASYNC_CI)
			CHECK(cdk2_ahci_async_step(&request, &complete) == EFI_SUCCESS);
		fixture.now = request.deadline + request.timeout;
		CHECK(cdk2_ahci_async_step(&request, &complete) == EFI_SUCCESS &&
			request.phase == CDK2_AHCI_ASYNC_ABORT_STOP && request.aborting &&
			request.terminal_status == EFI_TIMEOUT);
		complete = 0;
		for (unsigned int tick = 0; tick < 128 && !complete; tick++)
			(void)cdk2_ahci_async_abort(&request, &complete);
		CHECK(complete && request.cleaned && engine.active_slots == 0);
		fixture.hold_ci = 0;
	}
	cdk2_ahci_engine_destroy(&engine);
	CHECK(fixture.releases == 6);
	for (unsigned int failure = 1; failure <= 10; failure++) {
		initialize(&fixture, &services);
		fixture.registers[0x00 / 4] = 0x11111111U;
		fixture.registers[0x04 / 4] = 0x22222222U;
		fixture.registers[0x08 / 4] = 0x33333333U;
		fixture.registers[0x0c / 4] = 0x44444444U;
		fixture.registers[0x18 / 4] = 0x10U;
		CHECK(cdk2_ahci_engine_init(&engine, &services, 1U << 8, 1) ==
			EFI_SUCCESS);
		fixture.fail_write = failure;
		CHECK(cdk2_ahci_execute(&engine, 0, &packet, NULL, 0, 100) ==
			EFI_DEVICE_ERROR);
		CHECK(fixture.registers[0x00 / 4] == 0x11111111U &&
			fixture.registers[0x04 / 4] == 0x22222222U &&
			fixture.registers[0x08 / 4] == 0x33333333U &&
			fixture.registers[0x0c / 4] == 0x44444444U &&
			fixture.registers[0x18 / 4] == 0x10U);
		CHECK(engine.configured_ports == 0 && engine.active_port == 0xffffU);
		cdk2_ahci_engine_destroy(&engine);
	}
	initialize(&fixture, &services);
	CHECK(cdk2_ahci_engine_init(&engine, &services, 1U << 8, 1) == EFI_SUCCESS);
	fixture.registers[0x00 / 4] = 0x11111111U;
	fixture.hold_command = 0x8000U;
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, NULL, 0, 2) ==
		EFI_TIMEOUT);
	CHECK(engine.configured_ports == 1 && engine.active_port == 0xffffU);
	fixture.hold_command = 0;
	cdk2_ahci_engine_destroy(&engine);
	CHECK(fixture.releases == 4 && fixture.registers[0x00 / 4] == 0x11111111U);
	initialize(&fixture, &services); fixture.fail_allocate = 3;
	CHECK(cdk2_ahci_engine_init(&engine, &services, 1U << 8, 1) ==
		EFI_OUT_OF_RESOURCES);
	CHECK(fixture.releases == 2 && !engine.initialized);
	free(large);
	puts("ata atapi AHCI tests: PASS");
	return 0;
}
