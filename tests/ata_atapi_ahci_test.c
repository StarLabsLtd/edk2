/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	unsigned int allocations, releases, maps, unmaps, flushes, fail_allocate;
	unsigned int fail_map, fail_unmap, fail_flush, writes, ci_reads;
	unsigned int hold_ci, ghc_reads;
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
	if (*size > 0x500000U)
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
	return f->registers[offset / 4U]; }
static EFI_STATUS write_register(void *opaque, UINT16 port, UINT16 offset, UINT32 value)
{ struct fixture *f = opaque; (void)port; f->writes++; f->registers[offset / 4U] = value;
	return EFI_SUCCESS; }
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
	struct cdk2_ata_command_packet packet = { .acb = &acb };
	struct cdk2_ahci_command command; UINT8 atapi[12] = { 0x28 };
	void *large = malloc(0x600000U);
	CHECK(large != NULL);
	initialize(&fixture, &services);
	CHECK(cdk2_ahci_engine_init(&engine, &services, 3U << 8, 5) == EFI_SUCCESS);
	CHECK(engine.slots == 4 && fixture.allocations == 6);
	acb.command = 0x25; acb.sector_number = 4; acb.sector_count = 8;
	packet.in_data = large; packet.in_length = 0x600000U; packet.protocol = 0x0a;
	CHECK(cdk2_ahci_build_command(&packet, 3, atapi, sizeof(atapi), &command) ==
		EFI_SUCCESS);
	CHECK(command.fis[0] == 0x27 && command.fis[1] == 0x83 &&
		command.fis[2] == 0x25 && command.atapi_command);
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, atapi, sizeof(atapi), 100) ==
		EFI_SUCCESS);
	CHECK(fixture.operation == CDK2_AHCI_BUS_MASTER_WRITE && fixture.maps == 2 &&
		fixture.unmaps == 2 && engine.active_slots == 0);
	CHECK((get32(engine.command_list.host) >> 16) == 3);
	CHECK((get32((UINT8 *)engine.command_tables[0].host + 0x80U + 12U) &
		0x3fffffU) == CDK2_AHCI_PRDT_MAX_BYTES - 1U);
	fixture.ci_reads = 0; fixture.fail_map = fixture.maps + 1;
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, NULL, 0, 100) == EFI_DEVICE_ERROR);
	CHECK(engine.active_slots == 0);
	fixture.fail_map = 0; fixture.hold_ci = 1; fixture.now = 0;
	CHECK(cdk2_ahci_execute(&engine, 0, &packet, NULL, 0, 2) == EFI_TIMEOUT);
	CHECK(engine.active_slots == 0);
	fixture.hold_ci = 0; fixture.ci_reads = 0; fixture.registers[0x20 / 4] = 0;
	CHECK(cdk2_ahci_reset_port(&engine, 0, 100) == EFI_SUCCESS);
	fixture.registers[0x04 / 4] = 0;
	CHECK(cdk2_ahci_reset_controller(&engine, 100) == EFI_SUCCESS);
	cdk2_ahci_engine_destroy(&engine);
	CHECK(fixture.releases == 6);
	initialize(&fixture, &services); fixture.fail_allocate = 3;
	CHECK(cdk2_ahci_engine_init(&engine, &services, 1U << 8, 1) ==
		EFI_OUT_OF_RESOURCES);
	CHECK(fixture.releases == 2 && !engine.initialized);
	free(large);
	puts("ata atapi AHCI tests: PASS");
	return 0;
}
