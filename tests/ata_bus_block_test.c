/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_bus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINTN executes, signals, defers, fail_defer;
	struct cdk2_block_io2_token *reentrant;
	struct cdk2_ata_bus_block_instance *instance;
	UINT8 *buffer;
};
static EFI_STATUS execute(void *opaque, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet)
{ struct fixture *fixture = opaque; (void)child; (void)packet; fixture->executes++;
	return EFI_SUCCESS; }
static EFI_STATUS reset(void *opaque, struct cdk2_ata_bus_child *child,
	BOOLEAN extended)
{ (void)opaque; (void)child; (void)extended; return EFI_SUCCESS; }
static void signal_event(void *opaque, void *event)
{
	struct fixture *fixture = opaque; (void)event; fixture->signals++;
	if (fixture->reentrant != NULL) {
		struct cdk2_block_io2_token *token = fixture->reentrant;
		fixture->reentrant = NULL;
		CHECK(fixture->instance->block2.read_blocks(&fixture->instance->block2,
			0, 2, token, 512, fixture->buffer) == EFI_SUCCESS);
	}
}
static EFI_STATUS defer(void *opaque, struct cdk2_ata_bus_block_instance *instance)
{ struct fixture *fixture = opaque; (void)instance; fixture->defers++;
	return fixture->defers == fixture->fail_defer ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_ata_bus_transport transport = { &fixture, execute, reset,
		signal_event };
	struct cdk2_ata_bus_scheduler scheduler;
	struct cdk2_ata_bus_block_instance instance;
	struct cdk2_ata_bus_child child = { 0 };
	struct cdk2_block_io2_token first = { (void *)1, 0 };
	struct cdk2_block_io2_token second = { (void *)2, 0 };
	UINT8 *buffer = aligned_alloc(16, 1024);
	CHECK(buffer != NULL); child.geometry.blocks = 100;
	child.geometry.block_size = 512; child.geometry.io_align = 16;
	child.geometry.logical_blocks_per_physical_block = 1;
	CHECK(cdk2_ata_bus_scheduler_init(&scheduler, &transport) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_block_init(&instance, &child, &scheduler, defer,
		&fixture) == EFI_SUCCESS);
	fixture.instance = &instance; fixture.buffer = buffer;
	CHECK(instance.block.revision == 0x0002001fULL &&
		instance.block.media == instance.block2.media &&
		instance.block.media == &instance.media && instance.media.last_block == 99);
	CHECK(instance.block2.read_blocks(&instance.block2, 0, 0, &first, 512,
		buffer) == EFI_SUCCESS);
	CHECK(fixture.defers == 1 && fixture.executes == 0 && fixture.signals == 0 &&
		first.transaction_status == EFI_NOT_READY);
	CHECK(instance.block2.write_blocks(&instance.block2, 0, 1, &second, 512,
		buffer + 512) == EFI_SUCCESS && fixture.defers == 1);
	fixture.reentrant = &first;
	CHECK(cdk2_ata_bus_block_worker(&instance) == EFI_SUCCESS &&
		fixture.executes == 1 && fixture.signals == 1 &&
		first.transaction_status == EFI_NOT_READY && fixture.defers == 2);
	CHECK(cdk2_ata_bus_block_worker(&instance) == EFI_SUCCESS &&
		fixture.executes == 2 && second.transaction_status == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_block_worker(&instance) == EFI_SUCCESS &&
		fixture.executes == 3 && first.transaction_status == EFI_SUCCESS &&
		fixture.signals == 3);
	CHECK(instance.block.read_blocks(&instance.block, 0, 3, 512, buffer) ==
		EFI_SUCCESS && fixture.executes == 4);
	fixture.fail_defer = fixture.defers + 1U;
	CHECK(instance.block2.read_blocks(&instance.block2, 0, 4, &first, 512,
		buffer) == EFI_OUT_OF_RESOURCES && scheduler.count == 0 &&
		first.transaction_status == EFI_OUT_OF_RESOURCES);
	CHECK(instance.block2.read_blocks(&instance.block2, 0, 4, NULL, 512,
		buffer) == EFI_SUCCESS && fixture.executes == 5);
	free(buffer); puts("ata bus block protocol tests: PASS"); return 0;
}
