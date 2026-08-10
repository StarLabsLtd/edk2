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
	cdk2_ata_bus_complete_fn *complete; void *complete_context;
};
static EFI_STATUS execute(void *opaque, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet)
{ struct fixture *fixture = opaque; (void)child; (void)packet; fixture->executes++;
	return EFI_SUCCESS; }
static EFI_STATUS submit(void *opaque, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet, cdk2_ata_bus_complete_fn *complete,
	void *complete_context)
{ struct fixture *fixture = opaque; EFI_STATUS status = execute(opaque, child, packet);
	if (EFI_ERROR(status))
		return status;
	CHECK(fixture->complete == NULL);
	fixture->complete = complete; fixture->complete_context = complete_context;
	return EFI_SUCCESS; }
static EFI_STATUS wait_idle(void *opaque, struct cdk2_ata_bus_scheduler *scheduler)
{ struct fixture *fixture = opaque; cdk2_ata_bus_complete_fn *complete;
	(void)scheduler;
	void *context; if (fixture->complete == NULL) return EFI_NOT_READY;
	complete = fixture->complete; context = fixture->complete_context;
	fixture->complete = NULL; fixture->complete_context = NULL;
	complete(context, EFI_SUCCESS); return EFI_SUCCESS; }
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
	struct cdk2_ata_bus_transport transport = { .context = &fixture, .execute = execute,
		.submit = submit, .wait = wait_idle, .reset = reset, .signal = signal_event };
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
	CHECK(fixture.defers == 0 && fixture.executes == 1 && fixture.signals == 0 &&
		first.transaction_status == EFI_NOT_READY);
	CHECK(instance.block2.write_blocks(&instance.block2, 0, 1, &second, 512,
		buffer + 512) == EFI_SUCCESS && fixture.executes == 1);
	fixture.reentrant = &first;
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS && fixture.executes == 2 &&
		fixture.signals == 1 && first.transaction_status == EFI_NOT_READY);
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS &&
		fixture.executes == 3 && second.transaction_status == EFI_SUCCESS);
	CHECK(fixture.executes == 3 && wait_idle(&fixture, &scheduler) == EFI_SUCCESS &&
		fixture.executes == 3 && first.transaction_status == EFI_SUCCESS &&
		fixture.signals == 3);
	CHECK(instance.block.read_blocks(&instance.block, 0, 3, 512, buffer) ==
		EFI_SUCCESS && fixture.executes == 4);
	CHECK(instance.block2.read_blocks(&instance.block2, 0, 4, NULL, 512,
		buffer) == EFI_SUCCESS && fixture.executes == 5);
	free(buffer); puts("ata bus block protocol tests: PASS"); return 0;
}
