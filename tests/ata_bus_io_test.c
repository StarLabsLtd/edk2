/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_bus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINTN calls, fail_call, resets, signals, locks, unlocks, lock_depth;
	BOOLEAN fail_reset, complete_on_handoff;
	UINT8 commands[16], protocols[16]; UINT16 counts[16]; UINT64 lbas[16];
	void *events[16]; struct cdk2_ata_bus_scheduler *scheduler;
	cdk2_ata_bus_complete_fn *complete; void *complete_context;
};

static EFI_STATUS execute(void *opaque, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet)
{
	struct fixture *fixture = opaque; struct cdk2_ata_command_block *acb = packet->acb;
	UINTN index = fixture->calls++; (void)child;
	fixture->commands[index] = acb->command;
	fixture->protocols[index] = packet->protocol;
	fixture->counts[index] = acb->sector_count |
		((UINT16)acb->sector_count_exp << 8);
	fixture->lbas[index] = acb->sector_number |
		((UINT64)acb->cylinder_low << 8) |
		((UINT64)acb->cylinder_high << 16) |
		((UINT64)acb->sector_number_exp << 24) |
		((UINT64)acb->cylinder_low_exp << 32) |
		((UINT64)acb->cylinder_high_exp << 40);
	return fixture->calls == fixture->fail_call ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS submit(void *opaque, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet, cdk2_ata_bus_complete_fn *complete,
	void *complete_context)
{ struct fixture *fixture = opaque; EFI_STATUS status = execute(opaque, child, packet);
	if (EFI_ERROR(status))
		return status;
	CHECK(fixture->complete == NULL); fixture->complete = complete;
	fixture->complete_context = complete_context; return EFI_SUCCESS; }
static EFI_STATUS wait_idle(void *opaque, struct cdk2_ata_bus_scheduler *scheduler)
{ struct fixture *fixture = opaque; cdk2_ata_bus_complete_fn *complete;
	(void)scheduler;
	void *context; if (fixture->complete == NULL) return EFI_NOT_READY;
	complete = fixture->complete; context = fixture->complete_context;
	fixture->complete = NULL; fixture->complete_context = NULL;
	complete(context, EFI_SUCCESS); return EFI_SUCCESS; }
static EFI_STATUS reset(void *opaque, struct cdk2_ata_bus_child *child,
	BOOLEAN extended)
{ struct fixture *fixture = opaque; (void)child; fixture->resets += extended ? 2U : 1U;
	return fixture->fail_reset ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static void signal_event(void *opaque, void *event)
{ struct fixture *fixture = opaque; fixture->events[fixture->signals++] = event; }
static UINTN lock(void *opaque)
{
	struct fixture *fixture = opaque;

	fixture->locks++;
	CHECK(fixture->lock_depth++ == 0U);
	return 4U;
}
static void unlock(void *opaque, UINTN state)
{
	struct fixture *fixture = opaque;
	cdk2_ata_bus_complete_fn *complete = NULL;
	void *complete_context = NULL;

	CHECK(state == 4U && fixture->lock_depth-- == 1U);
	fixture->unlocks++;
	if (fixture->complete_on_handoff && fixture->scheduler != NULL &&
	    !fixture->scheduler->dispatching && fixture->complete != NULL) {
		fixture->complete_on_handoff = 0;
		complete = fixture->complete;
		complete_context = fixture->complete_context;
		fixture->complete = NULL;
		fixture->complete_context = NULL;
	}
	if (complete != NULL)
		complete(complete_context, EFI_SUCCESS);
}
static void init_child(struct cdk2_ata_bus_child *child, UINT64 blocks,
	BOOLEAN lba48)
{
	memset(child, 0, sizeof(*child)); child->geometry.blocks = blocks;
	child->geometry.block_size = 512; child->geometry.io_align = 16;
	child->geometry.lba48 = lba48; child->geometry.udma = 1;
}

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_ata_bus_scheduler scheduler;
	struct cdk2_ata_bus_transport transport = { .context = &fixture, .execute = execute,
		.submit = submit, .wait = wait_idle, .reset = reset, .signal = signal_event,
		.lock = lock, .unlock = unlock };
	struct cdk2_ata_bus_child first, second;
	struct cdk2_block_io2_token one = { (void *)1, 0 }, two = { (void *)2, 0 };
	struct cdk2_block_io2_token three = { (void *)3, 0 };
	UINT8 *data = aligned_alloc(16, 0x20200U * 512U);
	struct cdk2_ata_bus_request read, write, flush, sync;
	CHECK(data != NULL); init_child(&first, 0x100000, 1); init_child(&second, 0x1000, 0);
	CHECK(cdk2_ata_bus_scheduler_init(&scheduler, &transport) == EFI_SUCCESS);
	fixture.scheduler = &scheduler;
	read = (struct cdk2_ata_bus_request) { &first, CDK2_ATA_BUS_READ, &one, 0,
		7, 512, data };
	write = (struct cdk2_ata_bus_request) { &second, CDK2_ATA_BUS_WRITE, &two, 0,
		9, 512, data + 512 };
	flush = (struct cdk2_ata_bus_request) { .child = &first,
		.operation = CDK2_ATA_BUS_FLUSH, .token = &three };
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS &&
		one.transaction_status == EFI_NOT_READY);
	CHECK(cdk2_ata_bus_submit(&scheduler, &write) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_submit(&scheduler, &flush) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_ALREADY_STARTED);
	CHECK(cdk2_ata_bus_worker(&scheduler) == EFI_SUCCESS &&
		one.transaction_status == EFI_NOT_READY && fixture.signals == 0);
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS && one.transaction_status == EFI_SUCCESS &&
		fixture.events[0] == (void *)1 && two.transaction_status == EFI_NOT_READY);
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS &&
		two.transaction_status == EFI_SUCCESS && fixture.events[1] == (void *)2);
	CHECK(fixture.calls == 2 &&
		three.transaction_status == EFI_SUCCESS && fixture.events[2] == (void *)3);
	CHECK(fixture.commands[0] == 0x25 && fixture.counts[0] == 1 &&
		fixture.lbas[0] == 7 && fixture.commands[1] == 0xca);

	read.token = &one; read.lba = 0x1234; read.bytes = 0x20000U * 512U;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS);
	sync = (struct cdk2_ata_bus_request) { &second, CDK2_ATA_BUS_READ, NULL, 0,
		1, 512, data };
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &sync) == EFI_SUCCESS);
	CHECK(fixture.commands[2] == 0x25 && fixture.counts[2] == 0 &&
		fixture.commands[3] == 0x25 && fixture.counts[3] == 0 &&
		fixture.lbas[3] == 0x11234 && fixture.commands[4] == 0xc8);
	second.geometry.udma = 0; fixture.fail_call = 0;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &sync) == EFI_SUCCESS &&
		fixture.commands[5] == 0x20 && fixture.protocols[5] == 4);

	fixture.fail_call = fixture.calls + 2U; read.token = &one; read.bytes = 0x10001U * 512U;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_worker(&scheduler) == EFI_SUCCESS &&
		wait_idle(&fixture, &scheduler) == EFI_SUCCESS &&
		one.transaction_status == EFI_DEVICE_ERROR && fixture.signals == 5);
	read.token = &one; read.bytes = 512; write.token = &two;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS &&
		cdk2_ata_bus_submit(&scheduler, &write) == EFI_SUCCESS &&
		cdk2_ata_bus_worker(&scheduler) == EFI_SUCCESS && scheduler.parent_active);
	CHECK(cdk2_ata_bus_reset(&scheduler, &first, 0) == EFI_SUCCESS &&
		one.transaction_status == CDK2_EFI_ABORTED &&
		two.transaction_status == EFI_NOT_READY && scheduler.parent_active);
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS && two.transaction_status == EFI_SUCCESS);
	read.token = &one; read.bytes = 512; fixture.fail_reset = 1;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS &&
		cdk2_ata_bus_worker(&scheduler) == EFI_SUCCESS &&
		cdk2_ata_bus_reset(&scheduler, &first, 0) == EFI_DEVICE_ERROR &&
		!scheduler.abort_active && one.transaction_status == EFI_NOT_READY);
	fixture.fail_reset = 0;
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS &&
		one.transaction_status == EFI_SUCCESS);
	read.token = &one; read.bytes = 512; write.token = &two; flush.token = &three;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_submit(&scheduler, &write) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_submit(&scheduler, &flush) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_reset(&scheduler, &first, 1) == EFI_SUCCESS &&
		one.transaction_status == CDK2_EFI_ABORTED &&
		two.transaction_status == EFI_NOT_READY &&
		three.transaction_status == CDK2_EFI_ABORTED && fixture.resets >= 3 &&
		scheduler.count == 1);
	CHECK(wait_idle(&fixture, &scheduler) == EFI_SUCCESS &&
		two.transaction_status == EFI_SUCCESS);

	read.token = NULL; read.media_id = 1;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == CDK2_EFI_MEDIA_CHANGED);
	read.buffer = NULL; read.bytes = 0;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == CDK2_EFI_MEDIA_CHANGED);
	read.media_id = 0;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == EFI_SUCCESS);
	read.buffer = data; read.lba = first.geometry.blocks;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == EFI_SUCCESS);
	read.bytes = 513;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == EFI_BAD_BUFFER_SIZE);
	read.bytes = 512; read.buffer = data + 1;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == EFI_INVALID_PARAMETER);
	read.buffer = data; read.lba = first.geometry.blocks;
	CHECK(cdk2_ata_bus_execute_sync(&scheduler, &read) == EFI_INVALID_PARAMETER);
	read.lba = 0; read.token = &one; fixture.complete_on_handoff = 1;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_SUCCESS &&
		cdk2_ata_bus_worker(&scheduler) == EFI_SUCCESS && scheduler.count == 0U &&
		one.transaction_status == EFI_SUCCESS && !fixture.complete_on_handoff);
	CHECK(cdk2_ata_bus_stop_scheduler(&scheduler) == EFI_SUCCESS);
	read.lba = 0; read.token = &one;
	CHECK(cdk2_ata_bus_submit(&scheduler, &read) == EFI_NOT_READY);
	CHECK(fixture.locks == fixture.unlocks && fixture.lock_depth == 0U);
	free(data); puts("ata bus I/O scheduler tests: PASS"); return 0;
}
