/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	struct cdk2_ata_async_controller *async;
	UINTN begins, polls, aborts, arms, signals, complete_after;
	UINTN fail_begin, fail_poll, fail_arm;
	UINTN fail_signal;
	BOOLEAN reenter;
};
static EFI_STATUS begin(void *context, struct cdk2_ata_controller *controller,
	struct cdk2_ata_async_task *task)
{ struct fixture *f = context; (void)controller; (void)task; f->begins++;
	return f->begins == f->fail_begin ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS poll_task(void *context, struct cdk2_ata_controller *controller,
	struct cdk2_ata_async_task *task, BOOLEAN *complete)
{ struct fixture *f = context; (void)controller; (void)task; f->polls++;
	*complete = f->polls >= f->complete_after;
	return f->polls == f->fail_poll ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS abort_task(void *context, struct cdk2_ata_controller *controller,
	struct cdk2_ata_async_task *task)
{ struct fixture *f = context; (void)controller; (void)task; f->aborts++;
	return EFI_SUCCESS; }
static EFI_STATUS arm(void *context, struct cdk2_ata_controller *controller)
{ struct fixture *f = context; (void)controller; f->arms++;
	return f->arms == f->fail_arm ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS signal_event(void *context, void *event)
{ struct fixture *f = context; (void)event; f->signals++;
	if (f->reenter)
		CHECK(cdk2_ata_async_poll(f->async) == EFI_ALREADY_STARTED);
	return f->signals == f->fail_signal ? EFI_DEVICE_ERROR : EFI_SUCCESS; }

int main(void)
{
	struct fixture f = { .complete_after = 2 };
	struct cdk2_ata_controller controller = { 0 };
	struct cdk2_ata_async_controller async;
	struct cdk2_ata_async_services services = {
		&f, begin, poll_task, abort_task, arm, signal_event };
	struct cdk2_ata_command_block acb = { 0 };
	struct cdk2_ata_command_packet packet = { .acb = &acb };

	f.async = &async;
	CHECK(cdk2_ata_async_init(&async, &controller, &services) == EFI_SUCCESS);
	CHECK(cdk2_ata_async_submit(&async, 0, 0, &packet, (void *)1) == EFI_SUCCESS &&
		cdk2_ata_async_submit(&async, 1, 0, &packet, (void *)2) == EFI_SUCCESS &&
		async.count == 2 && f.arms == 1);
	CHECK(cdk2_ata_async_poll(&async) == EFI_SUCCESS && f.begins == 1 && f.signals == 0);
	CHECK(cdk2_ata_async_poll(&async) == EFI_SUCCESS && f.polls == 1 && f.signals == 0);
	f.reenter = 1;
	CHECK(cdk2_ata_async_poll(&async) == EFI_SUCCESS && f.signals == 1 && async.count == 1);
	f.reenter = 0;
	CHECK(cdk2_ata_async_poll(&async) == EFI_SUCCESS && f.begins == 2);
	CHECK(cdk2_ata_async_stop(&async) == EFI_SUCCESS && f.aborts == 1 &&
		f.signals == 2 && async.count == 0 && async.stopping);
	CHECK(cdk2_ata_async_submit(&async, 0, 0, &packet, (void *)3) == EFI_NOT_READY);
	memset(&async, 0, sizeof(async)); f = (struct fixture) { .fail_arm = 1 };
	f.async = &async; services.context = &f;
	CHECK(cdk2_ata_async_init(&async, &controller, &services) == EFI_SUCCESS &&
		cdk2_ata_async_submit(&async, 0, 0, &packet, (void *)1) == EFI_DEVICE_ERROR &&
		async.count == 0);
	memset(&async, 0, sizeof(async)); f = (struct fixture) {
		.complete_after = 1, .fail_signal = 1 };
	f.async = &async; services.context = &f;
	CHECK(cdk2_ata_async_init(&async, &controller, &services) == EFI_SUCCESS &&
		cdk2_ata_async_submit(&async, 0, 0, &packet, (void *)1) == EFI_SUCCESS);
	CHECK(cdk2_ata_async_poll(&async) == EFI_SUCCESS);
	CHECK(cdk2_ata_async_poll(&async) == EFI_NOT_READY && async.count == 0 &&
		f.signals == 1);
	CHECK(cdk2_ata_async_poll(&async) == EFI_NOT_READY && f.signals == 1);
	puts("ata async controller tests: PASS");
	return 0;
}
