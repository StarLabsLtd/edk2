/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ps2_mouse_driver.h>

#include <stddef.h>
#include <string.h>

#define OPEN_BY_DRIVER 0x10U
#define EVT_NOTIFY_WAIT 0x100U
#define EVT_TIMER_NOTIFY_SIGNAL 0x80000200U
#define TPL_NOTIFY 16U
#define TIMER_PERIODIC 1U
#define MOUSE_NOT_STARTED ((1ULL << 63) | 19ULL)
static const EFI_GUID sio_guid = {
	0x215fdd18,
	0xbd50,
	0x4feb,
	{0x89, 0x0b, 0x58, 0xca, 0x0b, 0x47, 0x39, 0xe9}};
static const EFI_GUID pointer_guid = {
	0x31878c87,
	0x0b75,
	0x11d5,
	{0x9a, 0x4f, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}};

static struct cdk2_mouse_device *
from_pointer(struct cdk2_simple_pointer *pointer)
{
	return (struct cdk2_mouse_device *)((uint8_t *)pointer -
					    offsetof(struct cdk2_mouse_device,
						     pointer));
}
static uint64_t CDK2_MS_ABI reset(struct cdk2_simple_pointer *pointer,
				  uint8_t extended)
{
	struct cdk2_mouse_device *device = from_pointer(pointer);
	(void)extended;
	return cdk2_ps2_mouse_controller_init(&device->io, &device->mouse);
}
static uint64_t CDK2_MS_ABI get_state(struct cdk2_simple_pointer *pointer,
				      struct cdk2_pointer_state *state)
{
	return cdk2_ps2_mouse_get_state(&from_pointer(pointer)->mouse, state);
}
static void CDK2_MS_ABI poll_notify(void *event, void *context)
{
	(void)event;
	(void)cdk2_ps2_mouse_poll(
		&((struct cdk2_mouse_device *)context)->io,
		&((struct cdk2_mouse_device *)context)->mouse);
}
static void CDK2_MS_ABI wait_notify(void *event, void *context)
{
	(void)event;
	poll_notify(NULL, context);
}

int cdk2_ps2_mouse_hid_supported(uint32_t hid, uint32_t uid)
{
	return hid == 0x030fd041U || hid == 0x130fd041U ||
	       (hid == 0x0303d041U && uid == 1);
}

uint64_t cdk2_ps2_mouse_start(struct cdk2_mouse_device *device,
			      struct cdk2_mouse_services *services,
			      struct cdk2_ps2_io io, void *driver,
			      void *controller)
{
	uint64_t status;
	if (device == NULL || services == NULL)
		return EFI_INVALID_PARAMETER;
	memset(device, 0, sizeof(*device));
	device->services = services;
	device->driver = driver;
	device->controller = controller;
	device->io = io;
	status = services->open(controller, &sio_guid, &device->sio, driver,
				controller, OPEN_BY_DRIVER);
	if (status != EFI_SUCCESS)
		return status;
	status = cdk2_ps2_mouse_controller_init(&device->io, &device->mouse);
	if (status != EFI_SUCCESS)
		goto close;
	device->pointer = (struct cdk2_simple_pointer){reset, get_state, NULL,
						       &device->mouse.mode};
	status =
		services->create_event(EVT_NOTIFY_WAIT, TPL_NOTIFY, wait_notify,
				       device, &device->wait_event);
	if (status != EFI_SUCCESS)
		goto disable;
	device->pointer.wait_for_input = device->wait_event;
	status = services->create_event(EVT_TIMER_NOTIFY_SIGNAL, TPL_NOTIFY,
					poll_notify, device,
					&device->poll_event);
	if (status != EFI_SUCCESS)
		goto close_wait;
	status =
		services->set_timer(device->poll_event, TIMER_PERIODIC, 100000);
	if (status != EFI_SUCCESS)
		goto close_poll;
	status = services->install(&device->controller, &pointer_guid,
				   &device->pointer, NULL);
	if (status != EFI_SUCCESS)
		goto cancel_timer;
	device->started = 1;
	return EFI_SUCCESS;
cancel_timer:
	(void)services->set_timer(device->poll_event, 0, 0);
close_poll:
	(void)services->close_event(device->poll_event);
close_wait:
	(void)services->close_event(device->wait_event);
disable:
	(void)cdk2_ps2_mouse_controller_disable(&device->io);
close:
	(void)services->close(controller, &sio_guid, driver, controller);
	return status;
}

uint64_t cdk2_ps2_mouse_stop(struct cdk2_mouse_device *device)
{
	uint64_t status;
	if (device == NULL || !device->started)
		return MOUSE_NOT_STARTED;
	status = device->services->uninstall(device->controller, &pointer_guid,
					     &device->pointer, NULL);
	if (status != EFI_SUCCESS)
		return status;
	(void)device->services->set_timer(device->poll_event, 0, 0);
	(void)device->services->close_event(device->poll_event);
	(void)device->services->close_event(device->wait_event);
	(void)cdk2_ps2_mouse_controller_disable(&device->io);
	(void)device->services->close(device->controller, &sio_guid,
				      device->driver, device->controller);
	device->started = 0;
	return EFI_SUCCESS;
}
