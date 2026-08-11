/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ps2_mouse_driver.h>

#define OPEN_GET 2U
struct boot_view {
	uint8_t before_create[80];
	cdk2_mouse_event_fn *create_event;
	cdk2_mouse_timer_fn *set_timer;
	uint8_t before_close_event[16];
	cdk2_mouse_close_event_fn *close_event;
	uint8_t before_open[160];
	cdk2_mouse_open_fn *open;
	cdk2_mouse_close_fn *close;
	uint8_t before_install[32];
	cdk2_mouse_install_fn *install;
	cdk2_mouse_uninstall_fn *uninstall;
};
struct system_view {
	uint8_t prefix[96];
	struct boot_view *boot;
};
struct binding;
typedef uint64_t CDK2_MS_ABI bind_fn(struct binding *, void *, void *);
typedef uint64_t CDK2_MS_ABI stop_fn(struct binding *, void *, size_t, void **);
struct binding {
	bind_fn *supported, *start;
	stop_fn *stop;
	uint32_t version, pad;
	void *image, *handle;
};
struct path_node {
	uint8_t type, subtype;
	uint16_t length;
	uint32_t hid, uid;
};
static const EFI_GUID binding_guid = {
	0x18a031ab,
	0xb443,
	0x4d1a,
	{0xa5, 0xc0, 0x0c, 9, 0x26, 0x1e, 0x9f, 0x71}};
static const EFI_GUID path_guid = {
	0x09576e91,
	0x6d3f,
	0x11d2,
	{0x8e, 0x39, 0, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};
static struct cdk2_mouse_services services;
static struct cdk2_mouse_device device;
static struct binding driver_binding;

static uint8_t CDK2_MS_ABI io_read(void *context, uint16_t port)
{
	uint8_t value;
	(void)context;
	__asm__ volatile("inb %1,%0" : "=a"(value) : "Nd"(port));
	return value;
}
static void CDK2_MS_ABI io_write(void *context, uint16_t port, uint8_t value)
{
	(void)context;
	__asm__ volatile("outb %0,%1" ::"a"(value), "Nd"(port));
}
static uint64_t CDK2_MS_ABI supported(struct binding *self, void *controller,
				      void *remaining)
{
	struct path_node *node = NULL;
	void *sio = NULL;
	uint64_t status;
	(void)remaining;
	status = services.open(controller, &path_guid, (void **)&node,
			       self->handle, controller, OPEN_GET);
	if (status != EFI_SUCCESS)
		return status;
	size_t nodes = 0;
	while (node->type != 0x7f && nodes++ < 64) {
		struct path_node *next;
		if (node->length < 4)
			return EFI_UNSUPPORTED;
		next = (void *)((uint8_t *)node + node->length);
		if (next->type == 0x7f)
			break;
		node = next;
	}
	if (node->type != 2 || node->subtype != 1 || node->length < 12 ||
	    !cdk2_ps2_mouse_hid_supported(node->hid, node->uid))
		return EFI_UNSUPPORTED;
	status = services.open(
		controller,
		&(EFI_GUID){0x215fdd18,
			    0xbd50,
			    0x4feb,
			    {0x89, 0x0b, 0x58, 0xca, 0x0b, 0x47, 0x39, 0xe9}},
		&sio, self->handle, controller, 0x10);
	if (status == EFI_SUCCESS)
		(void)services.close(controller,
				     &(EFI_GUID){0x215fdd18,
						 0xbd50,
						 0x4feb,
						 {0x89, 0x0b, 0x58, 0xca, 0x0b,
						  0x47, 0x39, 0xe9}},
				     self->handle, controller);
	return status;
}
static uint64_t CDK2_MS_ABI start(struct binding *self, void *controller,
				  void *remaining)
{
	struct cdk2_ps2_io io = {NULL, io_read, io_write, NULL, 20000};
	(void)remaining;
	return cdk2_ps2_mouse_start(&device, &services, io, self->handle,
				    controller);
}
static uint64_t CDK2_MS_ABI stop(struct binding *self, void *controller,
				 size_t count, void **children)
{
	(void)self;
	(void)controller;
	(void)count;
	(void)children;
	return cdk2_ps2_mouse_stop(&device);
}
uint64_t CDK2_MS_ABI cdk2_ps2_mouse_entry(void *image, void *system_table)
{
	struct system_view *system = system_table;
	if (system == NULL || system->boot == NULL)
		return EFI_INVALID_PARAMETER;
	services = (struct cdk2_mouse_services){
		system->boot->open,	    system->boot->close,
		system->boot->install,	    system->boot->uninstall,
		system->boot->create_event, system->boot->set_timer,
		system->boot->close_event};
	driver_binding =
		(struct binding){supported, start, stop, 0xa, 0, image, image};
	return services.install(&driver_binding.handle, &binding_guid,
				&driver_binding, NULL);
}
