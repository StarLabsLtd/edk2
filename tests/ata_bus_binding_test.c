/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_bus.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

enum failure { FAIL_NONE, FAIL_OPEN, FAIL_MARKER, FAIL_ALLOC, FAIL_INSTALL,
	FAIL_LINK, FAIL_UNINSTALL, FAIL_UNLINK, FAIL_UNMARK, FAIL_CLOSE };
struct fixture;
struct mock_protocol {
	struct cdk2_ata_pass_thru_protocol protocol;
	struct fixture *fixture;
	UINTN port_calls, device_calls;
};
struct fixture {
	struct mock_protocol protocols[2];
	struct cdk2_ata_bus_binding *binding;
	enum failure failure;
	UINTN allocs, releases, opens, closes, markers, installs, uninstalls;
	UINTN links, unlinks, defers, signals, execute;
	UINTN security_installs;
	UINT8 command, protocol, first_out;
	BOOLEAN ata_error, trusted;
	BOOLEAN reentrant_stop;
	EFI_STATUS reentrant_status;
};
static struct fixture *active;

static struct mock_protocol *mock(struct cdk2_ata_pass_thru_protocol *protocol)
{ return (struct mock_protocol *)((UINT8 *)protocol - offsetof(struct mock_protocol,
	protocol)); }
static void put16(UINT8 *p, UINT16 value)
{ p[0] = (UINT8)value; p[1] = (UINT8)(value >> 8); }
static void put32(UINT8 *p, UINT32 value)
{ put16(p, (UINT16)value); put16(p + 2, (UINT16)(value >> 16)); }
static EFI_STATUS CDK2_MS_ABI next_port(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 *port)
{ struct mock_protocol *m = mock(p); if (m->port_calls++ == 0U) {
	*port = 0; return EFI_SUCCESS; } return EFI_NOT_FOUND; }
static EFI_STATUS CDK2_MS_ABI next_device(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 port, UINT16 *device)
{ struct mock_protocol *m = mock(p); (void)port; if (m->device_calls < 2U) {
	*device = (UINT16)m->device_calls++; return EFI_SUCCESS; } return EFI_NOT_FOUND; }
static EFI_STATUS CDK2_MS_ABI pass(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 port, UINT16 device, struct cdk2_ata_command_packet *packet, void *event)
{ UINT8 *id = packet->in_data; (void)p; (void)port; (void)device; (void)event;
	memset(id, 0, 512); put16(id + 49 * 2, 1U << 9); put16(id + 83 * 2, 0x4400);
	put16(id + 48 * 2, active->trusted); put16(id + 106 * 2, 0x4000);
	put32(id + 100 * 2, 1000); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI build_path(struct cdk2_ata_pass_thru_protocol *p,
	UINT16 port, UINT16 device, void **path)
{ UINT8 *node; (void)p; active->allocs++; node = calloc(1, 10);
	if (node == NULL)
		return EFI_OUT_OF_RESOURCES;
	node[0] = 3; node[1] = 18; node[2] = 10;
	node[4] = (UINT8)port; node[6] = (UINT8)device; *path = node; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_device(struct cdk2_ata_pass_thru_protocol *p,
	void *path, UINT16 *port, UINT16 *device)
{ UINT8 *node = path; (void)p;
	if (node == NULL || node[0] != 3 || node[1] != 18 || node[2] != 10 || node[3] != 0)
		return EFI_UNSUPPORTED;
	*port = node[4];
	*device = node[6]; return *device < 2U ? EFI_SUCCESS : EFI_NOT_FOUND; }
static void reset_protocol(struct mock_protocol *m)
{ m->port_calls = 0; m->device_calls = 0; }

static EFI_STATUS open_parent(void *context, void *controller, BOOLEAN driver,
	struct cdk2_ata_pass_thru_protocol **protocol)
{ struct fixture *f = context; UINTN index = (UINTN)controller - 1U; (void)driver;
	f->opens++; if (f->failure == FAIL_OPEN) return EFI_DEVICE_ERROR;
	reset_protocol(&f->protocols[index]); *protocol = &f->protocols[index].protocol;
	return EFI_SUCCESS; }
static EFI_STATUS close_parent(void *context, void *controller, BOOLEAN driver)
{ struct fixture *f = context; (void)controller; (void)driver; f->closes++;
	return f->failure == FAIL_CLOSE ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS marker(void *context, void *controller, BOOLEAN install)
{ struct fixture *f = context; (void)controller; f->markers++;
	if ((install && f->failure == FAIL_MARKER) || (!install && f->failure == FAIL_UNMARK))
		return EFI_DEVICE_ERROR;
	return EFI_SUCCESS; }
static EFI_STATUS allocate_pool(void *context, UINTN size, void **buffer)
{ struct fixture *f = context;
	if (f->failure == FAIL_ALLOC)
		return EFI_OUT_OF_RESOURCES;
	*buffer = calloc(1, size);
	if (*buffer == NULL)
		return EFI_OUT_OF_RESOURCES;
	f->allocs++; return EFI_SUCCESS; }
static void release_pool(void *context, void *buffer)
{ struct fixture *f = context; f->releases++; memset(buffer, 0xa5, 16); free(buffer); }
static EFI_STATUS install_child(void *context, void **handle,
	struct cdk2_ata_bus_bound_child *child, BOOLEAN security)
{
	struct fixture *f = context;

	(void)child;
	if (security)
		f->security_installs++;
	f->installs++;
	if (f->failure == FAIL_INSTALL)
		return EFI_DEVICE_ERROR;
	*handle = (void *)(0x100U + f->installs);
	return EFI_SUCCESS;
}
static EFI_STATUS uninstall_child(void *context, void *handle,
	struct cdk2_ata_bus_bound_child *child, BOOLEAN security)
{ struct fixture *f = context; (void)handle; (void)child; (void)security;
	f->uninstalls++; return f->failure == FAIL_UNINSTALL ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS child_link(void *context, void *controller, void *child,
	BOOLEAN open)
{
	struct fixture *f = context;

	(void)controller;
	(void)child;
	if (open) {
		f->links++;
		return f->failure == FAIL_LINK ? EFI_DEVICE_ERROR : EFI_SUCCESS;
	}
	f->unlinks++;
	return f->failure == FAIL_UNLINK ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS defer(void *context, struct cdk2_ata_bus_block_instance *instance)
{ struct fixture *f = context; (void)instance; f->defers++; return EFI_SUCCESS; }
static EFI_STATUS execute(void *context, struct cdk2_ata_bus_child *child,
	struct cdk2_ata_command_packet *packet)
{
	struct fixture *f = context;

	(void)child;
	f->execute++;
	if (packet->acb != NULL) {
		f->command = packet->acb->command;
		f->protocol = packet->protocol;
		if (packet->out_length != 0U)
			f->first_out = *(UINT8 *)packet->out_data;
		if (packet->in_length != 0U)
			memset(packet->in_data, 0x5a, packet->in_length);
		if (f->ata_error)
			packet->asb->status = 1;
	}
	return EFI_SUCCESS;
}
static EFI_STATUS reset(void *context, struct cdk2_ata_bus_child *child, BOOLEAN ext)
{ (void)context; (void)child; (void)ext; return EFI_SUCCESS; }
static void signal_event(void *context, void *event)
{
	struct fixture *f = context;

	(void)event;
	f->signals++;
	if (f->reentrant_stop)
		f->reentrant_status = cdk2_ata_bus_binding_stop(f->binding,
			(void *)2, 0, NULL);
}

static void init(struct fixture *f, struct cdk2_ata_bus_binding *binding)
{
	memset(f, 0, sizeof(*f)); active = f; f->binding = binding; f->trusted = 1;
	for (UINTN index = 0; index < 2; index++) {
		f->protocols[index].fixture = f;
		f->protocols[index].protocol.pass_thru = pass;
		f->protocols[index].protocol.get_next_port = next_port;
		f->protocols[index].protocol.get_next_device = next_device;
		f->protocols[index].protocol.build_device_path = build_path;
		f->protocols[index].protocol.get_device = get_device;
	}
	struct cdk2_ata_bus_binding_services services = { .context = f,
		.open_parent = open_parent, .close_parent = close_parent, .marker = marker,
		.allocate = allocate_pool, .release = release_pool, .install_child = install_child,
		.uninstall_child = uninstall_child, .child_link = child_link, .defer = defer,
		.transport = { f, execute, reset, signal_event } };
	CHECK(cdk2_ata_bus_binding_init(binding, &services) == EFI_SUCCESS);
}

int main(void)
{
	struct fixture f;
	struct cdk2_ata_bus_binding binding;
	UINT8 path[10] = { 3, 18, 10 };
	UINT8 end[4] = { 0x7f, 0xff, 4, 0 };
	UINT8 buffer[512] __attribute__((aligned(512)));
	UINT8 identify_buffer[512];
	struct cdk2_block_io2_token token = { (void *)1, EFI_NOT_READY };
	UINTN transferred;
	UINTN execute_before;
	UINT32 identify_size;
	void *targets[1];
	init(&f, &binding);
	CHECK(cdk2_ata_bus_binding_supported(&binding, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(cdk2_ata_bus_binding_supported(&binding, (void *)1, end) == EFI_SUCCESS);
	path[2] = 9; CHECK(cdk2_ata_bus_binding_supported(&binding, (void *)1, path) ==
		EFI_UNSUPPORTED); path[2] = 10;
	path[6] = 7; CHECK(cdk2_ata_bus_binding_supported(&binding, (void *)1, path) ==
		EFI_NOT_FOUND); path[6] = 1;
	CHECK(cdk2_ata_bus_binding_start(&binding, (void *)1, path) == EFI_SUCCESS &&
		binding.controller_count == 1 && binding.controllers[0]->child_count == 1);
	CHECK(cdk2_ata_bus_binding_start(&binding, (void *)1, path) == EFI_ALREADY_STARTED);
	CHECK(cdk2_ata_bus_binding_start(&binding, (void *)2, NULL) == EFI_SUCCESS &&
		binding.controller_count == 2 && binding.controllers[1]->child_count == 2);
	identify_size = 511;
	CHECK(binding.controllers[1]->children[0]->disk_info.identify(
		&binding.controllers[1]->children[0]->disk_info, identify_buffer,
		&identify_size) == EFI_BUFFER_TOO_SMALL && identify_size == 512);
	CHECK(binding.controllers[1]->children[0]->disk_info.identify(
		&binding.controllers[1]->children[0]->disk_info, identify_buffer,
		&identify_size) == EFI_SUCCESS && identify_size == 512 &&
		memcmp(identify_buffer, binding.controllers[1]->children[0]->model.identify,
			512) == 0);
	CHECK(binding.controllers[1]->children[0]->disk_info.interface->data1 == 0x9e498932 &&
		binding.controllers[1]->children[0]->disk_info.which_ide(
			&binding.controllers[1]->children[0]->disk_info, NULL, NULL) ==
		EFI_INVALID_PARAMETER);
	memset(buffer, 0x33, sizeof(buffer)); transferred = 0;
	CHECK(binding.controllers[1]->children[0]->security.receive_data(
		&binding.controllers[1]->children[0]->security, 0, 99, 7, 0x1234,
		sizeof(buffer), buffer, &transferred) == EFI_SUCCESS && transferred == 512 &&
		buffer[0] == 0x5a && f.command == 0x5c && f.protocol == 4);
	memset(buffer, 0x33, sizeof(buffer));
	CHECK(binding.controllers[1]->children[0]->security.send_data(
		&binding.controllers[1]->children[0]->security, 0, 99, 7, 0x1234,
		sizeof(buffer), buffer) == EFI_SUCCESS && buffer[0] == 0x33 &&
		f.first_out == 0x33 && f.command == 0x5e && f.protocol == 5);
	CHECK(binding.controllers[1]->children[0]->security.send_data(
		&binding.controllers[1]->children[0]->security, 0, 99, 7, 0x1234,
		0, NULL) == EFI_SUCCESS && f.command == 0x5b && f.protocol == 2);
	CHECK(binding.controllers[1]->children[0]->security.receive_data(
		&binding.controllers[1]->children[0]->security, 1, 0, 0, 0, 1,
		buffer, &transferred) == CDK2_EFI_MEDIA_CHANGED);
	CHECK(binding.controllers[1]->children[0]->security.receive_data(
		&binding.controllers[1]->children[0]->security, 0, 0, 0, 0, 1,
		buffer, &transferred) == EFI_INVALID_PARAMETER);
	f.failure = FAIL_ALLOC;
	CHECK(binding.controllers[1]->children[0]->security.receive_data(
		&binding.controllers[1]->children[0]->security, 0, 0, 0, 0, 512,
		buffer, &transferred) == EFI_OUT_OF_RESOURCES && buffer[0] == 0x33);
	f.failure = FAIL_NONE; f.ata_error = 1;
	CHECK(binding.controllers[1]->children[0]->security.send_data(
		&binding.controllers[1]->children[0]->security, 0, 0, 0, 0, 512,
		buffer) == EFI_DEVICE_ERROR && buffer[0] == 0x33);
	f.ata_error = 0;
	execute_before = f.execute;
	CHECK(binding.controllers[1]->children[0]->block.block2.read_blocks(
		&binding.controllers[1]->children[0]->block.block2, 0, 0, &token,
		sizeof(buffer), buffer) == EFI_SUCCESS && f.defers == 1 &&
		f.execute == execute_before);
	f.reentrant_stop = 1;
	targets[0] = binding.controllers[1]->children[0]->handle; f.failure = FAIL_UNLINK;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)2, 1, targets) == EFI_DEVICE_ERROR &&
		binding.controllers[1]->child_count == 2 && f.execute == execute_before + 1U &&
		f.signals == 1 &&
		token.transaction_status == EFI_SUCCESS && f.reentrant_status == EFI_NOT_READY);
	f.reentrant_stop = 0;
	f.failure = FAIL_UNINSTALL;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)2, 1, targets) == EFI_DEVICE_ERROR &&
		binding.controllers[1]->child_count == 2 && f.links > 0);
	f.failure = FAIL_NONE;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)2, 1, targets) == EFI_SUCCESS &&
		binding.controllers[1]->child_count == 1);
	f.failure = FAIL_UNMARK;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)2, 0, NULL) == EFI_DEVICE_ERROR &&
		binding.controllers[1]->child_count == 0);
	f.failure = FAIL_NONE;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)2, 0, NULL) == EFI_SUCCESS &&
		binding.controller_count == 1);
	f.failure = FAIL_CLOSE;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)1, 0, NULL) == EFI_DEVICE_ERROR &&
		binding.controller_count == 1);
	f.failure = FAIL_NONE;
	CHECK(cdk2_ata_bus_binding_stop(&binding, (void *)1, 0, NULL) == EFI_SUCCESS &&
		binding.controller_count == 0 && f.allocs == f.releases);
	init(&f, &binding); f.trusted = 0;
	CHECK(cdk2_ata_bus_binding_start(&binding, (void *)1, NULL) == EFI_SUCCESS &&
		f.security_installs == 0 &&
		cdk2_ata_bus_binding_stop(&binding, (void *)1, 0, NULL) == EFI_SUCCESS);
	for (enum failure failure = FAIL_OPEN; failure <= FAIL_LINK; failure++) {
		init(&f, &binding); f.failure = failure;
		CHECK(EFI_ERROR(cdk2_ata_bus_binding_start(&binding, (void *)1, NULL)) &&
			binding.controller_count == 0 && f.allocs == f.releases);
	}
	puts("ata bus binding lifecycle tests: PASS"); return 0;
}
