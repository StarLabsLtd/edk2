/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/scsi_bus_binding.h>
#include <cdk2/scsi_disk_entry.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

typedef EFI_STATUS CDK2_MS_ABI handle_fn(void *, const EFI_GUID *, void **);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const EFI_GUID *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const EFI_GUID *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI create_fn(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI event_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const EFI_GUID *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const EFI_GUID *, void *, ...);
typedef UINTN CDK2_MS_ABI raise_fn(UINTN);
typedef void CDK2_MS_ABI restore_fn(UINTN);
struct fake_boot { UINT8 header[24]; raise_fn * raise; restore_fn * restore;
	void *pages[3]; allocate_fn * allocate; free_fn * free; create_fn * create;
	void *timer, *wait; event_fn * signal; event_fn * close_event; void *middle[4];
	handle_fn *handle; UINT8 before_open[120]; open_fn * open; close_fn * close;
	UINT8 before_install[32]; install_fn * install; uninstall_fn * uninstall; };
struct fake_system { UINT8 prefix[96]; struct fake_boot *boot; };
typedef char open_offset[offsetof(struct fake_boot, open) == 280 ? 1 : -1];
typedef char install_offset[offsetof(struct fake_boot, install) == 328 ? 1 : -1];

struct fixture { struct fake_boot boot; struct fake_system system;
	struct cdk2_scsi_disk_loaded_image loaded; struct cdk2_scsi_io io;
	UINTN opens, closes, installs, uninstalls, allocations, releases, commands;
	UINT32 last_attributes; struct cdk2_block_io *block;
	struct cdk2_block_io2 *block2; };
static struct fixture *active;
static UINTN tpl = 4U;

static UINTN CDK2_MS_ABI raise_tpl(UINTN value)
{ UINTN old = tpl; tpl = value; return old; }
static void CDK2_MS_ABI restore_tpl(UINTN value) { tpl = value; }
static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{ (void)type; active->allocations++; *buffer = malloc(size); return *buffer == NULL ?
	EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{ active->releases++; free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI handle(void *image, const EFI_GUID *guid, void **value)
{ (void)image; (void)guid; *value = &active->loaded; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI open(void *controller, const EFI_GUID *guid,
	void **interface, void *agent, void *child, UINT32 attributes)
{ (void)controller; (void)guid; (void)agent; (void)child; active->opens++;
	active->last_attributes = attributes; *interface = &active->io; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI close_protocol(void *controller,
	const EFI_GUID *guid, void *agent, void *child)
{ (void)controller; (void)guid; (void)agent; (void)child; active->closes++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, const EFI_GUID *first,
	void *first_interface, ...)
{ (void)first; active->installs++; if (*handle == NULL) *handle = (void *)0x7000;
	if (active->installs > 1U)
		active->block = first_interface;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, const EFI_GUID *first,
	void *first_interface, ...)
{ (void)handle; (void)first; (void)first_interface; active->uninstalls++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN event_tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{ (void)type; (void)event_tpl; (void)notify; (void)context; *event = malloc(1);
	return *event == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI event(void *value) { free(value); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_type(struct cdk2_scsi_io *io, UINT8 *type)
{ (void)io; *type = 0U; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI reset_device(struct cdk2_scsi_io *io)
{ (void)io; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI command(struct cdk2_scsi_io *io,
	struct cdk2_scsi_request *request, void *event_handle)
{ UINT8 opcode = ((UINT8 *)request->cdb)[0]; (void)io; (void)event_handle;
	active->commands++; request->host_status = 0U; request->target_status = 0U;
	if (opcode == 0x25U) {
		UINT8 value[8] = { 0, 0, 0, 7, 0, 0, 2, 0 };

		memcpy(request->in_data, value, sizeof(value));
	}
	return EFI_SUCCESS; }

int main(void)
{
	struct fixture fixture = { 0 };
	struct cdk2_scsi_disk_entry entry;
	UINT8 buffer[512];

	active = &fixture; fixture.system.boot = &fixture.boot;
	fixture.boot.raise = raise_tpl; fixture.boot.restore = restore_tpl;
	fixture.boot.allocate = allocate_pool; fixture.boot.free = free_pool;
	fixture.boot.create = create_event; fixture.boot.signal = event;
	fixture.boot.close_event = event; fixture.boot.handle = handle;
	fixture.boot.open = open; fixture.boot.close = close_protocol;
	fixture.boot.install = install; fixture.boot.uninstall = uninstall;
	fixture.io.get_device_type = get_type; fixture.io.reset_device = reset_device;
	fixture.io.execute_scsi_command = command; fixture.io.io_align = 1U;
	CHECK(cdk2_scsi_disk_entry_publish(&entry, &fixture, &fixture.system) ==
		EFI_SUCCESS && fixture.loaded.unload == cdk2_scsi_disk_entry_unload &&
		entry.driver.version == 0x10U);
	CHECK(entry.driver.supported(&entry.driver, (void *)1, NULL) == EFI_SUCCESS &&
		fixture.last_attributes == 0x10U);
	CHECK(entry.driver.start(&entry.driver, (void *)1, NULL) == EFI_SUCCESS &&
		entry.binding.count == 1U && fixture.block != NULL);
	fixture.block2 = &entry.binding.controllers[0]->block.block2;
	CHECK(fixture.block->read_blocks(fixture.block, 0U, 0U, sizeof(buffer), buffer) ==
		EFI_SUCCESS && active->commands == 2U);
	CHECK(entry.driver.stop(&entry.driver, (void *)1, 0U, NULL) == EFI_SUCCESS &&
		entry.binding.count == 0U && fixture.allocations == fixture.releases);
	CHECK(entry.loaded->unload(&fixture) == EFI_SUCCESS && !entry.published);
	puts("scsi disk entry tests: PASS");
	return 0;
}
