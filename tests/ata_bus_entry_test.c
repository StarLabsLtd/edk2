/* SPDX-License-Identifier: GPL-2.0-only */

#include "../src/modules/ata_bus/entry.c"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

enum fail_stage { FAIL_NONE, FAIL_HANDLE, FAIL_PUBLISH, FAIL_OPEN, FAIL_MARK,
	FAIL_CHILD, FAIL_LINK, FAIL_EVENT, FAIL_SIGNAL, FAIL_UNINSTALL };
struct fixture {
	struct cdk2_ata_bus_boot_services boot;
	struct system_view system;
	struct cdk2_ata_loaded_image loaded;
	struct cdk2_ata_pass_thru_protocol ata;
	enum fail_stage fail;
	UINTN allocs, frees, opens, closes, installs, uninstalls, creates, signals, child_links;
	UINT32 last_attribute;
	const EFI_GUID *last_open_guid;
	void (CDK2_MS_ABI * notify)(void *, void *);
	void *notify_context;
};
static struct fixture fixture;

static EFI_STATUS CDK2_MS_ABI mock_handle(void *handle, const EFI_GUID *guid,
	void **interface)
{
	(void)handle; (void)guid;
	if (fixture.fail == FAIL_HANDLE)
		return EFI_DEVICE_ERROR;
	*interface = &fixture.loaded;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_alloc(UINT32 type, UINTN size, void **buffer)
{
	(void)type;
	*buffer = calloc(1, (size_t)size);
	if (*buffer == NULL)
		return EFI_OUT_OF_RESOURCES;
	fixture.allocs++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_free(void *buffer)
{ fixture.frees++; memset(buffer, 0xa5, 16); free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI mock_install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)interface;
	fixture.installs++;
	if ((guid == &driver_guid && fixture.fail == FAIL_PUBLISH) ||
	    (guid == &marker_guid && fixture.fail == FAIL_MARK) ||
	    (guid == &path_guid && fixture.fail == FAIL_CHILD))
		return EFI_DEVICE_ERROR;
	if (*handle == NULL)
		*handle = (void *)(0x100U + fixture.installs);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_uninstall(void *handle, const EFI_GUID *guid,
	void *interface, ...)
{
	(void)handle; (void)guid; (void)interface;
	fixture.uninstalls++;
	return fixture.fail == FAIL_UNINSTALL ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_open(void *handle, const EFI_GUID *guid,
	void **interface, void *agent, void *controller, UINT32 attribute)
{
	(void)handle; (void)agent;
	fixture.opens++; fixture.last_attribute = attribute; fixture.last_open_guid = guid;
	if (fixture.fail == FAIL_OPEN)
		return EFI_DEVICE_ERROR;
	if (attribute == 0x08U) {
		fixture.child_links++;
		if (fixture.fail == FAIL_LINK)
			return EFI_DEVICE_ERROR;
	}
	*interface = guid == &ata_guid ? (void *)&fixture.ata : controller;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_close(void *handle, const EFI_GUID *guid,
	void *agent, void *controller)
{ (void)handle; (void)guid; (void)agent; (void)controller; fixture.closes++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI mock_create(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{
	(void)type; (void)tpl;
	fixture.creates++;
	if (fixture.fail == FAIL_EVENT)
		return EFI_DEVICE_ERROR;
	*event = (void *)0x99;
	fixture.notify = notify; fixture.notify_context = context;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_signal(void *event)
{
	(void)event; fixture.signals++;
	if (fixture.fail == FAIL_SIGNAL)
		return EFI_DEVICE_ERROR;
	if (event == (void *)0x99)
		fixture.notify(event, fixture.notify_context);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mock_close_event(void *event)
{ (void)event; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI next_port(struct cdk2_ata_pass_thru_protocol *ata,
	UINT16 * port)
{ (void)ata; if (*port == 0xffffU) { *port = 0; return EFI_SUCCESS; }
	return EFI_NOT_FOUND; }
static EFI_STATUS CDK2_MS_ABI next_device(struct cdk2_ata_pass_thru_protocol *ata,
	UINT16 port, UINT16 * device)
{ (void)ata; (void)port; if (*device == 0xffffU) { *device = 0; return EFI_SUCCESS; }
	return EFI_NOT_FOUND; }
static EFI_STATUS CDK2_MS_ABI pass(struct cdk2_ata_pass_thru_protocol *ata,
	UINT16 port, UINT16 device, struct cdk2_ata_command_packet *packet, void *event)
{
	UINT8 *identify = packet->in_data;
	(void)ata; (void)port; (void)device; (void)event;
	memset(identify, 0, 512); identify[99] = 2; identify[167] = 0x44;
	identify[212] = 0; identify[213] = 0x40; identify[200] = 8;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI build_path(struct cdk2_ata_pass_thru_protocol *ata,
	UINT16 port, UINT16 device, void **path)
{
	UINT8 *node;
	(void)ata; (void)port; (void)device;
	CHECK(mock_alloc(4, 10, (void **)&node) == EFI_SUCCESS);
	node[0] = 3; node[1] = 18; node[2] = 10; *path = node;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_device(struct cdk2_ata_pass_thru_protocol *ata,
	void *path, UINT16 * port, UINT16 * device)
{ (void)ata; (void)path; *port = 0; *device = 0; return EFI_SUCCESS; }

static void init(void)
{
	memset(&fixture, 0, sizeof(fixture));
	active = NULL;
	fixture.system.boot = &fixture.boot;
	fixture.boot.allocate_pool = mock_alloc; fixture.boot.free_pool = mock_free;
	fixture.boot.create_event = mock_create; fixture.boot.signal_event = mock_signal;
	fixture.boot.close_event = mock_close_event; fixture.boot.handle_protocol = mock_handle;
	fixture.boot.open_protocol = mock_open; fixture.boot.close_protocol = mock_close;
	fixture.boot.install_multiple = mock_install;
	fixture.boot.uninstall_multiple = mock_uninstall;
	fixture.ata.pass_thru = pass; fixture.ata.get_next_port = next_port;
	fixture.ata.get_next_device = next_device; fixture.ata.build_device_path = build_path;
	fixture.ata.get_device = get_device;
}

int main(void)
{
	struct cdk2_ata_bus_entry entry;
	struct cdk2_block_io2_token token = { (void *)9, EFI_NOT_READY };
	struct cdk2_block_io2_token token2 = { (void *)10, EFI_NOT_READY };
	UINT8 buffer[512] __attribute__((aligned(512)));
	CHAR16 *name;
	void *image = (void *)1;

	for (enum fail_stage fail = FAIL_HANDLE; fail <= FAIL_PUBLISH; fail++) {
		init(); fixture.fail = fail;
		CHECK(EFI_ERROR(cdk2_ata_bus_entry_publish(&entry, image, &fixture.system)) &&
			active == NULL);
	}
	for (enum fail_stage fail = FAIL_OPEN; fail <= FAIL_LINK; fail++) {
		init();
		CHECK(cdk2_ata_bus_entry_publish(&entry, image, &fixture.system) == EFI_SUCCESS);
		fixture.fail = fail;
		CHECK(EFI_ERROR(entry.driver.start(&entry.driver, (void *)2, NULL)) &&
			entry.binding.controller_count == 0);
		fixture.fail = FAIL_NONE;
		CHECK(cdk2_ata_bus_entry_unload(image) == EFI_SUCCESS &&
			fixture.allocs == fixture.frees);
	}
	init();
	CHECK(cdk2_ata_bus_entry_publish(&entry, image, &fixture.system) == EFI_SUCCESS &&
		fixture.loaded.unload == cdk2_ata_bus_entry_unload);
	CHECK(entry.driver.supported(&entry.driver, (void *)2, NULL) == EFI_SUCCESS &&
		fixture.last_open_guid == &ata_guid && fixture.last_attribute == 0x02U);
	CHECK(entry.driver.start(&entry.driver, (void *)2, NULL) == EFI_SUCCESS &&
		entry.binding.controller_count == 1 && fixture.child_links == 1);
	CHECK(entry.driver.start(&entry.driver, (void *)2, NULL) == EFI_ALREADY_STARTED);
	CHECK(entry.driver.start(&entry.driver, (void *)2,
		entry.binding.controllers[0]->children[0]->model.device_path) ==
		EFI_ALREADY_STARTED && entry.binding.controllers[0]->child_count == 1);
	CHECK(entry.driver.start(&entry.driver, (void *)3, NULL) == EFI_SUCCESS &&
		entry.binding.controller_count == 2 &&
		entry.binding.controllers[0]->children[0]->handle !=
		entry.binding.controllers[1]->children[0]->handle &&
		&entry.binding.controllers[0]->scheduler !=
		&entry.binding.controllers[1]->scheduler);
	CHECK(entry.component.get_driver_name(&entry.component, "eng", &name) == EFI_SUCCESS &&
		name == driver_name && entry.component.get_driver_name(&entry.component, "en", &name) ==
		EFI_UNSUPPORTED);
	CHECK(entry.component2.get_driver_name(&entry.component2, "en", &name) == EFI_SUCCESS &&
		entry.component2.get_driver_name(&entry.component2, "eng", &name) == EFI_UNSUPPORTED);
	CHECK(entry.component.get_controller_name(&entry.component, (void *)2, NULL,
		"eng", &name) == EFI_SUCCESS &&
		entry.component2.get_controller_name(&entry.component2, (void *)2,
			entry.binding.controllers[0]->children[0]->handle, "en", &name) == EFI_SUCCESS &&
		entry.component.get_controller_name(&entry.component, (void *)99, NULL,
			"eng", &name) == EFI_UNSUPPORTED &&
		entry.component.get_controller_name(&entry.component, (void *)2, (void *)99,
			"eng", &name) == EFI_UNSUPPORTED);
	fixture.fail = FAIL_EVENT;
	CHECK(entry.binding.controllers[0]->children[0]->block.block2.read_blocks(
		&entry.binding.controllers[0]->children[0]->block.block2, 0, 0, &token,
		sizeof(buffer), buffer) == EFI_DEVICE_ERROR &&
		entry.binding.controllers[0]->scheduler.count == 0);
	fixture.fail = FAIL_SIGNAL;
	CHECK(entry.binding.controllers[0]->children[0]->block.block2.read_blocks(
		&entry.binding.controllers[0]->children[0]->block.block2, 0, 0, &token,
		sizeof(buffer), buffer) == EFI_DEVICE_ERROR &&
		entry.binding.controllers[0]->scheduler.count == 0);
	fixture.fail = FAIL_NONE;
	CHECK(entry.binding.controllers[0]->children[0]->block.block2.read_blocks(
		&entry.binding.controllers[0]->children[0]->block.block2, 0, 0, &token,
		sizeof(buffer), buffer) == EFI_SUCCESS && token.transaction_status == EFI_SUCCESS &&
		fixture.creates == 3 && fixture.signals == 3);
	CHECK(entry.binding.controllers[1]->children[0]->block.block2.read_blocks(
		&entry.binding.controllers[1]->children[0]->block.block2, 0, 0, &token2,
		sizeof(buffer), buffer) == EFI_SUCCESS && token2.transaction_status == EFI_SUCCESS &&
		entry.binding.controllers[0]->scheduler.count == 0 &&
		entry.binding.controllers[1]->scheduler.count == 0);
	fixture.fail = FAIL_UNINSTALL;
	CHECK(cdk2_ata_bus_entry_unload(image) == EFI_DEVICE_ERROR && active == &entry);
	fixture.fail = FAIL_NONE;
	CHECK(cdk2_ata_bus_entry_unload(image) == EFI_SUCCESS && active == NULL &&
		fixture.allocs == fixture.frees);
	puts("ata bus entry tests: PASS");
	return 0;
}
