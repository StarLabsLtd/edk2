/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_binding.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); return 1; } } while (0)

typedef EFI_STATUS CDK2_MS_ABI unload_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI request_notify_fn(void *, UINTN, void *, void *,
	UINT8 *, void **);
struct loaded_image {
	uint32_t revision; void *parent, *system, *device, *path, *reserved;
	uint32_t option_size; void *options, *base; uint64_t size;
	uint32_t code, data; unload_fn * unload;
};
struct fake_boot {
	uint8_t before_pool[64]; void *allocate_pool, *free_pool;
	uint8_t before_handle[72]; void *handle_protocol;
	uint8_t before_load[40]; void *load_image;
	uint8_t before_unload[16]; void *unload_image;
	uint8_t before_open[48]; void *open_protocol, *close_protocol;
	uint8_t before_locate[24]; void *locate_protocol;
	void *install_multiple, *uninstall_multiple;
};
struct fake_system {
	uint8_t header[24]; void *vendor; uint32_t revision, pad;
	void *console[6], *runtime; struct fake_boot *boot;
};
struct fixture {
	struct fake_boot boot; struct fake_system system; struct loaded_image loaded;
	unsigned int installs, uninstalls, opens, closes; EFI_STATUS install_status;
	unsigned int next_root, submits, proposed, phase_count;
	unsigned int root_limit;
	unsigned int fail_proposed;
	unsigned int enable_hotplug, hpc_lists, hpc_inits, hpc_paddings;
	unsigned int fail_hpc_padding;
	unsigned int visible_devices, fail_install_number;
	UINTN phases[16];
	struct cdk2_driver_binding_protocol *driver;
	struct { void *notify; } *hotplug_request;
	uint8_t path[4], resources[48];
	struct {
		void *parent, *poll_mem, *poll_io;
		struct { void *read, *write; } mem, io, pci;
		void *copy, *map, *unmap, *allocate, *free, *flush;
		void *get_attributes, *set_attributes, *configuration;
		uint32_t segment;
	} root;
	struct {
		void *notify, *next, *attributes, *start_bus, *set_bus, *submit;
		void *get_proposed, *preprocess;
	} host;
	struct { void *list, *initialize, *padding; } hotplug;
	uint8_t hpc_path[10];
};
static struct fixture *active;

static EFI_STATUS CDK2_MS_ABI pool(uint32_t type, UINTN size, void **buffer)
{ (void)type; *buffer = calloc(1, size); return *buffer == NULL ? 9 : 0; }
static EFI_STATUS CDK2_MS_ABI release(void *buffer)
{ free(buffer); return 0; }
static EFI_STATUS CDK2_MS_ABI handle(void *object, const EFI_GUID * guid, void **interface)
{ (void)guid; *interface = object == active ? (void *)&active->loaded : active->path;
	return 0; }
static EFI_STATUS CDK2_MS_ABI open_protocol(void *handle, const EFI_GUID * guid,
	void **interface, void *agent, void *controller, uint32_t attributes)
{ (void)handle; (void)guid; (void)agent; (void)controller; (void)attributes;
	active->opens++; *interface = &active->root; return 0; }
static EFI_STATUS CDK2_MS_ABI close_protocol(void *handle, const EFI_GUID * guid,
	void *agent, void *controller)
{ (void)handle; (void)guid; (void)agent; (void)controller; active->closes++; return 0; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, const EFI_GUID * guid,
	void *interface, ...)
{ __builtin_ms_va_list arguments; const EFI_GUID * next;
	active->installs++; *handle = active;
	if (active->fail_install_number == active->installs)
		return EFI_DEVICE_ERROR;
	if (active->installs == 1)
		active->driver = interface;
	if (guid->data1 == 0x19cb87abU)
		active->hotplug_request = interface;
	__builtin_ms_va_start(arguments, interface);
	while ((next = __builtin_va_arg(arguments, const EFI_GUID *)) != NULL) {
		void *next_interface = __builtin_va_arg(arguments, void *);
		if (next->data1 == 0x19cb87abU)
			active->hotplug_request = next_interface;
	}
	__builtin_ms_va_end(arguments);
	return active->install_status; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, const EFI_GUID * guid,
	void *interface, ...)
{ (void)handle; (void)guid; (void)interface; active->uninstalls++; return 0; }
static EFI_STATUS CDK2_MS_ABI old_unload(void *image)
{ (void)image; return 0; }
static EFI_STATUS CDK2_MS_ABI config_read(void *root, UINTN width,
	uint64_t address, UINTN count, void *buffer)
{ (void)root; (void)width; (void)count;
	if (active->enable_hotplug && ((address >> 16) & 0x1fU) != 0U &&
	    ((address >> 16) & 0x1fU) <= active->visible_devices)
		*(uint32_t *)buffer = (address & 0xfffU) == 0U ?
			(0x56780000U | (uint32_t)((address >> 16) & 0x1fU)) : 0U;
	else
		*(uint32_t *)buffer = 0xffffffffU;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI configuration(void *root, void **resources)
{ (void)root; *resources = active->resources; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI notify(void *host, UINTN phase)
{ (void)host; active->phases[active->phase_count++] = phase; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI next_root(void *host, void **root)
{ (void)host; if (active->next_root == active->root_limit) return EFI_NOT_FOUND;
	*root = (void *)(uintptr_t)(++active->next_root); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI start_bus(void *host, void *root, void **resources)
{ (void)host; (void)root; *resources = calloc(1, 48); if (*resources == NULL) return 9;
	((uint8_t *)*resources)[0] = 0x8a; ((uint8_t *)*resources)[1] = 43;
	((uint8_t *)*resources)[3] = 2; ((uint8_t *)*resources)[38] = 1;
	((uint8_t *)*resources)[46] = 0x79; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI set_bus(void *host, void *root, void *resources)
{ (void)host; (void)root; (void)resources; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI submit(void *host, void *root, void *resources)
{ (void)host; (void)root; (void)resources; active->submits++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_proposed(void *host, void *root, void **resources)
{
	uint8_t *bytes = calloc(1, 4 * 46 + 2); (void)host; (void)root;
	if (active->fail_proposed && active->proposed++ == 1U) {
		free(bytes);
		return EFI_DEVICE_ERROR;
	}
	if (bytes == NULL)
		return 9;
	for (unsigned int i = 0; i < 4U; i++) {
		bytes[i * 46] = 0x8a; bytes[i * 46 + 1] = 43;
		bytes[i * 46 + 3] = i == 0U ? 1U : 0U;
		bytes[i * 46 + 6] = i == 2U ? 64U : (i == 0U ? 0U : 32U);
		bytes[i * 46 + 5] = i == 3U ? 6U : 0U;
		bytes[i * 46 + 14] = 0x10U * (i + 1U);
		bytes[i * 46 + 38] = 1;
	}
	bytes[4 * 46] = 0x79; *resources = bytes;
	if (!active->fail_proposed)
		active->proposed++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI locate(const EFI_GUID * guid, void *registration,
	void **interface)
{ (void)registration; if (guid->data1 == 0xaa0e8bc1U) {
		if (!active->enable_hotplug)
			return EFI_NOT_FOUND;
		*interface = &active->hotplug; return EFI_SUCCESS;
	}
	*interface = &active->host; return EFI_SUCCESS; }
struct test_hpc_location { void *hpc_path, *hpb_path; };
static EFI_STATUS CDK2_MS_ABI hpc_list(void *protocol, UINTN * count,
	struct test_hpc_location **locations)
{ (void)protocol; *locations = calloc(1, sizeof(**locations));
	if (*locations == NULL)
		return 9;
	(*locations)[0].hpc_path = active->hpc_path;
	(*locations)[0].hpb_path = active->hpc_path; *count = 1; active->hpc_lists++;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI hpc_initialize(void *protocol, void *path,
	uint64_t address, void *event, uint16_t *state)
{ (void)protocol; (void)path; (void)event;
	if (address != 0x10000U)
		return EFI_DEVICE_ERROR;
	*state = 3; active->hpc_inits++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI hpc_padding(void *protocol, void *path,
	uint64_t address, uint16_t *state, void **padding, UINTN * attributes)
{ uint8_t *bytes = calloc(1, 48); (void)protocol; (void)path; (void)address; (void)state;
	if (active->fail_hpc_padding)
		return EFI_DEVICE_ERROR;
	if (bytes == NULL)
		return 9;
	bytes[0] = 0x8a; bytes[1] = 43;
	bytes[6] = 32; bytes[38] = 0x10; bytes[46] = 0x79; *padding = bytes;
	*attributes = 0; active->hpc_paddings++; return EFI_SUCCESS; }

static void initialize(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture)); active = fixture;
	fixture->root_limit = 2;
	fixture->visible_devices = 1;
	fixture->boot.allocate_pool = pool; fixture->boot.free_pool = release;
	fixture->boot.handle_protocol = handle;
	fixture->boot.open_protocol = open_protocol;
	fixture->boot.close_protocol = close_protocol;
	fixture->boot.locate_protocol = locate;
	fixture->boot.install_multiple = install;
	fixture->boot.uninstall_multiple = uninstall;
	fixture->system.boot = &fixture->boot; fixture->loaded.unload = old_unload;
	fixture->path[0] = 0x7f; fixture->path[1] = 0xff; fixture->path[2] = 4;
	fixture->resources[0] = 0x8a; fixture->resources[1] = 43;
	fixture->resources[3] = 2; fixture->resources[14] = 0;
	fixture->resources[22] = 0; fixture->resources[46] = 0x79;
	fixture->root.pci.read = config_read; fixture->root.pci.write = config_read;
	fixture->root.mem.read = config_read; fixture->root.mem.write = config_read;
	fixture->root.io.read = config_read; fixture->root.io.write = config_read;
	fixture->root.map = config_read; fixture->root.unmap = config_read;
	fixture->root.allocate = config_read; fixture->root.free = config_read;
	fixture->root.flush = config_read; fixture->root.set_attributes = config_read;
	fixture->root.configuration = configuration;
	fixture->host.notify = notify; fixture->host.next = next_root;
	fixture->host.start_bus = start_bus; fixture->host.set_bus = set_bus;
	fixture->host.submit = submit; fixture->host.get_proposed = get_proposed;
	fixture->hotplug.list = hpc_list; fixture->hotplug.initialize = hpc_initialize;
	fixture->hotplug.padding = hpc_padding;
	fixture->hpc_path[0] = 1; fixture->hpc_path[1] = 1;
	fixture->hpc_path[2] = 6; fixture->hpc_path[4] = 0;
	fixture->hpc_path[5] = 1; fixture->hpc_path[6] = 0x7f;
	fixture->hpc_path[7] = 0xff; fixture->hpc_path[8] = 4;
}

int main(void)
{
	struct fixture fixture;
	CHECK(offsetof(struct fake_boot, allocate_pool) == 64);
	CHECK(offsetof(struct fake_boot, handle_protocol) == 152);
	CHECK(offsetof(struct fake_boot, open_protocol) == 280);
	CHECK(offsetof(struct fake_boot, close_protocol) == 288);
	CHECK(offsetof(struct fake_boot, load_image) == 200);
	CHECK(offsetof(struct fake_boot, unload_image) == 224);
	CHECK(offsetof(struct fake_boot, locate_protocol) == 320);
	CHECK(offsetof(struct fake_boot, install_multiple) == 328);
	CHECK(offsetof(struct fake_boot, uninstall_multiple) == 336);
	initialize(&fixture);
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.installs == 1 && fixture.loaded.unload == cdk2_pci_bus_unload);
	CHECK(fixture.driver != NULL);
	CHECK(fixture.driver->supported(fixture.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(fixture.opens == 1 && fixture.closes == 1);
	CHECK(fixture.driver->start(fixture.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(fixture.opens == 3 && fixture.closes == 1);
	CHECK(fixture.submits == 2 && fixture.proposed == 2);
	CHECK(fixture.phase_count == 7 && fixture.phases[0] == 0 &&
		fixture.phases[6] == 7);
	CHECK(fixture.driver->start(fixture.driver, (void *)2, NULL) ==
		EFI_ALREADY_STARTED);
	{
		UINT8 children = 99; void *new_children[4];
		request_notify_fn *notify_request = fixture.hotplug_request->notify;
		CHECK(notify_request(fixture.hotplug_request, 0U, (void *)1, NULL,
			&children, new_children) == EFI_SUCCESS);
		CHECK(children == 0);
	}
	CHECK(fixture.driver->stop(fixture.driver, (void *)1, 0, NULL) == EFI_SUCCESS);
	CHECK(fixture.closes == 2);
	CHECK(fixture.driver->stop(fixture.driver, (void *)2, 0, NULL) == EFI_SUCCESS);
	CHECK(fixture.closes == 3);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	CHECK(fixture.uninstalls == 1 && fixture.loaded.unload == old_unload);
	initialize(&fixture); fixture.enable_hotplug = 1; fixture.root_limit = 1;
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.driver->start(fixture.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(fixture.hpc_lists == 1 && fixture.hpc_inits == 1 &&
		fixture.hpc_paddings == 1);
	CHECK(fixture.hotplug_request != NULL);
	{
		UINT8 children = 0; void *new_children[2];
		uint8_t remaining[10] = { 1, 1, 6, 0, 0, 2, 0x7f, 0xff, 4, 0 };
		request_notify_fn *notify_request = fixture.hotplug_request->notify;
		fixture.visible_devices = 2;
		CHECK(notify_request(fixture.hotplug_request, 0U, (void *)1,
			remaining, &children, new_children) == EFI_SUCCESS);
		CHECK(children == 1);
		children = 0;
		CHECK(notify_request(fixture.hotplug_request, 1U, (void *)1, NULL,
			&children, NULL) == EFI_SUCCESS);
		CHECK(children == 0 && fixture.closes == 3);
	}
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	initialize(&fixture); fixture.enable_hotplug = 1; fixture.root_limit = 1;
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.driver->start(fixture.driver, (void *)1, NULL) == EFI_SUCCESS);
	{
		UINT8 children = 0; void *new_children[2];
		uint8_t remaining[10] = { 1, 1, 6, 0, 0, 2, 0x7f, 0xff, 4, 0 };
		request_notify_fn *notify_request = fixture.hotplug_request->notify;
		fixture.visible_devices = 2; fixture.fail_install_number = 3;
		CHECK(notify_request(fixture.hotplug_request, 0U, (void *)1,
			remaining, &children, new_children) == EFI_DEVICE_ERROR);
		CHECK(children == 0 && fixture.opens == 2 && fixture.closes == 0);
	}
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	initialize(&fixture); fixture.enable_hotplug = 1; fixture.root_limit = 1;
	fixture.fail_hpc_padding = 1;
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.driver->start(fixture.driver, (void *)1, NULL) ==
		EFI_DEVICE_ERROR);
	CHECK(fixture.hpc_lists == 1 && fixture.hpc_inits == 1 &&
		fixture.hpc_paddings == 0 && fixture.opens == fixture.closes);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	initialize(&fixture); fixture.install_status = EFI_OUT_OF_RESOURCES;
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_DEVICE_ERROR);
	CHECK(fixture.loaded.unload == old_unload && fixture.uninstalls == 0);
	initialize(&fixture); fixture.fail_proposed = 1;
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.driver->start(fixture.driver, (void *)1, NULL) ==
		EFI_DEVICE_ERROR);
	CHECK(fixture.phases[fixture.phase_count - 1U] == 6U);
	CHECK(fixture.opens == 2 && fixture.closes == 2);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	puts("pci bus entry tests: PASS");
	return 0;
}
