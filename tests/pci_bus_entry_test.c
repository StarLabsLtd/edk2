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
struct loaded_image {
	uint32_t revision; void *parent, *system, *device, *path, *reserved;
	uint32_t option_size; void *options, *base; uint64_t size;
	uint32_t code, data; unload_fn *unload;
};
struct fake_boot {
	uint8_t before_pool[64]; void *allocate_pool, *free_pool;
	uint8_t before_handle[72]; void *handle_protocol;
	uint8_t before_open[120]; void *open_protocol, *close_protocol;
	uint8_t before_install[32]; void *install_multiple, *uninstall_multiple;
};
struct fake_system {
	uint8_t header[24]; void *vendor; uint32_t revision, pad;
	void *console[6], *runtime; struct fake_boot *boot;
};
struct fixture {
	struct fake_boot boot; struct fake_system system; struct loaded_image loaded;
	unsigned int installs, uninstalls, opens, closes; EFI_STATUS install_status;
	struct cdk2_driver_binding_protocol *driver;
	uint8_t path[4], resources[48];
	struct {
		void *parent, *poll_mem, *poll_io;
		struct { void *read, *write; } mem, io, pci;
		void *copy, *map, *unmap, *allocate, *free, *flush;
		void *get_attributes, *set_attributes, *configuration;
		uint32_t segment;
	} root;
};
static struct fixture *active;

static EFI_STATUS CDK2_MS_ABI pool(uint32_t type, UINTN size, void **buffer)
{ (void)type; *buffer = calloc(1, size); return *buffer == NULL ? 9 : 0; }
static EFI_STATUS CDK2_MS_ABI release(void *buffer)
{ free(buffer); return 0; }
static EFI_STATUS CDK2_MS_ABI handle(void *object, const EFI_GUID *guid, void **interface)
{ (void)guid; *interface = object == active ? (void *)&active->loaded : active->path;
	return 0; }
static EFI_STATUS CDK2_MS_ABI open_protocol(void *handle, const EFI_GUID *guid,
	void **interface, void *agent, void *controller, uint32_t attributes)
{ (void)handle; (void)guid; (void)agent; (void)controller; (void)attributes;
	active->opens++; *interface = &active->root; return 0; }
static EFI_STATUS CDK2_MS_ABI close_protocol(void *handle, const EFI_GUID *guid,
	void *agent, void *controller)
{ (void)handle; (void)guid; (void)agent; (void)controller; active->closes++; return 0; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, const EFI_GUID *guid,
	void *interface, ...)
{ (void)guid; (void)interface; active->installs++; *handle = active;
	if (active->installs == 1)
		active->driver = interface;
	return active->install_status; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, const EFI_GUID *guid,
	void *interface, ...)
{ (void)handle; (void)guid; (void)interface; active->uninstalls++; return 0; }
static EFI_STATUS CDK2_MS_ABI old_unload(void *image)
{ (void)image; return 0; }
static EFI_STATUS CDK2_MS_ABI config_read(void *root, UINTN width,
	uint64_t address, UINTN count, void *buffer)
{ (void)root; (void)width; (void)address; (void)count;
	*(uint32_t *)buffer = 0xffffffffU; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI configuration(void *root, void **resources)
{ (void)root; *resources = active->resources; return EFI_SUCCESS; }

static void initialize(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture)); active = fixture;
	fixture->boot.allocate_pool = pool; fixture->boot.free_pool = release;
	fixture->boot.handle_protocol = handle;
	fixture->boot.open_protocol = open_protocol;
	fixture->boot.close_protocol = close_protocol;
	fixture->boot.install_multiple = install;
	fixture->boot.uninstall_multiple = uninstall;
	fixture->system.boot = &fixture->boot; fixture->loaded.unload = old_unload;
	fixture->path[0] = 0x7f; fixture->path[1] = 0xff; fixture->path[2] = 4;
	fixture->resources[0] = 0x8a; fixture->resources[1] = 43;
	fixture->resources[3] = 2; fixture->resources[14] = 0;
	fixture->resources[22] = 0; fixture->resources[46] = 0x79;
	fixture->root.pci.read = config_read; fixture->root.pci.write = config_read;
	fixture->root.configuration = configuration;
}

int main(void)
{
	struct fixture fixture;
	CHECK(offsetof(struct fake_boot, allocate_pool) == 64);
	CHECK(offsetof(struct fake_boot, handle_protocol) == 152);
	CHECK(offsetof(struct fake_boot, open_protocol) == 280);
	CHECK(offsetof(struct fake_boot, close_protocol) == 288);
	CHECK(offsetof(struct fake_boot, install_multiple) == 328);
	CHECK(offsetof(struct fake_boot, uninstall_multiple) == 336);
	initialize(&fixture);
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.installs == 1 && fixture.loaded.unload == cdk2_pci_bus_unload);
	CHECK(fixture.driver != NULL);
	CHECK(fixture.driver->supported(fixture.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(fixture.opens == 1 && fixture.closes == 1);
	CHECK(fixture.driver->start(fixture.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(fixture.opens == 2 && fixture.closes == 1);
	CHECK(fixture.driver->start(fixture.driver, (void *)2, NULL) == EFI_SUCCESS);
	CHECK(fixture.opens == 3 && fixture.closes == 1);
	CHECK(fixture.driver->stop(fixture.driver, (void *)1, 0, NULL) == EFI_SUCCESS);
	CHECK(fixture.closes == 2);
	CHECK(fixture.driver->stop(fixture.driver, (void *)2, 0, NULL) == EFI_SUCCESS);
	CHECK(fixture.closes == 3);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	CHECK(fixture.uninstalls == 1 && fixture.loaded.unload == old_unload);
	initialize(&fixture); fixture.install_status = EFI_OUT_OF_RESOURCES;
	CHECK(cdk2_pci_bus_entry(&fixture, &fixture.system) == EFI_DEVICE_ERROR);
	CHECK(fixture.loaded.unload == old_unload && fixture.uninstalls == 0);
	puts("pci bus entry tests: PASS");
	return 0;
}
