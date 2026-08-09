/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_entry.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)
typedef UINT64 native_uint64_t;
typedef UINT32 native_uint32_t;
typedef EFI_STATUS CDK2_MS_ABI handle_t(void *, const void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_t(void **, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_t(void *, ...);
struct fake_boot { UINT8 before_handle[152]; handle_t *handle;
	UINT8 before_install[168]; install_t *install; uninstall_t *uninstall; };
struct fake_system { UINT8 before_boot[96]; struct fake_boot *boot; };
struct fixture { struct fake_boot boot; struct fake_system system;
	struct cdk2_ata_loaded_image loaded; unsigned int installs, uninstalls;
	unsigned int fail_install, fail_uninstall, closes, releases; };
static struct fixture *active;
static EFI_STATUS CDK2_MS_ABI handle(void *image, const void *guid, void **interface)
{ (void)image; (void)guid; *interface = &active->loaded; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, ...)
{ active->installs++; *handle = (void *)0x9000;
	return active->fail_install ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{ (void)handle; active->uninstalls++;
	return active->fail_uninstall ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS open_path(void *context, void *controller)
{ (void)context; (void)controller; return EFI_SUCCESS; }
static EFI_STATUS close_path(void *context, void *controller)
{ (void)context; (void)controller; return EFI_SUCCESS; }
static EFI_STATUS open_ide(void *context, void *controller, void **ide)
{ (void)context; (void)controller; *ide = active; return EFI_SUCCESS; }
static EFI_STATUS close_ide(void *context, void *controller)
{ (void)controller; ((struct fixture *)context)->closes++; return EFI_SUCCESS; }
static EFI_STATUS get_pci(void *context, void *controller, void **pci)
{ (void)controller; *pci = context; return EFI_SUCCESS; }
static EFI_STATUS read_class(void *context, void *pci, UINT8 code[3])
{ (void)context; (void)pci; code[0] = 1; code[1] = 6; code[2] = 1;
	return EFI_SUCCESS; }
static EFI_STATUS get_attributes(void *context, void *pci, native_uint64_t *original,
	native_uint64_t *supported)
{ (void)context; (void)pci; *original = 0; *supported = 7; return EFI_SUCCESS; }
static EFI_STATUS set_attributes(void *context, void *pci, UINT64 attributes)
{ (void)context; (void)pci; (void)attributes; return EFI_SUCCESS; }
static EFI_STATUS discover_ide(void *context, void *pci, void *ide,
	struct cdk2_ata_topology *topology)
{ (void)context; (void)pci; (void)ide;
	return cdk2_ata_add_device(topology, 0, 0, CDK2_ATA_DISK); }
static EFI_STATUS discover_ahci(void *context, void *pci, native_uint32_t *cap,
	native_uint32_t *pi,
	struct cdk2_ata_topology *topology)
{ (void)context; (void)pci; *cap = 0; *pi = 1;
	return cdk2_ata_add_device(topology, 0, 0xffff, CDK2_ATA_DISK); }
static EFI_STATUS prepare(void *context, struct cdk2_ata_controller *controller)
{ (void)context; (void)controller; return EFI_SUCCESS; }
static void release_engines(void *context, struct cdk2_ata_controller *controller)
{ (void)controller; ((struct fixture *)context)->releases++; }
static EFI_STATUS publish_protocols(void *context, void *controller,
	struct cdk2_ata_topology *topology)
{ (void)context; (void)controller; (void)topology; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI old_unload(void *image)
{ (void)image; return EFI_SUCCESS; }
static void initialize(struct fixture *fixture, struct cdk2_ata_binding *binding)
{
	struct cdk2_ata_binding_services services = { .context = fixture,
		.open_path = open_path, .close_path = close_path, .open_ide = open_ide,
		.close_ide = close_ide, .get_pci = get_pci, .read_class = read_class,
		.get_attributes = get_attributes, .enable_attributes = set_attributes,
		.restore_attributes = set_attributes, .discover_ide = discover_ide,
		.discover_ahci = discover_ahci, .prepare_engines = prepare,
		.release_engines = release_engines, .install = publish_protocols,
		.uninstall = publish_protocols };
	memset(fixture, 0, sizeof(*fixture)); active = fixture;
	fixture->boot.handle = handle; fixture->boot.install = install;
	fixture->boot.uninstall = uninstall; fixture->system.boot = &fixture->boot;
	fixture->loaded.unload = old_unload;
	CHECK(cdk2_ata_binding_init(binding, &services) == EFI_SUCCESS);
}

int main(void)
{
	struct fixture fixture; struct cdk2_ata_binding binding; struct cdk2_ata_entry entry;
	CHAR16 *name = NULL;
	CHECK(offsetof(struct fake_boot, handle) == 152);
	CHECK(offsetof(struct fake_boot, install) == 328);
	CHECK(offsetof(struct fake_boot, uninstall) == 336);
	initialize(&fixture, &binding); fixture.fail_install = 1;
	CHECK(cdk2_ata_entry_publish(&entry, &binding, &fixture, &fixture.system) ==
		EFI_DEVICE_ERROR);
	CHECK(fixture.loaded.unload == old_unload);
	fixture.fail_install = 0;
	CHECK(cdk2_ata_entry_publish(&entry, &binding, &fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.loaded.unload == cdk2_ata_entry_unload && entry.driver.handle == (void *)0x9000);
	CHECK(entry.component.get_driver_name(&entry.component, "eng", &name) == EFI_SUCCESS);
	CHECK(name != NULL);
	CHECK(entry.driver.supported(&entry.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(entry.driver.start(&entry.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(entry.driver.start(&entry.driver, (void *)2, NULL) == EFI_SUCCESS);
	CHECK(binding.count == 2);
	fixture.fail_uninstall = 1;
	CHECK(entry.loaded->unload(&fixture) == EFI_DEVICE_ERROR);
	CHECK(entry.published && binding.count == 0);
	fixture.fail_uninstall = 0;
	CHECK(entry.loaded->unload(&fixture) == EFI_SUCCESS);
	CHECK(!entry.published && fixture.loaded.unload == old_unload);
	CHECK(fixture.releases == 2 && fixture.closes >= 3);
	puts("ata atapi entry tests: PASS");
	return 0;
}
