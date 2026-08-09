/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_pass_thru.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	unsigned int step, fail_step, opens, closes, installs, uninstalls;
	unsigned int restores, enables, ide_discovers, ahci_discovers;
	unsigned int prepares, engine_releases;
	UINT8 class_code[3];
};
static EFI_STATUS fault(struct fixture *fixture)
{ return ++fixture->step == fixture->fail_step ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS open_path(void *opaque, void *handle)
{ (void)handle; return fault(opaque); }
static EFI_STATUS close_path(void *opaque, void *handle)
{ (void)handle; return fault(opaque); }
static EFI_STATUS open_ide(void *opaque, void *handle, void **ide)
{ struct fixture *f = opaque; (void)handle; f->opens++; *ide = f; return fault(f); }
static EFI_STATUS close_ide(void *opaque, void *handle)
{ struct fixture *f = opaque; (void)handle; f->closes++; return fault(f); }
static EFI_STATUS get_pci(void *opaque, void *handle, void **pci)
{ struct fixture *f = opaque; (void)handle; *pci = f; return fault(f); }
static EFI_STATUS read_class(void *opaque, void *pci, UINT8 code[3])
{ struct fixture *f = opaque; (void)pci; memcpy(code, f->class_code, 3);
	return fault(f); }
static EFI_STATUS get_attributes(void *opaque, void *pci, UINT64 *original,
	UINT64 *supported)
{ struct fixture *f = opaque; (void)pci; *original = 0x80; *supported = 0x107;
	return fault(f); }
static EFI_STATUS enable(void *opaque, void *pci, UINT64 attributes)
{ struct fixture *f = opaque; (void)pci; CHECK(attributes == 7); f->enables++;
	return fault(f); }
static EFI_STATUS restore(void *opaque, void *pci, UINT64 attributes)
{ struct fixture *f = opaque; (void)pci; CHECK(attributes == 0x80); f->restores++;
	return fault(f); }
static EFI_STATUS discover_ide(void *opaque, void *pci, void *ide,
	struct cdk2_ata_topology *topology)
{ struct fixture *f = opaque; (void)pci; CHECK(ide == f); f->ide_discovers++;
	if (EFI_ERROR(fault(f)))
		return EFI_DEVICE_ERROR;
	return cdk2_ata_add_device(topology, 0, 0, CDK2_ATA_DISK); }
static EFI_STATUS discover_ahci(void *opaque, void *pci, UINT32 *cap, UINT32 *pi,
	struct cdk2_ata_topology *topology)
{ struct fixture *f = opaque; (void)pci; f->ahci_discovers++; *cap = 0x80000000;
	*pi = 5;
	if (EFI_ERROR(fault(f)))
		return EFI_DEVICE_ERROR;
	CHECK(cdk2_ata_add_device(topology, 0, 0xffff, CDK2_ATA_DISK) == EFI_SUCCESS);
	return cdk2_ata_add_device(topology, 2, 0xffff, CDK2_ATA_DISK); }
static EFI_STATUS create_protocols(void *opaque,
	struct cdk2_ata_controller *controller,
	struct cdk2_ata_protocol_bundle **protocols)
{ struct fixture *f = opaque; (void)controller; *protocols = calloc(1, sizeof(**protocols));
	if (*protocols == NULL)
		return EFI_OUT_OF_RESOURCES;
	return fault(f); }
static void destroy_protocols(void *opaque, struct cdk2_ata_protocol_bundle *protocols)
{ (void)opaque; free(protocols); }
static EFI_STATUS install(void *opaque, void *handle,
	struct cdk2_ata_protocol_bundle *protocols)
{ struct fixture *f = opaque; (void)handle; CHECK(protocols != NULL);
	f->installs++; return fault(f); }
static EFI_STATUS prepare_engines(void *opaque, struct cdk2_ata_controller *controller)
{ struct fixture *f = opaque; CHECK(controller->topology.count != 0U); f->prepares++;
	return fault(f); }
static void release_engines(void *opaque, struct cdk2_ata_controller *controller)
{ struct fixture *f = opaque; (void)controller; f->engine_releases++; }
static EFI_STATUS uninstall(void *opaque, void *handle,
	struct cdk2_ata_protocol_bundle *protocols)
{ struct fixture *f = opaque; (void)handle; CHECK(protocols != NULL);
	f->uninstalls++; return fault(f); }
static void initialize(struct fixture *fixture, struct cdk2_ata_binding *binding)
{
	struct cdk2_ata_binding_services services = {
		.context = fixture, .open_path = open_path, .close_path = close_path,
		.open_ide = open_ide, .close_ide = close_ide, .get_pci = get_pci,
		.read_class = read_class, .get_attributes = get_attributes,
		.enable_attributes = enable, .restore_attributes = restore,
		.discover_ide = discover_ide, .discover_ahci = discover_ahci,
		.prepare_engines = prepare_engines, .release_engines = release_engines,
		.create_protocols = create_protocols, .destroy_protocols = destroy_protocols,
		.install = install, .uninstall = uninstall };
	memset(fixture, 0, sizeof(*fixture)); fixture->class_code[2] = 1;
	fixture->class_code[1] = 1;
	CHECK(cdk2_ata_binding_init(binding, &services) == EFI_SUCCESS);
}

int main(void)
{
	struct fixture fixture; struct cdk2_ata_binding binding;
	initialize(&fixture, &binding);
	CHECK(cdk2_ata_binding_supported(&binding, (void *)1) == EFI_SUCCESS);
	CHECK(fixture.opens == 1 && fixture.closes == 1);
	fixture.step = 0;
	CHECK(cdk2_ata_binding_start(&binding, (void *)1) == EFI_SUCCESS);
	CHECK(binding.count == 1 && fixture.ide_discovers == 1 && fixture.installs == 1);
	fixture.class_code[1] = 6; fixture.class_code[0] = 1; fixture.step = 0;
	CHECK(cdk2_ata_binding_start(&binding, (void *)2) == EFI_SUCCESS);
	CHECK(binding.count == 2 && fixture.ahci_discovers == 1 &&
		binding.controllers[1].ports_implemented == 5);
	CHECK(cdk2_ata_binding_start(&binding, (void *)2) == EFI_ALREADY_STARTED);
	CHECK(cdk2_ata_binding_stop(&binding, (void *)1) == EFI_SUCCESS);
	CHECK(binding.count == 1 && binding.controllers[0].handle == (void *)2);
	CHECK(binding.controllers[0].protocols->ata.controller ==
		&binding.controllers[0]);
	CHECK(binding.controllers[0].protocols->ext_scsi.controller ==
		&binding.controllers[0]);
	CHECK(cdk2_ata_binding_stop(&binding, (void *)2) == EFI_SUCCESS);
	CHECK(binding.count == 0);
	for (unsigned int failure = 1; failure <= 9; failure++) {
		initialize(&fixture, &binding); fixture.fail_step = failure;
		CHECK(EFI_ERROR(cdk2_ata_binding_start(&binding, (void *)3)));
		CHECK(binding.count == 0);
		if (failure >= 5)
			CHECK(fixture.closes == 1);
	}
	for (unsigned int failure = 1; failure <= 3; failure++) {
		initialize(&fixture, &binding);
		CHECK(cdk2_ata_binding_start(&binding, (void *)5) == EFI_SUCCESS);
		fixture.step = 0; fixture.fail_step = failure;
		CHECK(EFI_ERROR(cdk2_ata_binding_stop(&binding, (void *)5)));
		CHECK(binding.count == 1 && binding.controllers[0].handle == (void *)5);
	}
	initialize(&fixture, &binding); fixture.class_code[1] = 6;
	fixture.class_code[0] = 0;
	CHECK(cdk2_ata_binding_supported(&binding, (void *)4) == EFI_UNSUPPORTED);
	puts("ata atapi binding tests: PASS");
	return 0;
}
