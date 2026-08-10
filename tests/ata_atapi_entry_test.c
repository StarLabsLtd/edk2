/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_entry.h>
#include <cdk2/ata_atapi_backend.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)
typedef UINT64 native_uint64_t;
typedef UINT32 native_uint32_t;
struct guid { UINT32 data1; UINT16 data2, data3; UINT8 data4[8]; };
typedef EFI_STATUS CDK2_MS_ABI handle_t(void *, const void *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_t(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_t(void *, ...);
typedef EFI_STATUS CDK2_MS_ABI open_t(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_t(void *, const struct guid *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_t(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_t(void *);
typedef EFI_STATUS CDK2_MS_ABI create_event_t(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI set_timer_t(void *, UINT32, UINT64);
typedef EFI_STATUS CDK2_MS_ABI event_t(void *);
struct fake_boot { UINT8 before_allocate[64]; allocate_t *allocate; free_t *free;
	create_event_t *create_event; set_timer_t *set_timer; void *wait;
	event_t *signal_event; event_t *close_event; UINT8 before_handle[32]; handle_t *handle;
	UINT8 before_open[120]; open_t *open; close_t *close;
	UINT8 before_install[32]; install_t *install; uninstall_t *uninstall; };
struct fake_system { UINT8 before_boot[96]; struct fake_boot *boot; };
struct fixture { struct fake_boot boot; struct fake_system system;
	struct cdk2_ata_loaded_image loaded; unsigned int installs, uninstalls;
	unsigned int fail_install, fail_uninstall, fail_open, fail_close, releases;
	unsigned int opens, closes, events, timers, signals, closes_event;
	unsigned int fail_timer, fail_signal, mode_ide;
	UINT32 open_guid[16], open_attributes[16];
	UINT32 close_guid[16]; void *controller[16], *agent[16], *child[16]; };
struct fake_event { void (CDK2_MS_ABI *notify)(void *, void *); void *context; };
static struct cdk2_ata_pass_thru_protocol *installed_ata;
static struct fake_event *pending_event;
static struct fixture *active;
static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **buffer)
{ (void)type; *buffer = calloc(1, size); return *buffer == NULL ?
	EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI free_pool(void *buffer)
{ free(buffer); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI handle(void *image, const void *guid, void **interface)
{ (void)image; (void)guid; *interface = &active->loaded; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI install(void **handle, const struct guid *guid,
	void *interface, ...)
{ active->installs++; *handle = (void *)0x9000;
	if (guid != NULL && guid->data1 == 0x1d3de7f0U)
		installed_ata = interface;
	return active->fail_install ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI uninstall(void *handle, ...)
{ (void)handle; active->uninstalls++;
	return active->fail_uninstall == active->uninstalls ?
		EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI open_protocol(void *controller,
	const struct guid *guid, void **interface, void *agent, void *child,
	UINT32 attributes)
{
	unsigned int call = active->opens++;

	active->open_guid[call] = guid->data1;
	active->open_attributes[call] = attributes;
	active->controller[call] = controller;
	active->agent[call] = agent;
	active->child[call] = child;
	*interface = active;
	return active->fail_open == call + 1U ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI close_protocol(void *controller,
	const struct guid *guid, void *agent, void *child)
{
	unsigned int call = active->closes++;

	active->close_guid[call] = guid->data1;
	active->controller[8U + call] = controller;
	active->agent[8U + call] = agent;
	active->child[8U + call] = child;
	return active->fail_close == call + 1U ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	void (CDK2_MS_ABI *notify)(void *, void *), void *context, void **event)
{ struct fake_event *created = calloc(1, sizeof(*created)); (void)type; (void)tpl;
	if (created == NULL)
		return EFI_OUT_OF_RESOURCES;
	active->events++;
	created->notify = notify; created->context = context; *event = created; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI set_timer(void *event, UINT32 type, UINT64 trigger)
{ (void)trigger; active->timers++;
	if (active->timers == active->fail_timer)
		return EFI_DEVICE_ERROR;
	pending_event = type == 0U ? NULL : event; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI signal_event(void *event)
{ (void)event; active->signals++;
	return active->signals == active->fail_signal ? EFI_DEVICE_ERROR : EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{ active->closes_event++; if (pending_event == event) pending_event = NULL;
	free(event); return EFI_SUCCESS; }
static void tick(void)
{ struct fake_event *event = pending_event; CHECK(event != NULL); pending_event = NULL;
	event->notify(event, event->context); }

static EFI_STATUS ahci_allocate(void *opaque, size_t size, size_t alignment,
	void **host, UINT64 *device)
{ (void)opaque; *host = aligned_alloc(alignment, size);
	if (*host == NULL)
		return EFI_OUT_OF_RESOURCES;
	*device = (UINT64)(uintptr_t)*host; return EFI_SUCCESS; }
static EFI_STATUS ahci_release(void *opaque, void *host, size_t size)
{ (void)opaque; (void)size; free(host); return EFI_SUCCESS; }
static EFI_STATUS ahci_map(void *opaque, enum cdk2_ahci_dma_operation operation,
	void *host, size_t *size, UINT64 *device, void **mapping)
{ (void)opaque; (void)operation; *device = (UINT64)(uintptr_t)host; *mapping = host;
	return *size == 0U ? EFI_INVALID_PARAMETER : EFI_SUCCESS; }
static EFI_STATUS ahci_unmap(void *opaque, void *mapping)
{ (void)opaque; (void)mapping; return EFI_SUCCESS; }
static EFI_STATUS ahci_flush(void *opaque) { (void)opaque; return EFI_SUCCESS; }
static UINT32 ahci_read(void *opaque, UINT16 port, UINT16 offset)
{ (void)opaque; (void)port; return offset == 0x38U ? 0U : 0U; }
static EFI_STATUS ahci_write(void *opaque, UINT16 port, UINT16 offset, UINT32 value)
{ (void)opaque; (void)port; (void)offset; (void)value; return EFI_SUCCESS; }
static UINT64 ahci_time(void *opaque) { static UINT64 now; (void)opaque; return now++; }
static void ahci_delay(void *opaque, UINTN delay) { (void)opaque; (void)delay; }
static UINT8 ide_read8(void *opaque, UINT16 port)
{ (void)opaque; (void)port; return 0U; }
static UINT16 ide_read16(void *opaque, UINT16 port)
{ (void)opaque; (void)port; return 0U; }
static EFI_STATUS ide_write8(void *opaque, UINT16 port, UINT8 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS ide_write16(void *opaque, UINT16 port, UINT16 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS ide_write32(void *opaque, UINT16 port, UINT32 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS ide_timing(void *opaque, UINT8 channel, UINT8 device)
{ (void)opaque; (void)channel; (void)device; return EFI_SUCCESS; }
static EFI_STATUS read_class(void *context, void *pci, UINT8 code[3])
{ struct fixture *fixture = context; (void)pci;
	code[0] = fixture->mode_ide ? 0U : 1U;
	code[1] = fixture->mode_ide ? 1U : 6U; code[2] = 1;
	return EFI_SUCCESS; }
static EFI_STATUS get_attributes(void *context, void *pci, native_uint64_t *original,
	native_uint64_t *supported)
{ (void)context; (void)pci; *original = 0; *supported = 7; return EFI_SUCCESS; }
static EFI_STATUS set_attributes(void *context, void *pci, UINT64 attributes)
{ (void)context; (void)pci; (void)attributes; return EFI_SUCCESS; }
static EFI_STATUS discover_ide(void *context, struct cdk2_ata_controller *controller,
	struct cdk2_ata_topology *topology)
{ (void)context; (void)controller;
	EFI_STATUS status = cdk2_ata_add_device(topology, 0, 0, CDK2_ATA_DISK);
	if (!EFI_ERROR(status))
		topology->devices[0].block_size = 512U;
	return status; }
static EFI_STATUS discover_ahci(void *context, struct cdk2_ata_controller *controller,
	native_uint32_t *cap,
	native_uint32_t *pi,
	struct cdk2_ata_topology *topology)
{ EFI_STATUS status; (void)context; (void)controller; *cap = 0; *pi = 3;
	status = cdk2_ata_add_device(topology, 0, 0xffff, CDK2_ATA_DISK);
	if (EFI_ERROR(status))
		return status;
	topology->devices[0].block_size = 512U;
	status = cdk2_ata_add_device(topology, 1, 0xffff, CDK2_ATA_DISK);
	if (!EFI_ERROR(status))
		topology->devices[1].block_size = 512U;
	return status; }
static EFI_STATUS prepare(void *context, struct cdk2_ata_controller *controller)
{ struct cdk2_ata_controller_backend *backend = calloc(1, sizeof(*backend));
	struct cdk2_ahci_dma_services services = { context, ahci_allocate, ahci_release,
		ahci_map, ahci_unmap, ahci_flush, ahci_read, ahci_write, ahci_time, ahci_delay };
	EFI_STATUS status; if (backend == NULL) return EFI_OUT_OF_RESOURCES;
	if (controller->topology.mode == CDK2_ATA_IDE) {
		struct cdk2_ide_channel channel = { 0x1f0U, 0x3f6U, 0xc000U };
		struct cdk2_ide_services ide = { context, ide_read8, ide_read16,
			ide_write8, ide_write16, ide_write32, ahci_map, ahci_unmap,
			ahci_flush, ide_timing, ahci_time, ahci_delay };

		status = cdk2_ide_engine_init(&backend->ide, &ide, &channel, 1U);
		if (!EFI_ERROR(status)) {
			backend->ide_initialized = 1; controller->ide_engine = &backend->ide;
		}
	} else {
		status = cdk2_ahci_engine_init(&backend->ahci, &services, 0U, 3U);
		if (!EFI_ERROR(status)) {
			backend->ahci_initialized = 1; controller->ahci = &backend->ahci;
		}
	}
	if (EFI_ERROR(status)) {
		free(backend);
		return status;
	}
	controller->backend = backend; return EFI_SUCCESS; }
static void release_engines(void *context, struct cdk2_ata_controller *controller)
{ struct cdk2_ata_controller_backend *backend = controller->backend;
	if (backend != NULL) {
		if (backend->ahci_initialized)
			cdk2_ahci_engine_destroy(&backend->ahci);
		free(backend);
	}
	controller->backend = NULL; controller->ahci = NULL; controller->ide_engine = NULL;
	((struct fixture *)context)->releases++; }
static EFI_STATUS create_protocols(void *context,
	struct cdk2_ata_controller *controller,
	struct cdk2_ata_protocol_bundle **protocols)
{ (void)context; (void)controller; *protocols = calloc(1, sizeof(**protocols));
	return *protocols == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void destroy_protocols(void *context, struct cdk2_ata_protocol_bundle *protocols)
{ (void)context; free(protocols); }
static EFI_STATUS publish_protocols(void *context, void *controller,
	struct cdk2_ata_protocol_bundle *protocols)
{ (void)context; (void)controller; (void)protocols; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI old_unload(void *image)
{ (void)image; return EFI_SUCCESS; }
static void initialize(struct fixture *fixture, struct cdk2_ata_binding *binding)
{
	struct cdk2_ata_binding_services services = { .context = fixture,
		.read_class = read_class, .get_attributes = get_attributes,
		.enable_attributes = set_attributes,
		.restore_attributes = set_attributes, .discover_ide = discover_ide,
		.discover_ahci = discover_ahci, .prepare_engines = prepare,
		.release_engines = release_engines, .create_protocols = create_protocols,
		.destroy_protocols = destroy_protocols, .install = publish_protocols,
		.uninstall = publish_protocols };
	memset(fixture, 0, sizeof(*fixture)); active = fixture;
	fixture->boot.handle = handle; fixture->boot.install = install;
	fixture->boot.allocate = allocate_pool; fixture->boot.free = free_pool;
	fixture->boot.create_event = create_event; fixture->boot.set_timer = set_timer;
	fixture->boot.signal_event = signal_event; fixture->boot.close_event = close_event;
	fixture->boot.uninstall = uninstall; fixture->boot.open = open_protocol;
	fixture->boot.close = close_protocol; fixture->system.boot = &fixture->boot;
	fixture->loaded.unload = old_unload;
	installed_ata = NULL; pending_event = NULL;
	CHECK(cdk2_ata_entry_publish_with_services(NULL, binding, &services,
		fixture, &fixture->system) == EFI_INVALID_PARAMETER);
}

int main(void)
{
	struct fixture fixture; struct cdk2_ata_binding binding; struct cdk2_ata_entry entry;
	CHAR16 *name = NULL;
	CHECK(offsetof(struct fake_boot, handle) == 152);
	CHECK(offsetof(struct fake_boot, allocate) == 64);
	CHECK(offsetof(struct fake_boot, free) == 72);
	CHECK(offsetof(struct fake_boot, open) == 280);
	CHECK(offsetof(struct fake_boot, close) == 288);
	CHECK(offsetof(struct fake_boot, install) == 328);
	CHECK(offsetof(struct fake_boot, uninstall) == 336);
	initialize(&fixture, &binding); fixture.fail_install = 1;
	{
		struct cdk2_ata_binding_services services = { .context = &fixture,
			.read_class = read_class, .get_attributes = get_attributes,
			.enable_attributes = set_attributes, .restore_attributes = set_attributes,
			.discover_ide = discover_ide, .discover_ahci = discover_ahci,
			.prepare_engines = prepare, .release_engines = release_engines,
			.create_protocols = create_protocols, .destroy_protocols = destroy_protocols,
			.install = publish_protocols, .uninstall = publish_protocols };
	CHECK(cdk2_ata_entry_publish_with_services(&entry, &binding, &services,
		&fixture, &fixture.system) ==
		EFI_DEVICE_ERROR);
	}
	CHECK(fixture.loaded.unload == old_unload);
	fixture.fail_install = 0;
	initialize(&fixture, &binding);
	{
		struct cdk2_ata_binding_services services = { .context = &fixture,
			.read_class = read_class, .get_attributes = get_attributes,
			.enable_attributes = set_attributes, .restore_attributes = set_attributes,
			.discover_ide = discover_ide, .discover_ahci = discover_ahci,
			.prepare_engines = prepare, .release_engines = release_engines,
			.create_protocols = create_protocols, .destroy_protocols = destroy_protocols,
			.install = publish_protocols, .uninstall = publish_protocols };
	CHECK(cdk2_ata_entry_publish_with_services(&entry, &binding, &services,
		&fixture, &fixture.system) == EFI_SUCCESS);
	}
	CHECK(fixture.loaded.unload == cdk2_ata_entry_unload && entry.driver.handle == (void *)0x9000);
	CHECK(entry.component.get_driver_name(&entry.component, "eng", &name) == EFI_SUCCESS);
	CHECK(name != NULL);
	fixture.fail_open = fixture.opens + 1U;
	CHECK(entry.driver.supported(&entry.driver, (void *)1, NULL) == EFI_DEVICE_ERROR);
	CHECK(binding.count == 0 && fixture.closes == 0);
	fixture.fail_open = 0;
	fixture.fail_close = fixture.closes + 1U;
	CHECK(entry.driver.supported(&entry.driver, (void *)1, NULL) == EFI_DEVICE_ERROR);
	CHECK(binding.count == 0 && fixture.closes == 1);
	fixture.fail_close = 0;
	CHECK(entry.driver.supported(&entry.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(fixture.opens == 5 && fixture.closes == 3);
	CHECK(fixture.open_guid[2] == 0x09576e91 && fixture.open_attributes[2] == 0x10);
	CHECK(fixture.open_guid[3] == 0xa1e37052 && fixture.open_attributes[3] == 0x10);
	CHECK(fixture.open_guid[4] == 0x4cf5b200 && fixture.open_attributes[4] == 0x02);
	CHECK(fixture.close_guid[1] == 0x09576e91 && fixture.close_guid[2] == 0xa1e37052);
	CHECK(fixture.agent[2] == &fixture && fixture.child[2] == (void *)1);
	CHECK(entry.driver.start(&entry.driver, (void *)1, NULL) == EFI_SUCCESS);
	CHECK(entry.driver.start(&entry.driver, (void *)2, NULL) == EFI_SUCCESS);
	CHECK(binding.count == 2);
	{
		struct cdk2_ata_command_block acb = { .command = 0xe7U };
		struct cdk2_ata_status_block asb = { .status = 0xffU };
		struct cdk2_ata_command_packet first = { .asb = &asb, .acb = &acb,
			.timeout = 100U, .protocol = 2U };
		struct cdk2_ata_command_packet second = first;
		unsigned int before_signals = fixture.signals;

		CHECK(installed_ata != NULL &&
			(installed_ata->mode->attributes &
			 CDK2_ATA_PASS_THRU_ATTRIBUTES_NONBLOCKIO) != 0U);
		CHECK(installed_ata->pass_thru(installed_ata, 0, 0xffffU, &first,
			(void *)0xa001U) ==
			EFI_SUCCESS && fixture.signals == before_signals);
		CHECK(installed_ata->pass_thru(installed_ata, 1, 0xffffU, &second,
			(void *)0xa002U) ==
			EFI_SUCCESS);
		for (unsigned int step = 0; step < 80U && fixture.signals < before_signals + 2U;
		     step++)
			tick();
		CHECK(fixture.signals == before_signals + 2U && asb.status == 0U);
		CHECK(installed_ata->reset_port(installed_ata, 0) == EFI_SUCCESS);
		fixture.fail_timer = fixture.timers + 1U;
		CHECK(installed_ata->pass_thru(installed_ata, 0, 0xffffU, &first,
			(void *)0xa003U) == EFI_DEVICE_ERROR);
		fixture.fail_timer = 0;
		fixture.fail_signal = fixture.signals + 1U;
		CHECK(installed_ata->pass_thru(installed_ata, 0, 0xffffU, &first,
			(void *)0xa004U) == EFI_SUCCESS);
		for (unsigned int step = 0; step < 40U && pending_event != NULL; step++)
			tick();
		CHECK(pending_event == NULL && fixture.signals == fixture.fail_signal);
		fixture.fail_signal = 0;
		CHECK(installed_ata->pass_thru(installed_ata, 0, 0xffffU, &first,
			(void *)0xa005U) == EFI_SUCCESS && pending_event != NULL);
		while (pending_event != NULL)
			tick();
	}
	fixture.mode_ide = 1U;
	CHECK(entry.driver.start(&entry.driver, (void *)3, NULL) == EFI_SUCCESS &&
		binding.count == 3 && installed_ata != NULL &&
		(installed_ata->mode->attributes &
		 CDK2_ATA_PASS_THRU_ATTRIBUTES_NONBLOCKIO) != 0U);
	{
		struct cdk2_ata_command_block acb = { .command = 0xe7U };
		struct cdk2_ata_status_block asb = { 0 };
		struct cdk2_ata_command_packet packet = { .asb = &asb, .acb = &acb,
			.timeout = 100U, .protocol = 2U };
		unsigned int before = fixture.signals;

		CHECK(installed_ata->pass_thru(installed_ata, 0, 0, &packet,
			(void *)0xb001U) == EFI_SUCCESS && fixture.signals == before);
		for (unsigned int step = 0; step < 32U && fixture.signals == before; step++)
			tick();
		CHECK(fixture.signals == before + 1U && asb.status == 0U);
		CHECK(installed_ata->pass_thru(installed_ata, 0, 0, &packet,
			(void *)0xb002U) == EFI_SUCCESS && pending_event != NULL);
	}
	fixture.fail_uninstall = fixture.uninstalls + 4U;
	CHECK(entry.loaded->unload(&fixture) == EFI_DEVICE_ERROR);
	CHECK(entry.published && binding.count == 0);
	fixture.fail_uninstall = 0;
	CHECK(entry.loaded->unload(&fixture) == EFI_SUCCESS);
	CHECK(!entry.published && fixture.loaded.unload == old_unload);
	CHECK(fixture.releases == 3 && fixture.closes >= 6);
	CHECK(pending_event == NULL && fixture.closes_event == fixture.events);
	CHECK(cdk2_ata_atapi_pass_thru_entry(&fixture, &fixture.system) == EFI_SUCCESS);
	CHECK(fixture.loaded.unload(&fixture) == EFI_SUCCESS);
	puts("ata atapi entry tests: PASS");
	return 0;
}
