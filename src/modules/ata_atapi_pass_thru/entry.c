/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ata_atapi_entry.h>
#include <cdk2/ata_atapi_backend.h>

#include <stddef.h>
#include <string.h>

struct guid { UINT32 data1; UINT16 data2, data3; UINT8 data4[8]; };
typedef EFI_STATUS CDK2_MS_ABI handle_t(void *, const struct guid *, void **);
typedef EFI_STATUS CDK2_MS_ABI install_t(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_t(void *, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI open_t(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_t(void *, const struct guid *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI allocate_t(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_t(void *);
typedef UINTN CDK2_MS_ABI raise_tpl_t(UINTN);
typedef void CDK2_MS_ABI restore_tpl_t(UINTN);
typedef EFI_STATUS CDK2_MS_ABI create_event_t(UINT32, UINTN,
	void (CDK2_MS_ABI *)(void *, void *), void *, void **);
typedef EFI_STATUS CDK2_MS_ABI set_timer_t(void *, UINT32, UINT64);
typedef EFI_STATUS CDK2_MS_ABI signal_event_t(void *);
typedef EFI_STATUS CDK2_MS_ABI close_event_t(void *);
typedef EFI_STATUS CDK2_MS_ABI stall_t(UINTN);
struct cdk2_ata_boot_services {
	UINT8 header[24];
	raise_tpl_t *raise_tpl; restore_tpl_t *restore_tpl;
	UINT8 before_allocate[24]; allocate_t *allocate_pool; free_t *free_pool;
	create_event_t *create_event; set_timer_t *set_timer; void *wait_for_event;
	signal_event_t *signal_event; close_event_t *close_event;
	UINT8 before_handle[32]; handle_t *handle_protocol;
	UINT8 before_stall[88]; stall_t *stall; UINT8 before_open[24];
	open_t *open_protocol; close_t *close_protocol;
	UINT8 before_install[32]; install_t *install_multiple;
	uninstall_t *uninstall_multiple;
};
struct system_table_view {
	UINT8 header[24]; cdk2_char16_t *vendor; UINT32 revision, pad;
	void *console[6], *runtime; struct cdk2_ata_boot_services *boot;
};
typedef char handle_offset_check[offsetof(struct cdk2_ata_boot_services,
	handle_protocol) == 152 ? 1 : -1];
typedef char install_offset_check[offsetof(struct cdk2_ata_boot_services,
	install_multiple) == 328 ? 1 : -1];
typedef char uninstall_offset_check[offsetof(struct cdk2_ata_boot_services,
	uninstall_multiple) == 336 ? 1 : -1];
typedef char open_offset_check[offsetof(struct cdk2_ata_boot_services,
	open_protocol) == 280 ? 1 : -1];
typedef char close_offset_check[offsetof(struct cdk2_ata_boot_services,
	close_protocol) == 288 ? 1 : -1];
typedef char stall_offset_check[offsetof(struct cdk2_ata_boot_services,
	stall) == 248 ? 1 : -1];
typedef char allocate_offset_check[offsetof(struct cdk2_ata_boot_services,
	allocate_pool) == 64 ? 1 : -1];
typedef char free_offset_check[offsetof(struct cdk2_ata_boot_services,
	free_pool) == 72 ? 1 : -1];
typedef char create_offset_check[offsetof(struct cdk2_ata_boot_services,
	create_event) == 80 ? 1 : -1];

static const struct guid loaded_image_guid = { 0x5b1b31a1, 0x9562, 0x11d2,
	{ 0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid driver_binding_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const struct guid component_name_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid component_name2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const struct guid device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid pci_io_guid = { 0x4cf5b200, 0x68b8, 0x4ca5,
	{ 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a } };
static const struct guid ide_init_guid = { 0xa1e37052, 0x80d9, 0x4e65,
	{ 0xa3, 0x17, 0x3e, 0x9a, 0x55, 0xc4, 0x3e, 0xc9 } };
static const struct guid ata_pass_thru_guid = { 0x1d3de7f0, 0x0807, 0x424f,
	{ 0xaa, 0x69, 0x11, 0xa5, 0x4e, 0x19, 0xa4, 0x6f } };
static const struct guid ext_scsi_guid = { 0x143b7632, 0xb81b, 0x4cb7,
	{ 0xab, 0xd3, 0xb6, 0x25, 0xa5, 0xb9, 0xbf, 0xfe } };
static CHAR16 driver_name[] = L"ATA/ATAPI Pass Thru Driver";
static CHAR16 controller_name[] = L"ATA/ATAPI Controller";
static struct cdk2_ata_entry *active_entry;
static struct cdk2_ata_entry image_entry;
static struct cdk2_ata_binding image_binding;
struct async_call { struct cdk2_ata_controller_backend *backend; void *event; };


static EFI_STATUS open_protocol(struct cdk2_ata_entry *entry, void *controller,
	const struct guid *guid, void **interface, UINT32 attributes)
{
	return entry->boot->open_protocol(controller, guid, interface, entry->image,
		controller, attributes);
}
static EFI_STATUS service_open_path(void *opaque, void *controller)
{
	struct cdk2_ata_entry *entry = active_entry;
	void *path = NULL;

	(void)opaque;
	if (entry == NULL)
		return EFI_NOT_READY;
	return open_protocol(entry, controller, &device_path_guid, &path, 0x10U);
}
static EFI_STATUS service_close_path(void *opaque, void *controller)
{
	struct cdk2_ata_entry *entry = active_entry;

	(void)opaque;
	if (entry == NULL)
		return EFI_NOT_READY;
	return entry->boot->close_protocol(controller,
		&device_path_guid, entry->image, controller);
}
static EFI_STATUS service_open_ide(void *opaque, void *controller, void **ide)
{
	(void)opaque;
	return active_entry == NULL ? EFI_NOT_READY :
		open_protocol(active_entry, controller, &ide_init_guid, ide, 0x10U);
}
static EFI_STATUS service_close_ide(void *opaque, void *controller)
{
	struct cdk2_ata_entry *entry = active_entry;

	(void)opaque;
	if (entry == NULL)
		return EFI_NOT_READY;
	return entry->boot->close_protocol(controller,
		&ide_init_guid, entry->image, controller);
}
static EFI_STATUS service_get_pci(void *opaque, void *controller, void **pci)
{
	(void)opaque;
	return active_entry == NULL ? EFI_NOT_READY :
		open_protocol(active_entry, controller, &pci_io_guid, pci, 0x02U);
}
static EFI_STATUS protocol_allocate(void *opaque, size_t size, void **buffer)
{
	struct cdk2_ata_entry *entry = active_entry;

	(void)opaque;
	return entry == NULL ? EFI_NOT_READY :
		entry->boot->allocate_pool(4U, size, buffer);
}
static void protocol_release(void *opaque, void *buffer)
{
	(void)opaque;
	if (active_entry != NULL)
		(void)active_entry->boot->free_pool(buffer);
}
static void backend_release_pool(void *opaque, void *buffer, size_t size)
{
	(void)size;
	protocol_release(opaque, buffer);
}
static EFI_STATUS hardware_read_class(void *opaque, void *pci, UINT8 code[3])
{
	(void)opaque;
	return cdk2_ata_pci_read_class(pci, code);
}
static EFI_STATUS hardware_get_attributes(void *opaque, void *pci,
	UINT64 *current, UINT64 *supported)
{
	(void)opaque;
	return cdk2_ata_pci_get_attributes(pci, current, supported);
}
static EFI_STATUS hardware_enable_attributes(void *opaque, void *pci,
	UINT64 attributes)
{
	(void)opaque;
	return cdk2_ata_pci_enable_attributes(pci, attributes);
}
static EFI_STATUS hardware_restore_attributes(void *opaque, void *pci,
	UINT64 attributes)
{
	(void)opaque;
	return cdk2_ata_pci_restore_attributes(pci, attributes);
}
static EFI_STATUS hardware_prepare(void *opaque,
	struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_backend_pool pool = {
		opaque, protocol_allocate, backend_release_pool };

	return cdk2_ata_backend_prepare(&pool, controller);
}
static void hardware_release(void *opaque,
	struct cdk2_ata_controller *controller)
{
	(void)opaque;
	cdk2_ata_backend_release(controller);
}
static EFI_STATUS hardware_discover_ide(void *opaque,
	struct cdk2_ata_controller *controller,
	struct cdk2_ata_topology *topology)
{
	(void)opaque;
	return cdk2_ata_backend_discover_ide(controller, topology);
}
static EFI_STATUS hardware_discover_ahci(void *opaque,
	struct cdk2_ata_controller *controller, UINT32 *capability,
	UINT32 *ports_implemented, struct cdk2_ata_topology *topology)
{
	(void)opaque;
	*capability = controller->ahci_capability;
	*ports_implemented = controller->ports_implemented;
	return cdk2_ata_backend_discover_ahci(controller, topology);
}
static EFI_STATUS async_begin(void *opaque, struct cdk2_ata_controller *controller,
	struct cdk2_ata_async_task *task)
{ struct cdk2_ata_controller_backend *backend = controller->backend; (void)opaque;
	if (task->atapi)
		return controller->topology.mode == CDK2_ATA_AHCI ?
			cdk2_ahci_atapi_async_prepare(&backend->async_request,
				controller->ahci, task->port, task->packet, task->cdb,
				task->cdb_size, task->packet->timeout) :
			cdk2_ide_atapi_async_prepare(&backend->ide_async_request,
				controller->ide_engine, (UINT8)task->port,
				(UINT8)task->multiplier, task->packet, task->cdb,
				task->cdb_size, task->packet->timeout);
	return controller->topology.mode == CDK2_ATA_AHCI ?
		cdk2_ahci_async_prepare(&backend->async_request, controller->ahci,
			task->port, task->packet, task->packet->timeout) :
		cdk2_ide_async_prepare(&backend->ide_async_request, controller->ide_engine,
			(UINT8)task->port, (UINT8)task->multiplier, task->packet,
			task->packet->timeout); }
static EFI_STATUS async_poll_task(void *opaque,
	struct cdk2_ata_controller *controller, struct cdk2_ata_async_task *task,
	BOOLEAN *complete)
{ struct cdk2_ata_controller_backend *backend = controller->backend;
	(void)opaque; (void)task;
	if (controller->topology.mode == CDK2_ATA_IDE)
		return cdk2_ide_async_step(&backend->ide_async_request, complete);
	if (backend->async_request.aborting) {
		EFI_STATUS status = cdk2_ahci_async_abort(&backend->async_request, complete);
		return *complete ? backend->async_request.terminal_status : status;
	}
	return cdk2_ahci_async_step(&backend->async_request, complete); }
static EFI_STATUS async_abort_task(void *opaque,
	struct cdk2_ata_controller *controller, struct cdk2_ata_async_task *task)
{ struct cdk2_ata_controller_backend *backend = controller->backend;
	BOOLEAN complete = 0; EFI_STATUS status; (void)opaque; (void)task;
	if (controller->topology.mode == CDK2_ATA_IDE) {
		status = cdk2_ide_async_abort(&backend->ide_async_request, &complete);
		return complete ? status : EFI_NOT_READY;
	}
	status = cdk2_ahci_async_abort(&backend->async_request, &complete);
	return complete ? status : EFI_NOT_READY; }
static void CDK2_MS_ABI async_notify(void *event, void *opaque)
{ struct async_call *call = opaque; struct cdk2_ata_controller_backend *backend =
		call->backend;
	UINTN tpl = active_entry->boot->raise_tpl(8U);
	backend->adapter.ticks += 10000U;
	(void)cdk2_ata_async_poll(&backend->async);
	active_entry->boot->restore_tpl(tpl);
	if (backend->async_call == call) {
		backend->async_call = NULL; backend->async_event = NULL;
	}
	(void)active_entry->boot->close_event(event);
	protocol_release(active_entry, call); }
static EFI_STATUS async_arm(void *opaque, struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_controller_backend *backend = controller->backend;
	struct async_call *call; EFI_STATUS status; (void)opaque;
	if (backend->sync_busy)
		return EFI_SUCCESS;
	status = protocol_allocate(active_entry, sizeof(*call), (void **)&call);
	if (EFI_ERROR(status))
		return status;
	*call = (struct async_call) { backend, NULL };
	status = active_entry->boot->create_event(0x80000200U, 8U, async_notify,
		call, &call->event);
	if (!EFI_ERROR(status)) {
		backend->async_call = call; backend->async_event = call->event;
		status = active_entry->boot->set_timer(call->event, 2U, 10000U);
	}
	if (EFI_ERROR(status)) {
		if (call->event != NULL)
			(void)active_entry->boot->close_event(call->event);
		protocol_release(active_entry, call);
	}
	return status;
}
static EFI_STATUS async_signal(void *opaque, void *event)
{ (void)opaque; return active_entry->boot->signal_event(event); }
static EFI_STATUS protocol_async_submit(void *opaque,
	struct cdk2_ata_controller *controller, UINT16 port, UINT16 multiplier,
	struct cdk2_ata_command_packet *packet, void *event)
{ struct cdk2_ata_async_controller *async =
		&((struct cdk2_ata_controller_backend *)controller->backend)->async;
	UINTN tpl = active_entry->boot->raise_tpl(8U); EFI_STATUS status; (void)opaque;
	status = cdk2_ata_async_submit(async, port, multiplier, packet, event);
	active_entry->boot->restore_tpl(tpl); return status; }
static EFI_STATUS protocol_async_cancel(void *opaque,
	struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_async_controller *async =
		&((struct cdk2_ata_controller_backend *)controller->backend)->async;
	EFI_STATUS status;

	(void)opaque;
	{
		UINTN tpl = active_entry->boot->raise_tpl(8U);
	status = cdk2_ata_async_stop(async);
		active_entry->boot->restore_tpl(tpl);
	}
	if (async->count == 0U)
		async->stopping = 0;
	return status;
}
static EFI_STATUS protocol_async_cancel_scope(void *opaque,
	struct cdk2_ata_controller *controller, UINT16 port, UINT16 multiplier,
	BOOLEAN match_multiplier)
{
	struct cdk2_ata_controller_backend *backend = controller->backend;
	EFI_STATUS status;
	UINTN tpl;

	(void)opaque;
	tpl = active_entry->boot->raise_tpl(8U);
	status = cdk2_ata_async_cancel(&backend->async, port, multiplier,
		match_multiplier);
	active_entry->boot->restore_tpl(tpl);
	return status;
}
static EFI_STATUS service_quiesce(void *opaque, struct cdk2_ata_controller *controller)
{ return protocol_async_cancel(opaque, controller); }
static void cancel_async_event(void *event, struct async_call *call)
{
	if (event == NULL)
		return;
	(void)active_entry->boot->set_timer(event, 0U, 0U);
	(void)active_entry->boot->close_event(event);
	protocol_release(active_entry, call);
}
static EFI_STATUS protocol_async_wait(void *opaque,
	struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_controller_backend *backend = controller->backend;
	struct cdk2_ata_async_controller *async = &backend->async;
	EFI_STATUS status;
	UINTN old_tpl;

	(void)opaque;
	old_tpl = active_entry->boot->raise_tpl(8U);
	if (async->count == 0U) {
		backend->sync_busy = 1;
		active_entry->boot->restore_tpl(old_tpl);
		return EFI_SUCCESS;
	}
	active_entry->boot->restore_tpl(old_tpl);
	if (old_tpl >= 8U || async->polling)
		return EFI_NOT_READY;
	old_tpl = active_entry->boot->raise_tpl(8U);
	backend->sync_busy = 1;
	active_entry->boot->restore_tpl(old_tpl);
	while (async->count != 0U) {
		void *event;
		struct async_call *call;

		old_tpl = active_entry->boot->raise_tpl(8U);
		event = backend->async_event; call = backend->async_call;
		backend->async_event = NULL; backend->async_call = NULL;
		active_entry->boot->restore_tpl(old_tpl);
		cancel_async_event(event, call);
		backend->adapter.ticks += 10000U;
		status = cdk2_ata_async_poll(async);
		if (EFI_ERROR(status) && status != EFI_NOT_READY)
			goto failed;
		if (async->count != 0U && EFI_ERROR(active_entry->boot->stall(1000U)))
			goto stall_failed;
	}
	return EFI_SUCCESS;
stall_failed:
	status = EFI_DEVICE_ERROR;
failed:
	old_tpl = active_entry->boot->raise_tpl(8U);
	backend->sync_busy = 0;
	active_entry->boot->restore_tpl(old_tpl);
	if (async->count != 0U && backend->async_event == NULL)
		(void)cdk2_ata_async_rearm(async);
	return status;
}
static void protocol_async_done(void *opaque,
	struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_controller_backend *backend = controller->backend;
	BOOLEAN rearm;
	UINTN old_tpl;

	(void)opaque;
	old_tpl = active_entry->boot->raise_tpl(8U);
	backend->sync_busy = 0;
	rearm = backend->async.count != 0U && backend->async_event == NULL;
	active_entry->boot->restore_tpl(old_tpl);
	if (rearm)
		(void)cdk2_ata_async_rearm(&backend->async);
}
static EFI_STATUS service_create_protocols(void *opaque,
	struct cdk2_ata_controller *controller,
	struct cdk2_ata_protocol_bundle **protocols)
{
	struct cdk2_ata_protocol_services services = {
		opaque, protocol_allocate, protocol_release, NULL, NULL, NULL, NULL, NULL };
	EFI_STATUS status;
	if (controller->backend != NULL &&
	    ((controller->topology.mode == CDK2_ATA_AHCI && controller->ahci != NULL) ||
	     (controller->topology.mode == CDK2_ATA_IDE && controller->ide_engine != NULL)) &&
	    active_entry->boot->create_event != NULL &&
	    active_entry->boot->set_timer != NULL && active_entry->boot->signal_event != NULL &&
	    active_entry->boot->close_event != NULL) {
		struct cdk2_ata_controller_backend *backend = controller->backend;
		struct cdk2_ata_async_services async_services = { opaque, async_begin,
			async_poll_task, async_abort_task, async_arm, async_signal };

		status = cdk2_ata_async_init(&backend->async, controller, &async_services);
		if (EFI_ERROR(status))
			return status;
		services.submit = protocol_async_submit; services.cancel = protocol_async_cancel;
		services.cancel_scope = protocol_async_cancel_scope;
		services.wait = protocol_async_wait;
		services.done = protocol_async_done;
	}

	status = protocol_allocate(opaque, sizeof(**protocols), (void **)protocols);
	if (EFI_ERROR(status))
		return status;
	memset(*protocols, 0, sizeof(**protocols));
	status = cdk2_ata_protocol_init(&(*protocols)->ata, controller, &services,
		sizeof(UINTN));
	if (!EFI_ERROR(status))
		status = cdk2_ext_scsi_init(&(*protocols)->ext_scsi, controller,
			&services, sizeof(UINTN));
	if (EFI_ERROR(status)) {
		protocol_release(opaque, *protocols);
		*protocols = NULL;
	}
	return status;
}
static void service_destroy_protocols(void *opaque,
	struct cdk2_ata_protocol_bundle *protocols)
{
	struct cdk2_ata_controller *controller = protocols->ata.controller;
	if (controller != NULL && controller->backend != NULL) {
		struct cdk2_ata_controller_backend *backend = controller->backend;

		UINTN tpl = active_entry->boot->raise_tpl(8U);
		(void)cdk2_ata_async_stop(&backend->async);
		active_entry->boot->restore_tpl(tpl);
		if (backend->async_event != NULL) {
			(void)active_entry->boot->set_timer(backend->async_event, 0U, 0U);
			(void)active_entry->boot->close_event(backend->async_event);
			protocol_release(active_entry, backend->async_call);
			backend->async_event = NULL; backend->async_call = NULL;
		}
	}
	protocol_release(opaque, protocols);
}
static void service_relocate(void *opaque, struct cdk2_ata_controller *controller)
{
	struct cdk2_ata_controller_backend *backend = controller->backend;

	(void)opaque;
	if (backend != NULL)
		backend->async.controller = controller;
}
static EFI_STATUS service_install(void *opaque, void *controller,
	struct cdk2_ata_protocol_bundle *protocols)
{
	(void)opaque;
	return active_entry->boot->install_multiple(&controller,
		&ata_pass_thru_guid, &protocols->ata.protocol,
		&ext_scsi_guid, &protocols->ext_scsi.protocol, NULL);
}
static EFI_STATUS service_uninstall(void *opaque, void *controller,
	struct cdk2_ata_protocol_bundle *protocols)
{
	(void)opaque;
	return active_entry->boot->uninstall_multiple(controller,
		&ata_pass_thru_guid, &protocols->ata.protocol,
		&ext_scsi_guid, &protocols->ext_scsi.protocol, NULL);
}

static struct cdk2_ata_entry *from_driver(struct cdk2_ata_driver_binding *driver)
{ return (struct cdk2_ata_entry *)((UINT8 *)driver - offsetof(struct cdk2_ata_entry, driver)); }
static EFI_STATUS CDK2_MS_ABI supported(struct cdk2_ata_driver_binding *driver,
	void *controller, void *remaining)
{ (void)remaining; return cdk2_ata_binding_supported(from_driver(driver)->binding,
	controller); }
static EFI_STATUS CDK2_MS_ABI start(struct cdk2_ata_driver_binding *driver,
	void *controller, void *remaining)
{ (void)remaining; return cdk2_ata_binding_start(from_driver(driver)->binding, controller); }
static EFI_STATUS CDK2_MS_ABI stop(struct cdk2_ata_driver_binding *driver,
	void *controller, UINTN children, void **child_buffer)
{
	if (children != 0U || child_buffer != NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_ata_binding_stop(from_driver(driver)->binding, controller);
}
static int language_equal(const CHAR8 *left, const CHAR8 *right)
{
	if (left == NULL || right == NULL)
		return 0;
	while (*left != 0 && *left == *right) {
		left++;
		right++;
	}
	return *left == *right;
}
static EFI_STATUS CDK2_MS_ABI get_driver_name(struct cdk2_ata_component_name *protocol,
	CHAR8 *language, CHAR16 **name)
{
	if (protocol == NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (!language_equal(language, protocol->languages))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_ata_component_name *protocol, void *controller, void *child,
	CHAR8 *language, CHAR16 **name)
{
	struct cdk2_ata_entry *entry = (struct cdk2_ata_entry *)((UINT8 *)protocol -
		(protocol->languages[0] == 'e' && protocol->languages[1] == 'n' &&
		 protocol->languages[2] == 0 ? offsetof(struct cdk2_ata_entry, component2) :
		offsetof(struct cdk2_ata_entry, component)));
	if (controller == NULL || child != NULL || language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (!language_equal(language, protocol->languages) ||
	    entry->binding == NULL || entry->binding->count == 0U)
		return EFI_UNSUPPORTED;
	for (size_t index = 0; index < entry->binding->count; index++)
		if (entry->binding->controllers[index].handle == controller) {
			*name = controller_name;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

EFI_STATUS cdk2_ata_entry_publish(struct cdk2_ata_entry *entry,
	struct cdk2_ata_binding *binding, void *image, void *system_table)
{
	struct system_table_view *system = system_table; EFI_STATUS status;
	if (entry == NULL || binding == NULL || image == NULL || system == NULL ||
	    system->boot == NULL || active_entry != NULL)
		return EFI_INVALID_PARAMETER;
	memset(entry, 0, sizeof(*entry)); entry->binding = binding; entry->image = image;
	entry->boot = system->boot;
	status = entry->boot->handle_protocol(image, &loaded_image_guid,
		(void **)&entry->loaded);
	if (EFI_ERROR(status) || entry->loaded == NULL)
		return EFI_ERROR(status) ? status : EFI_NOT_FOUND;
	entry->driver = (struct cdk2_ata_driver_binding) { supported, start, stop,
		0x10U, image, NULL };
	entry->component = (struct cdk2_ata_component_name) {
		get_driver_name, get_controller_name, "eng" };
	entry->component2 = (struct cdk2_ata_component_name) {
		get_driver_name, get_controller_name, "en" };
	status = entry->boot->install_multiple(&entry->driver_handle,
		&driver_binding_guid, &entry->driver, &component_name_guid, &entry->component,
		&component_name2_guid, &entry->component2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->driver.handle = entry->driver_handle;
	entry->original_unload = entry->loaded->unload;
	entry->loaded->unload = cdk2_ata_entry_unload;
	entry->published = 1; active_entry = entry;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_ata_entry_publish_with_services(struct cdk2_ata_entry *entry,
	struct cdk2_ata_binding *binding,
	const struct cdk2_ata_binding_services *hardware_services,
	void *image, void *system_table)
{
	struct cdk2_ata_binding_services services;
	EFI_STATUS status;

	if (binding == NULL || hardware_services == NULL)
		return EFI_INVALID_PARAMETER;
	services = *hardware_services;
	services.open_path = service_open_path;
	services.close_path = service_close_path;
	services.open_ide = service_open_ide;
	services.close_ide = service_close_ide;
	services.get_pci = service_get_pci;
	services.create_protocols = service_create_protocols;
	services.destroy_protocols = service_destroy_protocols;
	services.install = service_install;
	services.uninstall = service_uninstall;
	services.quiesce = service_quiesce;
	services.relocate = service_relocate;
	status = cdk2_ata_binding_init(binding, &services);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_ata_entry_publish(entry, binding, image, system_table);
	if (EFI_ERROR(status))
		memset(binding, 0, sizeof(*binding));
	return status;
}

EFI_STATUS CDK2_MS_ABI cdk2_ata_entry_unload(void *image)
{
	struct cdk2_ata_entry *entry = active_entry; EFI_STATUS status;
	if (entry == NULL || image != entry->image || !entry->published)
		return EFI_INVALID_PARAMETER;
	while (entry->binding->count != 0U) {
		void *controller = entry->binding->controllers[entry->binding->count - 1U].handle;
		status = cdk2_ata_binding_stop(entry->binding, controller);
		if (EFI_ERROR(status))
			return status;
	}
	status = entry->boot->uninstall_multiple(entry->driver_handle,
		&driver_binding_guid, &entry->driver, &component_name_guid, &entry->component,
		&component_name2_guid, &entry->component2, NULL);
	if (EFI_ERROR(status))
		return status;
	entry->loaded->unload = entry->original_unload;
	entry->published = 0; active_entry = NULL;
	return EFI_SUCCESS;
}

EFI_STATUS CDK2_MS_ABI cdk2_ata_atapi_pass_thru_entry(void *image,
	void *system_table)
{
	struct cdk2_ata_binding_services services = {
		.context = &image_entry, .read_class = hardware_read_class,
		.get_attributes = hardware_get_attributes,
		.enable_attributes = hardware_enable_attributes,
		.restore_attributes = hardware_restore_attributes,
		.discover_ide = hardware_discover_ide,
		.discover_ahci = hardware_discover_ahci,
		.prepare_engines = hardware_prepare,
		.release_engines = hardware_release
	};

	return cdk2_ata_entry_publish_with_services(&image_entry, &image_binding,
		&services, image, system_table);
}
typedef char raise_offset_check[offsetof(struct cdk2_ata_boot_services,
	raise_tpl) == 24 ? 1 : -1];
typedef char restore_offset_check[offsetof(struct cdk2_ata_boot_services,
	restore_tpl) == 32 ? 1 : -1];
