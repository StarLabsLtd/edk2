/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/scsi_bus_binding.h>

#define EFI_ALREADY_STARTED EFIERR(20)
#define EFI_NOT_STARTED EFIERR(19)

const EFI_GUID cdk2_ext_scsi_pass_thru_guid = { 0x143b7632, 0xb81b, 0x4cb7,
	{ 0xab, 0xd3, 0xb6, 0x25, 0xa5, 0xb9, 0xbf, 0xfe } };
const EFI_GUID cdk2_scsi_io_guid = { 0x932f47e6, 0x2362, 0x4002,
	{ 0x80, 0x3e, 0x3c, 0xd5, 0x4b, 0x13, 0x8f, 0x85 } };
const EFI_GUID cdk2_device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static CHAR16 driver_name[] = L"CDK2 SCSI Bus Driver";

static UINT16 node_length(const struct cdk2_device_path *node)
{
	return (UINT16)(node->length[0] | ((UINT16)node->length[1] << 8));
}

static BOOLEAN is_end(const struct cdk2_device_path *path)
{
	return path != NULL && path->type == 0x7fU && path->subtype == 0xffU;
}

static UINTN path_size(const struct cdk2_device_path *path)
{
	UINTN size = 0;
	UINT16 length;

	if (path == NULL)
		return 0;
	for (;;) {
		length = node_length(path);
		if (length < sizeof(*path))
			return 0;
		size += length;
		if (is_end(path))
			return size;
		path = (const void *)((const UINT8 *)path + length);
	}
}

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *to = destination;
	const UINT8 *from = source;

	while (size-- != 0U)
		*to++ = *from++;
}

static struct cdk2_scsi_child *from_io(struct cdk2_scsi_io *io)
{
	return (void *)((UINT8 *)io - offsetof(struct cdk2_scsi_child, io));
}

static EFI_STATUS CDK2_MS_ABI execute(struct cdk2_scsi_io *io,
	struct cdk2_scsi_request *packet, void *event);

static EFI_STATUS discover_device(struct cdk2_scsi_child *child)
{
	UINT8 cdb[6] = { 0x12, 0, 0, 0, 36, 0 };
	UINT8 *inquiry;
	UINT8 *sense;
	void *allocation;
	UINTN alignment = child->io.io_align;
	UINTN address;
	struct cdk2_scsi_request packet;
	EFI_STATUS status = EFI_NOT_FOUND;
	UINTN attempt;

	if (alignment == 0U)
		alignment = 1U;
	if ((alignment & (alignment - 1U)) != 0U || alignment > 0x10000U)
		return EFI_INVALID_PARAMETER;
	status = child->owner->ops->allocate(child->owner->context,
		36U + 18U + 2U * (alignment - 1U), &allocation);
	if (EFI_ERROR(status))
		return status;
	address = ((UINTN)allocation + alignment - 1U) & ~(alignment - 1U);
	inquiry = (UINT8 *)address;
	address = ((UINTN)(inquiry + 36U) + alignment - 1U) & ~(alignment - 1U);
	sense = (UINT8 *)address;
	for (attempt = 0; attempt < 2U; attempt++) {
		for (UINTN index = 0; index < 36U; index++)
			inquiry[index] = 0;
		for (UINTN index = 0; index < 18U; index++)
			sense[index] = 0;
		packet = (struct cdk2_scsi_request) {
			.timeout = 30000000ULL,
			.in_data = inquiry,
			.sense_data = sense,
			.cdb = cdb,
			.in_length = 36,
			.cdb_length = 6,
			.data_direction = 0,
			.sense_length = 18,
		};
		status = execute(&child->io, &packet, NULL);
		if (!EFI_ERROR(status))
			break;
		if (status == EFI_BAD_BUFFER_SIZE || status == EFI_INVALID_PARAMETER ||
		    status == EFI_UNSUPPORTED) {
			status = EFI_NOT_FOUND;
			break;
		}
	}
	if (!EFI_ERROR(status) && packet.host_status == 0U &&
	    packet.target_status == 2U && (sense[0] & 0x7fU) == 0x70U &&
	    (sense[2] & 0x0fU) == 5U)
		status = EFI_NOT_FOUND;
	if (!EFI_ERROR(status) && ((inquiry[0] >> 5) != 0U ||
	    ((inquiry[0] & 0x1fU) >= 0x12U && (inquiry[0] & 0x1fU) <= 0x1eU)))
		status = EFI_NOT_FOUND;
	if (!EFI_ERROR(status))
		child->device_type = inquiry[0] & 0x1fU;
	child->owner->ops->free(child->owner->context, allocation);
	return status;
}

static EFI_STATUS CDK2_MS_ABI get_type(struct cdk2_scsi_io *io, UINT8 *type)
{
	if (io == NULL || type == NULL)
		return EFI_INVALID_PARAMETER;
	*type = from_io(io)->device_type;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_location(struct cdk2_scsi_io *io, UINT8 **target,
	UINT64 *lun)
{
	if (io == NULL || target == NULL || *target == NULL || lun == NULL)
		return EFI_INVALID_PARAMETER;
	copy_bytes(*target, from_io(io)->target.id, CDK2_SCSI_TARGET_MAX);
	*lun = from_io(io)->target.lun;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI reset_bus(struct cdk2_scsi_io *io)
{
	struct cdk2_scsi_child *child;

	if (io == NULL)
		return EFI_INVALID_PARAMETER;
	child = from_io(io);
	if (child->owner->pass_thru->reset_channel == NULL)
		return EFI_UNSUPPORTED;
	return child->owner->pass_thru->reset_channel(child->owner->pass_thru);
}

static EFI_STATUS CDK2_MS_ABI reset_device(struct cdk2_scsi_io *io)
{
	struct cdk2_scsi_child *child;

	if (io == NULL)
		return EFI_INVALID_PARAMETER;
	child = from_io(io);
	if (child->owner->pass_thru->reset_target_lun == NULL)
		return EFI_UNSUPPORTED;
	return child->owner->pass_thru->reset_target_lun(child->owner->pass_thru,
		child->target.id, child->target.lun);
}

static EFI_STATUS CDK2_MS_ABI execute(struct cdk2_scsi_io *io,
	struct cdk2_scsi_request *packet, void *event)
{
	struct cdk2_scsi_child *child;
	EFI_STATUS status;
	void *pass_event = event;

	if (io == NULL || packet == NULL)
		return EFI_INVALID_PARAMETER;
	child = from_io(io);
	if (child->owner->pass_thru->pass_thru == NULL)
		return EFI_UNSUPPORTED;
	if ((child->owner->pass_thru->mode->attributes & CDK2_EXT_SCSI_NONBLOCKIO) == 0U)
		pass_event = NULL;
	status = child->owner->pass_thru->pass_thru(child->owner->pass_thru,
		child->target.id, child->target.lun, packet, pass_event);
	if (!EFI_ERROR(status) && event != NULL && pass_event == NULL &&
	    child->owner->ops->signal != NULL)
		(void)child->owner->ops->signal(child->owner->context, event);
	return status;
}

static EFI_STATUS append_path(struct cdk2_scsi_binding *binding,
	struct cdk2_device_path *node, struct cdk2_device_path **result)
{
	UINTN parent_size = path_size(binding->parent_path);
	UINTN child_size = path_size(node);
	EFI_STATUS status;

	if (parent_size < sizeof(*node) || child_size < sizeof(*node))
		return EFI_DEVICE_ERROR;
	status = binding->ops->allocate(binding->context,
		parent_size + child_size - sizeof(*node), (void **)result);
	if (EFI_ERROR(status))
		return status;
	copy_bytes(*result, binding->parent_path, parent_size - sizeof(*node));
	copy_bytes((UINT8 *)*result + parent_size - sizeof(*node), node, child_size);
	return EFI_SUCCESS;
}

static struct cdk2_scsi_child *find_child(struct cdk2_scsi_binding *binding,
	void *handle, const struct cdk2_scsi_target *target)
{
	struct cdk2_scsi_child *child;

	for (child = binding->children; child != NULL; child = child->next)
		if ((handle != NULL && child->handle == handle) ||
		    (target != NULL && cdk2_scsi_target_equal(&child->target, target)))
			return child;
	return NULL;
}

static EFI_STATUS add_child(struct cdk2_scsi_binding *binding,
	const struct cdk2_scsi_target *target)
{
	struct cdk2_device_path *node = NULL;
	struct cdk2_device_path *remaining;
	struct cdk2_scsi_child *child = NULL;
	void *existing = NULL;
	EFI_STATUS status;

	if (find_child(binding, NULL, target) != NULL)
		return EFI_ALREADY_STARTED;
	status = binding->pass_thru->build_device_path(binding->pass_thru,
		(UINT8 *)target->id, target->lun, &node);
	if (EFI_ERROR(status))
		return status;
	status = binding->ops->allocate(binding->context, sizeof(*child), (void **)&child);
	if (EFI_ERROR(status))
		goto done;
	*child = (struct cdk2_scsi_child) { 0 };
	status = append_path(binding, node, &child->path);
	if (EFI_ERROR(status))
		goto done;
	remaining = child->path;
	if (binding->ops->locate_device_path != NULL &&
	    !EFI_ERROR(binding->ops->locate_device_path(binding->context,
	    &cdk2_device_path_guid, &remaining, &existing)) && existing != NULL &&
	    is_end(remaining)) {
		status = EFI_ALREADY_STARTED;
		goto done;
	}
	child->owner = binding;
	child->target = *target;
	child->device_type = 0xffU;
	child->io = (struct cdk2_scsi_io) { get_type, get_location, reset_bus,
		reset_device, execute, binding->pass_thru->mode->io_align };
	status = discover_device(child);
	if (EFI_ERROR(status))
		goto done;
	status = binding->ops->install(binding->context, &child->handle,
		&cdk2_device_path_guid, child->path, &cdk2_scsi_io_guid, &child->io);
	if (EFI_ERROR(status))
		goto done;
	child->installed = TRUE;
	status = binding->ops->open(binding->context, binding->controller,
		&cdk2_ext_scsi_pass_thru_guid, (void **)&binding->pass_thru, binding->image,
		child->handle, CDK2_OPEN_BY_CHILD_CONTROLLER);
	if (EFI_ERROR(status)) {
		(void)binding->ops->uninstall(binding->context, child->handle,
			&cdk2_device_path_guid, child->path, &cdk2_scsi_io_guid, &child->io);
		child->installed = FALSE;
		goto done;
	}
	child->by_child = TRUE;
	child->next = binding->children;
	binding->children = child;
	child = NULL;
	status = EFI_SUCCESS;
done:
	if (node != NULL)
		binding->ops->free(binding->context, node);
	if (child != NULL) {
		if (child->path != NULL)
			binding->ops->free(binding->context, child->path);
		binding->ops->free(binding->context, child);
	}
	return status;
}

static EFI_STATUS remove_child(struct cdk2_scsi_binding *binding, void *handle)
{
	struct cdk2_scsi_child **link = &binding->children;
	struct cdk2_scsi_child *child;
	EFI_STATUS status;

	while (*link != NULL && (*link)->handle != handle)
		link = &(*link)->next;
	if (*link == NULL)
		return EFI_NOT_FOUND;
	child = *link;
	if (child->by_child) {
		status = binding->ops->close(binding->context, binding->controller,
			&cdk2_ext_scsi_pass_thru_guid, binding->image, child->handle);
		if (EFI_ERROR(status))
			return status;
		child->by_child = FALSE;
	}
	status = binding->ops->uninstall(binding->context, child->handle,
		&cdk2_device_path_guid, child->path, &cdk2_scsi_io_guid, &child->io);
	if (EFI_ERROR(status)) {
		if (!EFI_ERROR(binding->ops->open(binding->context, binding->controller,
		    &cdk2_ext_scsi_pass_thru_guid, (void **)&binding->pass_thru,
		    binding->image, child->handle, CDK2_OPEN_BY_CHILD_CONTROLLER)))
			child->by_child = TRUE;
		return status;
	}
	*link = child->next;
	binding->ops->free(binding->context, child->path);
	binding->ops->free(binding->context, child);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_scsi_binding_supported(struct cdk2_scsi_binding *binding,
	void *controller, struct cdk2_device_path *remaining)
{
	struct cdk2_ext_scsi *pass;
	UINT8 target_storage[CDK2_SCSI_TARGET_MAX];
	UINT8 *target = target_storage;
	UINT64 lun;
	EFI_STATUS status;

	if (binding == NULL || binding->ops == NULL || binding->ops->open == NULL ||
	    binding->ops->close == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->ops->open(binding->context, controller,
		&cdk2_ext_scsi_pass_thru_guid, (void **)&pass, binding->image, controller,
		CDK2_OPEN_BY_DRIVER);
	if (status == EFI_ALREADY_STARTED)
		return EFI_SUCCESS;
	if (EFI_ERROR(status))
		return status;
	if (remaining != NULL && !is_end(remaining)) {
		if (pass->get_target_lun == NULL)
			status = EFI_UNSUPPORTED;
		else
			status = pass->get_target_lun(pass, remaining, &target, &lun);
	}
	(void)binding->ops->close(binding->context, controller,
		&cdk2_ext_scsi_pass_thru_guid, binding->image, controller);
	return status;
}

EFI_STATUS cdk2_scsi_binding_start(struct cdk2_scsi_binding *binding,
	void *controller, struct cdk2_device_path *remaining)
{
	struct cdk2_scsi_target target = { { 0 }, 0 };
	UINT8 *id = target.id;
	EFI_STATUS status;
	BOOLEAN opened_path = FALSE;
	BOOLEAN opened_pass = FALSE;

	if (binding == NULL || binding->ops == NULL || binding->ops->allocate == NULL ||
	    binding->ops->free == NULL || binding->ops->install == NULL ||
	    binding->ops->uninstall == NULL)
		return EFI_INVALID_PARAMETER;
	status = binding->ops->open(binding->context, controller, &cdk2_device_path_guid,
		(void **)&binding->parent_path, binding->image, controller, CDK2_OPEN_BY_DRIVER);
	if (EFI_ERROR(status) && status != EFI_ALREADY_STARTED)
		return status;
	if (status == EFI_SUCCESS)
		opened_path = TRUE;
	status = binding->ops->open(binding->context, controller,
		&cdk2_ext_scsi_pass_thru_guid, (void **)&binding->pass_thru, binding->image,
		controller, CDK2_OPEN_BY_DRIVER);
	if (EFI_ERROR(status) && status != EFI_ALREADY_STARTED)
		goto fail;
	if (status == EFI_SUCCESS)
		opened_pass = TRUE;
	if (binding->pass_thru == NULL || binding->pass_thru->mode == NULL ||
	    binding->pass_thru->build_device_path == NULL) {
		status = EFI_DEVICE_ERROR;
		goto fail;
	}
	binding->controller = controller;
	binding->path_open = binding->path_open || opened_path;
	binding->pass_open = binding->pass_open || opened_pass;
	if (remaining != NULL && is_end(remaining))
		return EFI_SUCCESS;
	if (remaining != NULL) {
		if (binding->pass_thru->get_target_lun == NULL)
			return EFI_UNSUPPORTED;
		status = binding->pass_thru->get_target_lun(binding->pass_thru, remaining,
			&id, &target.lun);
		if (EFI_ERROR(status))
			return status;
		copy_bytes(target.id, id, sizeof(target.id));
		return add_child(binding, &target);
	}
	if (binding->pass_thru->get_next_target_lun == NULL)
		return EFI_UNSUPPORTED;
	id = NULL;
	for (;;) {
		status = binding->pass_thru->get_next_target_lun(binding->pass_thru, &id,
			&target.lun);
		if (status == EFI_NOT_FOUND)
			return EFI_SUCCESS;
		if (EFI_ERROR(status) || id == NULL)
			return EFI_ERROR(status) ? status : EFI_DEVICE_ERROR;
		copy_bytes(target.id, id, sizeof(target.id));
		if (*(const UINT32 *)target.id == binding->pass_thru->mode->adapter_id)
			continue;
		status = add_child(binding, &target);
		if (status == EFI_OUT_OF_RESOURCES)
			return status;
	}
fail:
	if (opened_pass)
		(void)binding->ops->close(binding->context, controller,
			&cdk2_ext_scsi_pass_thru_guid, binding->image, controller);
	if (opened_path)
		(void)binding->ops->close(binding->context, controller,
			&cdk2_device_path_guid, binding->image, controller);
	return status;
}

EFI_STATUS cdk2_scsi_binding_stop(struct cdk2_scsi_binding *binding,
	void *controller, UINTN number_of_children, void **children)
{
	EFI_STATUS status;
	EFI_STATUS result = EFI_SUCCESS;
	UINTN index;

	if (binding == NULL || controller != binding->controller)
		return EFI_INVALID_PARAMETER;
	if (number_of_children != 0U) {
		if (children == NULL)
			return EFI_INVALID_PARAMETER;
		for (index = 0; index < number_of_children; index++) {
			status = remove_child(binding, children[index]);
			if (EFI_ERROR(status))
				result = EFI_DEVICE_ERROR;
		}
		return result;
	}
	if (binding->children != NULL)
		return EFI_DEVICE_ERROR;
	if (binding->pass_open) {
		status = binding->ops->close(binding->context, controller,
			&cdk2_ext_scsi_pass_thru_guid, binding->image, controller);
		if (EFI_ERROR(status))
			return status;
		binding->pass_open = FALSE;
	}
	if (binding->path_open) {
		status = binding->ops->close(binding->context, controller,
			&cdk2_device_path_guid, binding->image, controller);
		if (EFI_ERROR(status))
			return status;
		binding->path_open = FALSE;
	}
	binding->controller = NULL;
	return EFI_SUCCESS;
}

static struct cdk2_scsi_binding *from_driver(struct cdk2_scsi_driver_binding *driver)
{
	return (void *)((UINT8 *)driver - offsetof(struct cdk2_scsi_binding, driver));
}

static EFI_STATUS CDK2_MS_ABI driver_supported(struct cdk2_scsi_driver_binding *driver,
	void *controller, struct cdk2_device_path *remaining)
{
	return cdk2_scsi_binding_supported(from_driver(driver), controller, remaining);
}

static EFI_STATUS CDK2_MS_ABI driver_start(struct cdk2_scsi_driver_binding *driver,
	void *controller, struct cdk2_device_path *remaining)
{
	return cdk2_scsi_binding_start(from_driver(driver), controller, remaining);
}

static EFI_STATUS CDK2_MS_ABI driver_stop(struct cdk2_scsi_driver_binding *driver,
	void *controller, UINTN count, void **children)
{
	return cdk2_scsi_binding_stop(from_driver(driver), controller, count, children);
}

static EFI_STATUS names(CHAR8 *language, CHAR16 **name, BOOLEAN modern)
{
	if (language == NULL || name == NULL)
		return EFI_INVALID_PARAMETER;
	if (language[0] != 'e' || language[1] != 'n')
		return EFI_UNSUPPORTED;
	if ((modern && language[2] != '\0') ||
	    (!modern && (language[2] != 'g' || language[3] != '\0')))
		return EFI_UNSUPPORTED;
	*name = driver_name;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI get_name(struct cdk2_scsi_component_name *component,
	CHAR8 *language, CHAR16 **name)
{
	(void)component;
	return names(language, name, FALSE);
}

static EFI_STATUS CDK2_MS_ABI get_name2(struct cdk2_scsi_component_name *component,
	CHAR8 *language, CHAR16 **name)
{
	(void)component;
	return names(language, name, TRUE);
}

static EFI_STATUS CDK2_MS_ABI get_controller_name(
	struct cdk2_scsi_component_name *component, void *controller, void *child,
	CHAR8 *language, CHAR16 **name)
{
	(void)component;
	(void)controller;
	(void)child;
	(void)language;
	(void)name;
	return EFI_UNSUPPORTED;
}

void cdk2_scsi_binding_init(struct cdk2_scsi_binding *binding,
	const struct cdk2_scsi_binding_ops *ops, void *context, void *image)
{
	*binding = (struct cdk2_scsi_binding) {
		.ops = ops,
		.context = context,
		.image = image,
		.driver = { driver_supported, driver_start, driver_stop, 0x0aU,
			image, image },
		.component_name = { get_name, get_controller_name, "eng" },
		.component_name2 = { get_name2, get_controller_name, "en" },
	};
}
