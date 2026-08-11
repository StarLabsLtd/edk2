/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/usb_mouse.h>

#define HID_LONG_TAG 0x0fU
#define HID_TYPE_GLOBAL 1U
#define HID_TYPE_LOCAL 2U
#define HID_USAGE_PAGE 0U
#define HID_USAGE_MINIMUM 1U
#define HID_USAGE_MAXIMUM 2U

const EFI_GUID cdk2_usb_io_guid = { 0x2b2f68d6, 0x0cd2, 0x44cf,
	{ 0x8e, 0x8b, 0xbb, 0xa2, 0x0b, 0x1b, 0x5b, 0x75 } };
const EFI_GUID cdk2_device_path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
const EFI_GUID cdk2_simple_pointer_guid = { 0x31878c87, 0x0b75, 0x11d5,
	{ 0x9a, 0x4f, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };

static void clear_bytes(void *buffer, UINTN size)
{
	UINT8 *bytes = buffer;

	while (size-- != 0U)
		*bytes++ = 0U;
}

static EFI_STATUS control(struct cdk2_usb_mouse *mouse, UINT8 request_type,
	UINT8 request, UINT16 value, UINT16 index, void *data, UINT16 length,
	UINT32 direction);

const UINT8 *cdk2_usb_mouse_next_item(const UINT8 *position, const UINT8 *end,
	struct cdk2_hid_item *item)
{
	UINT8 prefix;
	UINT8 encoded_size;

	if (position == NULL || end == NULL || item == NULL || position >= end)
		return NULL;
	prefix = *position++;
	item->type = (prefix >> 2) & 3U;
	item->tag = prefix >> 4;
	if (item->tag == HID_LONG_TAG) {
		item->format = 1U;
		if ((UINTN)(end - position) < 2U)
			return NULL;
		item->size = *position++;
		item->tag = *position++;
		if ((UINTN)(end - position) < item->size)
			return NULL;
		item->data.long_data = position;
		return position + item->size;
	}
	item->format = 0U;
	encoded_size = prefix & 3U;
	item->size = encoded_size == 3U ? 4U : encoded_size;
	if ((UINTN)(end - position) < item->size)
		return NULL;
	item->data.u32 = 0U;
	if (item->size >= 1U)
		item->data.u32 = position[0];
	if (item->size >= 2U)
		item->data.u32 |= (UINT32)position[1] << 8;
	if (item->size == 4U)
		item->data.u32 |= (UINT32)position[2] << 16 | (UINT32)position[3] << 24;
	return position + item->size;
}

EFI_STATUS cdk2_usb_mouse_parse_report(struct cdk2_usb_mouse *mouse,
	const UINT8 *report, UINTN size)
{
	const UINT8 *position = report;
	const UINT8 *next;
	struct cdk2_hid_item item;

	if (mouse == NULL || report == NULL || size == 0U)
		return EFI_INVALID_PARAMETER;
	mouse->button_page = FALSE;
	mouse->button_min = 0U;
	mouse->button_max = 0U;
	while (position < report + size) {
		next = cdk2_usb_mouse_next_item(position, report + size, &item);
		if (next == NULL)
			return EFI_COMPROMISED_DATA;
		if (item.format != 0U)
			return EFI_UNSUPPORTED;
		if (item.type == HID_TYPE_GLOBAL && item.tag == HID_USAGE_PAGE)
			mouse->button_page = item.data.u32 == 9U;
		else if (item.type == HID_TYPE_LOCAL && item.size != 0U &&
			 mouse->button_page && item.tag == HID_USAGE_MINIMUM)
			mouse->button_min = (UINT8)item.data.u32;
		else if (item.type == HID_TYPE_LOCAL && item.size != 0U &&
			 mouse->button_page && item.tag == HID_USAGE_MAXIMUM)
			mouse->button_max = (UINT8)item.data.u32;
		position = next;
	}
	if (!mouse->button_page || mouse->button_max < mouse->button_min)
		mouse->button_count = 0U;
	else
		mouse->button_count = mouse->button_max - mouse->button_min + 1U;
	mouse->mode.left_button = mouse->button_count >= 1U;
	mouse->mode.right_button = mouse->button_count > 1U;
	mouse->mode.resolution_x = 8U;
	mouse->mode.resolution_y = 8U;
	mouse->mode.resolution_z = 0U;
	return EFI_SUCCESS;
}

static struct cdk2_usb_mouse *from_pointer(struct cdk2_simple_pointer *pointer)
{
	return (void *)((UINT8 *)pointer - offsetof(struct cdk2_usb_mouse, pointer));
}

static EFI_STATUS CDK2_MS_ABI pointer_reset(struct cdk2_simple_pointer *pointer,
	BOOLEAN extended)
{
	struct cdk2_usb_mouse *mouse;

	(void)extended;
	if (pointer == NULL)
		return EFI_INVALID_PARAMETER;
	mouse = from_pointer(pointer);
	clear_bytes(&mouse->state, sizeof(mouse->state));
	mouse->state_changed = FALSE;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI pointer_get_state(struct cdk2_simple_pointer *pointer,
	struct cdk2_simple_pointer_state *state)
{
	struct cdk2_usb_mouse *mouse;

	if (pointer == NULL || state == NULL)
		return EFI_INVALID_PARAMETER;
	mouse = from_pointer(pointer);
	if (!mouse->state_changed)
		return EFI_NOT_READY;
	*state = mouse->state;
	mouse->state.relative_movement_x = 0;
	mouse->state.relative_movement_y = 0;
	mouse->state.relative_movement_z = 0;
	mouse->state_changed = FALSE;
	return EFI_SUCCESS;
}

static void CDK2_MS_ABI wait_notify(void *event, void *context)
{
	struct cdk2_usb_mouse *mouse = context;

	if (mouse->state_changed)
		(void)mouse->ops->signal_event(mouse->context, event);
}

static void CDK2_MS_ABI recovery_notify(void *event, void *context)
{
	struct cdk2_usb_mouse *mouse = context;

	(void)event;
	if (!EFI_ERROR(mouse->usb_io->async_interrupt_transfer(mouse->usb_io,
	    mouse->endpoint.endpoint_address, TRUE, mouse->endpoint.interval,
	    mouse->endpoint.maximum_packet_size, cdk2_usb_mouse_interrupt, mouse)))
		mouse->polling = TRUE;
}

EFI_STATUS CDK2_MS_ABI cdk2_usb_mouse_interrupt(void *data, UINTN length, void *context,
	UINT32 result)
{
	struct cdk2_usb_mouse *mouse = context;
	const INT8 *report = data;

	if (mouse == NULL)
		return EFI_INVALID_PARAMETER;
	if (result != 0U) {
		if ((result & CDK2_USB_ERR_STALL) != 0U &&
		    mouse->usb_io->control_transfer != NULL)
			(void)control(mouse, 0x02U, 1U, 0U,
				mouse->endpoint.endpoint_address, NULL, 0U, 2U);
		(void)mouse->usb_io->async_interrupt_transfer(mouse->usb_io,
			mouse->endpoint.endpoint_address, FALSE, 0, 0, NULL, NULL);
		mouse->polling = FALSE;
		if (mouse->recovery_event != NULL && mouse->ops->set_timer != NULL)
			(void)mouse->ops->set_timer(mouse->context, mouse->recovery_event,
				2U, 10000000ULL);
		return EFI_DEVICE_ERROR;
	}
	if (length == 0U || data == NULL)
		return EFI_SUCCESS;
	if (length < 3U)
		return EFI_DEVICE_ERROR;
	mouse->state.left_button = (((const UINT8 *)data)[0] & 1U) != 0U;
	mouse->state.right_button = (((const UINT8 *)data)[0] & 2U) != 0U;
	mouse->state.relative_movement_x += report[1];
	mouse->state.relative_movement_y += report[2];
	if (length > 3U)
		mouse->state.relative_movement_z += report[3];
	mouse->state_changed = TRUE;
	return EFI_SUCCESS;
}

BOOLEAN cdk2_is_usb_mouse(struct cdk2_usb_io *usb_io)
{
	struct cdk2_usb_interface_descriptor descriptor;

	if (usb_io == NULL || usb_io->get_interface_descriptor == NULL ||
	    EFI_ERROR(usb_io->get_interface_descriptor(usb_io, &descriptor)))
		return FALSE;
	return descriptor.interface_class == CDK2_USB_CLASS_HID &&
		descriptor.interface_subclass == CDK2_USB_SUBCLASS_BOOT &&
		descriptor.interface_protocol == CDK2_USB_PROTOCOL_MOUSE;
}

static EFI_STATUS control(struct cdk2_usb_mouse *mouse, UINT8 request_type,
	UINT8 request, UINT16 value, UINT16 index, void *data, UINT16 length,
	UINT32 direction)
{
	struct cdk2_usb_request usb_request = { request_type, request, value, index, length };
	UINT32 result;

	return mouse->usb_io->control_transfer(mouse->usb_io, &usb_request, direction,
		3000U, data, length, &result);
}

static EFI_STATUS initialize_device(struct cdk2_usb_mouse *mouse)
{
	struct cdk2_usb_config_descriptor config;
	UINT8 *configuration = NULL;
	UINT8 *report = NULL;
	UINT16 offset = 0U;
	UINT16 report_length = 0U;
	UINT8 protocol = 0U;
	EFI_STATUS status;

	if (mouse->usb_io->control_transfer == NULL ||
	    mouse->usb_io->get_config_descriptor == NULL)
		return EFI_UNSUPPORTED;
	status = mouse->usb_io->get_config_descriptor(mouse->usb_io, &config);
	if (EFI_ERROR(status) || config.total_length < sizeof(config))
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	status = mouse->ops->allocate(mouse->context, config.total_length,
		(void **)&configuration);
	if (EFI_ERROR(status))
		return status;
	status = control(mouse, 0x80U, 6U,
		(UINT16)(0x0200U | (config.configuration_value - 1U)), 0U,
		configuration, config.total_length, 0U);
	if (EFI_ERROR(status))
		goto done;
	while (offset + 2U <= config.total_length) {
		UINT8 length = configuration[offset];
		UINT8 type = configuration[offset + 1U];

		if (length < 2U || length > config.total_length - offset) {
			status = EFI_COMPROMISED_DATA;
			goto done;
		}
		if (type == 0x21U && length >= 9U && configuration[offset + 6U] == 0x22U) {
			report_length = (UINT16)(configuration[offset + 7U] |
				((UINT16)configuration[offset + 8U] << 8));
			break;
		}
		offset += length;
	}
	if (report_length == 0U) {
		status = EFI_UNSUPPORTED;
		goto done;
	}
	status = mouse->ops->allocate(mouse->context, report_length, (void **)&report);
	if (EFI_ERROR(status))
		goto done;
	status = control(mouse, 0x81U, 6U, 0x2200U, mouse->interface.interface_number,
		report, report_length, 0U);
	if (!EFI_ERROR(status))
		status = cdk2_usb_mouse_parse_report(mouse, report, report_length);
	if (EFI_ERROR(status))
		goto done;
	status = control(mouse, 0xa1U, 3U, 0U, mouse->interface.interface_number,
		&protocol, 1U, 0U);
	if (!EFI_ERROR(status) && protocol != 0U)
		status = control(mouse, 0x21U, 11U, 0U, mouse->interface.interface_number,
			NULL, 0U, 2U);
done:
	if (report != NULL)
		mouse->ops->free(mouse->context, report);
	mouse->ops->free(mouse->context, configuration);
	return status;
}

static EFI_STATUS rollback(struct cdk2_usb_mouse *mouse)
{
	EFI_STATUS status;

	if (mouse->polling) {
		(void)mouse->usb_io->async_interrupt_transfer(mouse->usb_io,
			mouse->endpoint.endpoint_address, FALSE, 0, 0, NULL, NULL);
		mouse->polling = FALSE;
	}
	if (mouse->pointer_installed) {
		status = mouse->ops->uninstall(mouse->context, mouse->controller,
			&cdk2_simple_pointer_guid, &mouse->pointer);
		if (EFI_ERROR(status)) {
			if (!EFI_ERROR(mouse->usb_io->async_interrupt_transfer(mouse->usb_io,
			    mouse->endpoint.endpoint_address, TRUE, mouse->endpoint.interval,
			    mouse->endpoint.maximum_packet_size, cdk2_usb_mouse_interrupt,
			    mouse)))
				mouse->polling = TRUE;
			return status;
		}
		mouse->pointer_installed = FALSE;
	}
	if (mouse->pointer.wait_for_input != NULL) {
		(void)mouse->ops->close_event(mouse->context, mouse->pointer.wait_for_input);
		mouse->pointer.wait_for_input = NULL;
	}
	if (mouse->recovery_event != NULL) {
		(void)mouse->ops->close_event(mouse->context, mouse->recovery_event);
		mouse->recovery_event = NULL;
	}
	if (mouse->usb_open) {
		status = mouse->ops->close(mouse->context, mouse->controller,
			&cdk2_usb_io_guid, mouse->image, mouse->controller);
		if (EFI_ERROR(status))
			return status;
		mouse->usb_open = FALSE;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_usb_mouse_start(struct cdk2_usb_mouse *mouse, void *controller)
{
	EFI_STATUS status;
	UINT8 index;

	if (mouse == NULL || mouse->ops == NULL || mouse->ops->open == NULL ||
	    mouse->ops->close == NULL || mouse->ops->install == NULL ||
	    mouse->ops->uninstall == NULL || mouse->ops->create_event == NULL ||
	    mouse->ops->close_event == NULL)
		return EFI_INVALID_PARAMETER;
	mouse->controller = controller;
	status = mouse->ops->open(mouse->context, controller, &cdk2_usb_io_guid,
		(void **)&mouse->usb_io, mouse->image, controller, CDK2_OPEN_BY_DRIVER);
	if (EFI_ERROR(status))
		return status;
	mouse->usb_open = TRUE;
	if (!cdk2_is_usb_mouse(mouse->usb_io)) {
		status = EFI_UNSUPPORTED;
		goto fail;
	}
	status = mouse->usb_io->get_interface_descriptor(mouse->usb_io, &mouse->interface);
	if (EFI_ERROR(status))
		goto fail;
	for (index = 0; index < mouse->interface.endpoint_count; index++) {
		status = mouse->usb_io->get_endpoint_descriptor(mouse->usb_io, index,
			&mouse->endpoint);
		if (!EFI_ERROR(status) &&
		    (mouse->endpoint.attributes & 3U) == CDK2_USB_INTERRUPT &&
		    (mouse->endpoint.endpoint_address & CDK2_USB_ENDPOINT_IN) != 0U)
			break;
	}
	if (index == mouse->interface.endpoint_count) {
		status = EFI_UNSUPPORTED;
		goto fail;
	}
	status = initialize_device(mouse);
	if (EFI_ERROR(status))
		goto fail;
	mouse->pointer.reset = pointer_reset;
	mouse->pointer.get_state = pointer_get_state;
	mouse->pointer.mode = &mouse->mode;
	status = mouse->ops->create_event(mouse->context, 0x00000100U, 16U,
		(void *)wait_notify, mouse, &mouse->pointer.wait_for_input);
	if (EFI_ERROR(status))
		goto fail;
	status = mouse->ops->create_event(mouse->context, 0x80000200U, 16U,
		(void *)recovery_notify, mouse, &mouse->recovery_event);
	if (EFI_ERROR(status))
		goto fail;
	status = mouse->ops->install(mouse->context, controller,
		&cdk2_simple_pointer_guid, &mouse->pointer);
	if (EFI_ERROR(status))
		goto fail;
	mouse->pointer_installed = TRUE;
	status = mouse->usb_io->async_interrupt_transfer(mouse->usb_io,
		mouse->endpoint.endpoint_address, TRUE, mouse->endpoint.interval,
		mouse->endpoint.maximum_packet_size, cdk2_usb_mouse_interrupt, mouse);
	if (EFI_ERROR(status))
		goto fail;
	mouse->polling = TRUE;
	return EFI_SUCCESS;
fail:
	(void)rollback(mouse);
	return status;
}

EFI_STATUS cdk2_usb_mouse_stop(struct cdk2_usb_mouse *mouse)
{
	if (mouse == NULL || !mouse->usb_open)
		return EFI_UNSUPPORTED;
	return rollback(mouse);
}
