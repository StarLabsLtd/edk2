/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/xhci.h>

#include <stddef.h>
#include <string.h>

#define USB_PORT_CONNECTION 0U
#define USB_PORT_ENABLE 1U
#define USB_PORT_RESET 4U
#define USB_PORT_POWER 8U
#define USB_PORT_CONNECT_CHANGE 16U
#define USB_PORT_ENABLE_CHANGE 17U
#define USB_PORT_RESET_CHANGE 20U

static struct cdk2_xhci_usb2 *owner(struct cdk2_usb2_hc_protocol *protocol)
{
	return (void *)((UINT8 *)protocol - offsetof(struct cdk2_xhci_usb2, protocol));
}

static EFI_STATUS CDK2_MS_ABI get_capability(struct cdk2_usb2_hc_protocol *this,
	UINT8 *maximum_speed, UINT8 *port_count, UINT8 *is_64bit)
{
	struct cdk2_xhci_usb2 *usb2;

	if (this == NULL || maximum_speed == NULL || port_count == NULL ||
	    is_64bit == NULL)
		return EFI_INVALID_PARAMETER;
	usb2 = owner(this);
	*maximum_speed = 3U;
	*port_count = usb2->controller->capability.maximum_ports;
	*is_64bit = 1U;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI reset(struct cdk2_usb2_hc_protocol *this,
	UINT16 attributes)
{
	(void)this;
	return attributes <= 1U ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static EFI_STATUS CDK2_MS_ABI get_state(struct cdk2_usb2_hc_protocol *this,
	UINTN * state)
{
	if (this == NULL || state == NULL)
		return EFI_INVALID_PARAMETER;
	*state = owner(this)->state;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI set_state(struct cdk2_usb2_hc_protocol *this,
	UINTN state)
{
	if (this == NULL || state > 2U)
		return EFI_INVALID_PARAMETER;
	owner(this)->state = state;
	return EFI_SUCCESS;
}

static EFI_STATUS ensure_device(struct cdk2_xhci_usb2 *usb2, UINT8 address,
	UINT8 speed, UINTN maximum_packet, struct cdk2_xhci_device **device)
{
	struct cdk2_xhci_device *candidate = &usb2->devices[address];

	if (!candidate->enabled) {
		if (usb2->current_port == 0U || maximum_packet > UINT16_MAX)
			return EFI_NOT_READY;
		if (EFI_ERROR(cdk2_xhci_device_enable(usb2->controller,
			usb2->current_port, speed + 1U, maximum_packet, candidate)))
			return EFI_DEVICE_ERROR;
	}
	*device = candidate;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI control_transfer(
	struct cdk2_usb2_hc_protocol *this, UINT8 address, UINT8 speed,
	UINTN maximum_packet, struct cdk2_usb_request *request, UINTN direction,
	void *data, UINTN * length, UINTN timeout, void *translator, UINT32 * result)
{
	struct cdk2_xhci_device *device;
	struct cdk2_xhci_usb2 *usb2;
	EFI_STATUS status;

	(void)timeout;
	(void)translator;
	if (this == NULL || request == NULL || length == NULL || result == NULL ||
	    direction > 2U)
		return EFI_INVALID_PARAMETER;
	usb2 = owner(this);
	status = ensure_device(usb2, address, speed, maximum_packet, &device);
	if (!EFI_ERROR(status) && request->request == 5U &&
	    (request->request_type & 0x7fU) == 0U && request->value < 256U) {
		UINT8 new_address = request->value;

		if (address != new_address) {
			usb2->devices[new_address] = *device;
			memset(device, 0, sizeof(*device));
		}
		*result = CDK2_USB_NOERROR;
		return EFI_SUCCESS;
	}
	if (!EFI_ERROR(status))
		status = cdk2_xhci_control_transfer(device, request, data, length,
			direction == 1U);
	*result = EFI_ERROR(status) ? CDK2_USB_ERR_SYSTEM : CDK2_USB_NOERROR;
	return status;
}

static EFI_STATUS CDK2_MS_ABI bulk_transfer(struct cdk2_usb2_hc_protocol *this,
	UINT8 address, UINT8 endpoint, UINT8 speed, UINTN maximum_packet,
	UINT8 buffers, void **data, UINTN * length, UINT8 *toggle, UINTN timeout,
	void *translator, UINT32 * result)
{
	struct cdk2_xhci_usb2 *usb2;
	struct cdk2_xhci_device *device;
	EFI_STATUS status;

	(void)speed;
	(void)timeout;
	(void)translator;
	if (this == NULL || buffers != 1U || data == NULL || data[0] == NULL ||
	    length == NULL || toggle == NULL || result == NULL || *toggle > 1U ||
	    maximum_packet > UINT16_MAX)
		return EFI_INVALID_PARAMETER;
	usb2 = owner(this);
	device = &usb2->devices[address];
	if (!device->enabled)
		return EFI_NOT_FOUND;
	status = cdk2_xhci_device_configure_endpoint(device, endpoint, 2U,
		maximum_packet);
	if (status == EFI_ALREADY_STARTED)
		status = EFI_SUCCESS;
	if (!EFI_ERROR(status))
		status = cdk2_xhci_bulk_transfer(device, endpoint, data[0], length);
	*result = EFI_ERROR(status) ? CDK2_USB_ERR_SYSTEM : CDK2_USB_NOERROR;
	return status;
}

static EFI_STATUS CDK2_MS_ABI unsupported(void)
{
	return EFI_UNSUPPORTED;
}

static EFI_STATUS CDK2_MS_ABI get_port(struct cdk2_usb2_hc_protocol *this,
	UINT8 port, struct cdk2_usb_port_status *status)
{
	struct cdk2_xhci_port_status native;
	EFI_STATUS result;

	if (this == NULL || status == NULL)
		return EFI_INVALID_PARAMETER;
	result = cdk2_xhci_controller_get_port(owner(this)->controller, port + 1U,
		&native);
	if (EFI_ERROR(result))
		return result;
	status->status = (native.connected ? 1U : 0U) |
		(native.enabled ? 1U << 1 : 0U) | (native.powered ? 1U << 8 : 0U);
	if (native.speed == 2U)
		status->status |= 1U << 9;
	else if (native.speed == 3U)
		status->status |= 1U << 10;
	else if (native.speed >= 4U)
		status->status |= 1U << 11;
	status->change = (native.changes & 1U) | (native.changes & 2U) << 1 |
		(native.changes & 0x10U) << 1;
	return EFI_SUCCESS;
}

static EFI_STATUS port_feature(struct cdk2_usb2_hc_protocol *this, UINT8 port,
	UINTN feature, BOOLEAN set)
{
	struct cdk2_xhci_usb2 *usb2;
	enum cdk2_xhci_port_feature native;
	EFI_STATUS status;

	if (this == NULL)
		return EFI_INVALID_PARAMETER;
	usb2 = owner(this);
	switch (feature) {
	case USB_PORT_ENABLE:
		native = CDK2_XHCI_PORT_ENABLE;
		break;
	case USB_PORT_RESET:
		native = CDK2_XHCI_PORT_RESET;
		break;
	case USB_PORT_POWER:
		native = CDK2_XHCI_PORT_POWER;
		break;
	case USB_PORT_CONNECT_CHANGE:
		native = CDK2_XHCI_PORT_CONNECT_CHANGE;
		break;
	case USB_PORT_ENABLE_CHANGE:
		native = CDK2_XHCI_PORT_ENABLE_CHANGE;
		break;
	case USB_PORT_RESET_CHANGE:
		native = CDK2_XHCI_PORT_RESET_CHANGE;
		break;
	case USB_PORT_CONNECTION:
		return EFI_UNSUPPORTED;
	default:
		return EFI_INVALID_PARAMETER;
	}
	status = cdk2_xhci_controller_set_port(usb2->controller, port + 1U, native,
		set);
	if (!EFI_ERROR(status) && feature == USB_PORT_RESET && set) {
		struct cdk2_xhci_port_status port_status;

		status = cdk2_xhci_controller_get_port(usb2->controller, port + 1U,
			&port_status);
		if (!EFI_ERROR(status)) {
			usb2->current_port = port + 1U;
			usb2->current_speed = port_status.speed;
		}
	}
	return status;
}

static EFI_STATUS CDK2_MS_ABI set_port(struct cdk2_usb2_hc_protocol *this,
	UINT8 port, UINTN feature)
{
	return port_feature(this, port, feature, TRUE);
}

static EFI_STATUS CDK2_MS_ABI clear_port(struct cdk2_usb2_hc_protocol *this,
	UINT8 port, UINTN feature)
{
	return port_feature(this, port, feature, FALSE);
}

EFI_STATUS cdk2_xhci_usb2_init(struct cdk2_xhci_usb2 *usb2,
	struct cdk2_xhci_controller *controller)
{
	if (usb2 == NULL || controller == NULL || !controller->running)
		return EFI_INVALID_PARAMETER;
	memset(usb2, 0, sizeof(*usb2));
	usb2->controller = controller;
	usb2->state = 1U;
	usb2->protocol = (struct cdk2_usb2_hc_protocol) {
		get_capability, reset, get_state, set_state, control_transfer,
		bulk_transfer, unsupported, unsupported, unsupported, unsupported,
		get_port, set_port, clear_port, 3U, 0U };
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_xhci_usb2_release(struct cdk2_xhci_usb2 *usb2)
{
	EFI_STATUS first = EFI_SUCCESS;

	if (usb2 == NULL || usb2->controller == NULL)
		return EFI_INVALID_PARAMETER;
	for (UINTN address = 0U; address < 256U; address++)
		if (usb2->devices[address].enabled) {
			EFI_STATUS status = cdk2_xhci_device_disable(&usb2->devices[address]);

			if (EFI_ERROR(status) && !EFI_ERROR(first))
				first = status;
		}
	if (!EFI_ERROR(first))
		memset(usb2, 0, sizeof(*usb2));
	return first;
}
