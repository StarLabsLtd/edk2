/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/ps2_mouse.h>

#include <limits.h>
#include <string.h>

#define KBC_DATA 0x60U
#define KBC_STATUS 0x64U
#define KBC_INPUT_FULL 2U
#define KBC_OUTPUT_FULL 1U
#define KBC_AUX_DATA 0x20U
#define KBC_WRITE_AUX 0xd4U
#define MOUSE_ACK 0xfaU
#define MOUSE_RESEND 0xfeU
#define PS2_DEVICE_ERROR ((1ULL << 63) | 7ULL)
#define PS2_TIMEOUT ((1ULL << 63) | 18ULL)

static int32_t saturating_add(int32_t left, int32_t right)
{
	if (right > 0 && left > INT32_MAX - right)
		return INT32_MAX;
	if (right < 0 && left < INT32_MIN - right)
		return INT32_MIN;
	return left + right;
}

void cdk2_ps2_mouse_init(struct cdk2_ps2_mouse *mouse, uint8_t wheel)
{
	memset(mouse, 0, sizeof(*mouse));
	mouse->packet_size = wheel ? 4 : 3;
	mouse->mode.resolution_x = mouse->mode.resolution_y = 4;
	mouse->mode.resolution_z = wheel ? 1 : 0;
	mouse->mode.left_button = mouse->mode.right_button = 1;
}

static void packet(struct cdk2_ps2_mouse *mouse)
{
	uint8_t flags = mouse->packet[0];
	int32_t x = (flags & 0x10) ? (int32_t)mouse->packet[1] - 256
				   : mouse->packet[1];
	int32_t y = (flags & 0x20) ? (int32_t)mouse->packet[2] - 256
				   : mouse->packet[2];
	int32_t z = 0;
	uint8_t left = (flags & 1) != 0, right = (flags & 2) != 0;

	if ((flags & 0x40) != 0)
		x = x < 0 ? -255 : 255;
	if ((flags & 0x80) != 0)
		y = y < 0 ? -255 : 255;
	if (mouse->packet_size == 4) {
		z = mouse->packet[3] & 0x0f;
		if ((z & 8) != 0)
			z -= 16;
	}
	mouse->state.relative_x = saturating_add(mouse->state.relative_x, x);
	mouse->state.relative_y = saturating_add(mouse->state.relative_y, -y);
	mouse->state.relative_z = saturating_add(mouse->state.relative_z, z);
	if (x != 0 || y != 0 || z != 0 || left != mouse->state.left_button ||
	    right != mouse->state.right_button)
		mouse->changed = 1;
	mouse->state.left_button = left;
	mouse->state.right_button = right;
}

uint64_t cdk2_ps2_mouse_feed(struct cdk2_ps2_mouse *mouse, const uint8_t *bytes,
			     size_t length)
{
	size_t index;
	if (mouse == NULL || (bytes == NULL && length != 0) ||
	    (mouse->packet_size != 3 && mouse->packet_size != 4))
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < length; index++) {
		uint8_t value = bytes[index];
		if (mouse->packet_index == 0 && (value & 8) == 0)
			continue;
		mouse->packet[mouse->packet_index++] = value;
		if (mouse->packet_index == mouse->packet_size) {
			packet(mouse);
			mouse->packet_index = 0;
		}
	}
	return EFI_SUCCESS;
}

uint64_t cdk2_ps2_mouse_get_state(struct cdk2_ps2_mouse *mouse,
				  struct cdk2_pointer_state *state)
{
	if (mouse == NULL || state == NULL)
		return EFI_INVALID_PARAMETER;
	if (!mouse->changed)
		return EFI_NOT_READY;
	*state = mouse->state;
	mouse->state.relative_x = mouse->state.relative_y =
		mouse->state.relative_z = 0;
	mouse->changed = 0;
	return EFI_SUCCESS;
}

static uint64_t wait_status(struct cdk2_ps2_io *io, uint8_t mask, uint8_t value)
{
	size_t count;
	if (io == NULL || io->read8 == NULL || io->write8 == NULL ||
	    io->poll_limit == 0)
		return EFI_INVALID_PARAMETER;
	for (count = 0; count < io->poll_limit; count++) {
		if ((io->read8(io->context, KBC_STATUS) & mask) == value)
			return EFI_SUCCESS;
		if (io->stall != NULL)
			io->stall(io->context, 50);
	}
	return PS2_TIMEOUT;
}

static uint64_t command(struct cdk2_ps2_io *io, uint8_t value)
{
	uint64_t status = wait_status(io, KBC_INPUT_FULL, 0);
	if (status == EFI_SUCCESS)
		io->write8(io->context, KBC_STATUS, value);
	return status;
}

static uint64_t data_write(struct cdk2_ps2_io *io, uint8_t value)
{
	uint64_t status = wait_status(io, KBC_INPUT_FULL, 0);
	if (status == EFI_SUCCESS)
		io->write8(io->context, KBC_DATA, value);
	return status;
}

static uint64_t data_read(struct cdk2_ps2_io *io, uint8_t *value, uint8_t aux)
{
	uint64_t status =
		wait_status(io, KBC_OUTPUT_FULL | (aux ? KBC_AUX_DATA : 0),
			    KBC_OUTPUT_FULL | (aux ? KBC_AUX_DATA : 0));
	if (status == EFI_SUCCESS)
		*value = io->read8(io->context, KBC_DATA);
	return status;
}

static uint64_t mouse_command(struct cdk2_ps2_io *io, uint8_t value)
{
	unsigned int retry;
	for (retry = 0; retry < 3; retry++) {
		uint8_t response;
		uint64_t status = command(io, KBC_WRITE_AUX);
		if (status != EFI_SUCCESS ||
		    (status = data_write(io, value)) != EFI_SUCCESS ||
		    (status = data_read(io, &response, 1)) != EFI_SUCCESS)
			return status;
		if (response == MOUSE_ACK)
			return EFI_SUCCESS;
		if (response != MOUSE_RESEND)
			return PS2_DEVICE_ERROR;
	}
	return PS2_DEVICE_ERROR;
}

uint64_t cdk2_ps2_mouse_controller_disable(struct cdk2_ps2_io *io)
{
	return command(io, 0xa7);
}

uint64_t cdk2_ps2_mouse_controller_init(struct cdk2_ps2_io *io,
					struct cdk2_ps2_mouse *mouse)
{
	static const uint8_t setup[] = {0xf6, 0xf3, 20, 0xe8, 2, 0xe6, 0xf4};
	uint8_t response;
	size_t index;
	uint64_t status;
	if (mouse == NULL)
		return EFI_INVALID_PARAMETER;
	status = command(io, 0xaa);
	if (status != EFI_SUCCESS ||
	    (status = data_read(io, &response, 0)) != EFI_SUCCESS ||
	    response != 0x55)
		return status == EFI_SUCCESS ? PS2_DEVICE_ERROR : status;
	if ((status = command(io, 0xa8)) != EFI_SUCCESS ||
	    (status = mouse_command(io, 0xff)) != EFI_SUCCESS ||
	    (status = data_read(io, &response, 1)) != EFI_SUCCESS ||
	    response != 0xaa ||
	    (status = data_read(io, &response, 1)) != EFI_SUCCESS ||
	    response != 0x00)
		goto fail;
	for (index = 0; index < sizeof(setup); index++)
		if ((status = mouse_command(io, setup[index])) != EFI_SUCCESS)
			goto fail;
	cdk2_ps2_mouse_init(mouse, 0);
	return EFI_SUCCESS;
fail:
	(void)cdk2_ps2_mouse_controller_disable(io);
	return status == EFI_SUCCESS ? PS2_DEVICE_ERROR : status;
}

uint64_t cdk2_ps2_mouse_poll(struct cdk2_ps2_io *io,
			     struct cdk2_ps2_mouse *mouse)
{
	uint8_t data[16];
	size_t count = 0;
	if (io == NULL || mouse == NULL)
		return EFI_INVALID_PARAMETER;
	while (count < sizeof(data)) {
		uint8_t status = io->read8(io->context, KBC_STATUS);
		if ((status & KBC_OUTPUT_FULL) == 0)
			break;
		if ((status & KBC_AUX_DATA) == 0) {
			(void)io->read8(io->context, KBC_DATA);
			continue;
		}
		data[count++] = io->read8(io->context, KBC_DATA);
	}
	return cdk2_ps2_mouse_feed(mouse, data, count);
}
