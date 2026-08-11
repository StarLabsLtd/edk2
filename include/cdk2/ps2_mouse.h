/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PS2_MOUSE_H_
#define CDK2_PS2_MOUSE_H_

#include <stddef.h>
#include <stdint.h>
#include <uefi.h>

struct cdk2_pointer_state {
	int32_t relative_x, relative_y, relative_z;
	uint8_t left_button, right_button;
};
struct cdk2_pointer_mode {
	uint64_t resolution_x, resolution_y, resolution_z;
	uint8_t left_button, right_button;
};
struct cdk2_ps2_mouse {
	struct cdk2_pointer_state state;
	struct cdk2_pointer_mode mode;
	uint8_t packet[4], packet_size, packet_index, changed;
};

typedef uint8_t CDK2_MS_ABI cdk2_ps2_read8_fn(void *, uint16_t);
typedef void CDK2_MS_ABI cdk2_ps2_write8_fn(void *, uint16_t, uint8_t);
typedef void CDK2_MS_ABI cdk2_ps2_stall_fn(void *, size_t);
struct cdk2_ps2_io {
	void *context;
	cdk2_ps2_read8_fn *read8;
	cdk2_ps2_write8_fn *write8;
	cdk2_ps2_stall_fn *stall;
	size_t poll_limit;
};

void cdk2_ps2_mouse_init(struct cdk2_ps2_mouse *mouse, uint8_t wheel);
uint64_t cdk2_ps2_mouse_feed(struct cdk2_ps2_mouse *mouse, const uint8_t *bytes,
			     size_t length);
uint64_t cdk2_ps2_mouse_get_state(struct cdk2_ps2_mouse *mouse,
				  struct cdk2_pointer_state *state);
uint64_t cdk2_ps2_mouse_controller_init(struct cdk2_ps2_io *io,
					struct cdk2_ps2_mouse *mouse);
uint64_t cdk2_ps2_mouse_controller_disable(struct cdk2_ps2_io *io);
uint64_t cdk2_ps2_mouse_poll(struct cdk2_ps2_io *io,
			     struct cdk2_ps2_mouse *mouse);

#endif
