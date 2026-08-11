/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ps2_mouse.h>

#include <stdio.h>

struct script {
	uint8_t data[32], aux[32];
	size_t count, index, writes;
};
static uint8_t CDK2_MS_ABI read8(void *context, uint16_t port)
{
	struct script *script = context;
	if (port == 0x64)
		return script->index < script->count
			       ? 1 | (script->aux[script->index] ? 0x20 : 0)
			       : 0;
	return script->data[script->index++];
}
static void CDK2_MS_ABI write8(void *context, uint16_t port, uint8_t value)
{
	struct script *script = context;
	(void)port;
	(void)value;
	script->writes++;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "ps2 mouse test: %s\n", message);
	return condition ? 0 : 1;
}

int main(void)
{
	struct cdk2_ps2_mouse mouse;
	struct cdk2_pointer_state state;
	struct script script = {{0x55, 0xfa, 0xaa, 0x00, 0xfa, 0xfa, 0xfa, 0xfa,
				 0xfa, 0xfa, 0xfa},
				{0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
				11,
				0,
				0};
	struct cdk2_ps2_io io = {&script, read8, write8, NULL, 8};
	static const uint8_t packets[] = {0, 1,	   2,	 0x09, 5,
					  3, 0x38, 0xfe, 0xfd};
	static const uint8_t wheel[] = {0x08, 0, 0, 0x0f};
	int failures = 0;

	cdk2_ps2_mouse_init(&mouse, 0);
	failures +=
		expect(mouse.mode.resolution_x == 4 && mouse.packet_size == 3,
		       "standard mode initialized");
	failures += expect(cdk2_ps2_mouse_feed(&mouse, packets,
					       sizeof(packets)) == EFI_SUCCESS,
			   "noise resynchronized and packets decoded");
	failures += expect(
		cdk2_ps2_mouse_get_state(&mouse, &state) == EFI_SUCCESS &&
			state.relative_x == 3 && state.relative_y == 0 &&
			state.left_button == 0,
		"signed motion accumulated and button transition retained");
	failures += expect(cdk2_ps2_mouse_get_state(&mouse, &state) ==
				   EFI_NOT_READY,
			   "consumed state reports not-ready");
	cdk2_ps2_mouse_init(&mouse, 1);
	failures += expect(cdk2_ps2_mouse_feed(&mouse, wheel, sizeof(wheel)) ==
					   EFI_SUCCESS &&
				   cdk2_ps2_mouse_get_state(&mouse, &state) ==
					   EFI_SUCCESS &&
				   state.relative_z == -1,
			   "IntelliMouse wheel nibble sign-extended");
	failures += expect(
		cdk2_ps2_mouse_controller_init(&io, &mouse) == EFI_SUCCESS &&
			script.index == script.count && script.writes != 0,
		"8042 self-test, reset, defaults, sample, resolution, scaling "
		"and enable");
	script = (struct script){{0}, {0}, 0, 0, 0};
	failures += expect(cdk2_ps2_mouse_controller_init(&io, &mouse) !=
				   EFI_SUCCESS,
			   "bounded controller timeout reported");
	return failures == 0 ? 0 : 1;
}
