/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_PS2_MOUSE_DRIVER_H_
#define CDK2_PS2_MOUSE_DRIVER_H_

#include <cdk2/ps2_mouse.h>

struct cdk2_simple_pointer;
typedef uint64_t CDK2_MS_ABI cdk2_pointer_reset_fn(struct cdk2_simple_pointer *,
						   uint8_t);
typedef uint64_t CDK2_MS_ABI cdk2_pointer_state_fn(struct cdk2_simple_pointer *,
						   struct cdk2_pointer_state *);
struct cdk2_simple_pointer {
	cdk2_pointer_reset_fn *reset;
	cdk2_pointer_state_fn *get_state;
	void *wait_for_input;
	struct cdk2_pointer_mode *mode;
};
typedef uint64_t CDK2_MS_ABI cdk2_mouse_open_fn(void *, const EFI_GUID *,
						void **, void *, void *,
						uint32_t);
typedef uint64_t CDK2_MS_ABI cdk2_mouse_close_fn(void *, const EFI_GUID *,
						 void *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_mouse_install_fn(void **, const EFI_GUID *,
						   void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_mouse_uninstall_fn(void *, const EFI_GUID *,
						     void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_mouse_event_fn(uint32_t, size_t, void *,
						 void *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_mouse_timer_fn(void *, uint32_t, uint64_t);
typedef uint64_t CDK2_MS_ABI cdk2_mouse_close_event_fn(void *);
struct cdk2_mouse_services {
	cdk2_mouse_open_fn *open;
	cdk2_mouse_close_fn *close;
	cdk2_mouse_install_fn *install;
	cdk2_mouse_uninstall_fn *uninstall;
	cdk2_mouse_event_fn *create_event;
	cdk2_mouse_timer_fn *set_timer;
	cdk2_mouse_close_event_fn *close_event;
};
struct cdk2_mouse_device {
	struct cdk2_ps2_mouse mouse;
	struct cdk2_simple_pointer pointer;
	struct cdk2_ps2_io io;
	struct cdk2_mouse_services *services;
	void *driver, *controller, *sio, *wait_event, *poll_event;
	uint8_t started;
};

int cdk2_ps2_mouse_hid_supported(uint32_t hid, uint32_t uid);
uint64_t cdk2_ps2_mouse_start(struct cdk2_mouse_device *device,
			      struct cdk2_mouse_services *services,
			      struct cdk2_ps2_io io, void *driver,
			      void *controller);
uint64_t cdk2_ps2_mouse_stop(struct cdk2_mouse_device *device);

#endif
