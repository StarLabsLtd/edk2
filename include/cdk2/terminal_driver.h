/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TERMINAL_DRIVER_H_
#define CDK2_TERMINAL_DRIVER_H_

#include <cdk2/terminal.h>

typedef uint64_t CDK2_MS_ABI cdk2_terminal_read_serial_fn(void *, size_t,
							  size_t *, void *);

struct cdk2_serial_io {
	uint32_t revision;
	void *reset, *set_attributes, *set_control, *get_control;
	cdk2_terminal_write_fn *write;
	cdk2_terminal_read_serial_fn *read;
};

struct cdk2_terminal_device_path {
	uint8_t type, subtype;
	uint16_t length;
	EFI_GUID terminal_type;
	uint8_t end_type, end_subtype;
	uint16_t end_length;
};

struct cdk2_simple_text_input;
struct cdk2_simple_text_input_ex;
struct cdk2_simple_text_output;
typedef uint64_t CDK2_MS_ABI cdk2_text_reset_fn(void *, uint8_t);
typedef uint64_t CDK2_MS_ABI cdk2_text_read_fn(void *,
					       struct cdk2_terminal_key *);
typedef uint64_t CDK2_MS_ABI cdk2_text_output_fn(void *, const uint16_t *);
typedef uint64_t CDK2_MS_ABI cdk2_text_state_fn(void *, uint8_t *);
typedef uint64_t CDK2_MS_ABI cdk2_text_register_fn(void *,
						   struct cdk2_terminal_key *,
						   void *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_text_unregister_fn(void *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_text_query_fn(void *, size_t, size_t *,
						size_t *);
typedef uint64_t CDK2_MS_ABI cdk2_text_mode_fn(void *, size_t);
typedef uint64_t CDK2_MS_ABI cdk2_text_clear_fn(void *);
typedef uint64_t CDK2_MS_ABI cdk2_text_cursor_fn(void *, size_t, size_t);
typedef uint64_t CDK2_MS_ABI cdk2_text_visible_fn(void *, uint8_t);

struct cdk2_simple_text_input {
	cdk2_text_reset_fn *reset;
	cdk2_text_read_fn *read_key_stroke;
	void *wait_for_key;
};

struct cdk2_simple_text_input_ex {
	cdk2_text_reset_fn *reset;
	cdk2_text_read_fn *read_key_stroke_ex;
	void *wait_for_key_ex;
	cdk2_text_state_fn *set_state;
	cdk2_text_register_fn *register_key_notify;
	cdk2_text_unregister_fn *unregister_key_notify;
};

struct cdk2_text_output_mode {
	int32_t max_mode, mode, attribute, cursor_column, cursor_row;
	uint8_t cursor_visible;
};

struct cdk2_simple_text_output {
	cdk2_text_reset_fn *reset;
	cdk2_text_output_fn *output_string;
	cdk2_text_output_fn *test_string;
	cdk2_text_query_fn *query_mode;
	cdk2_text_mode_fn *set_mode;
	cdk2_text_mode_fn *set_attribute;
	cdk2_text_clear_fn *clear_screen;
	cdk2_text_cursor_fn *set_cursor_position;
	cdk2_text_visible_fn *enable_cursor;
	struct cdk2_text_output_mode *mode;
};

typedef uint64_t CDK2_MS_ABI cdk2_terminal_open_fn(void *, const EFI_GUID *,
						   void **, void *, void *,
						   uint32_t);
typedef uint64_t CDK2_MS_ABI cdk2_terminal_close_fn(void *, const EFI_GUID *,
						    void *, void *);
typedef uint64_t CDK2_MS_ABI cdk2_terminal_install_fn(void **, const EFI_GUID *,
						      void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_terminal_uninstall_fn(void *,
							const EFI_GUID *,
							void *, ...);
typedef uint64_t CDK2_MS_ABI cdk2_terminal_event_fn(uint32_t, size_t, void *,
						    void *, void **);
typedef uint64_t CDK2_MS_ABI cdk2_terminal_close_event_fn(void *);

struct cdk2_terminal_services {
	cdk2_terminal_open_fn *open_protocol;
	cdk2_terminal_close_fn *close_protocol;
	cdk2_terminal_install_fn *install_protocols;
	cdk2_terminal_uninstall_fn *uninstall_protocols;
	cdk2_terminal_event_fn *create_event;
	cdk2_terminal_close_event_fn *close_event;
};

struct cdk2_terminal_notify {
	struct cdk2_terminal_key key;
	void *callback;
	void *handle;
};

struct cdk2_terminal_child {
	struct cdk2_terminal terminal;
	struct cdk2_simple_text_input input;
	struct cdk2_simple_text_input_ex input_ex;
	struct cdk2_simple_text_output output;
	struct cdk2_text_output_mode mode;
	struct cdk2_terminal_device_path path;
	struct cdk2_terminal_notify notifications[16];
	struct cdk2_terminal_services *services;
	struct cdk2_serial_io *serial;
	void *controller, *driver, *handle;
	void *wait_key, *wait_key_ex;
	uint8_t started;
};

uint64_t cdk2_terminal_supported(struct cdk2_terminal_services *services,
				 void *driver, void *controller);
uint64_t cdk2_terminal_start(struct cdk2_terminal_child *child,
			     struct cdk2_terminal_services *services,
			     void *driver, void *controller,
			     enum cdk2_terminal_type type);
uint64_t cdk2_terminal_stop(struct cdk2_terminal_child *child);

#endif
