/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_H_
#define CDK2_CON_SPLITTER_H_

#include <uefi.h>

#define CDK2_CON_SPLITTER_MAX_OUTPUTS 16U
#define CDK2_CON_SPLITTER_MAX_MODES 32U
#define CDK2_CON_SPLITTER_ALREADY_STARTED EFIERR(20)
#define CDK2_CON_SPLITTER_MAX_INPUTS 16U

struct cdk2_split_text_out;
typedef EFI_STATUS cdk2_split_output_fn(void *, const CHAR16 *);
typedef EFI_STATUS cdk2_split_query_fn(void *, UINTN, UINTN *, UINTN *);
typedef EFI_STATUS cdk2_split_value_fn(void *, UINTN);
typedef EFI_STATUS cdk2_split_cursor_fn(void *, UINTN, UINTN);
typedef EFI_STATUS cdk2_split_visible_fn(void *, BOOLEAN);

struct cdk2_split_text_out_ops {
	cdk2_split_output_fn *output;
	cdk2_split_output_fn *test;
	cdk2_split_query_fn *query;
	cdk2_split_value_fn *set_mode;
	cdk2_split_value_fn *set_attribute;
	EFI_STATUS (*clear)(void *context);
	cdk2_split_cursor_fn *set_cursor;
	cdk2_split_visible_fn *enable_cursor;
};

struct cdk2_split_text_out_device {
	const struct cdk2_split_text_out_ops *ops;
	void *context;
	UINTN max_mode;
};

struct cdk2_split_text_mode {
	UINTN columns, rows;
	INT32 device_mode[CDK2_CON_SPLITTER_MAX_OUTPUTS];
};

struct cdk2_split_text_out {
	struct cdk2_split_text_out_device devices[CDK2_CON_SPLITTER_MAX_OUTPUTS];
	struct cdk2_split_text_mode modes[CDK2_CON_SPLITTER_MAX_MODES];
	UINTN device_count, mode_count, columns, rows, column, row, mode, attribute;
	BOOLEAN cursor_visible;
};

EFI_STATUS cdk2_split_text_out_init(struct cdk2_split_text_out *splitter,
	UINTN columns, UINTN rows);
EFI_STATUS cdk2_split_text_out_add(struct cdk2_split_text_out *splitter,
	const struct cdk2_split_text_out_ops *ops, void *context, UINTN max_mode);
EFI_STATUS cdk2_split_text_out_remove(struct cdk2_split_text_out *splitter,
	void *context);
EFI_STATUS cdk2_split_text_out_output(struct cdk2_split_text_out *splitter,
	const CHAR16 *string);
EFI_STATUS cdk2_split_text_out_test(struct cdk2_split_text_out *splitter,
	const CHAR16 *string);
EFI_STATUS cdk2_split_text_out_set_attribute(struct cdk2_split_text_out *splitter,
	UINTN attribute);
EFI_STATUS cdk2_split_text_out_clear(struct cdk2_split_text_out *splitter);
EFI_STATUS cdk2_split_text_out_set_cursor(struct cdk2_split_text_out *splitter,
	UINTN column, UINTN row);
EFI_STATUS cdk2_split_text_out_enable_cursor(struct cdk2_split_text_out *splitter,
	BOOLEAN visible);
EFI_STATUS cdk2_split_text_out_query_mode(struct cdk2_split_text_out *splitter,
	UINTN mode, UINTN *columns, UINTN *rows);
EFI_STATUS cdk2_split_text_out_set_mode(struct cdk2_split_text_out *splitter, UINTN mode);

struct cdk2_split_key { UINT16 scan_code; CHAR16 unicode; };
typedef EFI_STATUS cdk2_split_key_read_fn(void *, struct cdk2_split_key *);
typedef EFI_STATUS cdk2_split_reset_fn(void *, BOOLEAN);
struct cdk2_split_text_in_device {
	cdk2_split_key_read_fn *read;
	cdk2_split_reset_fn *reset;
	void *context;
};
struct cdk2_split_text_in {
	struct cdk2_split_text_in_device devices[CDK2_CON_SPLITTER_MAX_INPUTS];
	UINTN device_count;
};
EFI_STATUS cdk2_split_text_in_add(struct cdk2_split_text_in *splitter,
	cdk2_split_key_read_fn *read, cdk2_split_reset_fn *reset, void *context);
EFI_STATUS cdk2_split_text_in_remove(struct cdk2_split_text_in *splitter, void *context);
EFI_STATUS cdk2_split_text_in_read(struct cdk2_split_text_in *splitter,
	struct cdk2_split_key *key);
EFI_STATUS cdk2_split_text_in_reset(struct cdk2_split_text_in *splitter,
	BOOLEAN extended);

struct cdk2_split_pointer_state {
	INT32 x, y, z;
	BOOLEAN left, right;
};
struct cdk2_split_pointer_device {
	EFI_STATUS (*get_state)(void *context, struct cdk2_split_pointer_state *state);
	void *context;
	UINT64 resolution_x, resolution_y, resolution_z;
};
struct cdk2_split_pointer {
	struct cdk2_split_pointer_device devices[CDK2_CON_SPLITTER_MAX_INPUTS];
	UINTN device_count;
	UINT64 resolution_x, resolution_y, resolution_z;
};
EFI_STATUS cdk2_split_pointer_get_state(struct cdk2_split_pointer *splitter,
	struct cdk2_split_pointer_state *state);
EFI_STATUS cdk2_split_pointer_add(struct cdk2_split_pointer *splitter,
	const struct cdk2_split_pointer_device *device);
EFI_STATUS cdk2_split_pointer_remove(struct cdk2_split_pointer *splitter, void *context);

struct cdk2_split_absolute_state { UINT64 x, y, z; UINT32 buttons; };
struct cdk2_split_absolute_device {
	EFI_STATUS (*get_state)(void *context, struct cdk2_split_absolute_state *state);
	void *context;
	UINT64 min_x, min_y, min_z, max_x, max_y, max_z;
};
struct cdk2_split_absolute {
	struct cdk2_split_absolute_device devices[CDK2_CON_SPLITTER_MAX_INPUTS];
	UINTN device_count;
	UINT64 min_x, min_y, min_z, max_x, max_y, max_z;
};
EFI_STATUS cdk2_split_absolute_get_state(struct cdk2_split_absolute *splitter,
	struct cdk2_split_absolute_state *state);
EFI_STATUS cdk2_split_absolute_add(struct cdk2_split_absolute *splitter,
	const struct cdk2_split_absolute_device *device);
EFI_STATUS cdk2_split_absolute_remove(struct cdk2_split_absolute *splitter, void *context);

#endif
