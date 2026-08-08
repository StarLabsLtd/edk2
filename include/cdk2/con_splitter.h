/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_H_
#define CDK2_CON_SPLITTER_H_

#include <uefi.h>

#define CDK2_CON_SPLITTER_MAX_OUTPUTS 16U
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
	EFI_STATUS (*clear)(void *);
	cdk2_split_cursor_fn *set_cursor;
	cdk2_split_visible_fn *enable_cursor;
};

struct cdk2_split_text_out_device {
	const struct cdk2_split_text_out_ops *ops;
	void *context;
};

struct cdk2_split_text_out {
	struct cdk2_split_text_out_device devices[CDK2_CON_SPLITTER_MAX_OUTPUTS];
	UINTN device_count, columns, rows, column, row, mode, attribute;
	BOOLEAN cursor_visible;
};

EFI_STATUS cdk2_split_text_out_init(struct cdk2_split_text_out *splitter,
	UINTN columns, UINTN rows);
EFI_STATUS cdk2_split_text_out_add(struct cdk2_split_text_out *splitter,
	const struct cdk2_split_text_out_ops *ops, void *context);
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
	EFI_STATUS (*get_state)(void *, struct cdk2_split_pointer_state *);
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

struct cdk2_split_absolute_state { UINT64 x, y, z; UINT32 buttons; };
struct cdk2_split_absolute_device {
	EFI_STATUS (*get_state)(void *, struct cdk2_split_absolute_state *);
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

#endif
