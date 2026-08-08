/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_ENTRY_H_
#define CDK2_CON_SPLITTER_ENTRY_H_

#include <cdk2/con_splitter.h>

struct cdk2_split_text_out_protocol;
typedef EFI_STATUS CDK2_MS_ABI split_text_bool_fn(
	struct cdk2_split_text_out_protocol *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI split_text_string_fn(
	struct cdk2_split_text_out_protocol *, CHAR16 *);
typedef EFI_STATUS CDK2_MS_ABI split_text_query_fn(
	struct cdk2_split_text_out_protocol *, UINTN, UINTN *, UINTN *);
typedef EFI_STATUS CDK2_MS_ABI split_text_value_fn(
	struct cdk2_split_text_out_protocol *, UINTN);
typedef EFI_STATUS CDK2_MS_ABI split_text_clear_fn(
	struct cdk2_split_text_out_protocol *);
typedef EFI_STATUS CDK2_MS_ABI split_text_cursor_fn(
	struct cdk2_split_text_out_protocol *, UINTN, UINTN);
struct cdk2_split_text_out_mode {
	INT32 max_mode, mode, attribute, cursor_column, cursor_row;
	BOOLEAN cursor_visible;
};
struct cdk2_split_text_out_protocol {
	split_text_bool_fn *reset;
	split_text_string_fn *output, *test;
	split_text_query_fn *query;
	split_text_value_fn *set_mode, *set_attribute;
	split_text_clear_fn *clear;
	split_text_cursor_fn *set_cursor;
	split_text_bool_fn *enable_cursor;
	struct cdk2_split_text_out_mode *mode;
};

struct cdk2_split_input_key { UINT16 scan_code; CHAR16 unicode; };
struct cdk2_split_text_in_protocol;
typedef EFI_STATUS CDK2_MS_ABI split_input_reset_fn(
	struct cdk2_split_text_in_protocol *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI split_input_read_fn(
	struct cdk2_split_text_in_protocol *, struct cdk2_split_input_key *);
struct cdk2_split_text_in_protocol {
	split_input_reset_fn *reset;
	split_input_read_fn *read;
	void *wait_for_key;
};
struct cdk2_split_text_in_ex_protocol;
typedef EFI_STATUS CDK2_MS_ABI split_input_ex_reset_fn(
	struct cdk2_split_text_in_ex_protocol *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI split_input_ex_read_fn(
	struct cdk2_split_text_in_ex_protocol *, struct cdk2_split_key_data *);
typedef EFI_STATUS CDK2_MS_ABI split_input_ex_state_fn(
	struct cdk2_split_text_in_ex_protocol *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI split_input_ex_register_fn(
	struct cdk2_split_text_in_ex_protocol *, struct cdk2_split_key_data *,
	cdk2_split_key_notify_fn *, void **);
typedef EFI_STATUS CDK2_MS_ABI split_input_ex_unregister_fn(
	struct cdk2_split_text_in_ex_protocol *, void *);
struct cdk2_split_text_in_ex_protocol {
	split_input_ex_reset_fn *reset;
	split_input_ex_read_fn *read;
	void *wait_for_key_ex;
	split_input_ex_state_fn *set_state;
	split_input_ex_register_fn *register_notify;
	split_input_ex_unregister_fn *unregister_notify;
};

struct cdk2_split_pointer_mode {
	UINT64 resolution_x, resolution_y, resolution_z;
	BOOLEAN left_button, right_button;
};
struct cdk2_split_pointer_protocol;
typedef EFI_STATUS CDK2_MS_ABI split_pointer_reset_fn(
	struct cdk2_split_pointer_protocol *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI split_pointer_state_fn(
	struct cdk2_split_pointer_protocol *, struct cdk2_split_pointer_state *);
struct cdk2_split_pointer_protocol {
	split_pointer_reset_fn *reset;
	split_pointer_state_fn *get_state;
	void *wait_for_input;
	struct cdk2_split_pointer_mode *mode;
};
struct cdk2_split_absolute_mode {
	UINT64 min_x, min_y, min_z, max_x, max_y, max_z;
	UINT32 attributes;
};
struct cdk2_split_absolute_protocol;
typedef EFI_STATUS CDK2_MS_ABI split_absolute_reset_fn(
	struct cdk2_split_absolute_protocol *, BOOLEAN);
typedef EFI_STATUS CDK2_MS_ABI split_absolute_state_fn(
	struct cdk2_split_absolute_protocol *, struct cdk2_split_absolute_state *);
struct cdk2_split_absolute_protocol {
	split_absolute_reset_fn *reset;
	split_absolute_state_fn *get_state;
	void *wait_for_input;
	struct cdk2_split_absolute_mode *mode;
};
struct cdk2_split_gop_mode_info {
	UINT32 version, horizontal_resolution, vertical_resolution, pixel_format;
	UINT32 pixel_information[4], pixels_per_scan_line;
};
struct cdk2_split_gop_protocol_mode {
	UINT32 max_mode, mode;
	struct cdk2_split_gop_mode_info *info;
	UINTN size_of_info;
	UINT64 frame_buffer_base;
	UINTN frame_buffer_size;
};
struct cdk2_split_gop_protocol;
typedef EFI_STATUS CDK2_MS_ABI split_gop_query_fn(
	struct cdk2_split_gop_protocol *, UINT32, UINTN *,
	struct cdk2_split_gop_mode_info **);
typedef EFI_STATUS CDK2_MS_ABI split_gop_set_fn(
	struct cdk2_split_gop_protocol *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI split_gop_blt_fn(
	struct cdk2_split_gop_protocol *, void *, UINTN, UINTN, UINTN, UINTN,
	UINTN, UINTN, UINTN, UINTN);
struct cdk2_split_gop_protocol {
	split_gop_query_fn *query_mode;
	split_gop_set_fn *set_mode;
	split_gop_blt_fn *blt;
	struct cdk2_split_gop_protocol_mode *mode;
};

struct cdk2_split_system_table;
EFI_STATUS CDK2_MS_ABI cdk2_con_splitter_entry(void *image,
	struct cdk2_split_system_table *system);

#endif
