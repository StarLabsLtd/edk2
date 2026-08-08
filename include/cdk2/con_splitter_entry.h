/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_ENTRY_H_
#define CDK2_CON_SPLITTER_ENTRY_H_

#include <cdk2/con_splitter.h>

struct cdk2_split_text_out_protocol;
struct cdk2_split_text_out_mode {
	INT32 max_mode, mode, attribute, cursor_column, cursor_row;
	BOOLEAN cursor_visible;
};
struct cdk2_split_text_out_protocol {
	EFI_STATUS (CDK2_MS_ABI *reset)(struct cdk2_split_text_out_protocol *, BOOLEAN);
	EFI_STATUS (CDK2_MS_ABI *output)(struct cdk2_split_text_out_protocol *, CHAR16 *);
	EFI_STATUS (CDK2_MS_ABI *test)(struct cdk2_split_text_out_protocol *, CHAR16 *);
	EFI_STATUS (CDK2_MS_ABI *query)(struct cdk2_split_text_out_protocol *, UINTN,
		UINTN *, UINTN *);
	EFI_STATUS (CDK2_MS_ABI *set_mode)(struct cdk2_split_text_out_protocol *, UINTN);
	EFI_STATUS (CDK2_MS_ABI *set_attribute)(struct cdk2_split_text_out_protocol *, UINTN);
	EFI_STATUS (CDK2_MS_ABI *clear)(struct cdk2_split_text_out_protocol *);
	EFI_STATUS (CDK2_MS_ABI *set_cursor)(struct cdk2_split_text_out_protocol *,
		UINTN, UINTN);
	EFI_STATUS (CDK2_MS_ABI *enable_cursor)(struct cdk2_split_text_out_protocol *, BOOLEAN);
	struct cdk2_split_text_out_mode *mode;
};

struct cdk2_split_input_key { UINT16 scan_code; CHAR16 unicode; };
struct cdk2_split_text_in_protocol {
	EFI_STATUS (CDK2_MS_ABI *reset)(struct cdk2_split_text_in_protocol *, BOOLEAN);
	EFI_STATUS (CDK2_MS_ABI *read)(struct cdk2_split_text_in_protocol *,
		struct cdk2_split_input_key *);
	void *wait_for_key;
};

struct cdk2_split_pointer_mode {
	UINT64 resolution_x, resolution_y, resolution_z;
	BOOLEAN left_button, right_button;
};
struct cdk2_split_pointer_protocol {
	EFI_STATUS (CDK2_MS_ABI *reset)(struct cdk2_split_pointer_protocol *, BOOLEAN);
	EFI_STATUS (CDK2_MS_ABI *get_state)(struct cdk2_split_pointer_protocol *,
		struct cdk2_split_pointer_state *);
	void *wait_for_input;
	struct cdk2_split_pointer_mode *mode;
};
struct cdk2_split_absolute_mode {
	UINT64 min_x, min_y, min_z, max_x, max_y, max_z;
	UINT32 attributes;
};
struct cdk2_split_absolute_protocol {
	EFI_STATUS (CDK2_MS_ABI *reset)(struct cdk2_split_absolute_protocol *, BOOLEAN);
	EFI_STATUS (CDK2_MS_ABI *get_state)(struct cdk2_split_absolute_protocol *,
		struct cdk2_split_absolute_state *);
	void *wait_for_input;
	struct cdk2_split_absolute_mode *mode;
};

struct cdk2_split_system_table;
EFI_STATUS CDK2_MS_ABI cdk2_con_splitter_entry(void *image,
	struct cdk2_split_system_table *system);

#endif
