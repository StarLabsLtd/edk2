/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_H_
#define CDK2_CON_SPLITTER_H_

#include <uefi.h>

#define CDK2_CON_SPLITTER_MAX_OUTPUTS 16U
#define CDK2_CON_SPLITTER_ALREADY_STARTED EFIERR(20)

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

#endif
