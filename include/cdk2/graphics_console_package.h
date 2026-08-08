/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_GRAPHICS_CONSOLE_PACKAGE_H_
#define CDK2_GRAPHICS_CONSOLE_PACKAGE_H_

#include <uefi.h>

struct cdk2_hii_database_view;
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_new_package_fn(
	const struct cdk2_hii_database_view *, const void *, void *, void **);
typedef EFI_STATUS CDK2_MS_ABI cdk2_hii_remove_package_fn(
	const struct cdk2_hii_database_view *, void *);
typedef EFI_STATUS cdk2_font_allocate_fn(void *, UINTN, void **);
typedef void cdk2_font_free_fn(void *, void *);

struct cdk2_hii_database_view {
	cdk2_hii_new_package_fn *new_package_list;
	cdk2_hii_remove_package_fn *remove_package_list;
};

struct cdk2_graphics_font_package {
	struct cdk2_hii_database_view *database;
	cdk2_font_free_fn *free;
	void *context;
	void *allocation;
	void *handle;
};

EFI_STATUS cdk2_graphics_font_install(struct cdk2_graphics_font_package *package,
	struct cdk2_hii_database_view *database, cdk2_font_allocate_fn *allocate,
	cdk2_font_free_fn *free, void *context);
EFI_STATUS cdk2_graphics_font_remove(struct cdk2_graphics_font_package *package);

#endif
