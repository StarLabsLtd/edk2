/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_PLATFORM_ENTRY_H_
#define CDK2_CON_PLATFORM_ENTRY_H_

#include <cdk2/con_platform.h>

struct cdk2_con_driver_binding;
typedef EFI_STATUS CDK2_MS_ABI cdk2_con_supported_fn(
	struct cdk2_con_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_con_start_fn(
	struct cdk2_con_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_con_stop_fn(
	struct cdk2_con_driver_binding *, void *, UINTN, void **);

struct cdk2_con_driver_binding {
	cdk2_con_supported_fn *supported;
	cdk2_con_start_fn *start;
	cdk2_con_stop_fn *stop;
	UINT32 version;
	void *image_handle, *driver_binding_handle;
};

struct cdk2_con_component_name;
typedef CHAR16 * cdk2_con_name_ptr;
typedef EFI_STATUS CDK2_MS_ABI cdk2_con_get_driver_name_fn(
	struct cdk2_con_component_name *, CHAR8 *, cdk2_con_name_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_con_get_controller_name_fn(
	struct cdk2_con_component_name *, void *, void *, CHAR8 *, cdk2_con_name_ptr *);

struct cdk2_con_component_name {
	cdk2_con_get_driver_name_fn *get_driver_name;
	cdk2_con_get_controller_name_fn *get_controller_name;
	CHAR8 *supported_languages;
};

struct cdk2_con_boot_services;
struct cdk2_con_system_table {
	UINT8 before_runtime_services[88];
	void *runtime;
	struct cdk2_con_boot_services *boot;
};

EFI_STATUS CDK2_MS_ABI cdk2_con_platform_entry(void *image,
	struct cdk2_con_system_table *system);

#endif
