/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_CON_SPLITTER_BINDING_H_
#define CDK2_CON_SPLITTER_BINDING_H_

#include <cdk2/con_splitter.h>

#define CDK2_CON_SPLITTER_OPEN_BY_DRIVER 0x10U
typedef EFI_STATUS cdk2_split_binding_open_fn(void *, void *, const EFI_GUID *,
	UINT32, void **);
typedef EFI_STATUS cdk2_split_binding_close_fn(void *, void *, const EFI_GUID *);
typedef EFI_STATUS cdk2_split_binding_device_fn(void *, void *);
struct cdk2_split_binding_ops {
	cdk2_split_binding_open_fn *open;
	cdk2_split_binding_close_fn *close;
	cdk2_split_binding_device_fn *admit;
	cdk2_split_binding_device_fn *remove;
};
struct cdk2_split_binding_instance {
	void *controller, *interface;
	BOOLEAN active;
};
struct cdk2_split_binding {
	const struct cdk2_split_binding_ops *ops;
	void *context;
	const EFI_GUID *protocol;
	struct cdk2_split_binding_instance instances[CDK2_CON_SPLITTER_MAX_INPUTS];
};
struct cdk2_split_driver_binding;
typedef EFI_STATUS CDK2_MS_ABI cdk2_split_driver_supported_fn(
	struct cdk2_split_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_split_driver_start_fn(
	struct cdk2_split_driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_split_driver_stop_fn(
	struct cdk2_split_driver_binding *, void *, UINTN, void **);
struct cdk2_split_driver_binding {
	cdk2_split_driver_supported_fn *supported;
	cdk2_split_driver_start_fn *start;
	cdk2_split_driver_stop_fn *stop;
	UINT32 version;
	void *image_handle, *driver_binding_handle;
	struct cdk2_split_binding *binding;
};
struct cdk2_split_component_name;
typedef CHAR16 * split_char16_ptr;
typedef EFI_STATUS CDK2_MS_ABI cdk2_split_driver_name_fn(
	struct cdk2_split_component_name *, CHAR8 *, split_char16_ptr *);
typedef EFI_STATUS CDK2_MS_ABI cdk2_split_controller_name_fn(
	struct cdk2_split_component_name *, void *, void *, CHAR8 *,
	split_char16_ptr *);
struct cdk2_split_component_name {
	cdk2_split_driver_name_fn *get_driver_name;
	cdk2_split_controller_name_fn *get_controller_name;
	CHAR8 *supported_languages;
};
struct cdk2_split_publication {
	struct cdk2_split_driver_binding driver;
	struct cdk2_split_component_name component_name, component_name2;
	void *handle;
};
typedef EFI_STATUS cdk2_split_publish_fn(void *context, void **handle,
	void *driver, void *component_name, void *component_name2);
typedef EFI_STATUS cdk2_split_unpublish_fn(void *context, void *handle,
	void *driver, void *component_name, void *component_name2);
EFI_STATUS cdk2_split_binding_supported(struct cdk2_split_binding *binding,
	void *controller);
EFI_STATUS cdk2_split_binding_start(struct cdk2_split_binding *binding,
	void *controller);
EFI_STATUS cdk2_split_binding_stop(struct cdk2_split_binding *binding,
	void *controller);
void cdk2_split_publication_prepare(struct cdk2_split_publication *publication,
	struct cdk2_split_binding *binding, void *image_handle);
EFI_STATUS cdk2_split_publications_install(
	struct cdk2_split_publication *publications, UINTN count,
	cdk2_split_publish_fn *publish, cdk2_split_unpublish_fn *unpublish,
	void *context);

#endif
