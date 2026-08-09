/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_ATA_ATAPI_ENTRY_H_
#define CDK2_ATA_ATAPI_ENTRY_H_

#include <cdk2/ata_atapi_pass_thru.h>

struct cdk2_ata_driver_binding;
typedef CHAR8 cdk2_char8_t;
typedef CHAR16 cdk2_char16_t;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_supported_fn(
	struct cdk2_ata_driver_binding *driver, void *controller, void *remaining);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_start_fn(
	struct cdk2_ata_driver_binding *driver, void *controller, void *remaining);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_stop_fn(
	struct cdk2_ata_driver_binding *driver, void *controller, UINTN children,
	void **child_buffer);
struct cdk2_ata_driver_binding {
	cdk2_ata_supported_fn *supported;
	cdk2_ata_start_fn *start;
	cdk2_ata_stop_fn *stop;
	UINT32 version;
	void *image, *handle;
};
struct cdk2_ata_component_name;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_driver_name_fn(
	struct cdk2_ata_component_name *protocol, cdk2_char8_t *language,
	cdk2_char16_t **name);
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_controller_name_fn(
	struct cdk2_ata_component_name *protocol, void *controller, void *child,
	cdk2_char8_t *language, cdk2_char16_t **name);
struct cdk2_ata_component_name {
	cdk2_ata_driver_name_fn *get_driver_name;
	cdk2_ata_controller_name_fn *get_controller_name;
	CHAR8 *languages;
};
struct cdk2_ata_boot_services;
typedef EFI_STATUS CDK2_MS_ABI cdk2_ata_image_unload_t(void *image);
struct cdk2_ata_loaded_image {
	UINT32 revision; void *parent, *system, *device, *path, *reserved;
	UINT32 options_size; void *options, *base; UINT64 size;
	UINT32 code_type, data_type; cdk2_ata_image_unload_t *unload;
};
struct cdk2_ata_entry {
	struct cdk2_ata_binding *binding;
	struct cdk2_ata_boot_services *boot;
	struct cdk2_ata_loaded_image *loaded;
	cdk2_ata_image_unload_t *original_unload;
	void *image, *driver_handle;
	struct cdk2_ata_driver_binding driver;
	struct cdk2_ata_component_name component, component2;
	UINT8 published;
};

EFI_STATUS cdk2_ata_entry_publish(struct cdk2_ata_entry *entry,
	struct cdk2_ata_binding *binding, void *image, void *system_table);
EFI_STATUS cdk2_ata_entry_publish_with_services(struct cdk2_ata_entry *entry,
	struct cdk2_ata_binding *binding,
	const struct cdk2_ata_binding_services *hardware_services,
	void *image, void *system_table);
EFI_STATUS CDK2_MS_ABI cdk2_ata_entry_unload(void *image);
EFI_STATUS CDK2_MS_ABI cdk2_ata_atapi_pass_thru_entry(void *image,
	void *system_table);

#endif
