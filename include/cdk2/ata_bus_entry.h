/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef CDK2_ATA_BUS_ENTRY_H
#define CDK2_ATA_BUS_ENTRY_H

#include <cdk2/ata_atapi_entry.h>
#include <cdk2/ata_bus.h>

struct cdk2_ata_bus_boot_services;
struct cdk2_ata_bus_entry {
	struct cdk2_ata_bus_binding binding;
	struct cdk2_ata_bus_boot_services *boot;
	struct cdk2_ata_loaded_image *loaded;
	cdk2_ata_image_unload_t *original_unload;
	void *image, *driver_handle;
	struct cdk2_ata_driver_binding driver;
	struct cdk2_ata_component_name component, component2;
	void *parent_calls;
	BOOLEAN published;
};

EFI_STATUS cdk2_ata_bus_entry_publish(struct cdk2_ata_bus_entry *entry,
	void *image, void *system_table);
EFI_STATUS CDK2_MS_ABI cdk2_ata_bus_entry_unload(void *image);
EFI_STATUS CDK2_MS_ABI cdk2_ata_bus_entry(void *image, void *system_table);

#endif
