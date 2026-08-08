/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_TCG2_SERVICE_H_
#define CDK2_TCG2_SERVICE_H_

#include <cdk2/tcg2_commands.h>
#include <cdk2/tcg2_measure.h>
#include <protocol/tcg2.h>

#define CDK2_TCG2_EVENT_LOG_FORMAT_TCG_2 2U
#define CDK2_TCG2_FINAL_EVENTS_VERSION 1U
#define CDK2_TCG2_EXPORT_REVISION 1U

typedef UINT64 cdk2_physical_address_ptr[1];
typedef const EFI_GUID cdk2_const_guid_ptr[1];

typedef EFI_STATUS cdk2_tcg2_allocate_fn(
	void *context, EFI_MEMORY_TYPE type, UINT32 size,
	void **buffer, cdk2_physical_address_ptr address);
typedef EFI_STATUS cdk2_tcg2_free_fn(
	void *context, EFI_PHYSICAL_ADDRESS address, UINT32 size);
typedef EFI_STATUS cdk2_tcg2_install_protocol_fn(
	void *context, cdk2_const_guid_ptr guid, void *interface);
typedef EFI_STATUS cdk2_tcg2_install_config_fn(
	void *context, cdk2_const_guid_ptr guid, void *table);
typedef EFI_STATUS cdk2_tcg2_set_banks_fn(
	void *context, UINT32 active, void *response);
typedef EFI_STATUS cdk2_tcg2_physical_presence_fn(void *context, BOOLEAN asserted);
typedef EFI_STATUS cdk2_tcg2_reset_fn(void *context);
typedef cdk2_tcg2_allocate_fn * cdk2_tcg2_allocate_ptr;
typedef cdk2_tcg2_free_fn * cdk2_tcg2_free_ptr;
typedef cdk2_tcg2_install_protocol_fn * cdk2_tcg2_install_protocol_ptr;
typedef cdk2_tcg2_install_config_fn * cdk2_tcg2_install_config_ptr;
typedef cdk2_tcg2_set_banks_fn * cdk2_tcg2_set_banks_ptr;
typedef cdk2_tcg2_hash_fn * cdk2_tcg2_hash_ptr;
typedef cdk2_tcg2_extend_fn * cdk2_tcg2_extend_ptr;
typedef cdk2_tcg2_physical_presence_fn * cdk2_tcg2_physical_presence_ptr;
typedef cdk2_tcg2_reset_fn * cdk2_tcg2_reset_ptr;
typedef const CHAR16 cdk2_const_char16[1];

struct cdk2_tcg2_capability {
	UINT8 structure_version_major;
	UINT8 structure_version_minor;
	UINT8 protocol_version_major;
	UINT8 protocol_version_minor;
	UINT32 hash_algorithm_bitmap;
	UINT32 supported_event_logs;
	BOOLEAN tpm_present;
	UINT16 max_command_size;
	UINT16 max_response_size;
	UINT32 manufacturer_id;
	UINT32 number_of_pcr_banks;
	UINT32 active_pcr_banks;
};

struct cdk2_tcg2_final_events_table {
	UINT64 version;
	UINT64 number_of_events;
	UINT8 events[];
};

struct cdk2_tcg2_acpi_export {
	UINT16 revision;
	UINT16 size;
	UINT8 active_interface;
	UINT8 reserved[3];
	UINT64 tpm_base;
	EFI_PHYSICAL_ADDRESS log_base;
	UINT32 log_capacity;
	UINT32 reserved2;
};

struct cdk2_tcg2_service {
	EFI_TCG2_PROTOCOL protocol;
	struct cdk2_tpm2_transport transport;
	struct cdk2_tcg2_logs logs;
	struct cdk2_tcg2_measurement measurement;
	struct cdk2_tcg2_capability capability;
	struct cdk2_tcg2_acpi_export export;
	struct cdk2_tcg2_final_events_table *final_table;
	EFI_PHYSICAL_ADDRESS main_address;
	EFI_PHYSICAL_ADDRESS final_address;
	UINT32 main_capacity;
	UINT32 final_allocation_size;
	BOOLEAN main_allocated;
	BOOLEAN final_allocated;
	void *protocol_context;
	void *allocation_context;
	cdk2_tcg2_free_ptr free;
	cdk2_tcg2_set_banks_ptr set_banks;
	cdk2_tcg2_physical_presence_ptr physical_presence;
	cdk2_tcg2_reset_ptr reset;
	UINT32 set_operation_present;
	UINT32 set_response;
};

EFI_STATUS cdk2_tcg2_service_init(struct cdk2_tcg2_service *service,
	const struct cdk2_tpm2_transport *transport, void *context,
	cdk2_tcg2_allocate_ptr allocate, cdk2_tcg2_free_ptr free,
	cdk2_tcg2_hash_ptr hash,
	cdk2_tcg2_extend_ptr extend, UINT32 main_capacity, UINT32 final_capacity);
void cdk2_tcg2_service_release(struct cdk2_tcg2_service *service);
EFI_STATUS cdk2_tcg2_get_capability(const struct cdk2_tcg2_service *service,
	struct cdk2_tcg2_capability *capability);
EFI_STATUS cdk2_tcg2_service_import_hobs(struct cdk2_tcg2_service *service,
	const void *hob_list, const void *hob_end);
EFI_STATUS cdk2_tcg2_measure_image(struct cdk2_tcg2_service *service,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const void *image,
	UINT32 image_size, const void *event, UINT32 event_size,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_measure_boot_variable(struct cdk2_tcg2_service *service,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const EFI_GUID *vendor,
	cdk2_const_char16 name, UINT32 name_bytes, const void *data, UINT32 data_size,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_boot_attempt(struct cdk2_tcg2_service *service,
	BOOLEAN returning, UINT32 *response_code);
EFI_STATUS cdk2_tcg2_exit_boot_services(struct cdk2_tcg2_service *service,
	BOOLEAN returned, BOOLEAN success, UINT32 *response_code);
EFI_STATUS cdk2_tcg2_configure_platform(struct cdk2_tcg2_service *service,
	void *context, cdk2_tcg2_physical_presence_ptr physical_presence,
	cdk2_tcg2_reset_ptr reset);
EFI_STATUS cdk2_tcg2_apply_pending_reset(struct cdk2_tcg2_service *service);
EFI_STATUS cdk2_tcg2_get_event_log(struct cdk2_tcg2_service *service,
	UINT32 format, efi_physical_address_ptr location,
	efi_physical_address_ptr last_entry, efi_boolean_ptr truncated);
EFI_STATUS cdk2_tcg2_hash_log_extend(struct cdk2_tcg2_service *service,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const void *data,
	UINT32 data_size, const void *event, UINT32 event_size,
	UINT32 *response_code);
EFI_STATUS cdk2_tcg2_submit_command(struct cdk2_tcg2_service *service,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size, UINT32 *response_code);
const struct cdk2_tcg2_acpi_export *cdk2_tcg2_acpi_info(
	const struct cdk2_tcg2_service *service);
EFI_STATUS cdk2_tcg2_publish_protocols(struct cdk2_tcg2_service *service,
	void *context, cdk2_tcg2_install_protocol_ptr install_protocol,
	cdk2_tcg2_install_config_ptr install_config,
	cdk2_tcg2_set_banks_ptr set_banks);

#endif
