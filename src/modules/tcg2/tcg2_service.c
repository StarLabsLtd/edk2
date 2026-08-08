/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_service.h>

#define TPM2_PT_MANUFACTURER 0x00000105U

static UINT32 interface_export(enum cdk2_tpm2_interface interface)
{
	return interface == CDK2_TPM2_INTERFACE_CRB ? 1U : 0U;
}

EFI_STATUS cdk2_tcg2_service_init(struct cdk2_tcg2_service *service,
	const struct cdk2_tpm2_transport *transport, void *context,
	cdk2_tcg2_allocate_fn *allocate, cdk2_tcg2_hash_fn *hash,
	cdk2_tcg2_extend_fn *extend, UINT32 main_capacity, UINT32 final_capacity)
{
	EFI_PHYSICAL_ADDRESS main_address;
	EFI_PHYSICAL_ADDRESS final_address;
	void *main_buffer;
	void *final_buffer;
	UINT32 supported;
	UINT32 active;
	UINT32 banks;
	UINT32 response_code;
	UINT32 manufacturer;
	UINT32 index;
	EFI_STATUS status;

	if (service == NULL || transport == NULL || allocate == NULL || hash == NULL ||
	    extend == NULL || main_capacity == 0 || final_capacity == 0 ||
	    final_capacity > MAX_UINT32 - sizeof(*service->final_table))
		return EFI_INVALID_PARAMETER;
	*service = (struct cdk2_tcg2_service){0};
	status = allocate(context, efi_acpi_memory_nvs, main_capacity, &main_buffer,
		&main_address);
	if (EFI_ERROR(status)) return status;
	status = allocate(context, efi_acpi_memory_nvs,
		final_capacity + sizeof(*service->final_table), &final_buffer,
		&final_address);
	if (EFI_ERROR(status)) return status;
	service->transport = *transport;
	status = cdk2_tpm2_request_locality(&service->transport);
	if (EFI_ERROR(status)) return status;
	status = cdk2_tpm2_startup(&service->transport, CDK2_TPM2_SU_CLEAR,
		&response_code);
	if (EFI_ERROR(status)) return status;
	status = cdk2_tpm2_get_property(&service->transport, TPM2_PT_MANUFACTURER,
		&manufacturer, &response_code);
	if (EFI_ERROR(status)) return status;
	status = cdk2_tpm2_get_pcr_banks(&service->transport, &supported, &active,
		&banks, &response_code);
	if (EFI_ERROR(status)) return status;
	status = cdk2_tcg2_log_init(&service->logs.main, main_buffer, main_capacity);
	if (EFI_ERROR(status)) return status;
	service->final_table = final_buffer;
	service->final_table->version = CDK2_TCG2_FINAL_EVENTS_VERSION;
	service->final_table->number_of_events = 0;
	service->logs.final_count_export = &service->final_table->number_of_events;
	status = cdk2_tcg2_log_init(&service->logs.final,
		service->final_table->events, final_capacity);
	if (EFI_ERROR(status)) return status;
	service->main_address = main_address; service->final_address = final_address;
	service->capability = (struct cdk2_tcg2_capability){
		.structure_version_major = 1, .structure_version_minor = 1,
		.protocol_version_major = 1, .protocol_version_minor = 1,
		.hash_algorithm_bitmap = supported,
		.supported_event_logs = CDK2_TCG2_EVENT_LOG_FORMAT_TCG_2,
		.tpm_present = TRUE, .max_command_size = 0x0f80,
		.max_response_size = 0x0f80, .manufacturer_id = manufacturer,
		.number_of_pcr_banks = banks, .active_pcr_banks = active,
	};
	service->measurement = (struct cdk2_tcg2_measurement){
		.logs = &service->logs, .context = context, .hash = hash, .extend = extend,
	};
	for (index = 0; index < HASH_COUNT; index++)
		if ((active & (1U << index)) != 0)
			service->measurement.algorithms[service->measurement.algorithm_count++] =
				(TPMI_ALG_HASH[]){ TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
				TPM_ALG_SHA512, TPM_ALG_SM3_256 }[index];
	if (service->measurement.algorithm_count == 0) return EFI_DEVICE_ERROR;
	service->export = (struct cdk2_tcg2_acpi_export){
		.revision = CDK2_TCG2_EXPORT_REVISION, .size = sizeof(service->export),
		.active_interface = (UINT8)interface_export(transport->interface),
		.tpm_base = transport->base, .log_base = main_address,
		.log_capacity = main_capacity,
	};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_get_capability(const struct cdk2_tcg2_service *service,
	struct cdk2_tcg2_capability *capability)
{
	if (service == NULL || capability == NULL) return EFI_INVALID_PARAMETER;
	*capability = service->capability;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_get_event_log(struct cdk2_tcg2_service *service,
	UINT32 format, EFI_PHYSICAL_ADDRESS *location,
	EFI_PHYSICAL_ADDRESS *last_entry, BOOLEAN *truncated)
{
	if (service == NULL || location == NULL || last_entry == NULL ||
	    truncated == NULL || format != CDK2_TCG2_EVENT_LOG_FORMAT_TCG_2)
		return EFI_INVALID_PARAMETER;
	*location = service->main_address;
	*last_entry = service->logs.main.used == 0 ? 0 : service->main_address +
		service->logs.main.last_entry_offset;
	*truncated = service->logs.main.truncated;
	cdk2_tcg2_activate_final_log(&service->logs);
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_hash_log_extend(struct cdk2_tcg2_service *service,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const void *data,
	UINT32 data_size, const void *event, UINT32 event_size,
	UINT32 *response_code)
{
	struct cdk2_tcg2_span span;
	EFI_STATUS status;

	if (service == NULL || data == NULL || data_size == 0)
		return EFI_INVALID_PARAMETER;
	span = (struct cdk2_tcg2_span){ data, data_size };
	status = cdk2_tcg2_measure_spans(&service->measurement, pcr_index,
		event_type, &span, 1, event, event_size, response_code);
	return status;
}

EFI_STATUS cdk2_tcg2_submit_command(struct cdk2_tcg2_service *service,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size, UINT32 *response_code)
{
	struct cdk2_tpm2_result result;
	EFI_STATUS status;
	if (service == NULL || response_code == NULL) return EFI_INVALID_PARAMETER;
	status = cdk2_tpm2_execute(&service->transport, command, command_size,
		response, response_size, &result);
	if (!EFI_ERROR(status)) *response_code = result.response_code;
	return status;
}

const struct cdk2_tcg2_acpi_export *cdk2_tcg2_acpi_info(
	const struct cdk2_tcg2_service *service)
{
	return service == NULL ? NULL : &service->export;
}
