/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_service.h>

#define TPM2_PT_MANUFACTURER 0x00000105U

const EFI_GUID efi_tcg2_protocol_guid = {
	0x607f766c, 0x7455, 0x42be,
	{0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f}
};
const EFI_GUID efi_tcg2_final_events_table_guid = {
	0x1e2ed096, 0x30e2, 0x4254,
	{0xbd, 0x89, 0x86, 0x3b, 0xbe, 0xf8, 0x23, 0x25}
};

static void copy_bytes(void *destination, const void *source, UINTN size)
{
	UINT8 *out = destination;
	const UINT8 *in = source;
	UINTN index;
	for (index = 0; index < size; index++)
		out[index] = in[index];
}

static struct cdk2_tcg2_service *from_protocol(EFI_TCG2_PROTOCOL *protocol)
{
	return (struct cdk2_tcg2_service *)((UINT8 *)protocol -
		OFFSET_OF(struct cdk2_tcg2_service, protocol));
}

static EFI_STATUS CDK2_MS_ABI protocol_get_capability(EFI_TCG2_PROTOCOL *protocol,
	efi_tcg2_capability_ptr output)
{
	struct cdk2_tcg2_service *service;
	EFI_TCG2_BOOT_SERVICE_CAPABILITY capability;
	UINT8 supplied;

	if (protocol == NULL || output == NULL)
		return EFI_INVALID_PARAMETER;
	service = from_protocol(protocol); supplied = output->size;
	capability = (EFI_TCG2_BOOT_SERVICE_CAPABILITY){
		.size = sizeof(capability), .structure_version = {1, 1},
		.protocol_version = {1, 1},
		.hash_algorithm_bitmap = service->capability.hash_algorithm_bitmap,
		.supported_event_logs = service->capability.supported_event_logs,
		.tpm_present_flag = service->capability.tpm_present,
		.max_command_size = service->capability.max_command_size,
		.max_response_size = service->capability.max_response_size,
		.manufacturer_id = service->capability.manufacturer_id,
		.number_of_pcr_banks = service->capability.number_of_pcr_banks,
		.active_pcr_banks = service->capability.active_pcr_banks,
	};
	copy_bytes(output, &capability, supplied < sizeof(capability) ? supplied :
		sizeof(capability));
	output->size = sizeof(capability);
	return supplied < sizeof(capability) ? EFI_BUFFER_TOO_SMALL : EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI protocol_get_event_log(EFI_TCG2_PROTOCOL *protocol,
	EFI_TCG2_EVENT_LOG_FORMAT format, efi_physical_address_ptr location,
	efi_physical_address_ptr last_entry, efi_boolean_ptr truncated)
{
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_tcg2_get_event_log(from_protocol(protocol), format, location,
		last_entry, truncated);
}

static EFI_STATUS CDK2_MS_ABI protocol_hash_log_extend(EFI_TCG2_PROTOCOL *protocol,
	UINT64 flags, EFI_PHYSICAL_ADDRESS data, UINT64 data_size,
	efi_tcg2_event_ptr event)
{
	struct cdk2_tcg2_service *service;
	UINT32 event_offset = OFFSET_OF(EFI_TCG2_EVENT, event);
	UINT32 response_code;

	if (protocol == NULL || event == NULL || (data == 0 && data_size != 0) ||
	    data_size > MAX_UINT32 || (flags & ~(EFI_TCG2_EXTEND_ONLY | PE_COFF_IMAGE)) != 0 ||
	    event->size < event_offset ||
	    event->header.header_size != sizeof(event->header) ||
	    event->header.header_version != EFI_TCG2_EVENT_HEADER_VERSION ||
	    event->header.pcr_index > 23U)
		return EFI_INVALID_PARAMETER;
	service = from_protocol(protocol);
	if ((flags & EFI_TCG2_EXTEND_ONLY) != 0) {
		if ((flags & PE_COFF_IMAGE) != 0)
			return cdk2_tcg2_extend_pe(&service->measurement,
				event->header.pcr_index, (const void *)(UINTN)data,
				(UINT32)data_size, &response_code);
		{
			struct cdk2_tcg2_span span = {
				(const UINT8 *)(UINTN)data, (UINT32)data_size
			};
			return cdk2_tcg2_extend_spans(&service->measurement,
				event->header.pcr_index, &span, 1, &response_code);
		}
	}
	if ((flags & PE_COFF_IMAGE) != 0)
		return cdk2_tcg2_measure_pe(&service->measurement,
			event->header.pcr_index, event->header.event_type,
			(const void *)(UINTN)data, (UINT32)data_size, event->event,
			event->size - event_offset, &response_code);
	return cdk2_tcg2_hash_log_extend(service, event->header.pcr_index,
		event->header.event_type, (const void *)(UINTN)data, (UINT32)data_size,
		event->event, event->size - event_offset, &response_code);
}

static EFI_STATUS CDK2_MS_ABI protocol_submit(EFI_TCG2_PROTOCOL *protocol,
	UINT32 input_size, UINT8 *input, UINT32 output_size, UINT8 *output)
{
	UINT32 response_code;
	if (protocol == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_tcg2_submit_command(from_protocol(protocol), input, input_size,
		output, &output_size, &response_code);
}

static EFI_STATUS CDK2_MS_ABI protocol_get_active(EFI_TCG2_PROTOCOL *protocol,
	UINT32 *active)
{
	if (protocol == NULL || active == NULL)
		return EFI_INVALID_PARAMETER;
	*active = from_protocol(protocol)->capability.active_pcr_banks;
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI protocol_set_active(EFI_TCG2_PROTOCOL *protocol,
	UINT32 active)
{
	struct cdk2_tcg2_service *service;
	EFI_STATUS status;
	if (protocol == NULL || active == 0)
		return EFI_INVALID_PARAMETER;
	service = from_protocol(protocol);
	if ((active & ~service->capability.hash_algorithm_bitmap) != 0)
		return EFI_INVALID_PARAMETER;
	if (active == service->capability.active_pcr_banks)
		return EFI_SUCCESS;
	if (service->set_banks == NULL)
		return EFI_UNSUPPORTED;
	service->set_operation_present = 1;
	status = service->set_banks(service->protocol_context, active,
		&service->set_response);
	return status;
}

static EFI_STATUS CDK2_MS_ABI protocol_get_set_result(EFI_TCG2_PROTOCOL *protocol,
	UINT32 *operation_present, UINT32 *response)
{
	struct cdk2_tcg2_service *service;
	if (protocol == NULL || operation_present == NULL || response == NULL)
		return EFI_INVALID_PARAMETER;
	service = from_protocol(protocol); *operation_present = service->set_operation_present;
	*response = service->set_response; return EFI_SUCCESS;
}

static UINT32 interface_export(enum cdk2_tpm2_interface interface)
{
	return interface == CDK2_TPM2_INTERFACE_CRB ? 1U : 0U;
}

EFI_STATUS cdk2_tcg2_service_init(struct cdk2_tcg2_service *service,
	const struct cdk2_tpm2_transport *transport, void *context,
	cdk2_tcg2_allocate_ptr allocate, cdk2_tcg2_hash_ptr hash,
	cdk2_tcg2_extend_ptr extend, UINT32 main_capacity, UINT32 final_capacity)
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

	if (service == NULL || transport == NULL || allocate == NULL ||
	    ((hash == NULL) != (extend == NULL)) || main_capacity == 0 ||
	    final_capacity == 0 ||
	    final_capacity > MAX_UINT32 - sizeof(*service->final_table))
		return EFI_INVALID_PARAMETER;
	*service = (struct cdk2_tcg2_service){0};
	service->protocol = (EFI_TCG2_PROTOCOL){
		.get_capability = protocol_get_capability,
		.get_event_log = protocol_get_event_log,
		.hash_log_extend_event = protocol_hash_log_extend,
		.submit_command = protocol_submit,
		.get_active_pcr_banks = protocol_get_active,
		.set_active_pcr_banks = protocol_set_active,
		.get_result_of_set_active_pcr_banks = protocol_get_set_result,
	};
	status = allocate(context, efi_acpi_memory_nvs, main_capacity, &main_buffer,
		&main_address);
	if (EFI_ERROR(status))
		return status;
	status = allocate(context, efi_acpi_memory_nvs,
		final_capacity + sizeof(*service->final_table), &final_buffer,
		&final_address);
	if (EFI_ERROR(status))
		return status;
	service->transport = *transport;
	status = cdk2_tpm2_request_locality(&service->transport);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_tpm2_startup(&service->transport, CDK2_TPM2_SU_CLEAR,
		&response_code);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_tpm2_get_property(&service->transport, TPM2_PT_MANUFACTURER,
		&manufacturer, &response_code);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_tpm2_get_pcr_banks(&service->transport, &supported, &active,
		&banks, &response_code);
	if (EFI_ERROR(status))
		return status;
	status = cdk2_tcg2_log_init(&service->logs.main, main_buffer, main_capacity);
	if (EFI_ERROR(status))
		return status;
	service->final_table = final_buffer;
	service->final_table->version = CDK2_TCG2_FINAL_EVENTS_VERSION;
	service->final_table->number_of_events = 0;
	service->logs.final_count_export = &service->final_table->number_of_events;
	status = cdk2_tcg2_log_init(&service->logs.final,
		service->final_table->events, final_capacity);
	if (EFI_ERROR(status))
		return status;
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
		.logs = &service->logs,
		.context = hash == NULL ? &service->transport : context,
		.hash = hash == NULL ? cdk2_tpm2_hash_spans : hash,
		.extend = extend == NULL ? cdk2_tpm2_extend_digests : extend,
	};
	for (index = 0; index < HASH_COUNT; index++)
		if ((active & (1U << index)) != 0)
			service->measurement.algorithms[service->measurement.algorithm_count++] =
				((TPMI_ALG_HASH[]) { TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_ALG_SHA384,
				TPM_ALG_SHA512, TPM_ALG_SM3_256 })[index];
	if (service->measurement.algorithm_count == 0)
		return EFI_DEVICE_ERROR;
	status = cdk2_tcg2_write_specid(&service->logs,
		service->measurement.algorithms, service->measurement.algorithm_count,
		sizeof(UINTN) == sizeof(UINT64) ? 2 : 1);
	if (EFI_ERROR(status))
		return status;
	service->export = (struct cdk2_tcg2_acpi_export){
		.revision = CDK2_TCG2_EXPORT_REVISION, .size = sizeof(service->export),
		.active_interface = (UINT8)interface_export(transport->interface),
		.tpm_base = transport->base, .log_base = main_address,
		.log_capacity = main_capacity,
	};
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_service_import_hobs(struct cdk2_tcg2_service *service,
	const void *hob_list, const void *hob_end)
{
	if (service == NULL)
		return EFI_INVALID_PARAMETER;
	return cdk2_tcg2_import_event2_hobs(&service->logs, hob_list, hob_end);
}

EFI_STATUS cdk2_tcg2_get_capability(const struct cdk2_tcg2_service *service,
	struct cdk2_tcg2_capability *capability)
{
	if (service == NULL || capability == NULL)
		return EFI_INVALID_PARAMETER;
	*capability = service->capability;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_get_event_log(struct cdk2_tcg2_service *service,
	UINT32 format, efi_physical_address_ptr location,
	efi_physical_address_ptr last_entry, efi_boolean_ptr truncated)
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
	if (service == NULL || response_code == NULL)
		return EFI_INVALID_PARAMETER;
	status = cdk2_tpm2_execute(&service->transport, command, command_size,
		response, response_size, &result);
	if (!EFI_ERROR(status))
		*response_code = result.response_code;
	return status;
}

const struct cdk2_tcg2_acpi_export *cdk2_tcg2_acpi_info(
	const struct cdk2_tcg2_service *service)
{
	return service == NULL ? NULL : &service->export;
}

EFI_STATUS cdk2_tcg2_publish_protocols(struct cdk2_tcg2_service *service,
	void *context, cdk2_tcg2_install_protocol_ptr install_protocol,
	cdk2_tcg2_install_config_ptr install_config,
	cdk2_tcg2_set_banks_ptr set_banks)
{
	EFI_STATUS status;
	if (service == NULL || install_protocol == NULL || install_config == NULL)
		return EFI_INVALID_PARAMETER;
	service->protocol_context = context; service->set_banks = set_banks;
	status = install_config(context, &efi_tcg2_final_events_table_guid,
		service->final_table);
	if (EFI_ERROR(status))
		return status;
	status = install_protocol(context, &efi_tcg2_protocol_guid, &service->protocol);
	if (EFI_ERROR(status))
		install_config(context, &efi_tcg2_final_events_table_guid, NULL);
	return status;
}
