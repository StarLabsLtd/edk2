/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_service.h>
#include <stdio.h>
#include <string.h>

static UINT8 main_memory[1024], final_memory[1024];
static UINT32 allocation_count;
static UINT32 free_count;
static UINT32 fail_allocation_number = MAX_UINT32;
static UINT32 extend_count;
static BOOLEAN fail_protocol_install;
static UINT32 physical_presence_changes;
static UINT32 reset_count;
static const EFI_GUID *installed_protocol_guid, *installed_config_guid;
static void *installed_protocol, *installed_config;

EFI_STATUS cdk2_tpm2_request_locality(const struct cdk2_tpm2_transport *transport)
{
	return transport == NULL ? EFI_INVALID_PARAMETER : EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_startup(const struct cdk2_tpm2_transport *transport,
	UINT16 type, UINT32 *code)
{
	(void)transport; (void)type; *code = 0; return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_get_property(const struct cdk2_tpm2_transport *transport,
	UINT32 property, UINT32 *value, UINT32 *code)
{
	(void)transport; (void)property; *value = 0x53575450U; *code = 0;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_get_pcr_banks(const struct cdk2_tpm2_transport *transport,
	UINT32 *supported, UINT32 *active, UINT32 *banks, UINT32 *code)
{
	(void)transport; *supported = 3; *active = 3; *banks = 2; *code = 0;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_execute(const struct cdk2_tpm2_transport *transport,
	const UINT8 *command, UINT32 command_size, UINT8 *response,
	UINT32 *response_size, struct cdk2_tpm2_result *result)
{
	(void)transport; (void)command; (void)command_size; (void)response;
	result->response_code = 0x143U; result->response_size = *response_size;
	return EFI_SUCCESS;
}

static EFI_STATUS allocate(void *context, EFI_MEMORY_TYPE type, UINT32 size,
	void **buffer, EFI_PHYSICAL_ADDRESS *address)
{
	(void)context;
	if (type != efi_acpi_memory_nvs || size > sizeof(main_memory))
		return EFI_OUT_OF_RESOURCES;
	if (allocation_count == fail_allocation_number) {
		allocation_count++;
		return EFI_OUT_OF_RESOURCES;
	}
	*buffer = allocation_count++ == 0 ? main_memory : final_memory;
	*address = (EFI_PHYSICAL_ADDRESS)(UINTN)*buffer;
	return EFI_SUCCESS;
}

static EFI_STATUS release(void *context, EFI_PHYSICAL_ADDRESS address, UINT32 size)
{
	(void)context; (void)address; (void)size; free_count++; return EFI_SUCCESS;
}

static EFI_STATUS hash(void *context, TPMI_ALG_HASH algorithm,
	const struct cdk2_tcg2_span *spans, UINT32 span_count, UINT8 *digest,
	UINT16 digest_size)
{
	(void)context; (void)spans; (void)span_count;
	memset(digest, (int)algorithm, digest_size); return EFI_SUCCESS;
}

static EFI_STATUS extend(void *context, TPM_PCRINDEX pcr,
	const struct cdk2_tcg2_digest *digests, UINT32 count, UINT32 *code)
{
	(void)context; (void)pcr; (void)digests; (void)count; *code = 0;
	extend_count++;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tpm2_hash_spans(void *context, TPMI_ALG_HASH algorithm,
	const struct cdk2_tcg2_span *spans, UINT32 span_count, UINT8 *digest,
	UINT16 digest_size)
{
	return hash(context, algorithm, spans, span_count, digest, digest_size);
}

EFI_STATUS cdk2_tpm2_extend_digests(void *context, TPM_PCRINDEX pcr,
	const struct cdk2_tcg2_digest *digests, UINT32 count, UINT32 *code)
{
	return extend(context, pcr, digests, count, code);
}

EFI_STATUS cdk2_tpm2_pcr_allocate(const struct cdk2_tpm2_transport *transport,
	UINT32 supported, UINT32 requested, BOOLEAN *allocation_success,
	UINT32 *response_code)
{
	(void)transport;
	(void)supported;
	(void)requested;
	*allocation_success = TRUE;
	*response_code = 0;
	return EFI_SUCCESS;
}

static EFI_STATUS install_protocol(void *context, const EFI_GUID *guid,
	void *interface)
{
	(void)context; installed_protocol_guid = guid; installed_protocol = interface;
	return fail_protocol_install ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS install_config(void *context, const EFI_GUID *guid, void *table)
{
	(void)context; installed_config_guid = guid; installed_config = table;
	return EFI_SUCCESS;
}

static EFI_STATUS set_banks(void *context, UINT32 active, void *response_buffer)
{
	UINT32 *response_code = response_buffer;
	(void)context; *response_code = active == 1U ? 0 : 1; return EFI_SUCCESS;
}

static EFI_STATUS physical_presence(void *context, BOOLEAN asserted)
{
	(void)context;
	physical_presence_changes++;
	return asserted || physical_presence_changes == 2 ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}

static EFI_STATUS reset(void *context)
{
	(void)context;
	reset_count++;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tcg2-service test: %s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_tcg2_service service;
	struct cdk2_tpm2_transport transport = {
		.interface = CDK2_TPM2_INTERFACE_CRB, .base = 0xfed40000U,
		.timeout_us = 100,
	};
	struct cdk2_tcg2_capability capability;
	const struct cdk2_tcg2_acpi_export *export;
	EFI_PHYSICAL_ADDRESS location, last;
	BOOLEAN truncated;
	UINT8 response[16], command[10] = { 0x80, 1, 0, 0, 0, 10 };
	UINT32 size, code;
	EFI_TCG2_BOOT_SERVICE_CAPABILITY abi_capability;
	UINT32 operation;
	EFI_GUID variable_guid = {0};
	CHAR16 variable_name[2] = { 'X', 0 };
	UINT8 extend_event_buffer[OFFSET_OF(EFI_TCG2_EVENT, event) + 4] = {0};
	EFI_TCG2_EVENT *extend_event = (EFI_TCG2_EVENT *)extend_event_buffer;
	int failures = 0;
	extend_event->size = sizeof(extend_event_buffer);
	extend_event->header.header_size = sizeof(EFI_TCG2_EVENT_HEADER);
	extend_event->header.header_version = EFI_TCG2_EVENT_HEADER_VERSION;
	extend_event->header.pcr_index = 7;
	extend_event->header.event_type = 5;
	fail_allocation_number = 1;
	failures += expect(cdk2_tcg2_service_init(&service, &transport, NULL,
		allocate, release, hash, extend, 768, 768) == EFI_OUT_OF_RESOURCES &&
		free_count == 1 && service.main_address == 0,
		"partial event-log allocation was not rolled back");
	allocation_count = 0;
	free_count = 0;
	fail_allocation_number = MAX_UINT32;

	failures += expect(cdk2_tcg2_service_init(&service, &transport, NULL,
		allocate, release, hash, extend, 768, 768) == EFI_SUCCESS &&
		allocation_count == 2,
		"service initialization failed");
	failures += expect(cdk2_tcg2_get_capability(&service, &capability) ==
		EFI_SUCCESS && capability.tpm_present &&
		capability.manufacturer_id == 0x53575450U &&
		capability.active_pcr_banks == 3U, "capability publication is wrong");
	failures += expect(sizeof(abi_capability) == 36U &&
		sizeof(EFI_TCG2_EVENT_HEADER) == 14U &&
		OFFSET_OF(EFI_TCG2_EVENT, event) == 18U,
		"standard TCG2 ABI layout changed");
	failures += expect(cdk2_tcg2_publish_protocols(&service, NULL,
		install_protocol, install_config, set_banks) == EFI_SUCCESS &&
		installed_protocol_guid == &efi_tcg2_protocol_guid &&
		installed_config_guid == &efi_tcg2_final_events_table_guid &&
		installed_protocol == &service.protocol && installed_config == service.final_table,
		"TCG2 protocol/config tables were not installed");
	memset(&abi_capability, 0, sizeof(abi_capability));
	abi_capability.size = sizeof(abi_capability);
	failures += expect(service.protocol.get_capability(&service.protocol,
		&abi_capability) == EFI_SUCCESS && abi_capability.size ==
		sizeof(abi_capability) && abi_capability.manufacturer_id == 0x53575450U,
		"protocol GetCapability failed");
	failures += expect(service.protocol.get_active_pcr_banks(&service.protocol,
		&code) == EFI_SUCCESS && code == 3U &&
		service.protocol.set_active_pcr_banks(&service.protocol, 1U) == EFI_SUCCESS &&
		service.protocol.get_result_of_set_active_pcr_banks(&service.protocol,
			&operation, &code) == EFI_SUCCESS && operation == 1U && code == 0,
		"PCR bank protocol lifecycle failed");
	{
		UINT32 before_main = service.logs.main.used;
		UINT32 before_final = service.logs.final.used;
		UINT32 before_extend = extend_count;
		failures += expect(service.protocol.hash_log_extend_event(&service.protocol,
			EFI_TCG2_EXTEND_ONLY, (EFI_PHYSICAL_ADDRESS)(UINTN)"abc", 3,
			extend_event) == EFI_SUCCESS && extend_count == before_extend + 1 &&
			service.logs.main.used == before_main &&
			service.logs.final.used == before_final,
			"EXTEND_ONLY changed an event log");
	}
	fail_protocol_install = 1;
	installed_config = service.final_table;
	failures += expect(cdk2_tcg2_publish_protocols(&service, NULL,
		install_protocol, install_config, set_banks) == EFI_DEVICE_ERROR &&
		installed_config == NULL,
		"failed protocol publication did not roll back the config table");
	fail_protocol_install = 0;
	failures += expect(cdk2_tcg2_configure_platform(&service, NULL,
		physical_presence, reset) == EFI_SUCCESS &&
		service.protocol.set_active_pcr_banks(&service.protocol, 2) == EFI_SUCCESS &&
		physical_presence_changes == 2 &&
		cdk2_tcg2_apply_pending_reset(&service) == EFI_SUCCESS && reset_count == 1,
		"native PCR allocation did not enforce physical presence/reset");
	export = cdk2_tcg2_acpi_info(&service);
	failures += expect(export != NULL && export->active_interface == 1U &&
		export->tpm_base == 0xfed40000U && export->log_capacity == 768U &&
		export->log_base == (EFI_PHYSICAL_ADDRESS)(UINTN)main_memory,
		"immutable ACPI export is wrong");
	failures += expect(cdk2_tcg2_get_event_log(&service,
		CDK2_TCG2_EVENT_LOG_FORMAT_TCG_2, &location, &last, &truncated) ==
		EFI_SUCCESS && location == export->log_base && last == location && !truncated,
		"GetEventLog failed");
	failures += expect(cdk2_tcg2_hash_log_extend(&service, 7, 5, "abc", 3,
		"event", 5, &code) == EFI_SUCCESS && code == 0 &&
		service.final_table->number_of_events == 1U && service.logs.final.used != 0,
		"post-GetEventLog final event was not published");
	{
		UINT64 before = service.final_table->number_of_events;
		failures += expect(cdk2_tcg2_measure_boot_variable(&service, 7,
			EV_EFI_VARIABLE_BOOT, &variable_guid, variable_name,
			sizeof(variable_name), "v", 1, &code) == EFI_SUCCESS &&
			cdk2_tcg2_boot_attempt(&service, FALSE, &code) == EFI_SUCCESS &&
			cdk2_tcg2_boot_attempt(&service, TRUE, &code) == EFI_SUCCESS &&
			cdk2_tcg2_exit_boot_services(&service, FALSE, FALSE, &code) ==
			EFI_SUCCESS && cdk2_tcg2_exit_boot_services(&service, TRUE, TRUE,
			&code) == EFI_SUCCESS &&
			service.final_table->number_of_events == before + 5,
			"measured-boot lifecycle events were not recorded");
	}
	size = sizeof(response);
	failures += expect(cdk2_tcg2_submit_command(&service, command, sizeof(command),
		response, &size, &code) == EFI_SUCCESS && code == 0x143U,
		"raw SubmitCommand lost TPM response code");
	cdk2_tcg2_service_release(&service);
	failures += expect(free_count == 2 && service.main_address == 0 &&
		service.final_address == 0,
		"service release did not free both event-log allocations");
	return failures == 0 ? 0 : 1;
}
