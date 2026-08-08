/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_service.h>
#include <stdio.h>
#include <string.h>

static UINT8 main_memory[1024], final_memory[1024];
static UINT32 allocation_count;

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
	*buffer = allocation_count++ == 0 ? main_memory : final_memory;
	*address = (EFI_PHYSICAL_ADDRESS)(UINTN)*buffer;
	return EFI_SUCCESS;
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
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition) fprintf(stderr, "tcg2-service test: %s\n", message);
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
	int failures = 0;

	failures += expect(cdk2_tcg2_service_init(&service, &transport, NULL,
		allocate, hash, extend, 512, 512) == EFI_SUCCESS && allocation_count == 2,
		"service initialization failed");
	failures += expect(cdk2_tcg2_get_capability(&service, &capability) ==
		EFI_SUCCESS && capability.tpm_present &&
		capability.manufacturer_id == 0x53575450U &&
		capability.active_pcr_banks == 3U, "capability publication is wrong");
	export = cdk2_tcg2_acpi_info(&service);
	failures += expect(export != NULL && export->active_interface == 1U &&
		export->tpm_base == 0xfed40000U && export->log_capacity == 512U &&
		export->log_base == (EFI_PHYSICAL_ADDRESS)(UINTN)main_memory,
		"immutable ACPI export is wrong");
	failures += expect(cdk2_tcg2_get_event_log(&service,
		CDK2_TCG2_EVENT_LOG_FORMAT_TCG_2, &location, &last, &truncated) ==
		EFI_SUCCESS && location == export->log_base && last == 0 && !truncated,
		"GetEventLog failed");
	failures += expect(cdk2_tcg2_hash_log_extend(&service, 7, 5, "abc", 3,
		"event", 5, &code) == EFI_SUCCESS && code == 0 &&
		service.final_table->number_of_events == 1U && service.logs.final.used != 0,
		"post-GetEventLog final event was not published");
	size = sizeof(response);
	failures += expect(cdk2_tcg2_submit_command(&service, command, sizeof(command),
		response, &size, &code) == EFI_SUCCESS && code == 0x143U,
		"raw SubmitCommand lost TPM response code");
	return failures == 0 ? 0 : 1;
}
