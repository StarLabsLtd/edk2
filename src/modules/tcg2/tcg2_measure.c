/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/tcg2_measure.h>
#include <industry_standard/pe_image.h>

#define PE_SECURITY_DIRECTORY 4U
#define PE_MAX_SECTIONS 96U

struct variable_event_header {
	EFI_GUID vendor;
	UINT64 name_length;
	UINT64 data_length;
} __packed;

static UINT16 algorithm_size(TPMI_ALG_HASH algorithm)
{
	switch (algorithm) {
	case TPM_ALG_SHA1: return SHA1_DIGEST_SIZE;
	case TPM_ALG_SHA256: return SHA256_DIGEST_SIZE;
	case TPM_ALG_SHA384: return SHA384_DIGEST_SIZE;
	case TPM_ALG_SHA512: return SHA512_DIGEST_SIZE;
	case TPM_ALG_SM3_256: return SM3_256_DIGEST_SIZE;
	default: return 0;
	}
}

static UINT32 string_size(const char *string)
{
	UINT32 size = 0;
	if (string == NULL) return 0;
	while (string[size] != '\0') size++;
	return size;
}

static EFI_STATUS measure_parts(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type,
	const struct cdk2_tcg2_span *spans, UINT32 span_count,
	const struct cdk2_tcg2_data_span *event_spans, UINT32 event_span_count,
	UINT32 event_size, UINT32 *response_code)
{
	struct cdk2_tcg2_digest digests[CDK2_TCG2_MAX_DIGESTS];
	struct cdk2_tcg2_event log_event;
	UINT32 index;
	EFI_STATUS status;

	if (measurement == NULL || measurement->logs == NULL ||
	    measurement->hash == NULL || measurement->extend == NULL ||
	    response_code == NULL || spans == NULL || span_count == 0 ||
	    span_count > CDK2_TCG2_MAX_SPANS || measurement->algorithm_count == 0 ||
	    measurement->algorithm_count > CDK2_TCG2_MAX_DIGESTS ||
	    event_spans == NULL || event_span_count == 0)
		return EFI_INVALID_PARAMETER;
	for (index = 0; index < measurement->algorithm_count; index++) {
		digests[index].algorithm = measurement->algorithms[index];
		digests[index].size = algorithm_size(digests[index].algorithm);
		if (digests[index].size == 0) return EFI_UNSUPPORTED;
		status = measurement->hash(measurement->context, digests[index].algorithm,
			spans, span_count, digests[index].bytes, digests[index].size);
		if (EFI_ERROR(status)) return status;
	}
	status = measurement->extend(measurement->context, pcr_index, digests,
		measurement->algorithm_count, response_code);
	if (EFI_ERROR(status)) return status;
	log_event = (struct cdk2_tcg2_event){
		.pcr_index = pcr_index, .event_type = event_type,
		.digest_count = measurement->algorithm_count, .digests = digests,
		.event_size = event_size, .event = event_spans[0].data,
	};
	return cdk2_tcg2_append_event_spans(measurement->logs, &log_event,
		event_spans, event_span_count);
}

EFI_STATUS cdk2_tcg2_measure_spans(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type,
	const struct cdk2_tcg2_span *spans, UINT32 span_count,
	const void *event, UINT32 event_size, UINT32 *response_code)
{
	struct cdk2_tcg2_data_span event_span = { event, event_size };
	if (event_size != 0 && event == NULL) return EFI_INVALID_PARAMETER;
	return measure_parts(measurement, pcr_index, event_type, spans, span_count,
		&event_span, 1, event_size, response_code);
}

static EFI_STATUS add_span(struct cdk2_tcg2_span *spans, UINT32 *count,
	const UINT8 *image, UINT32 image_size, UINT32 offset, UINT32 size)
{
	if (offset > image_size || size > image_size - offset)
		return EFI_COMPROMISED_DATA;
	if (size == 0) return EFI_SUCCESS;
	if (*count >= CDK2_TCG2_MAX_SPANS) return EFI_OUT_OF_RESOURCES;
	spans[*count] = (struct cdk2_tcg2_span){ image + offset, size };
	(*count)++;
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_tcg2_measure_pe(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const void *image_buffer,
	UINT32 image_size, const void *event, UINT32 event_size,
	UINT32 *response_code)
{
	const UINT8 *image = image_buffer;
	const EFI_IMAGE_DOS_HEADER *dos;
	const EFI_IMAGE_NT_HEADERS64 *nt;
	const EFI_IMAGE_SECTION_HEADER *sections;
	struct cdk2_tcg2_span spans[CDK2_TCG2_MAX_SPANS];
	UINT32 order[PE_MAX_SECTIONS];
	UINT32 span_count = 0;
	UINT32 section_offset;
	UINT32 checksum_offset;
	UINT32 security_offset;
	UINT32 cert_offset;
	UINT32 cert_size;
	UINT32 sum = 0;
	UINT32 index;
	UINT32 next;
	UINT32 temp;
	EFI_STATUS status;

	if (image == NULL || image_size < sizeof(*dos)) return EFI_INVALID_PARAMETER;
	dos = (const EFI_IMAGE_DOS_HEADER *)image;
	if (dos->e_magic != EFI_IMAGE_DOS_SIGNATURE || dos->e_lfanew > image_size -
	    sizeof(*nt)) return EFI_COMPROMISED_DATA;
	nt = (const EFI_IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
	if (nt->signature != EFI_IMAGE_NT_SIGNATURE ||
	    nt->optional_header.magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
	    nt->file_header.number_of_sections > PE_MAX_SECTIONS ||
	    nt->file_header.size_of_optional_header < sizeof(nt->optional_header) ||
	    nt->optional_header.number_of_rva_and_sizes <= PE_SECURITY_DIRECTORY ||
	    nt->optional_header.size_of_headers > image_size)
		return EFI_COMPROMISED_DATA;
	checksum_offset = dos->e_lfanew + OFFSET_OF(EFI_IMAGE_NT_HEADERS64,
		optional_header.check_sum);
	security_offset = dos->e_lfanew + OFFSET_OF(EFI_IMAGE_NT_HEADERS64,
		optional_header.data_directory[PE_SECURITY_DIRECTORY]);
	if (checksum_offset + 4U > security_offset || security_offset + 8U >
	    nt->optional_header.size_of_headers) return EFI_COMPROMISED_DATA;
	status = add_span(spans, &span_count, image, image_size, 0, checksum_offset);
	if (EFI_ERROR(status)) return status;
	status = add_span(spans, &span_count, image, image_size, checksum_offset + 4U,
		security_offset - checksum_offset - 4U);
	if (EFI_ERROR(status)) return status;
	status = add_span(spans, &span_count, image, image_size, security_offset + 8U,
		nt->optional_header.size_of_headers - security_offset - 8U);
	if (EFI_ERROR(status)) return status;
	section_offset = dos->e_lfanew + sizeof(UINT32) + sizeof(EFI_IMAGE_FILE_HEADER) +
		nt->file_header.size_of_optional_header;
	if (section_offset > image_size || nt->file_header.number_of_sections >
	    (image_size - section_offset) / sizeof(*sections))
		return EFI_COMPROMISED_DATA;
	sections = (const EFI_IMAGE_SECTION_HEADER *)(image + section_offset);
	sum = nt->optional_header.size_of_headers;
	for (index = 0; index < nt->file_header.number_of_sections; index++) order[index] = index;
	for (index = 0; index < nt->file_header.number_of_sections; index++)
		for (next = index + 1; next < nt->file_header.number_of_sections; next++)
			if (sections[order[next]].pointer_to_raw_data <
			    sections[order[index]].pointer_to_raw_data) {
				temp = order[index]; order[index] = order[next]; order[next] = temp;
			}
	for (index = 0; index < nt->file_header.number_of_sections; index++) {
		const EFI_IMAGE_SECTION_HEADER *section = &sections[order[index]];
		if (section->pointer_to_raw_data < sum || section->size_of_raw_data >
		    image_size - section->pointer_to_raw_data)
			return EFI_COMPROMISED_DATA;
		status = add_span(spans, &span_count, image, image_size,
			section->pointer_to_raw_data, section->size_of_raw_data);
		if (EFI_ERROR(status)) return status;
		sum = section->pointer_to_raw_data + section->size_of_raw_data;
	}
	cert_offset = nt->optional_header.data_directory[PE_SECURITY_DIRECTORY].virtual_address;
	cert_size = nt->optional_header.data_directory[PE_SECURITY_DIRECTORY].size;
	if (cert_size != 0 && (cert_offset < sum || cert_offset > image_size ||
	    cert_size > image_size - cert_offset)) return EFI_COMPROMISED_DATA;
	if (cert_size == 0) cert_offset = image_size;
	status = add_span(spans, &span_count, image, image_size, sum,
		cert_offset - sum);
	if (EFI_ERROR(status)) return status;
	return cdk2_tcg2_measure_spans(measurement, pcr_index, event_type, spans,
		span_count, event, event_size, response_code);
}

EFI_STATUS cdk2_tcg2_measure_variable(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const EFI_GUID *vendor,
	const CHAR16 *name, UINT32 name_bytes, const void *data, UINT32 data_size,
	UINT32 *response_code)
{
	struct variable_event_header header;
	struct cdk2_tcg2_span spans[3];
	struct cdk2_tcg2_data_span event_spans[3];
	UINT32 total_size;

	if (vendor == NULL || (name_bytes != 0 && name == NULL) ||
	    (data_size != 0 && data == NULL) || (name_bytes & 1U) != 0)
		return EFI_INVALID_PARAMETER;
	header.vendor = *vendor; header.name_length = name_bytes / sizeof(*name);
	header.data_length = data_size;
	if (name_bytes > MAX_UINT32 - sizeof(header) || data_size >
	    MAX_UINT32 - sizeof(header) - name_bytes)
		return EFI_BAD_BUFFER_SIZE;
	total_size = sizeof(header) + name_bytes + data_size;
	spans[0] = (struct cdk2_tcg2_span){ (const UINT8 *)&header, sizeof(header) };
	spans[1] = (struct cdk2_tcg2_span){ (const UINT8 *)name, name_bytes };
	spans[2] = (struct cdk2_tcg2_span){ data, data_size };
	event_spans[0] = (struct cdk2_tcg2_data_span){ (const UINT8 *)&header,
		sizeof(header) };
	event_spans[1] = (struct cdk2_tcg2_data_span){ (const UINT8 *)name, name_bytes };
	event_spans[2] = (struct cdk2_tcg2_data_span){ data, data_size };
	return measure_parts(measurement, pcr_index, event_type, spans, 3,
		event_spans, 3, total_size, response_code);
}

EFI_STATUS cdk2_tcg2_measure_action(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, const char *action,
	UINT32 *response_code)
{
	struct cdk2_tcg2_span span;
	UINT32 size = string_size(action);
	if (size == 0) return EFI_INVALID_PARAMETER;
	span = (struct cdk2_tcg2_span){ (const UINT8 *)action, size };
	return cdk2_tcg2_measure_spans(measurement, pcr_index, event_type, &span, 1,
		action, size, response_code);
}

EFI_STATUS cdk2_tcg2_measure_separator(struct cdk2_tcg2_measurement *measurement,
	TPM_PCRINDEX pcr_index, UINT32 event_type, UINT32 value,
	UINT32 *response_code)
{
	struct cdk2_tcg2_span span = { (const UINT8 *)&value, sizeof(value) };
	return cdk2_tcg2_measure_spans(measurement, pcr_index, event_type, &span, 1,
		&value, sizeof(value), response_code);
}
