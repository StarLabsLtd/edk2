/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_measure.h>
#include <industry_standard/pe_image.h>
#include <stdio.h>
#include <string.h>

struct mock { UINT32 hash_calls, extend_calls, hashed_bytes; };

static EFI_STATUS hash(void *context, TPMI_ALG_HASH algorithm,
	const struct cdk2_tcg2_span *spans, UINT32 span_count, UINT8 *digest,
	UINT16 digest_size)
{
	struct mock *mock = context;
	UINT32 index, byte;
	mock->hash_calls++;
	for (index = 0; index < span_count; index++)
		mock->hashed_bytes += spans[index].size;
	for (byte = 0; byte < digest_size; byte++)
		digest[byte] = (UINT8)algorithm;
	return EFI_SUCCESS;
}

static EFI_STATUS extend(void *context, TPM_PCRINDEX pcr,
	const struct cdk2_tcg2_digest *digests, UINT32 count, UINT32 *code)
{
	struct mock *mock = context;
	(void)pcr; (void)digests; mock->extend_calls++; *code = count == 2 ? 0 : 1;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tcg2-measure test: %s\n", message);
	return !condition;
}

int main(void)
{
	UINT8 image[0x500], main_log[4096], final_log[1024];
	EFI_IMAGE_DOS_HEADER *dos = (EFI_IMAGE_DOS_HEADER *)image;
	EFI_IMAGE_NT_HEADERS64 *nt;
	EFI_IMAGE_SECTION_HEADER *section;
	struct cdk2_tcg2_logs logs = {0};
	struct mock mock = {0};
	struct cdk2_tcg2_measurement measurement = {
		.logs = &logs, .context = &mock, .hash = hash, .extend = extend,
		.algorithms = { TPM_ALG_SHA1, TPM_ALG_SHA256 }, .algorithm_count = 2,
	};
	EFI_GUID vendor = { 1, 2, 3, {4, 5, 6, 7, 8, 9, 10, 11} };
	CHAR16 name[] = { 'd', 'b' };
	UINT8 data[] = { 1, 2, 3, 4 };
	UINT32 code;
	TPM_PCRINDEX classified_pcr;
	UINT32 classified_event;
	UINT32 before;
	int failures = 0;

	memset(image, 0x5a, sizeof(image)); memset(dos, 0, sizeof(*dos));
	dos->e_magic = EFI_IMAGE_DOS_SIGNATURE; dos->e_lfanew = 0x80;
	nt = (EFI_IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew); memset(nt, 0, sizeof(*nt));
	nt->signature = EFI_IMAGE_NT_SIGNATURE; nt->file_header.number_of_sections = 1;
	nt->file_header.size_of_optional_header = sizeof(nt->optional_header);
	nt->optional_header.magic = EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt->optional_header.size_of_headers = 0x200;
	nt->optional_header.number_of_rva_and_sizes = 16;
	nt->optional_header.data_directory[4].virtual_address = 0x400;
	nt->optional_header.data_directory[4].size = 0x80;
	section = (EFI_IMAGE_SECTION_HEADER *)((UINT8 *)nt + 4 +
		sizeof(nt->file_header) + nt->file_header.size_of_optional_header);
	memset(section, 0, sizeof(*section)); section->pointer_to_raw_data = 0x200;
	section->size_of_raw_data = 0x100;
	nt->optional_header.subsystem = 10;
	failures += expect(cdk2_tcg2_classify_pe(image, sizeof(image),
		&classified_pcr, &classified_event) == EFI_SUCCESS &&
		classified_pcr == 4 && classified_event == EV_EFI_BOOT_SERVICES_APPLICATION,
		"EFI application classification failed");
	nt->optional_header.subsystem = 11;
	failures += expect(cdk2_tcg2_classify_pe(image, sizeof(image),
		&classified_pcr, &classified_event) == EFI_SUCCESS &&
		classified_pcr == 2 && classified_event == EV_EFI_BOOT_SERVICES_DRIVER,
		"EFI boot driver classification failed");
	nt->optional_header.subsystem = 12;
	failures += expect(cdk2_tcg2_classify_pe(image, sizeof(image),
		&classified_pcr, &classified_event) == EFI_SUCCESS &&
		classified_pcr == 2 && classified_event == EV_EFI_RUNTIME_SERVICES_DRIVER,
		"EFI runtime driver classification failed");
	nt->optional_header.subsystem = 9;
	failures += expect(cdk2_tcg2_classify_pe(image, sizeof(image),
		&classified_pcr, &classified_event) == EFI_UNSUPPORTED,
		"non-EFI subsystem was classified");
	cdk2_tcg2_log_init(&logs.main, main_log, sizeof(main_log));
	cdk2_tcg2_log_init(&logs.final, final_log, sizeof(final_log));
	failures += expect(cdk2_tcg2_measure_pe(&measurement, 4, 0x80000003U,
		image, sizeof(image), "image", 5, &code) == EFI_SUCCESS && code == 0 &&
		mock.hash_calls == 2U && mock.extend_calls == 1U && logs.event_count == 1U,
		"PE measurement failed");
	failures += expect(mock.hashed_bytes == 2U * (0x400U - 12U),
		"Authenticode exclusions are wrong");
	section->size_of_raw_data = 0x400;
	failures += expect(cdk2_tcg2_measure_pe(&measurement, 4, 1, image,
		sizeof(image), "bad", 3, &code) == EFI_COMPROMISED_DATA,
		"overflowing PE section accepted");
	section->size_of_raw_data = 0x100;
	before = logs.main.used;
	failures += expect(cdk2_tcg2_measure_variable(&measurement, 7, 0x800000e0U,
		&vendor, name, sizeof(name), data, sizeof(data), &code) == EFI_SUCCESS &&
		logs.main.used > before + sizeof(data) + sizeof(name),
		"variable event omitted variable data");
	cdk2_tcg2_activate_final_log(&logs);
	failures += expect(cdk2_tcg2_measure_action(&measurement, 5, 5,
		"Calling EFI Application", &code) == EFI_SUCCESS && logs.final.used != 0,
		"boot action was not added to final log");
	failures += expect(cdk2_tcg2_measure_separator(&measurement, 7, 4, 0,
		&code) == EFI_SUCCESS, "separator measurement failed");
	measurement.algorithms[0] = 0xffffU;
	failures += expect(cdk2_tcg2_measure_action(&measurement, 5, 5, "bad",
		&code) == EFI_UNSUPPORTED, "unknown hash bank accepted");
	return failures == 0 ? 0 : 1;
}
