/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_event_log.h>
#include <stdio.h>
#include <string.h>

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tcg2-event-log test: %s\n", message);
	return !condition;
}

int main(void)
{
	UINT8 main_buffer[512], final_buffer[256];
	struct cdk2_tcg2_logs logs = {0};
	struct cdk2_tcg2_digest digests[2] = {
		{ .algorithm = TPM_ALG_SHA1, .size = SHA1_DIGEST_SIZE },
		{ .algorithm = TPM_ALG_SHA256, .size = SHA256_DIGEST_SIZE },
	};
	const UINT8 data[] = "measured action";
	struct cdk2_tcg2_event event = {
		.pcr_index = 7, .event_type = 5, .digest_count = 2,
		.digests = digests, .event_size = sizeof(data), .event = data,
	};
	UINT8 hob_bytes[256];
	EFI_HOB_GUID_TYPE *guid_hob;
	EFI_HOB_GENERIC_HEADER *end_hob;
	UINT32 record_size;
	int failures = 0;

	memset(hob_bytes, 0, sizeof(hob_bytes));
	memset(digests[0].bytes, 0x11, SHA1_DIGEST_SIZE);
	memset(digests[1].bytes, 0x22, SHA256_DIGEST_SIZE);
	failures += expect(cdk2_tcg2_log_init(&logs.main, main_buffer,
		sizeof(main_buffer)) == EFI_SUCCESS &&
		cdk2_tcg2_log_init(&logs.final, final_buffer,
		sizeof(final_buffer)) == EFI_SUCCESS, "log initialization failed");
	failures += expect(cdk2_tcg2_append_event(&logs, &event) == EFI_SUCCESS &&
		logs.main.used == 16U + 2U + SHA1_DIGEST_SIZE + 2U +
		SHA256_DIGEST_SIZE + sizeof(data) && logs.event_count == 1U,
		"multi-bank event encoding failed");
	record_size = logs.main.used;
	cdk2_tcg2_activate_final_log(&logs);
	failures += expect(cdk2_tcg2_append_event(&logs, &event) == EFI_SUCCESS &&
		logs.final.used == record_size && logs.event_count == 2U,
		"final event log did not activate");
	digests[1].algorithm = TPM_ALG_SHA1;
	failures += expect(cdk2_tcg2_append_event(&logs, &event) ==
		EFI_COMPROMISED_DATA, "duplicate digest bank accepted");
	digests[1].algorithm = 0xffffU;
	failures += expect(cdk2_tcg2_append_event(&logs, &event) ==
		EFI_COMPROMISED_DATA, "unknown digest bank accepted");
	digests[1].algorithm = TPM_ALG_SHA256;
	logs.main.capacity = logs.main.used;
	failures += expect(cdk2_tcg2_append_event(&logs, &event) == EFI_VOLUME_FULL &&
		logs.main.truncated, "primary log overflow was not contained");

	memset(&logs, 0, sizeof(logs));
	cdk2_tcg2_log_init(&logs.main, main_buffer, sizeof(main_buffer));
	guid_hob = (EFI_HOB_GUID_TYPE *)hob_bytes;
	guid_hob->header.hob_type = EFI_HOB_TYPE_GUID_EXTENSION;
	guid_hob->header.hob_length = sizeof(*guid_hob) + record_size;
	guid_hob->name = cdk2_tcg_event2_entry_hob_guid;
	memcpy(hob_bytes + sizeof(*guid_hob), main_buffer, record_size);
	end_hob = (EFI_HOB_GENERIC_HEADER *)(hob_bytes +
		((guid_hob->header.hob_length + 7U) & ~7U));
	end_hob->hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	end_hob->hob_length = sizeof(*end_hob);
	failures += expect(cdk2_tcg2_import_event2_hobs(&logs, hob_bytes,
		(const UINT8 *)end_hob + sizeof(*end_hob)) == EFI_SUCCESS &&
		logs.main.used == record_size, "event HOB import failed");
	hob_bytes[sizeof(*guid_hob) + 8] = 0xff;
	logs.main.used = 0;
	failures += expect(cdk2_tcg2_import_event2_hobs(&logs, hob_bytes,
		(const UINT8 *)end_hob + sizeof(*end_hob)) == EFI_COMPROMISED_DATA,
		"corrupt event HOB was accepted");
	guid_hob->header.hob_length = MAX_UINT16;
	failures += expect(cdk2_tcg2_import_event2_hobs(&logs, hob_bytes,
		(const UINT8 *)end_hob + sizeof(*end_hob)) == EFI_COMPROMISED_DATA,
		"overflowing HOB length was accepted");
	return failures == 0 ? 0 : 1;
}
