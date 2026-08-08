/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/tcg2_transport.h>
#include <stdio.h>

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "tcg2-transport test: %s\n", message);
	return !condition;
}

int main(void)
{
	UINT8 command[] = { 0x80, 0x01, 0, 0, 0, 12, 0, 0, 1, 0x44, 0, 0 };
	UINT8 response[] = { 0x80, 0x01, 0, 0, 0, 10, 0, 0, 0, 0 };
	struct cdk2_tpm2_response header;
	int failures = 0;

	failures += expect(cdk2_tpm2_detect_interface(0x00002100U, 0x30000697U) ==
		CDK2_TPM2_INTERFACE_FIFO, "QEMU FIFO interface not detected");
	failures += expect(cdk2_tpm2_detect_interface(0x00025811U, 0) ==
		CDK2_TPM2_INTERFACE_CRB, "QEMU CRB interface not detected");
	failures += expect(cdk2_tpm2_detect_interface(0x0000000fU, 0) ==
		CDK2_TPM2_INTERFACE_TIS, "legacy TIS interface not detected");
	failures += expect(cdk2_tpm2_detect_interface(0xffffffffU, 0xffffffffU) ==
		CDK2_TPM2_INTERFACE_INVALID, "absent TPM was accepted");
	failures += expect(cdk2_tpm2_validate_command(command, sizeof(command)) ==
		EFI_SUCCESS, "valid command rejected");
	command[5] = 10;
	failures += expect(cdk2_tpm2_validate_command(command, sizeof(command)) ==
		EFI_COMPROMISED_DATA, "mismatched command size accepted");
	failures += expect(cdk2_tpm2_parse_response(response, sizeof(response), &header) ==
		EFI_SUCCESS && header.size == 10U && header.code == 0,
		"valid response rejected");
	response[5] = 11;
	failures += expect(cdk2_tpm2_parse_response(response, sizeof(response), &header) ==
		EFI_BUFFER_TOO_SMALL, "oversized response accepted");
	response[0] = 0;
	failures += expect(cdk2_tpm2_parse_response(response, sizeof(response), &header) ==
		EFI_COMPROMISED_DATA, "invalid response tag accepted");
	return failures == 0 ? 0 : 1;
}
