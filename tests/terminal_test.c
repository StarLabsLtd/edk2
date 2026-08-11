/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/terminal.h>

#include <stdio.h>
#include <string.h>

static uint8_t output[256];
static size_t output_size;

static uint64_t CDK2_MS_ABI mock_write(void *serial, size_t size,
				       size_t *written, const void *data)
{
	(void)serial;
	if (size > sizeof(output) - output_size)
		return EFI_OUT_OF_RESOURCES;
	memcpy(output + output_size, data, size);
	output_size += size;
	*written = size;
	return EFI_SUCCESS;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "terminal test: %s\n", message);
	return condition ? 0 : 1;
}

int main(void)
{
	struct cdk2_terminal terminal;
	struct cdk2_terminal_key key;
	static const uint8_t input[] = {'A', 0x1b, '[', 'A', 0xc2, 0xa3};
	static const uint16_t text[] = {'x', 0x00a3, 0};
	int failures = 0;
	size_t i;

	cdk2_terminal_init(&terminal, CDK2_TERMINAL_VT_UTF8, NULL, mock_write);
	failures += expect(cdk2_terminal_input(&terminal, input,
					       sizeof(input)) == EFI_SUCCESS,
			   "ASCII, escape, and UTF-8 input accepted");
	failures +=
		expect(cdk2_terminal_read_key(&terminal, &key) == EFI_SUCCESS &&
			       key.unicode_char == 'A',
		       "ASCII key queued");
	failures +=
		expect(cdk2_terminal_read_key(&terminal, &key) == EFI_SUCCESS &&
			       key.scan_code == 1,
		       "cursor-up escape decoded");
	failures +=
		expect(cdk2_terminal_read_key(&terminal, &key) == EFI_SUCCESS &&
			       key.unicode_char == 0x00a3,
		       "UTF-8 decoded");
	failures +=
		expect(cdk2_terminal_read_key(&terminal, &key) == EFI_NOT_READY,
		       "empty queue reports not-ready");
	failures += expect(
		cdk2_terminal_output(&terminal, text) == EFI_SUCCESS &&
			output_size == 3 && memcmp(output, "x\xc2\xa3", 3) == 0,
		"UTF-16 output encoded as UTF-8");
	failures += expect(cdk2_terminal_input(&terminal,
					       (const uint8_t *)"\x1b[999~",
					       6) == EFI_INVALID_PARAMETER,
			   "unknown escape rejected without stale state");
	for (i = 0; i < CDK2_TERMINAL_QUEUE - 1; i++)
		failures += expect(cdk2_terminal_input(&terminal,
						       (const uint8_t *)"z",
						       1) == EFI_SUCCESS,
				   "queue fill");
	failures += expect(cdk2_terminal_input(&terminal, (const uint8_t *)"z",
					       1) == EFI_OUT_OF_RESOURCES,
			   "queue overflow rejected");
	cdk2_terminal_init(&terminal, CDK2_TERMINAL_VT_UTF8, NULL, mock_write);
	failures += expect(cdk2_terminal_input(&terminal,
					       (const uint8_t *)"\xc0\x80",
					       2) == EFI_INVALID_PARAMETER,
			   "overlong UTF-8 rejected");
	return failures == 0 ? 0 : 1;
}
