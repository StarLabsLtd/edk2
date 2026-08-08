/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer) { (void)context; free(buffer); }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII config test: %s\n", message); return !condition; }
int main(void)
{
	static const struct cdk2_hii_database_ops ops = { allocate, release };
	struct cdk2_hii_database database = { .ops = &ops };
	UINT8 source[8] = { 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U };
	UINT8 destination[8] = { 0 };
	CHAR16 *configuration;
	const CHAR16 *progress;
	UINTN size = sizeof(destination);
	int failures = 0;

	failures += expect(cdk2_hii_block_to_config(&database,
		L"GUID=x&OFFSET=2&WIDTH=3", source, sizeof(source), &configuration,
		&progress) == EFI_SUCCESS &&
		cdk2_hii_config_to_block(configuration, destination, &size, &progress) ==
			EFI_SUCCESS && destination[2] == 2U && destination[4] == 4U,
		"block/config round trip failed");
	failures += expect(cdk2_hii_block_to_config(&database,
		L"GUID=x&OFFSET=7&WIDTH=2", source, sizeof(source), &configuration,
		&progress) == EFI_INVALID_PARAMETER,
		"out-of-range request was accepted");
	return failures == 0 ? 0 : 1;
}
