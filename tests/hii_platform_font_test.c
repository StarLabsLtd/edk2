/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>
#include <stdlib.h>

typedef char admitted_string_capacity[(CDK2_HII_MAX_STRINGS >= 4096U) ? 1 : -1];

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{ (void)context; *buffer = malloc(size); return *buffer == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS; }
static void release(void *context, void *buffer)
{ (void)context; free(buffer); }

int main(void)
{
	static const struct cdk2_hii_database_ops ops = { .allocate = allocate, .release = release };
	struct cdk2_hii_database database;
	FILE *fixture = fopen(HII_PLATFORM_SIMPLE_FONT_FIXTURE, "rb");
	UINT8 *list = NULL;
	void *handle = NULL;
	long size;
	int result = 1;

	if (fixture == NULL || fseek(fixture, 0, SEEK_END) != 0 ||
	    (size = ftell(fixture)) <= 0 || fseek(fixture, 0, SEEK_SET) != 0)
		goto out;
	list = malloc((UINTN)size);
	if (list == NULL || fread(list, 1, (UINTN)size, fixture) != (UINTN)size)
		goto out;
	(void)cdk2_hii_database_init(&database, &ops, NULL);
	if (cdk2_hii_new_package_list(&database, list, NULL, &handle) != EFI_SUCCESS ||
	    handle == NULL) {
		fprintf(stderr, "HII platform font test: valid default-glyph sentinel rejected\n");
		goto out;
	}
	result = 0;
out:
	free(list);
	if (fixture != NULL)
		(void)fclose(fixture);
	return result;
}
