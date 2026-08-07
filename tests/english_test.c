/* SPDX-License-Identifier: GPL-2.0-only */

#include <stdio.h>
#include <string.h>
#include "../src/modules/english/english.c"

static UINTN installed;

static UINTN CDK2_MS_ABI install_protocol(UINTN handle_address, UINTN guid_address,
	UINTN interface_address, ...)
{
	VOID **handle = (VOID **)handle_address;
	const EFI_GUID *guid = (const EFI_GUID *)guid_address;
	struct cdk2_unicode_collation *protocol =
		(struct cdk2_unicode_collation *)interface_address;

	if (handle == NULL || guid->data1 != 0xa4c751fc || protocol == NULL ||
	    strcmp(protocol->supported_languages, "en") != 0)
		return 3;
	installed++;
	return 0;
}

static int expect(int condition, const char *message)
{
	if (condition)
		return 0;
	fprintf(stderr, "english_test: %s\n", message);
	return 1;
}

int main(void)
{
	struct boot_services_view boot = { 0 };
	struct system_table_view system = { 0 };
	CHAR16 mixed[] = { 'a', 'B', 0xe9, 0 };
	CHAR16 upper_expected[] = { 'A', 'B', 0xc9, 0 };
	CHAR16 pattern_string[] = { 'F', 'i', 'l', 'e', '7', 0 };
	CHAR16 pattern[] = { 'f', '*', '[', '0', '-', '9', ']', 0 };
	CHAR16 bad_pattern[] = { '[', 'a', ']', 0 };
	CHAR16 fat_source[] = { 'a', '.', 'b', ' ', 0x2603, 'c', 0 };
	CHAR8 fat[8] = { 0 };
	CHAR16 expanded[8] = { 0 };
	int failed = 0;

	boot.install_multiple = install_protocol;
	system.boot = &boot;
	failed |= expect(cdk2_english_entry(NULL, &system) == 0 && installed == 1,
		"entry did not install Unicode Collation 2");
	failed |= expect(cdk2_english_stri_coll(&english, mixed, upper_expected) == 0,
		"case-insensitive comparison failed");
	cdk2_english_str_upr(&english, mixed);
	failed |= expect(memcmp(mixed, upper_expected, sizeof(mixed)) == 0,
		"upper-case mapping failed");
	cdk2_english_str_lwr(&english, mixed);
	failed |= expect(mixed[0] == 'a' && mixed[1] == 'b' && mixed[2] == 0xe9,
		"lower-case mapping failed");
	failed |= expect(cdk2_english_meta_match(&english, pattern_string, pattern),
		"wildcard/range match failed");
	failed |= expect(!cdk2_english_meta_match(&english, pattern_string, bad_pattern),
		"non-match was accepted");
	failed |= expect(cdk2_english_str_to_fat(&english, fat_source, sizeof(fat), fat) &&
		memcmp(fat, "AB_C", 4) == 0, "FAT substitution failed");
	cdk2_english_fat_to_str(&english, 4, fat, expanded);
	failed |= expect(expanded[0] == 'A' && expanded[3] == 'C' && expanded[4] == 0,
		"FAT expansion failed");
	return failed;
}
