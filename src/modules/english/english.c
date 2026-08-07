/* SPDX-License-Identifier: BSD-2-Clause-Patent */

/* Derived from the pre-standalone EnglishDxe implementation.
 * Copyright (c) 2006-2018 Intel Corporation.
 */

#include <stddef.h>
#include <stdint.h>
#include <cdk2/english.h>

#define MAP_SIZE 0x100U
#define FAT_VALID 1U

typedef UINTN CDK2_MS_ABI install_multiple_type(UINTN, UINTN, UINTN, ...);
typedef install_multiple_type * install_multiple_fn;

struct boot_services_view {
	uint8_t unused[328];
	install_multiple_fn install_multiple;
};

struct system_table_view {
	uint8_t unused[96];
	struct boot_services_view *boot;
};

static CHAR8 upper_map[MAP_SIZE];
static CHAR8 lower_map[MAP_SIZE];
static CHAR8 info_map[MAP_SIZE];
static VOID *protocol_handle;
static CHAR8 language[] = "en";
static const EFI_GUID collation2_guid = { 0xa4c751fc, 0x23ae, 0x4c3e,
	{ 0x92, 0xe9, 0x49, 0x64, 0xcf, 0x63, 0xf3, 0x49 } };
static const CHAR8 other_chars[] = "0123456789\\._^$~!#%&-{}()@`'";

static CHAR16 upper(CHAR16 character)
{
	return character < MAP_SIZE ? (uint8_t)upper_map[character] : character;
}

static CHAR16 lower(CHAR16 character)
{
	return character < MAP_SIZE ? (uint8_t)lower_map[character] : character;
}

static void initialize_maps(void)
{
	UINTN index;

	for (index = 0; index < MAP_SIZE; index++) {
		upper_map[index] = (CHAR8)index;
		lower_map[index] = (CHAR8)index;
		info_map[index] = 0;
		if ((index >= 'a' && index <= 'z') ||
		    (index >= 0xe0 && index <= 0xf6) ||
		    (index >= 0xf8 && index <= 0xfe)) {
			upper_map[index] = (CHAR8)(index - 0x20);
			lower_map[index - 0x20] = (CHAR8)index;
			info_map[index] |= FAT_VALID;
			info_map[index - 0x20] |= FAT_VALID;
		}
	}
	for (index = 0; other_chars[index] != 0; index++)
		info_map[(uint8_t)other_chars[index]] |= FAT_VALID;
}

INTN CDK2_MS_ABI cdk2_english_stri_coll(struct cdk2_unicode_collation *self,
	CHAR16 *first, CHAR16 *second)
{
	(void)self;
	while (*first != 0 && upper(*first) == upper(*second)) {
		first++;
		second++;
	}
	return (INTN)upper(*first) - (INTN)upper(*second);
}

VOID CDK2_MS_ABI cdk2_english_str_lwr(struct cdk2_unicode_collation *self, CHAR16 *string)
{
	(void)self;
	while (*string != 0) {
		*string = lower(*string);
		string++;
	}
}

VOID CDK2_MS_ABI cdk2_english_str_upr(struct cdk2_unicode_collation *self, CHAR16 *string)
{
	(void)self;
	while (*string != 0) {
		*string = upper(*string);
		string++;
	}
}

BOOLEAN CDK2_MS_ABI cdk2_english_meta_match(struct cdk2_unicode_collation *self,
	CHAR16 *string, CHAR16 *pattern)
{
	CHAR16 character, pattern_character, previous;

	for (;;) {
		pattern_character = *pattern++;
		switch (pattern_character) {
		case 0:
			return *string == 0;
		case '*':
			while (*string != 0) {
				if (cdk2_english_meta_match(self, string, pattern))
					return TRUE;
				string++;
			}
			return cdk2_english_meta_match(self, string, pattern);
		case '?':
			if (*string == 0)
				return FALSE;
			string++;
			break;
		case '[':
			character = *string;
			if (character == 0)
				return FALSE;
			previous = 0;
			pattern_character = *pattern++;
			while (pattern_character != 0) {
				if (pattern_character == ']')
					return FALSE;
				if (pattern_character == '-') {
					pattern_character = *pattern;
					if (pattern_character == 0 || pattern_character == ']')
						return FALSE;
					if (upper(character) >= upper(previous) &&
					    upper(character) <= upper(pattern_character))
						break;
				}
				previous = pattern_character;
				if (upper(character) == upper(pattern_character))
					break;
				pattern_character = *pattern++;
			}
			while (pattern_character != 0 && pattern_character != ']')
				pattern_character = *pattern++;
			string++;
			break;
		default:
			character = *string;
			if (upper(character) != upper(pattern_character))
				return FALSE;
			string++;
			break;
		}
	}
}

VOID CDK2_MS_ABI cdk2_english_fat_to_str(struct cdk2_unicode_collation *self,
	UINTN fat_size, CHAR8 *fat, CHAR16 *string)
{
	(void)self;
	while (*fat != 0 && fat_size != 0) {
		*string++ = (uint8_t)*fat++;
		fat_size--;
	}
	*string = 0;
}

BOOLEAN CDK2_MS_ABI cdk2_english_str_to_fat(struct cdk2_unicode_collation *self,
	CHAR16 *string, UINTN fat_size, CHAR8 *fat)
{
	BOOLEAN substituted = FALSE;

	(void)self;
	while (*string != 0 && fat_size != 0) {
		if (*string != '.' && *string != ' ') {
			if (*string < MAP_SIZE && (info_map[*string] & FAT_VALID) != 0)
				*fat = upper_map[*string];
			else {
				*fat = '_';
				substituted = TRUE;
			}
			fat++;
			fat_size--;
		}
		string++;
	}
	return substituted;
}

static struct cdk2_unicode_collation english = {
	cdk2_english_stri_coll,
	cdk2_english_meta_match,
	cdk2_english_str_lwr,
	cdk2_english_str_upr,
	cdk2_english_fat_to_str,
	cdk2_english_str_to_fat,
	language
};

UINTN CDK2_MS_ABI cdk2_english_entry(VOID *image, VOID *table)
{
	struct system_table_view *system_table = table;

	(void)image;
	initialize_maps();
	if (system_table == NULL || system_table->boot == NULL ||
	    system_table->boot->install_multiple == NULL)
		return 2;
	return system_table->boot->install_multiple((UINTN)&protocol_handle,
		(UINTN)&collation2_guid, (UINTN)&english, NULL);
}
