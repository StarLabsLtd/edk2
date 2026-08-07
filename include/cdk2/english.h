/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#ifndef CDK2_ENGLISH_H
#define CDK2_ENGLISH_H

#include <uefi.h>

struct cdk2_unicode_collation;

typedef INTN CDK2_MS_ABI cdk2_stricoll_type(struct cdk2_unicode_collation *,
	CHAR16 *, CHAR16 *);
typedef BOOLEAN CDK2_MS_ABI cdk2_meta_match_type(struct cdk2_unicode_collation *,
	CHAR16 *, CHAR16 *);
typedef VOID CDK2_MS_ABI cdk2_str_case_type(struct cdk2_unicode_collation *, CHAR16 *);
typedef VOID CDK2_MS_ABI cdk2_fat_to_str_type(struct cdk2_unicode_collation *,
	UINTN, CHAR8 *, CHAR16 *);
typedef BOOLEAN CDK2_MS_ABI cdk2_str_to_fat_type(struct cdk2_unicode_collation *,
	CHAR16 *, UINTN, CHAR8 *);
typedef cdk2_stricoll_type * cdk2_stricoll_fn;
typedef cdk2_meta_match_type * cdk2_meta_match_fn;
typedef cdk2_str_case_type * cdk2_str_case_fn;
typedef cdk2_fat_to_str_type * cdk2_fat_to_str_fn;
typedef cdk2_str_to_fat_type * cdk2_str_to_fat_fn;

struct cdk2_unicode_collation {
	cdk2_stricoll_fn stri_coll;
	cdk2_meta_match_fn meta_match;
	cdk2_str_case_fn str_lwr;
	cdk2_str_case_fn str_upr;
	cdk2_fat_to_str_fn fat_to_str;
	cdk2_str_to_fat_fn str_to_fat;
	CHAR8 *supported_languages;
};

INTN CDK2_MS_ABI cdk2_english_stri_coll(struct cdk2_unicode_collation *, CHAR16 *, CHAR16 *);
BOOLEAN CDK2_MS_ABI cdk2_english_meta_match(struct cdk2_unicode_collation *, CHAR16 *, CHAR16 *);
VOID CDK2_MS_ABI cdk2_english_str_lwr(struct cdk2_unicode_collation *, CHAR16 *);
VOID CDK2_MS_ABI cdk2_english_str_upr(struct cdk2_unicode_collation *, CHAR16 *);
VOID CDK2_MS_ABI cdk2_english_fat_to_str(struct cdk2_unicode_collation *, UINTN,
	CHAR8 *, CHAR16 *);
BOOLEAN CDK2_MS_ABI cdk2_english_str_to_fat(struct cdk2_unicode_collation *, CHAR16 *,
	UINTN, CHAR8 *);
UINTN CDK2_MS_ABI cdk2_english_entry(VOID *, VOID *);

#endif
