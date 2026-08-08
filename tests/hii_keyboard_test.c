/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/hii_database.h>
#include <stdio.h>

static UINTN notifications;
static void notify(void *context, const EFI_GUID *layout)
{ (void)context; (void)layout; notifications++; }
static int expect(int condition, const char *message)
{ if (!condition) fprintf(stderr, "HII keyboard test: %s\n", message); return !condition; }
int main(void)
{
	struct cdk2_hii_database database = { 0 };
	EFI_GUID first = { .data1 = 1U }, second = { .data1 = 2U }, current;
	EFI_GUID layouts[2]; UINT16 count = 2U; int failures = 0;
	(void)cdk2_hii_add_keyboard_layout(&database, &first);
	(void)cdk2_hii_add_keyboard_layout(&database, &second);
	cdk2_hii_set_keyboard_notify(&database, notify, NULL);
	failures += expect(cdk2_hii_set_keyboard_layout(&database, &second) ==
		EFI_SUCCESS && notifications == 1U &&
		cdk2_hii_get_keyboard_layout(&database, &current) == EFI_SUCCESS &&
		current.data1 == 2U, "layout selection or notification failed");
	failures += expect(cdk2_hii_find_keyboard_layouts(&database, &count, layouts) ==
		EFI_SUCCESS && count == 2U && layouts[0].data1 == 1U,
		"layout enumeration failed");
	return failures == 0 ? 0 : 1;
}
