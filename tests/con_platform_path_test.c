/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/con_platform.h>
#include <stdio.h>

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "con platform path test: %s\n", message);
	return !condition;
}

int main(void)
{
	UINT8 gop_a[] = { 1, 1, 4, 0, 2, 3, 4, 0, 0x7f, 0xff, 4, 0 };
	UINT8 gop_b[] = { 1, 1, 4, 0, 1, 5, 4, 0, 2, 3, 4, 0, 0x7f, 0xff, 4, 0 };
	UINT8 class_path[] = { 3, 0x0f, 11, 0, 0xff, 0xff, 0xff, 0xff, 3, 1, 1,
		0x7f, 0xff, 4, 0 };
	UINT8 wwid_path[] = { 3, 0x10, 16, 0, 2, 0, 0x34, 0x12, 0x78, 0x56,
		'1', 0, '2', 0, '3', 0, 0x7f, 0xff, 4, 0 };
	static const CHAR16 serial[] = { 'A', 'B', 'C', '1', '2', '3', 0 };
	struct cdk2_usb_identity usb = { 0x1234, 0x5678, 0, 0, 0, 2, 3, 1, 1, serial };
	int failures = 0;

	failures += expect(cdk2_con_path_valid(gop_a, sizeof(gop_a)),
		"valid path rejected");
	gop_a[2] = 3;
	failures += expect(!cdk2_con_path_valid(gop_a, sizeof(gop_a)),
		"short node accepted");
	gop_a[2] = 4;
	failures += expect(cdk2_con_gop_siblings(gop_a, sizeof(gop_a), gop_b, sizeof(gop_b)),
		"GOP children with the same parent did not match");
	failures += expect(cdk2_con_usb_short_match(&usb, class_path, sizeof(class_path)),
		"USB class wildcard/IAD match failed");
	class_path[12] = CDK2_DP_END_INSTANCE;
	failures += expect(cdk2_con_path_instance_match(gop_a, sizeof(gop_a), class_path,
		sizeof(class_path), &usb), "USB short-form instance terminator was rejected");
	class_path[12] = CDK2_DP_END_ENTIRE;
	failures += expect(cdk2_con_usb_short_match(&usb, wwid_path, sizeof(wwid_path)),
		"USB WWID serial suffix match failed");
	wwid_path[10] = '9';
	failures += expect(!cdk2_con_usb_short_match(&usb, wwid_path, sizeof(wwid_path)),
		"wrong USB WWID suffix matched");
	class_path[8] = 8;
	failures += expect(!cdk2_con_usb_short_match(&usb, class_path, sizeof(class_path)),
		"wrong USB class matched");
	return failures == 0 ? 0 : 1;
}
