/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/con_platform.h>

static UINT16 read16(const void *pointer)
{
	const UINT8 *bytes = pointer;

	return (UINT16)(bytes[0] | ((UINT16)bytes[1] << 8));
}

static BOOLEAN bytes_equal(const void *left, const void *right, UINTN size)
{
	const UINT8 *a = left, *b = right;
	UINTN index;

	for (index = 0; index < size; index++)
		if (a[index] != b[index])
			return FALSE;
	return TRUE;
}

static const struct cdk2_dp_node *next_node(const struct cdk2_dp_node *node)
{
	return (const void *)((const UINT8 *)node + read16(&node->length));
}

static BOOLEAN path_valid(const void *path, UINTN size, BOOLEAN allow_instance)
{
	const struct cdk2_dp_node *node = path;
	const UINT8 *end = (const UINT8 *)path + size;
	UINT16 length;

	if (path == NULL || size < sizeof(*node))
		return FALSE;
	while ((const UINT8 *)node + sizeof(*node) <= end) {
		length = read16(&node->length);
		if (length < sizeof(*node) || (const UINT8 *)node + length > end)
			return FALSE;
		if (node->type == CDK2_DP_END &&
		    (node->subtype == CDK2_DP_END_ENTIRE ||
		     (allow_instance && node->subtype == CDK2_DP_END_INSTANCE)))
			return (const UINT8 *)node + length == end;
		node = next_node(node);
	}
	return FALSE;
}

BOOLEAN cdk2_con_path_valid(const void *path, UINTN size)
{
	return path_valid(path, size, FALSE);
}

static const UINT8 *gop_prefix_end(const void *path, UINTN size)
{
	const struct cdk2_dp_node *node = path;
	const UINT8 *end = (const UINT8 *)path + size;

	while ((const UINT8 *)node + sizeof(*node) <= end) {
		UINT16 length = read16(&node->length);
		const struct cdk2_dp_node *next;

		if (length < sizeof(*node) || (const UINT8 *)node + length > end)
			return NULL;
		if (node->type == CDK2_DP_ACPI && node->subtype == CDK2_DP_ACPI_ADR)
			return (const UINT8 *)node;
		next = next_node(node);
		if (node->type == CDK2_DP_HARDWARE && node->subtype == CDK2_DP_CONTROLLER &&
		    (const UINT8 *)next + sizeof(*next) <= end &&
		    next->type == CDK2_DP_ACPI && next->subtype == CDK2_DP_ACPI_ADR)
			return (const UINT8 *)node;
		if (node->type == CDK2_DP_END)
			return NULL;
		node = next;
	}
	return NULL;
}

BOOLEAN cdk2_con_gop_siblings(const void *left, UINTN left_size,
	const void *right, UINTN right_size)
{
	const UINT8 *left_end = gop_prefix_end(left, left_size);
	const UINT8 *right_end = gop_prefix_end(right, right_size);
	UINTN prefix;

	if (left_end == NULL || right_end == NULL)
		return FALSE;
	prefix = (UINTN)(left_end - (const UINT8 *)left);
	if (prefix != (UINTN)(right_end - (const UINT8 *)right))
		return FALSE;
	return bytes_equal(left, right, prefix);
}

static BOOLEAN wildcard(UINT8 expected, UINT8 actual)
{
	return expected == 0xffU || expected == actual;
}

static BOOLEAN match_class(const struct cdk2_usb_identity *usb, const UINT8 *node,
	UINT16 length)
{
	UINT16 vendor, product;
	UINT8 device_class, subclass, protocol;

	if (length < 11U)
		return FALSE;
	vendor = read16(node + 4);
	product = read16(node + 6);
	if ((vendor != 0xffffU && vendor != usb->vendor) ||
	    (product != 0xffffU && product != usb->product))
		return FALSE;
	device_class = usb->device_class;
	subclass = usb->device_subclass;
	protocol = usb->device_protocol;
	if (device_class == 0U || (device_class == 0xefU && subclass == 2U && protocol == 1U)) {
		device_class = usb->interface_class;
		subclass = usb->interface_subclass;
		protocol = usb->interface_protocol;
	}
	return wildcard(node[8], device_class) && wildcard(node[9], subclass) &&
		wildcard(node[10], protocol);
}

static BOOLEAN match_wwid(const struct cdk2_usb_identity *usb, const UINT8 *node,
	UINT16 length)
{
	const CHAR16 *suffix;
	UINTN suffix_length, serial_length = 0;

	if (length < 10U || read16(node + 6) != usb->vendor ||
	    read16(node + 8) != usb->product || read16(node + 4) != usb->interface_number ||
	    usb->serial == NULL || ((length - 10U) & 1U) != 0U)
		return FALSE;
	suffix = (const void *)(node + 10);
	suffix_length = (length - 10U) / sizeof(CHAR16);
	if (suffix_length != 0U && suffix[suffix_length - 1U] == 0U)
		suffix_length--;
	while (usb->serial[serial_length] != 0U)
		serial_length++;
	return suffix_length != 0U && serial_length >= suffix_length &&
		bytes_equal(usb->serial + serial_length - suffix_length, suffix,
			suffix_length * sizeof(CHAR16));
}

BOOLEAN cdk2_con_usb_short_match(const struct cdk2_usb_identity *usb,
	const void *short_path, UINTN short_size)
{
	const struct cdk2_dp_node *node = short_path;
	const UINT8 *end = (const UINT8 *)short_path + short_size;

	if (usb == NULL || short_path == NULL)
		return FALSE;
	while ((const UINT8 *)node + sizeof(*node) <= end) {
		UINT16 length = read16(&node->length);

		if (length < sizeof(*node) || (const UINT8 *)node + length > end)
			return FALSE;
		if (node->type == CDK2_DP_MESSAGING && node->subtype == CDK2_DP_USB_CLASS)
			return match_class(usb, (const UINT8 *)node, length);
		if (node->type == CDK2_DP_MESSAGING && node->subtype == CDK2_DP_USB_WWID)
			return match_wwid(usb, (const UINT8 *)node, length);
		if (node->type == CDK2_DP_END)
			return FALSE;
		node = next_node(node);
	}
	return FALSE;
}

BOOLEAN cdk2_con_path_instance_match(const void *single, UINTN single_size,
	const void *instance, UINTN instance_size, const struct cdk2_usb_identity *usb)
{
	if (!cdk2_con_path_valid(single, single_size) ||
	    !path_valid(instance, instance_size, TRUE))
		return FALSE;
	if (single_size == instance_size &&
	    bytes_equal(single, instance, single_size))
		return TRUE;
	return cdk2_con_gop_siblings(single, single_size, instance, instance_size) ||
		cdk2_con_usb_short_match(usb, instance, instance_size);
}
