/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/device_path.h>

#define HW 1U
#define ACPI 2U

struct slice { const CHAR16 *p; UINTN n; };

static BOOLEAN equal(struct slice s, const char *a)
{
	UINTN i = 0;
	while (a[i] != 0 && i < s.n && s.p[i] == (CHAR16)(UINT8)a[i]) i++;
	return i == s.n && a[i] == 0;
}

static int hex(CHAR16 c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static BOOLEAN number(struct slice s, UINT64 max, UINT64 *v)
{
	UINTN i = 0; UINTN base = 10; UINT64 x = 0; int d;
	if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
		base = 16; i = 2;
	}
	if (i == s.n) return FALSE;
	for (; i < s.n; i++) {
		d = hex(s.p[i]);
		if (d < 0 || (UINTN)d >= base || x > (max - (UINTN)d) / base) return FALSE;
		x = x * base + (UINTN)d;
	}
	*v = x; return TRUE;
}

static BOOLEAN hex_number(struct slice s, UINT64 max, UINT64 *v)
{
	UINTN i; UINT64 x = 0; int d;
	if (s.n == 0) return FALSE;
	for (i = 0; i < s.n; i++) {
		d = hex(s.p[i]);
		if (d < 0 || x > (max - (UINTN)d) / 16) return FALSE;
		x = x * 16 + (UINTN)d;
	}
	*v = x; return TRUE;
}

static BOOLEAN bytes(struct slice s, UINT8 *out, UINTN *count)
{
	UINTN i;
	if ((s.n & 1) != 0) return FALSE;
	for (i = 0; i < s.n; i += 2) {
		int hi = hex(s.p[i]), lo = hex(s.p[i + 1]);
		if (hi < 0 || lo < 0) return FALSE;
		if (out != NULL) out[i / 2] = (UINT8)(hi * 16 + lo);
	}
	*count = s.n / 2; return TRUE;
}

static void put16(UINT8 *p, UINT16 v) { p[0] = (UINT8)v; p[1] = (UINT8)(v >> 8); }
static void put32(UINT8 *p, UINT32 v) { put16(p, (UINT16)v); put16(p + 2, (UINT16)(v >> 16)); }
static void put64(UINT8 *p, UINT64 v) { put32(p, (UINT32)v); put32(p + 4, (UINT32)(v >> 32)); }

static BOOLEAN guid(struct slice s, UINT8 *out)
{
	static const UINT8 groups[] = {8, 4, 4, 4, 12};
	UINTN g, at = 0, byte = 0; UINT64 value;
	if (s.n != 36) return FALSE;
	for (g = 0; g < 5; g++) {
		struct slice part = {s.p + at, groups[g]};
		if (!hex_number(part, g == 0 ? MAX_UINT32 : g < 3 ? MAX_UINT16 : MAX_UINT64, &value)) return FALSE;
		if (out != NULL) {
			if (g == 0) put32(out, (UINT32)value);
			else if (g < 3) put16(out + (g == 1 ? 4 : 6), (UINT16)value);
			else {
				UINTN j;
				for (j = groups[g] / 2; j != 0; j--) out[8 + byte++] = (UINT8)(value >> ((j - 1) * 8));
			}
		}
		at += groups[g]; if (g != 4 && s.p[at++] != '-') return FALSE;
	}
	return TRUE;
}

static BOOLEAN eisa(struct slice s, UINT32 *id)
{
	UINT64 product; UINT32 letters;
	if (s.n != 7 || s.p[0] < '@' || s.p[0] > 'Z' || s.p[1] < '@' ||
	    s.p[1] > 'Z' || s.p[2] < '@' || s.p[2] > 'Z' ||
	    !hex_number((struct slice){s.p + 3, 4}, MAX_UINT16, &product)) return FALSE;
	letters = ((UINT32)(s.p[0] - 'A' + 1) << 10) |
		((UINT32)(s.p[1] - 'A' + 1) << 5) | (UINT32)(s.p[2] - 'A' + 1);
	*id = letters | (UINT32)product << 16; return TRUE;
}

static BOOLEAN args(struct slice inside, struct slice *a, UINTN capacity, UINTN *count)
{
	UINTN start = 0, n = 0, i;
	for (i = 0; i <= inside.n; i++) if (i == inside.n || inside.p[i] == ',') {
		if (n == capacity) return FALSE;
		a[n++] = (struct slice){inside.p + start, i - start}; start = i + 1;
	}
	*count = n; return TRUE;
}

static void header(UINT8 *p, UINT8 type, UINT8 subtype, UINT16 length)
{ if (p != NULL) { p[0] = type; p[1] = subtype; put16(p + 2, length); } }

static EFI_STATUS parse_raw(struct slice name, struct slice *a, UINTN n,
	UINT8 *out, UINTN *size)
{
	UINT64 subtype; UINTN data = 0; UINT8 type;
	if (equal(name, "HardwarePath")) type = HW;
	else if (equal(name, "AcpiPath")) type = ACPI;
	else return EFI_UNSUPPORTED;
	if ((n != 1 && n != 2) || !number(a[0], MAX_UINT8, &subtype) ||
	    (n == 2 && !bytes(a[1], out == NULL ? NULL : out + 4, &data)) ||
	    data > MAX_UINT16 - 4) return EFI_INVALID_PARAMETER;
	*size = 4 + data; header(out, type, (UINT8)subtype, (UINT16)*size); return EFI_SUCCESS;
}

static EFI_STATUS parse_hw(struct slice name, struct slice *a, UINTN n,
	UINT8 *out, UINTN *size)
{
	UINT64 x[3]; UINTN data; UINT8 subtype; UINT16 length;
	if (equal(name, "Pci") && n == 2 && number(a[0], 255, &x[0]) && number(a[1], 255, &x[1])) {
		subtype = 1; length = 6; if (out) { out[4] = (UINT8)x[1]; out[5] = (UINT8)x[0]; }
	} else if (equal(name, "PcCard") && n == 1 && number(a[0], 255, &x[0])) {
		subtype = 2; length = 5; if (out) out[4] = (UINT8)x[0];
	} else if (equal(name, "MemoryMapped") && n == 3 && number(a[0], MAX_UINT32, &x[0]) &&
	    number(a[1], MAX_UINT64, &x[1]) && number(a[2], MAX_UINT64, &x[2])) {
		subtype = 3; length = 24; if (out) { put32(out + 4, (UINT32)x[0]); put64(out + 8, x[1]); put64(out + 16, x[2]); }
	} else if (equal(name, "VenHw") && (n == 1 || n == 2) && guid(a[0], out ? out + 4 : NULL) &&
	    (n == 1 || bytes(a[1], out ? out + 20 : NULL, &data)) && (n != 1 || (data = 0, TRUE)) && data <= MAX_UINT16 - 20) {
		subtype = 4; length = (UINT16)(20 + data);
	} else if (equal(name, "Ctrl") && n == 1 && number(a[0], MAX_UINT32, &x[0])) {
		subtype = 5; length = 8; if (out) put32(out + 4, (UINT32)x[0]);
	} else if (equal(name, "BMC") && n == 2 && number(a[0], 255, &x[0]) && number(a[1], MAX_UINT64, &x[1])) {
		subtype = 6; length = 13; if (out) { out[4] = (UINT8)x[0]; put64(out + 5, x[1]); }
	} else return EFI_UNSUPPORTED;
	*size = length; header(out, HW, subtype, length); return EFI_SUCCESS;
}

static EFI_STATUS hid_alias(struct slice name, UINT32 *hid)
{
	static const struct { const char *name; UINT32 hid; } aliases[] = {
		{"PciRoot",0x0a0341d0},{"PcieRoot",0x0a0841d0},{"Floppy",0x060441d0},
		{"Keyboard",0x030141d0},{"Serial",0x050141d0},{"ParallelPort",0x040141d0}};
	UINTN i;
	for (i = 0; i < ARRAY_SIZE(aliases); i++) if (equal(name, aliases[i].name)) { *hid = aliases[i].hid; return EFI_SUCCESS; }
	return EFI_UNSUPPORTED;
}

static EFI_STATUS parse_acpi(struct slice name, struct slice *a, UINTN n,
	UINT8 *out, UINTN *size)
{
	UINT64 value; UINT32 hid, cid; UINTN i, length;
	if (!EFI_ERROR(hid_alias(name, &hid))) {
		if (n != 1 || !number(a[0], MAX_UINT32, &value)) return EFI_INVALID_PARAMETER;
		length = 12; if (out) { put32(out + 4, hid); put32(out + 8, (UINT32)value); }
		header(out, ACPI, 1, 12); *size = 12; return EFI_SUCCESS;
	}
	if (equal(name, "Acpi")) {
		if (n != 2 || (!eisa(a[0], &hid) && !number(a[0], MAX_UINT32, &value)) ||
		    !number(a[1], MAX_UINT32, &value)) return EFI_INVALID_PARAMETER;
		if (!eisa(a[0], &hid)) { number(a[0], MAX_UINT32, &value); hid = (UINT32)value; }
		if (out) { put32(out + 4, hid); number(a[1], MAX_UINT32, &value); put32(out + 8, (UINT32)value); }
		header(out, ACPI, 1, 12); *size = 12; return EFI_SUCCESS;
	}
	if (equal(name, "AcpiAdr")) {
		if (n == 0 || n > (MAX_UINT16 - 4) / 4) return EFI_INVALID_PARAMETER;
		for (i = 0; i < n; i++) if (!number(a[i], MAX_UINT32, &value)) return EFI_INVALID_PARAMETER;
		length = 4 + 4 * n; header(out, ACPI, 3, (UINT16)length);
		if (out) for (i = 0; i < n; i++) { number(a[i], MAX_UINT32, &value); put32(out + 4 + i * 4, (UINT32)value); }
		*size = length; return EFI_SUCCESS;
	}
	if (equal(name, "AcpiExp")) {
		if (n != 3 || !eisa(a[0], &hid) ||
		    !(equal(a[1], "0") ? (cid = 0, TRUE) : eisa(a[1], &cid)) || a[2].n == 0) return EFI_INVALID_PARAMETER;
		length = 19 + a[2].n; if (length > MAX_UINT16) return EFI_INVALID_PARAMETER;
		header(out, ACPI, 2, (UINT16)length); if (out) {
			put32(out + 4, hid); put32(out + 8, 0); put32(out + 12, cid); out[16] = 0;
			for (i = 0; i < a[2].n; i++) { if (a[2].p[i] > 255) return EFI_INVALID_PARAMETER; out[17 + i] = (UINT8)a[2].p[i]; }
			out[17 + a[2].n] = 0; out[18 + a[2].n] = 0;
		}
		*size = length; return EFI_SUCCESS;
	}
	if (equal(name, "AcpiEx")) {
		if (n != 6 || !eisa(a[0], &hid) || !eisa(a[1], &cid) || !number(a[2], MAX_UINT32, &value)) return EFI_INVALID_PARAMETER;
		length = 19 + a[3].n + a[4].n + a[5].n; if (length > MAX_UINT16) return EFI_INVALID_PARAMETER;
		header(out, ACPI, 2, (UINT16)length); if (out) {
			static const UINT8 order[] = {3, 5, 4};
			UINTN at = 16; put32(out + 4, hid); put32(out + 8, (UINT32)value); put32(out + 12, cid);
			for (i = 0; i < ARRAY_SIZE(order); i++) { UINTN j; UINTN which = order[i]; for (j = 0; j < a[which].n; j++) { if (a[which].p[j] > 255) return EFI_INVALID_PARAMETER; out[at++] = (UINT8)a[which].p[j]; } out[at++] = 0; }
		}
		*size = length; return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}

static EFI_STATUS parse_node(struct slice text, UINT8 *out, UINTN *size)
{
	UINTN i, count; struct slice name, inside, a[64]; EFI_STATUS status;
	for (i = 0; i < text.n && text.p[i] != '('; i++);
	if (i == 0 || i + 1 >= text.n || text.p[text.n - 1] != ')') return EFI_INVALID_PARAMETER;
	name = (struct slice){text.p, i}; inside = (struct slice){text.p + i + 1, text.n - i - 2};
	if (!args(inside, a, ARRAY_SIZE(a), &count)) return EFI_INVALID_PARAMETER;
	status = parse_hw(name, a, count, out, size); if (status != EFI_UNSUPPORTED) return status;
	status = parse_acpi(name, a, count, out, size); if (status != EFI_UNSUPPORTED) return status;
	status = parse_raw(name, a, count, out, size); return status == EFI_UNSUPPORTED ? EFI_INVALID_PARAMETER : status;
}

static EFI_STATUS parse_path(const CHAR16 *text, UINT8 *out, UINTN *total)
{
	UINTN at = 0, start = 0, depth = 0, used = 0, node_size; EFI_STATUS status;
	if (text == NULL || text[0] == 0) return EFI_INVALID_PARAMETER;
	for (;;) {
		CHAR16 c = text[at];
		if (c == '(') depth++; else if (c == ')') { if (depth == 0) return EFI_INVALID_PARAMETER; depth--; }
		if ((c == '/' || c == ',' || c == 0) && depth == 0) {
			if (at == start) return EFI_INVALID_PARAMETER;
			status = parse_node((struct slice){text + start, at - start}, out ? out + used : NULL, &node_size);
			if (EFI_ERROR(status) || node_size > CDK2_DEVICE_PATH_MAX_SIZE - used - 4) return EFI_ERROR(status) ? status : EFI_OUT_OF_RESOURCES;
			used += node_size;
			if (c == ',' && out) header(out + used, CDK2_DEVICE_PATH_END_TYPE, CDK2_DEVICE_PATH_END_INSTANCE, 4);
			if (c == ',') used += 4;
			start = at + 1;
			if (c == 0) break;
		}
		if (c == 0) { if (depth != 0) return EFI_INVALID_PARAMETER; break; } at++;
	}
	if (out) header(out + used, CDK2_DEVICE_PATH_END_TYPE, CDK2_DEVICE_PATH_END_ENTIRE, 4);
	*total = used + 4; return EFI_SUCCESS;
}

static BOOLEAN allocator_valid(const struct cdk2_device_path_allocator *a)
{ return a != NULL && a->allocate != NULL && a->free != NULL; }

EFI_STATUS cdk2_device_path_from_text(const CHAR16 *text,
	const struct cdk2_device_path_allocator *allocator, struct cdk2_device_path **path)
{
	UINTN size, written; EFI_STATUS status;
	if (!allocator_valid(allocator) || path == NULL) return EFI_INVALID_PARAMETER;
	*path = NULL; status = parse_path(text, NULL, &size); if (EFI_ERROR(status)) return status;
	status = allocator->allocate(allocator->context, size, (void **)path); if (EFI_ERROR(status)) return status;
	status = parse_path(text, (UINT8 *)*path, &written);
	if (EFI_ERROR(status) || written != size) { allocator->free(allocator->context, *path); *path = NULL; return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA; }
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_device_path_node_from_text(const CHAR16 *text,
	const struct cdk2_device_path_allocator *allocator, struct cdk2_device_path **node)
{
	UINTN n = 0, size, written; EFI_STATUS status;
	if (!allocator_valid(allocator) || node == NULL || text == NULL) return EFI_INVALID_PARAMETER;
	*node = NULL; while (text[n] != 0) n++;
	status = parse_node((struct slice){text, n}, NULL, &size); if (EFI_ERROR(status)) return status;
	status = allocator->allocate(allocator->context, size, (void **)node); if (EFI_ERROR(status)) return status;
	status = parse_node((struct slice){text, n}, (UINT8 *)*node, &written);
	if (EFI_ERROR(status) || written != size) { allocator->free(allocator->context, *node); *node = NULL; return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA; }
	return EFI_SUCCESS;
}
