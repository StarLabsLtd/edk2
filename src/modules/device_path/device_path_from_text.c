/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/device_path.h>

#define HW 1U
#define ACPI 2U
#define MSG 3U

struct slice {
	const CHAR16 *p;
	UINTN n;
};

static BOOLEAN equal(struct slice s, const char *a)
{
	UINTN i = 0;
	while (a[i] != 0 && i < s.n && s.p[i] == (CHAR16)(UINT8)a[i])
		i++;
	return i == s.n && a[i] == 0;
}

static int hex(CHAR16 c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static BOOLEAN number(struct slice s, UINT64 max, UINT64 *v)
{
	UINTN i = 0;
	UINTN base = 10;
	UINT64 x = 0;
	int d;
	if (s.n > 2 && s.p[0] == '0' && (s.p[1] == 'x' || s.p[1] == 'X')) {
		base = 16;
		i = 2;
	}
	if (i == s.n)
		return FALSE;
	for (; i < s.n; i++) {
		d = hex(s.p[i]);
		if (d < 0 || (UINTN)d >= base || x > (max - (UINTN)d) / base)
			return FALSE;
		x = x * base + (UINTN)d;
	}
	*v = x;
	return TRUE;
}

static BOOLEAN hex_number(struct slice s, UINT64 max, UINT64 *v)
{
	UINTN i;
	UINT64 x = 0;
	int d;
	if (s.n == 0)
		return FALSE;
	for (i = 0; i < s.n; i++) {
		d = hex(s.p[i]);
		if (d < 0 || x > (max - (UINTN)d) / 16)
			return FALSE;
		x = x * 16 + (UINTN)d;
	}
	*v = x;
	return TRUE;
}

static BOOLEAN bytes(struct slice s, UINT8 *out, UINTN *count)
{
	UINTN i;
	if ((s.n & 1) != 0)
		return FALSE;
	for (i = 0; i < s.n; i += 2) {
		int hi = hex(s.p[i]), lo = hex(s.p[i + 1]);
		if (hi < 0 || lo < 0)
			return FALSE;
		if (out != NULL)
			out[i / 2] = (UINT8)(hi * 16 + lo);
	}
	*count = s.n / 2;
	return TRUE;
}

static void put16(UINT8 *p, UINT16 v)
{
	p[0] = (UINT8)v;
	p[1] = (UINT8)(v >> 8);
}
static void put32(UINT8 *p, UINT32 v)
{
	put16(p, (UINT16)v);
	put16(p + 2, (UINT16)(v >> 16));
}
static void put64(UINT8 *p, UINT64 v)
{
	put32(p, (UINT32)v);
	put32(p + 4, (UINT32)(v >> 32));
}
static void zero(UINT8 *p, UINTN n)
{
	while (n-- != 0)
		*p++ = 0;
}

static BOOLEAN guid(struct slice s, UINT8 *out)
{
	static const UINT8 groups[] = {8, 4, 4, 4, 12};
	UINTN g, at = 0, byte = 0;
	UINT64 value;
	if (s.n != 36)
		return FALSE;
	for (g = 0; g < 5; g++) {
		struct slice part = {s.p + at, groups[g]};
		if (!hex_number(part,
				g == 0	? MAX_UINT32
				: g < 3 ? MAX_UINT16
					: MAX_UINT64,
				&value))
			return FALSE;
		if (out != NULL) {
			if (g == 0)
				put32(out, (UINT32)value);
			else if (g < 3)
				put16(out + (g == 1 ? 4 : 6), (UINT16)value);
			else {
				UINTN j;
				for (j = groups[g] / 2; j != 0; j--)
					out[8 + byte++] = (UINT8)(value >> ((j - 1) * 8));
			}
		}
		at += groups[g];
		if (g != 4 && s.p[at++] != '-')
			return FALSE;
	}
	return TRUE;
}

static BOOLEAN eisa(struct slice s, UINT32 *id)
{
	UINT64 product;
	UINT32 letters;
	if (s.n != 7 || s.p[0] < '@' || s.p[0] > 'Z' || s.p[1] < '@' || s.p[1] > 'Z' ||
	    s.p[2] < '@' || s.p[2] > 'Z' ||
	    !hex_number((struct slice){s.p + 3, 4}, MAX_UINT16, &product))
		return FALSE;
	letters = ((UINT32)(s.p[0] - 'A' + 1) << 10) | ((UINT32)(s.p[1] - 'A' + 1) << 5) |
		  (UINT32)(s.p[2] - 'A' + 1);
	*id = letters | (UINT32)product << 16;
	return TRUE;
}

static BOOLEAN args(struct slice inside, struct slice *a, UINTN capacity, UINTN *count)
{
	UINTN start = 0, n = 0, i;
	BOOLEAN quoted = FALSE;
	for (i = 0; i <= inside.n; i++) {
		if (i < inside.n && inside.p[i] == '"')
			quoted = !quoted;
		if (i == inside.n || (inside.p[i] == ',' && !quoted)) {
			if (n == capacity)
				return FALSE;
			a[n++] = (struct slice){inside.p + start, i - start};
			start = i + 1;
		}
	}
	if (quoted)
		return FALSE;
	*count = n;
	return TRUE;
}

static void header(UINT8 *p, UINT8 type, UINT8 subtype, UINT16 length)
{
	if (p != NULL) {
		p[0] = type;
		p[1] = subtype;
		put16(p + 2, length);
	}
}

static EFI_STATUS parse_raw(struct slice name, struct slice *a, UINTN n, UINT8 *out,
			    UINTN *size)
{
	UINT64 subtype;
	UINTN data = 0;
	UINT8 type;
	if (equal(name, "HardwarePath"))
		type = HW;
	else if (equal(name, "AcpiPath"))
		type = ACPI;
	else
		return EFI_UNSUPPORTED;
	if ((n != 1 && n != 2) || !number(a[0], MAX_UINT8, &subtype) ||
	    (n == 2 && !bytes(a[1], out == NULL ? NULL : out + 4, &data)) ||
	    data > MAX_UINT16 - 4)
		return EFI_INVALID_PARAMETER;
	*size = 4 + data;
	header(out, type, (UINT8)subtype, (UINT16)*size);
	return EFI_SUCCESS;
}

static EFI_STATUS parse_hw(struct slice name, struct slice *a, UINTN n, UINT8 *out, UINTN *size)
{
	UINT64 x[3];
	UINTN data;
	UINT8 subtype;
	UINT16 length;
	if (equal(name, "Pci") && n == 2 && number(a[0], 255, &x[0]) &&
	    number(a[1], 255, &x[1])) {
		subtype = 1;
		length = 6;
		if (out) {
			out[4] = (UINT8)x[1];
			out[5] = (UINT8)x[0];
		}
	} else if (equal(name, "PcCard") && n == 1 && number(a[0], 255, &x[0])) {
		subtype = 2;
		length = 5;
		if (out)
			out[4] = (UINT8)x[0];
	} else if (equal(name, "MemoryMapped") && n == 3 && number(a[0], MAX_UINT32, &x[0]) &&
		   number(a[1], MAX_UINT64, &x[1]) && number(a[2], MAX_UINT64, &x[2])) {
		subtype = 3;
		length = 24;
		if (out) {
			put32(out + 4, (UINT32)x[0]);
			put64(out + 8, x[1]);
			put64(out + 16, x[2]);
		}
	} else if (equal(name, "VenHw") && (n == 1 || n == 2) &&
		   guid(a[0], out ? out + 4 : NULL) &&
		   (n == 1 || bytes(a[1], out ? out + 20 : NULL, &data)) &&
		   (n != 1 || (data = 0, TRUE)) && data <= MAX_UINT16 - 20) {
		subtype = 4;
		length = (UINT16)(20 + data);
	} else if (equal(name, "Ctrl") && n == 1 && number(a[0], MAX_UINT32, &x[0])) {
		subtype = 5;
		length = 8;
		if (out)
			put32(out + 4, (UINT32)x[0]);
	} else if (equal(name, "BMC") && n == 2 && number(a[0], 255, &x[0]) &&
		   number(a[1], MAX_UINT64, &x[1])) {
		subtype = 6;
		length = 13;
		if (out) {
			out[4] = (UINT8)x[0];
			put64(out + 5, x[1]);
		}
	} else
		return EFI_UNSUPPORTED;
	*size = length;
	header(out, HW, subtype, length);
	return EFI_SUCCESS;
}

static EFI_STATUS hid_alias(struct slice name, UINT32 *hid)
{
	static const struct {
		const char *name;
		UINT32 hid;
	} aliases[] = {{"PciRoot", 0x0a0341d0}, {"PcieRoot", 0x0a0841d0},
		       {"Floppy", 0x060441d0},	{"Keyboard", 0x030141d0},
		       {"Serial", 0x050141d0},	{"ParallelPort", 0x040141d0}};
	UINTN i;
	for (i = 0; i < ARRAY_SIZE(aliases); i++)
		if (equal(name, aliases[i].name)) {
			*hid = aliases[i].hid;
			return EFI_SUCCESS;
		}
	return EFI_UNSUPPORTED;
}

static EFI_STATUS parse_acpi(struct slice name, struct slice *a, UINTN n, UINT8 *out,
			     UINTN *size)
{
	UINT64 value;
	UINT32 hid, cid;
	UINTN i, length;
	if (!EFI_ERROR(hid_alias(name, &hid))) {
		if (n != 1 || !number(a[0], MAX_UINT32, &value))
			return EFI_INVALID_PARAMETER;
		length = 12;
		if (out) {
			put32(out + 4, hid);
			put32(out + 8, (UINT32)value);
		}
		header(out, ACPI, 1, 12);
		*size = 12;
		return EFI_SUCCESS;
	}
	if (equal(name, "Acpi")) {
		if (n != 2 || (!eisa(a[0], &hid) && !number(a[0], MAX_UINT32, &value)) ||
		    !number(a[1], MAX_UINT32, &value))
			return EFI_INVALID_PARAMETER;
		if (!eisa(a[0], &hid)) {
			number(a[0], MAX_UINT32, &value);
			hid = (UINT32)value;
		}
		if (out) {
			put32(out + 4, hid);
			number(a[1], MAX_UINT32, &value);
			put32(out + 8, (UINT32)value);
		}
		header(out, ACPI, 1, 12);
		*size = 12;
		return EFI_SUCCESS;
	}
	if (equal(name, "AcpiAdr")) {
		if (n == 0 || n > (MAX_UINT16 - 4) / 4)
			return EFI_INVALID_PARAMETER;
		for (i = 0; i < n; i++)
			if (!number(a[i], MAX_UINT32, &value))
				return EFI_INVALID_PARAMETER;
		length = 4 + 4 * n;
		header(out, ACPI, 3, (UINT16)length);
		if (out)
			for (i = 0; i < n; i++) {
				number(a[i], MAX_UINT32, &value);
				put32(out + 4 + i * 4, (UINT32)value);
			}
		*size = length;
		return EFI_SUCCESS;
	}
	if (equal(name, "AcpiExp")) {
		if (n != 3 || !eisa(a[0], &hid) ||
		    !(equal(a[1], "0") ? (cid = 0, TRUE) : eisa(a[1], &cid)) || a[2].n == 0)
			return EFI_INVALID_PARAMETER;
		length = 19 + a[2].n;
		if (length > MAX_UINT16)
			return EFI_INVALID_PARAMETER;
		header(out, ACPI, 2, (UINT16)length);
		if (out) {
			put32(out + 4, hid);
			put32(out + 8, 0);
			put32(out + 12, cid);
			out[16] = 0;
			for (i = 0; i < a[2].n; i++) {
				if (a[2].p[i] > 255)
					return EFI_INVALID_PARAMETER;
				out[17 + i] = (UINT8)a[2].p[i];
			}
			out[17 + a[2].n] = 0;
			out[18 + a[2].n] = 0;
		}
		*size = length;
		return EFI_SUCCESS;
	}
	if (equal(name, "AcpiEx")) {
		if (n != 6 || !eisa(a[0], &hid) || !eisa(a[1], &cid) ||
		    !number(a[2], MAX_UINT32, &value))
			return EFI_INVALID_PARAMETER;
		length = 19 + a[3].n + a[4].n + a[5].n;
		if (length > MAX_UINT16)
			return EFI_INVALID_PARAMETER;
		header(out, ACPI, 2, (UINT16)length);
		if (out) {
			static const UINT8 order[] = {3, 5, 4};
			UINTN at = 16;
			put32(out + 4, hid);
			put32(out + 8, (UINT32)value);
			put32(out + 12, cid);
			for (i = 0; i < ARRAY_SIZE(order); i++) {
				UINTN j;
				UINTN which = order[i];
				for (j = 0; j < a[which].n; j++) {
					if (a[which].p[j] > 255)
						return EFI_INVALID_PARAMETER;
					out[at++] = (UINT8)a[which].p[j];
				}
				out[at++] = 0;
			}
		}
		*size = length;
		return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}

static BOOLEAN ipv4(struct slice s, UINT8 *out)
{
	UINTN i, start = 0, part = 0;
	UINT64 value;
	for (i = 0; i <= s.n; i++)
		if (i == s.n || s.p[i] == '.') {
			if (part == 4 ||
			    !number((struct slice){s.p + start, i - start}, 255, &value))
				return FALSE;
			if (out)
				out[part] = (UINT8)value;
			part++;
			start = i + 1;
		}
	return part == 4;
}

static BOOLEAN ipv6(struct slice s, UINT8 *out)
{
	UINTN i, start = 0, part = 0;
	UINT64 value;
	for (i = 0; i <= s.n; i++)
		if (i == s.n || s.p[i] == ':') {
			if (part == 8 || i - start != 4 ||
			    !hex_number((struct slice){s.p + start, 4}, MAX_UINT16, &value))
				return FALSE;
			if (out) {
				out[part * 2] = (UINT8)(value >> 8);
				out[part * 2 + 1] = (UINT8)value;
			}
			part++;
			start = i + 1;
		}
	return part == 8;
}

static BOOLEAN protocol(struct slice s, UINT16 *value)
{
	UINT64 n;
	if (equal(s, "TCP"))
		*value = 6;
	else if (equal(s, "UDP"))
		*value = 17;
	else if (number(s, MAX_UINT16, &n))
		*value = (UINT16)n;
	else
		return FALSE;
	return TRUE;
}

static BOOLEAN keyword(struct slice s, const char *const *names, UINTN count, UINT8 *value)
{
	UINTN i;
	for (i = 0; i < count; i++)
		if (equal(s, names[i])) {
			*value = (UINT8)i;
			return TRUE;
		}
	return FALSE;
}

static void fixed_guid(UINT8 *out, UINT32 d1, UINT16 d2, UINT16 d3, const UINT8 d4[8])
{
	if (!out)
		return;
	put32(out, d1);
	put16(out + 4, d2);
	put16(out + 6, d3);
	for (UINTN i = 0; i < 8; i++)
		out[8 + i] = d4[i];
}

static EFI_STATUS parse_msg_vendor(struct slice name, struct slice *a, UINTN n, UINT8 *out,
				   UINTN *size)
{
	static const UINT8 pcansi[8] = {0x9a, 0x0c, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d};
	static const UINT8 vt100[8] = {0x9a, 0x2d, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d};
	static const UINT8 vt100p[8] = {0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43};
	static const UINT8 utf8[8] = {0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88};
	static const UINT8 debug[8] = {0xa2, 0x81, 0x26, 0x47, 0xba, 0x96, 0x60, 0xd0};
	static const struct {
		const char *name;
		UINT32 d1;
		UINT16 d2, d3;
		const UINT8 *d4;
	} aliases[] = {
	    {"VenPcAnsi", 0xe0c14753, 0xf9be, 0x11d2, pcansi},
	    {"VenVt100", 0xdfa66065, 0xb419, 0x11d3, vt100},
	    {"VenVt100Plus", 0x7baec70b, 0x57e0, 0x4c76, vt100p},
	    {"VenUtf8", 0xad15a0d6, 0x8bec, 0x4acf, utf8},
	    {"DebugPort", 0xeba4e8d2, 0x3858, 0x41ec, debug},
	};
	UINTN i, data = 0;
	if (equal(name, "VenMsg")) {
		if ((n != 1 && n != 2) || !guid(a[0], out ? out + 4 : NULL) ||
		    (n == 2 && !bytes(a[1], out ? out + 20 : NULL, &data)) ||
		    data > MAX_UINT16 - 20)
			return EFI_INVALID_PARAMETER;
		*size = 20 + data;
		header(out, MSG, 0x0a, (UINT16)*size);
		return EFI_SUCCESS;
	}
	for (i = 0; i < ARRAY_SIZE(aliases); i++)
		if (equal(name, aliases[i].name)) {
			if (n != 1 || a[0].n != 0)
				return EFI_INVALID_PARAMETER;
			*size = 20;
			header(out, MSG, 0x0a, 20);
			fixed_guid(out ? out + 4 : NULL, aliases[i].d1, aliases[i].d2,
				   aliases[i].d3, aliases[i].d4);
			return EFI_SUCCESS;
		}
	if (equal(name, "UartFlowCtrl")) {
		static const UINT8 uart[8] = {0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4};
		UINT32 flow;
		if (n != 1 || !(equal(a[0], "None")	  ? (flow = 0, TRUE)
				: equal(a[0], "Hardware") ? (flow = 1, TRUE)
				: equal(a[0], "XonXoff")  ? (flow = 2, TRUE)
							  : FALSE))
			return EFI_INVALID_PARAMETER;
		*size = 24;
		header(out, MSG, 0x0a, 24);
		fixed_guid(out ? out + 4 : NULL, 0x37499a9d, 0x542f, 0x4c89, uart);
		if (out)
			put32(out + 20, flow);
		return EFI_SUCCESS;
	}
	if (equal(name, "SAS")) {
		static const UINT8 sas[8] = {0xaf, 0xdc, 0, 0x10, 0x83, 0xff, 0xca, 0x4d};
		UINT64 x[4];
		UINT16 topology;
		if (n != 8 || !number(a[0], MAX_UINT64, &x[0]) ||
		    !number(a[1], MAX_UINT64, &x[1]) || !number(a[2], MAX_UINT16, &x[2]) ||
		    !number(a[7], MAX_UINT32, &x[3]))
			return EFI_INVALID_PARAMETER;
		if (equal(a[3], "NoTopology") && equal(a[4], "0") && equal(a[5], "0") &&
		    equal(a[6], "0"))
			topology = 0;
		else if ((equal(a[3], "SAS") || equal(a[3], "SATA")) &&
			 (equal(a[4], "Internal") || equal(a[4], "External")) &&
			 (equal(a[5], "Direct") || equal(a[5], "Expanded")) &&
			 number(a[6], 256, &x[0])) {
			topology = (UINT16)((equal(a[3], "SATA") ? 0x10 : 0) |
					    (equal(a[4], "External") ? 0x20 : 0) |
					    (equal(a[5], "Expanded") ? 0x40 : 0));
			if (x[0] == 0)
				topology |= 1;
			else
				topology |= (UINT16)(2 | (x[0] - 1) << 8);
		} else if (number(a[3], MAX_UINT16, &x[0]) && equal(a[4], "0") &&
			   equal(a[5], "0") && equal(a[6], "0"))
			topology = (UINT16)x[0];
		else
			return EFI_INVALID_PARAMETER;
		*size = 44;
		header(out, MSG, 0x0a, 44);
		fixed_guid(out ? out + 4 : NULL, 0xd487ddb4, 0x008b, 0x11d9, sas);
		if (out) {
			number(a[0], MAX_UINT64, &x[0]);
			number(a[1], MAX_UINT64, &x[1]);
			put32(out + 20, (UINT32)x[3]);
			put64(out + 24, x[0]);
			put64(out + 32, x[1]);
			put16(out + 40, topology);
			put16(out + 42, (UINT16)x[2]);
		}
		return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}

static EFI_STATUS parse_msg_simple(struct slice name, struct slice *a, UINTN n, UINT8 *out,
				   UINTN *size)
{
	UINT64 x[5];
	UINT8 subtype = 0;
	UINT16 length = 0;
	UINTN i, count;
	if (equal(name, "Scsi") && n == 2 && number(a[0], MAX_UINT16, &x[0]) &&
	    number(a[1], MAX_UINT16, &x[1])) {
		subtype = 2;
		length = 8;
		if (out) {
			put16(out + 4, (UINT16)x[0]);
			put16(out + 6, (UINT16)x[1]);
		}
	} else if (equal(name, "Fibre") && n == 2 && number(a[0], MAX_UINT64, &x[0]) &&
		   number(a[1], MAX_UINT64, &x[1])) {
		subtype = 3;
		length = 24;
		if (out) {
			put64(out + 8, x[0]);
			put64(out + 16, x[1]);
		}
	} else if (equal(name, "I1394") && n == 1 && hex_number(a[0], MAX_UINT64, &x[0])) {
		subtype = 4;
		length = 16;
		if (out)
			put64(out + 8, x[0]);
	} else if (equal(name, "USB") && n == 2 && number(a[0], 255, &x[0]) &&
		   number(a[1], 255, &x[1])) {
		subtype = 5;
		length = 6;
		if (out) {
			out[4] = (UINT8)x[0];
			out[5] = (UINT8)x[1];
		}
	} else if (equal(name, "I2O") && n == 1 && number(a[0], MAX_UINT32, &x[0])) {
		subtype = 6;
		length = 8;
		if (out)
			put32(out + 4, (UINT32)x[0]);
	} else if (equal(name, "Unit") && n == 1 && number(a[0], 255, &x[0])) {
		subtype = 0x11;
		length = 5;
		if (out)
			out[4] = (UINT8)x[0];
	} else if (equal(name, "Sata") && n == 3 && number(a[0], MAX_UINT16, &x[0]) &&
		   number(a[1], MAX_UINT16, &x[1]) && number(a[2], MAX_UINT16, &x[2])) {
		subtype = 0x12;
		length = 10;
		if (out) {
			put16(out + 4, (UINT16)x[0]);
			put16(out + 6, (UINT16)x[1]);
			put16(out + 8, (UINT16)x[2]);
		}
	} else if (equal(name, "Vlan") && n == 1 && number(a[0], MAX_UINT16, &x[0])) {
		subtype = 0x14;
		length = 6;
		if (out)
			put16(out + 4, (UINT16)x[0]);
	} else if (equal(name, "UFS") && n == 2 && number(a[0], 255, &x[0]) &&
		   number(a[1], 255, &x[1])) {
		subtype = 0x19;
		length = 6;
		if (out) {
			out[4] = (UINT8)x[0];
			out[5] = (UINT8)x[1];
		}
	} else if ((equal(name, "SD") || equal(name, "eMMC")) && n == 1 &&
		   number(a[0], 255, &x[0])) {
		subtype = equal(name, "SD") ? 0x1a : 0x1d;
		length = 5;
		if (out)
			out[4] = (UINT8)x[0];
	} else if (equal(name, "Bluetooth") && n == 1 &&
		   bytes(a[0], out ? out + 4 : NULL, &count) && count == 6) {
		subtype = 0x1b;
		length = 10;
	} else if (equal(name, "BluetoothLE") && n == 2 &&
		   bytes(a[0], out ? out + 4 : NULL, &count) && count == 6 &&
		   number(a[1], 255, &x[0])) {
		subtype = 0x1e;
		length = 11;
		if (out)
			out[10] = (UINT8)x[0];
	} else
		return EFI_UNSUPPORTED;
	(void)i;
	*size = length;
	header(out, MSG, subtype, length);
	return EFI_SUCCESS;
}

static EFI_STATUS parse_msg(struct slice name, struct slice inside, struct slice *a, UINTN n,
			    UINT8 *out, UINTN *size)
{
	UINT64 x[5];
	UINTN i, count, length;
	UINT16 proto;
	UINT8 method;
	EFI_STATUS status = parse_msg_vendor(name, a, n, out, size);
	if (status != EFI_UNSUPPORTED)
		return status;
	status = parse_msg_simple(name, a, n, out, size);
	if (status != EFI_UNSUPPORTED)
		return status;
	if (equal(name, "Ata")) {
		if (n == 1 && number(a[0], MAX_UINT16, &x[0])) {
			x[1] = 0;
			x[2] = 0;
		} else if (n == 3 &&
			   (equal(a[0], "Primary")     ? (x[1] = 0, TRUE)
			    : equal(a[0], "Secondary") ? (x[1] = 1, TRUE)
						       : FALSE) &&
			   (equal(a[1], "Master")  ? (x[2] = 0, TRUE)
			    : equal(a[1], "Slave") ? (x[2] = 1, TRUE)
						   : FALSE) &&
			   number(a[2], MAX_UINT16, &x[0])) {
		} else
			return EFI_INVALID_PARAMETER;
		*size = 8;
		header(out, MSG, 1, 8);
		if (out) {
			out[4] = (UINT8)x[1];
			out[5] = (UINT8)x[2];
			put16(out + 6, (UINT16)x[0]);
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "Infiniband")) {
		if (n != 5 || !number(a[0], MAX_UINT32, &x[0]) ||
		    !guid(a[1], out ? out + 8 : NULL) || !number(a[2], MAX_UINT64, &x[2]) ||
		    !number(a[3], MAX_UINT64, &x[3]) || !number(a[4], MAX_UINT64, &x[4]))
			return EFI_INVALID_PARAMETER;
		*size = 48;
		header(out, MSG, 9, 48);
		if (out) {
			put32(out + 4, (UINT32)x[0]);
			put64(out + 24, x[2]);
			put64(out + 32, x[3]);
			put64(out + 40, x[4]);
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "MAC")) {
		if (n != 2 || !number(a[1], 255, &x[0]) ||
		    !bytes(a[0], out ? out + 4 : NULL, &count) ||
		    !((x[0] <= 1 && count == 6) || (x[0] > 1 && count == 32)))
			return EFI_INVALID_PARAMETER;
		*size = 37;
		header(out, MSG, 0x0b, 37);
		if (out)
			out[36] = (UINT8)x[0];
		return EFI_SUCCESS;
	}
	if (equal(name, "IPv4")) {
		if (n != 1 && n != 4 && n != 6)
			return EFI_INVALID_PARAMETER;
		if (!ipv4(a[0], out ? out + 8 : NULL))
			return EFI_INVALID_PARAMETER;
		proto = 0;
		method = 0;
		length = n == 6 ? 27 : 19;
		if (n > 1 && (!protocol(a[1], &proto) ||
			      !(equal(a[2], "DHCP")	? (method = 0, TRUE)
				: equal(a[2], "Static") ? (method = 1, TRUE)
							: FALSE) ||
			      !ipv4(a[3], out ? out + 4 : NULL) ||
			      (n == 6 && (!ipv4(a[4], out ? out + 19 : NULL) ||
					  !ipv4(a[5], out ? out + 23 : NULL)))))
			return EFI_INVALID_PARAMETER;
		*size = length;
		header(out, MSG, 0x0c, (UINT16)length);
		if (out) {
			put16(out + 16, proto);
			out[18] = method;
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "IPv6")) {
		if (n != 1 && n != 4 && n != 6)
			return EFI_INVALID_PARAMETER;
		if (!ipv6(a[0], out ? out + 20 : NULL))
			return EFI_INVALID_PARAMETER;
		proto = 0;
		method = 0;
		length = n == 6 ? 60 : 44;
		if (n > 1 && (!protocol(a[1], &proto) ||
			      !(equal(a[2], "Static")			? (method = 0, TRUE)
				: equal(a[2], "StatelessAutoConfigure") ? (method = 1, TRUE)
				: equal(a[2], "StatefulAutoConfigure")	? (method = 2, TRUE)
									: FALSE) ||
			      !ipv6(a[3], out ? out + 4 : NULL) ||
			      (n == 6 && (!number(a[4], 255, &x[0]) ||
					  !ipv6(a[5], out ? out + 44 : NULL)))))
			return EFI_INVALID_PARAMETER;
		*size = length;
		header(out, MSG, 0x0d, (UINT16)length);
		if (out) {
			put16(out + 40, proto);
			out[42] = method;
			if (n == 6)
				out[43] = (UINT8)x[0];
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "Uart")) {
		static const char *const parity[] = {"D", "N", "E", "O", "M", "S"};
		static const char *const stop[] = {"D", "1", "1.5", "2"};
		UINT8 p, s;
		if (n != 4 || (!equal(a[0], "DEFAULT") && !number(a[0], MAX_UINT64, &x[0])) ||
		    (!equal(a[1], "DEFAULT") && !number(a[1], 255, &x[1])) ||
		    !keyword(a[2], parity, 6, &p) || !keyword(a[3], stop, 4, &s))
			return EFI_INVALID_PARAMETER;
		*size = 19;
		header(out, MSG, 0x0e, 19);
		if (out) {
			put64(out + 8, equal(a[0], "DEFAULT") ? 0 : x[0]);
			out[16] = equal(a[1], "DEFAULT") ? 0 : (UINT8)x[1];
			out[17] = p;
			out[18] = s;
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "UsbClass") ||
	    (name.n >= 3 && name.p[0] == 'U' && name.p[1] == 's' && name.p[2] == 'b')) {
		static const struct {
			const char *name;
			UINT8 cls, sub;
		} u[] = {{"UsbAudio", 1, 0},
			 {"UsbCDCControl", 2, 0},
			 {"UsbHID", 3, 0},
			 {"UsbImage", 6, 0},
			 {"UsbPrinter", 7, 0},
			 {"UsbMassStorage", 8, 0},
			 {"UsbHub", 9, 0},
			 {"UsbCDCData", 10, 0},
			 {"UsbSmartCard", 11, 0},
			 {"UsbVideo", 14, 0},
			 {"UsbDiagnostic", 0xdc, 0},
			 {"UsbWireless", 0xe0, 0},
			 {"UsbDeviceFirmwareUpdate", 0xfe, 1},
			 {"UsbIrdaBridge", 0xfe, 2},
			 {"UsbTestAndMeasurement", 0xfe, 3}};
		UINT8 cls = 0, sub = 0;
		UINTN expected = 5;
		if (!equal(name, "UsbClass")) {
			for (i = 0; i < ARRAY_SIZE(u) && !equal(name, u[i].name); i++)
				;
			if (i == ARRAY_SIZE(u))
				goto not_usb;
			cls = u[i].cls;
			sub = u[i].sub;
			expected = cls == 0xfe ? 3 : 4;
		}
		if (n != expected)
			return EFI_INVALID_PARAMETER;
		for (i = 0; i < n; i++)
			if (!number(a[i], i < 2 ? MAX_UINT16 : 255, &x[i]))
				return EFI_INVALID_PARAMETER;
		*size = 11;
		header(out, MSG, 0x0f, 11);
		if (out) {
			put16(out + 4, (UINT16)x[0]);
			put16(out + 6, (UINT16)x[1]);
			out[8] = equal(name, "UsbClass") ? (UINT8)x[2] : cls;
			out[9] = equal(name, "UsbClass") ? (UINT8)x[3]
							 : (cls == 0xfe ? sub : (UINT8)x[2]);
			out[10] =
			    equal(name, "UsbClass") ? (UINT8)x[4] : (UINT8)x[expected - 1];
		}
		return EFI_SUCCESS;
	}
not_usb:
	if (equal(name, "Unit"))
		return EFI_UNSUPPORTED;
	if (equal(name, "UsbWwid")) {
		if (n != 4 || a[3].n < 2 || a[3].p[0] != '"' || a[3].p[a[3].n - 1] != '"' ||
		    !number(a[0], MAX_UINT16, &x[0]) || !number(a[1], MAX_UINT16, &x[1]) ||
		    !number(a[2], MAX_UINT16, &x[2]) || a[3].n - 2 > (MAX_UINT16 - 10) / 2)
			return EFI_INVALID_PARAMETER;
		length = 10 + (a[3].n - 2) * 2;
		*size = length;
		header(out, MSG, 0x10, (UINT16)length);
		if (out) {
			put16(out + 4, (UINT16)x[2]);
			put16(out + 6, (UINT16)x[0]);
			put16(out + 8, (UINT16)x[1]);
			for (i = 1; i + 1 < a[3].n; i++)
				put16(out + 8 + i * 2, a[3].p[i]);
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "iSCSI")) {
		UINT16 options = 0;
		UINTN data;
		if (n != 7 || !number(a[1], MAX_UINT16, &x[0]) || a[2].n != 18 ||
		    a[2].p[0] != '0' || a[2].p[1] != 'x' ||
		    !bytes((struct slice){a[2].p + 2, 16}, out ? out + 8 : NULL, &data) ||
		    !(equal(a[3], "None") ||
		      (equal(a[3], "CRC32C") ? (options |= 2, TRUE) : FALSE)) ||
		    !(equal(a[4], "None") ||
		      (equal(a[4], "CRC32C") ? (options |= 8, TRUE) : FALSE)) ||
		    !(equal(a[5], "None")	? (options |= 0x800, TRUE)
		      : equal(a[5], "CHAP_UNI") ? (options |= 0x1000, TRUE)
						: equal(a[5], "CHAP_BI")) ||
		    (!equal(a[6], "TCP") && !equal(a[6], "reserved")) ||
		    a[0].n > MAX_UINT16 - 19)
			return EFI_INVALID_PARAMETER;
		length = 19 + a[0].n;
		*size = length;
		header(out, MSG, 0x13, (UINT16)length);
		if (out) {
			put16(out + 4, equal(a[6], "TCP") ? 0 : 1);
			put16(out + 6, options);
			put16(out + 16, (UINT16)x[0]);
			for (i = 0; i < a[0].n; i++) {
				if (a[0].p[i] > 255)
					return EFI_INVALID_PARAMETER;
				out[18 + i] = (UINT8)a[0].p[i];
			}
			out[length - 1] = 0;
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "FibreEx")) {
		if (n != 2 || a[0].n != 18 || a[1].n != 18 || a[0].p[0] != '0' ||
		    a[0].p[1] != 'x' || a[1].p[0] != '0' || a[1].p[1] != 'x' ||
		    !bytes((struct slice){a[0].p + 2, 16}, out ? out + 8 : NULL, &count) ||
		    !bytes((struct slice){a[1].p + 2, 16}, out ? out + 16 : NULL, &count))
			return EFI_INVALID_PARAMETER;
		*size = 24;
		header(out, MSG, 0x15, 24);
		return EFI_SUCCESS;
	}
	if (equal(name, "SasEx")) {
		UINT16 topology;
		if (n != 7 || a[0].n != 18 || a[1].n != 18 || a[0].p[0] != '0' ||
		    a[0].p[1] != 'x' || a[1].p[0] != '0' || a[1].p[1] != 'x' ||
		    !bytes((struct slice){a[0].p + 2, 16}, out ? out + 4 : NULL, &count) ||
		    !bytes((struct slice){a[1].p + 2, 16}, out ? out + 12 : NULL, &count) ||
		    !number(a[2], MAX_UINT16, &x[2]))
			return EFI_INVALID_PARAMETER;
		if (equal(a[3], "NoTopology") && equal(a[4], "0") && equal(a[5], "0") &&
		    equal(a[6], "0"))
			topology = 0;
		else if ((equal(a[3], "SAS") || equal(a[3], "SATA")) &&
			 (equal(a[4], "Internal") || equal(a[4], "External")) &&
			 (equal(a[5], "Direct") || equal(a[5], "Expanded")) &&
			 number(a[6], 256, &x[0])) {
			topology = (UINT16)((equal(a[3], "SATA") ? 0x10 : 0) |
					    (equal(a[4], "External") ? 0x20 : 0) |
					    (equal(a[5], "Expanded") ? 0x40 : 0));
			if (x[0] == 0)
				topology |= 1;
			else
				topology |= (UINT16)(2 | (x[0] - 1) << 8);
		} else if (number(a[3], MAX_UINT16, &x[0]) && equal(a[4], "0") &&
			   equal(a[5], "0") && equal(a[6], "0"))
			topology = (UINT16)x[0];
		else
			return EFI_INVALID_PARAMETER;
		*size = 24;
		header(out, MSG, 0x16, 24);
		if (out) {
			put16(out + 20, topology);
			put16(out + 22, (UINT16)x[2]);
		}
		return EFI_SUCCESS;
	}
	if (equal(name, "NVMe")) {
		if (n != 2 || !number(a[0], MAX_UINT32, &x[0]))
			return EFI_INVALID_PARAMETER;
		struct slice parts[8];
		UINTN start = 0;
		for (i = 0; i < 8; i++) {
			UINTN end = start;
			while (end < a[1].n && a[1].p[end] != '-')
				end++;
			parts[i] = (struct slice){a[1].p + start, end - start};
			start = end + 1;
			if (parts[i].n != 2 || !hex_number(parts[i], 255, &x[1]))
				return EFI_INVALID_PARAMETER;
			if (out)
				out[15 - i] = (UINT8)x[1];
		}
		if (start != a[1].n + 1)
			return EFI_INVALID_PARAMETER;
		*size = 16;
		header(out, MSG, 0x17, 16);
		if (out)
			put32(out + 4, (UINT32)x[0]);
		return EFI_SUCCESS;
	}
	if (equal(name, "Uri")) {
		if (inside.n > MAX_UINT16 - 4)
			return EFI_INVALID_PARAMETER;
		length = 4 + inside.n;
		*size = length;
		header(out, MSG, 0x18, (UINT16)length);
		if (out)
			for (i = 0; i < inside.n; i++) {
				if (inside.p[i] > 255)
					return EFI_INVALID_PARAMETER;
				out[4 + i] = (UINT8)inside.p[i];
			}
		return EFI_SUCCESS;
	}
	if (equal(name, "Wi-Fi")) {
		if (n != 1 || a[0].n > 32)
			return EFI_INVALID_PARAMETER;
		*size = 36;
		header(out, MSG, 0x1c, 36);
		if (out)
			for (i = 0; i < a[0].n; i++) {
				if (a[0].p[i] > 255)
					return EFI_INVALID_PARAMETER;
				out[4 + i] = (UINT8)a[0].p[i];
			}
		return EFI_SUCCESS;
	}
	if (equal(name, "Dns")) {
		BOOLEAN six;
		if (n == 1 && a[0].n == 0) {
			*size = 5;
			header(out, MSG, 0x1f, 5);
			return EFI_SUCCESS;
		}
		if (n < 1 || n > (MAX_UINT16 - 5) / 16)
			return EFI_INVALID_PARAMETER;
		six = !ipv4(a[0], NULL);
		for (i = 0; i < n; i++)
			if (six ? !ipv6(a[i], out ? out + 5 + i * 16 : NULL)
				: !ipv4(a[i], out ? out + 5 + i * 16 : NULL))
				return EFI_INVALID_PARAMETER;
		length = 5 + n * 16;
		*size = length;
		header(out, MSG, 0x1f, (UINT16)length);
		if (out)
			out[4] = six;
		return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}

static EFI_STATUS parse_node(struct slice text, UINT8 *out, UINTN *size)
{
	UINTN i, count;
	struct slice name, inside, a[64];
	EFI_STATUS status;
	for (i = 0; i < text.n && text.p[i] != '('; i++)
		;
	if (i == 0 || i + 1 >= text.n || text.p[text.n - 1] != ')')
		return EFI_INVALID_PARAMETER;
	name = (struct slice){text.p, i};
	inside = (struct slice){text.p + i + 1, text.n - i - 2};
	if (!args(inside, a, ARRAY_SIZE(a), &count))
		return EFI_INVALID_PARAMETER;
	status = parse_hw(name, a, count, out, size);
	if (status != EFI_UNSUPPORTED)
		return status;
	status = parse_acpi(name, a, count, out, size);
	if (status != EFI_UNSUPPORTED)
		return status;
	status = parse_msg(name, inside, a, count, out, size);
	if (status != EFI_UNSUPPORTED)
		return status;
	status = parse_raw(name, a, count, out, size);
	return status == EFI_UNSUPPORTED ? EFI_INVALID_PARAMETER : status;
}

static EFI_STATUS parse_path(const CHAR16 *text, UINT8 *out, UINTN *total)
{
	UINTN at = 0, start = 0, depth = 0, used = 0, node_size;
	EFI_STATUS status;
	if (text == NULL || text[0] == 0)
		return EFI_INVALID_PARAMETER;
	for (;;) {
		CHAR16 c = text[at];
		if (c == '(')
			depth++;
		else if (c == ')') {
			if (depth == 0)
				return EFI_INVALID_PARAMETER;
			depth--;
		}
		if ((c == '/' || c == ',' || c == 0) && depth == 0) {
			if (at == start)
				return EFI_INVALID_PARAMETER;
			status = parse_node((struct slice){text + start, at - start},
					    out ? out + used : NULL, &node_size);
			if (EFI_ERROR(status) ||
			    node_size > CDK2_DEVICE_PATH_MAX_SIZE - used - 4)
				return EFI_ERROR(status) ? status : EFI_OUT_OF_RESOURCES;
			used += node_size;
			if (c == ',' && out)
				header(out + used, CDK2_DEVICE_PATH_END_TYPE,
				       CDK2_DEVICE_PATH_END_INSTANCE, 4);
			if (c == ',')
				used += 4;
			start = at + 1;
			if (c == 0)
				break;
		}
		if (c == 0) {
			if (depth != 0)
				return EFI_INVALID_PARAMETER;
			break;
		}
		at++;
	}
	if (out)
		header(out + used, CDK2_DEVICE_PATH_END_TYPE, CDK2_DEVICE_PATH_END_ENTIRE, 4);
	*total = used + 4;
	return EFI_SUCCESS;
}

static BOOLEAN allocator_valid(const struct cdk2_device_path_allocator *a)
{
	return a != NULL && a->allocate != NULL && a->free != NULL;
}

EFI_STATUS cdk2_device_path_from_text(const CHAR16 *text,
				      const struct cdk2_device_path_allocator *allocator,
				      struct cdk2_device_path **path)
{
	UINTN size, written;
	EFI_STATUS status;
	if (!allocator_valid(allocator) || path == NULL)
		return EFI_INVALID_PARAMETER;
	*path = NULL;
	status = parse_path(text, NULL, &size);
	if (EFI_ERROR(status))
		return status;
	status = allocator->allocate(allocator->context, size, (void **)path);
	if (EFI_ERROR(status))
		return status;
	zero((UINT8 *)*path, size);
	status = parse_path(text, (UINT8 *)*path, &written);
	if (EFI_ERROR(status) || written != size) {
		allocator->free(allocator->context, *path);
		*path = NULL;
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	}
	return EFI_SUCCESS;
}

EFI_STATUS cdk2_device_path_node_from_text(const CHAR16 *text,
					   const struct cdk2_device_path_allocator *allocator,
					   struct cdk2_device_path **node)
{
	UINTN n = 0, size, written;
	EFI_STATUS status;
	if (!allocator_valid(allocator) || node == NULL || text == NULL)
		return EFI_INVALID_PARAMETER;
	*node = NULL;
	while (text[n] != 0)
		n++;
	status = parse_node((struct slice){text, n}, NULL, &size);
	if (EFI_ERROR(status))
		return status;
	status = allocator->allocate(allocator->context, size, (void **)node);
	if (EFI_ERROR(status))
		return status;
	zero((UINT8 *)*node, size);
	status = parse_node((struct slice){text, n}, (UINT8 *)*node, &written);
	if (EFI_ERROR(status) || written != size) {
		allocator->free(allocator->context, *node);
		*node = NULL;
		return EFI_ERROR(status) ? status : EFI_COMPROMISED_DATA;
	}
	return EFI_SUCCESS;
}
