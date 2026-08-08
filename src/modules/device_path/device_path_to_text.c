/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/device_path.h>

#define HARDWARE_DEVICE_PATH 0x01U
#define HW_PCI_DP 0x01U
#define HW_PCCARD_DP 0x02U
#define HW_MEMMAP_DP 0x03U
#define HW_VENDOR_DP 0x04U
#define HW_CONTROLLER_DP 0x05U
#define HW_BMC_DP 0x06U
#define ACPI_DEVICE_PATH 0x02U
#define ACPI_DP 0x01U
#define ACPI_EXTENDED_DP 0x02U
#define ACPI_ADR_DP 0x03U
#define MESSAGING_DEVICE_PATH 0x03U
#define MSG_VENDOR_DP 0x0aU
#define MEDIA_DEVICE_PATH 0x04U
#define MEDIA_VENDOR_DP 0x03U

struct writer {
	CHAR16 *text;
	UINTN capacity;
	UINTN count;
};

struct guid {
	UINT32 data1;
	UINT16 data2;
	UINT16 data3;
	UINT8 data4[8];
};

static UINT16 read16(const UINT8 *bytes)
{
	return (UINT16)bytes[0] | (UINT16)bytes[1] << 8;
}

static UINT32 read32(const UINT8 *bytes)
{
	return (UINT32)read16(bytes) | (UINT32)read16(bytes + 2) << 16;
}

static UINT64 read64(const UINT8 *bytes)
{
	return (UINT64)read32(bytes) | (UINT64)read32(bytes + 4) << 32;
}

static void put(struct writer *writer, CHAR16 character)
{
	if (writer->text != NULL && writer->count < writer->capacity)
		writer->text[writer->count] = character;
	writer->count++;
}

static void puts8(struct writer *writer, const char *text)
{
	while (*text != '\0')
		put(writer, (CHAR16)(UINT8)*text++);
}

static void put_ascii(struct writer *writer, const UINT8 *text)
{
	while (*text != 0)
		put(writer, *text++);
}

static void put_hex(struct writer *writer, UINT64 value, UINTN width,
	BOOLEAN upper)
{
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	UINTN actual = 1;
	UINT64 copy = value;
	while (copy >= 16) {
		copy >>= 4;
		actual++;
	}
	if (width < actual)
		width = actual;
	while (width-- != 0)
		put(writer, digits[(value >> (width * 4)) & 0xf]);
}

static void put_dec(struct writer *writer, UINT8 value)
{
	if (value >= 100)
		put(writer, (CHAR16)('0' + value / 100));
	if (value >= 10)
		put(writer, (CHAR16)('0' + value / 10 % 10));
	put(writer, (CHAR16)('0' + value % 10));
}

static void put_0x(struct writer *writer, UINT64 value)
{
	puts8(writer, "0x");
	put_hex(writer, value, 0, FALSE);
}

static void put_guid(struct writer *writer, const UINT8 *bytes)
{
	put_hex(writer, read32(bytes), 8, FALSE);
	put(writer, '-');
	put_hex(writer, read16(bytes + 4), 4, FALSE);
	put(writer, '-');
	put_hex(writer, read16(bytes + 6), 4, FALSE);
	put(writer, '-');
	put_hex(writer, bytes[8], 2, FALSE);
	put_hex(writer, bytes[9], 2, FALSE);
	put(writer, '-');
	put_hex(writer, bytes[10], 2, FALSE);
	put_hex(writer, bytes[11], 2, FALSE);
	put_hex(writer, bytes[12], 2, FALSE);
	put_hex(writer, bytes[13], 2, FALSE);
	put_hex(writer, bytes[14], 2, FALSE);
	put_hex(writer, bytes[15], 2, FALSE);
}

static BOOLEAN guid_equal(const UINT8 *bytes, UINT32 data1, UINT16 data2,
	UINT16 data3, const UINT8 data4[8])
{
	UINTN index;
	if (read32(bytes) != data1 || read16(bytes + 4) != data2 ||
	    read16(bytes + 6) != data3)
		return FALSE;
	for (index = 0; index < 8; index++)
		if (bytes[8 + index] != data4[index])
			return FALSE;
	return TRUE;
}

static void put_eisa(struct writer *writer, UINT32 id)
{
	put(writer, (CHAR16)(((id >> 10) & 0x1f) + 'A' - 1));
	put(writer, (CHAR16)(((id >> 5) & 0x1f) + 'A' - 1));
	put(writer, (CHAR16)((id & 0x1f) + 'A' - 1));
	put_hex(writer, id >> 16, 4, TRUE);
}

static EFI_STATUS render_vendor(struct writer *writer, const UINT8 *node,
	UINT16 length, BOOLEAN shortcuts)
{
	static const UINT8 pcansi[8] = {0x9a, 0x0c, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d};
	static const UINT8 vt100[8] = {0x9a, 0x2d, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d};
	static const UINT8 vt100p[8] = {0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43};
	static const UINT8 utf8[8] = {0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88};
	static const UINT8 uart[8] = {0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4};
	static const UINT8 sas[8] = {0xaf, 0xdc, 0, 0x10, 0x83, 0xff, 0xca, 0x4d};
	static const UINT8 debug[8] = {0xa2, 0x81, 0x26, 0x47, 0xba, 0x96, 0x60, 0xd0};
	const UINT8 *guid = node + 4;
	const char *kind;
	UINTN index;
	if (length < 20)
		return EFI_COMPROMISED_DATA;
	if (node[0] == MESSAGING_DEVICE_PATH && shortcuts) {
		if (guid_equal(guid, 0xe0c14753, 0xf9be, 0x11d2, pcansi))
			puts8(writer, "VenPcAnsi()");
		else if (guid_equal(guid, 0xdfa66065, 0xb419, 0x11d3, vt100))
			puts8(writer, "VenVt100()");
		else if (guid_equal(guid, 0x7baec70b, 0x57e0, 0x4c76, vt100p))
			puts8(writer, "VenVt100Plus()");
		else if (guid_equal(guid, 0xad15a0d6, 0x8bec, 0x4acf, utf8))
			puts8(writer, "VenUtf8()");
		else if (guid_equal(guid, 0xeba4e8d2, 0x3858, 0x41ec, debug))
			puts8(writer, "DebugPort()");
		else if (guid_equal(guid, 0xd487ddb4, 0x008b, 0x11d9, sas)) {
			UINT16 topology;
			if (length != 44)
				return EFI_COMPROMISED_DATA;
			topology = read16(node + 40);
			puts8(writer, "SAS("); put_0x(writer, read64(node + 24));
			put(writer, ','); put_0x(writer, read64(node + 32));
			put(writer, ','); put_0x(writer, read16(node + 42)); put(writer, ',');
			if ((topology & 0x0f) == 0 && (topology & 0x80) == 0)
				puts8(writer, "NoTopology,0,0,0,");
			else if ((topology & 0x0f) <= 2 && (topology & 0x80) == 0) {
				puts8(writer, (topology & 0x10) != 0 ? "SATA," : "SAS,");
				puts8(writer, (topology & 0x20) != 0 ? "External," : "Internal,");
				puts8(writer, (topology & 0x40) != 0 ? "Expanded," : "Direct,");
				if ((topology & 0x0f) == 1)
					puts8(writer, "0,");
				else {
					put_0x(writer, ((topology >> 8) & 0xff) + 1);
					put(writer, ',');
				}
			} else {
				put_0x(writer, topology); puts8(writer, ",0,0,0,");
			}
			put_0x(writer, read32(node + 20)); put(writer, ')');
		} else if (guid_equal(guid, 0x37499a9d, 0x542f, 0x4c89, uart)) {
			UINT32 flow;
			if (length < 24)
				return EFI_COMPROMISED_DATA;
			flow = read32(node + 20) & 3;
			if (flow == 3)
				return EFI_UNSUPPORTED;
			puts8(writer, "UartFlowCtrl(");
			puts8(writer, flow == 0 ? "None" : flow == 1 ? "Hardware" : "XonXoff");
			put(writer, ')');
		} else
			goto generic;
		return EFI_SUCCESS;
	}
generic:
	kind = node[0] == HARDWARE_DEVICE_PATH ? "Hw" :
		node[0] == MESSAGING_DEVICE_PATH ? "Msg" :
		node[0] == MEDIA_DEVICE_PATH ? "Media" : "?";
	puts8(writer, "Ven");
	puts8(writer, kind);
	put(writer, '(');
	put_guid(writer, guid);
	if (length > 20) {
		put(writer, ',');
		for (index = 20; index < length; index++)
			put_hex(writer, node[index], 2, FALSE);
	}
	put(writer, ')');
	return EFI_SUCCESS;
}

static EFI_STATUS acpi_strings(const UINT8 *node, UINT16 length,
	const UINT8 **hid, const UINT8 **uid, const UINT8 **cid)
{
	const UINT8 **strings[3] = {hid, uid, cid};
	UINTN offset = 16;
	UINTN which;
	*hid = NULL;
	*uid = NULL;
	*cid = NULL;
	for (which = 0; which < 3 && offset < length; which++) {
		UINTN start = offset;
		while (offset < length && node[offset] != 0)
			offset++;
		if (offset == length)
			return EFI_COMPROMISED_DATA;
		*strings[which] = node + start;
		offset++;
	}
	return offset == length ? EFI_SUCCESS : EFI_COMPROMISED_DATA;
}

static EFI_STATUS render_acpi_ex(struct writer *writer, const UINT8 *node,
	UINT16 length, BOOLEAN display_only)
{
	const UINT8 *hid_string;
	const UINT8 *uid_string;
	const UINT8 *cid_string;
	UINT32 hid;
	UINT32 uid;
	UINT32 cid;
	EFI_STATUS status;
	if (length < 16)
		return EFI_COMPROMISED_DATA;
	status = acpi_strings(node, length, &hid_string, &uid_string, &cid_string);
	if (EFI_ERROR(status))
		return status;
	hid = read32(node + 4);
	uid = read32(node + 8);
	cid = read32(node + 12);
	if (display_only && ((hid >> 16) == 0x0a03 ||
	    ((cid >> 16) == 0x0a03 && (hid >> 16) != 0x0a08))) {
		puts8(writer, "PciRoot(");
		if (uid_string != NULL)
			put_ascii(writer, uid_string);
		else
			put_0x(writer, uid);
		put(writer, ')');
		return EFI_SUCCESS;
	}
	if (display_only && ((hid >> 16) == 0x0a08 || (cid >> 16) == 0x0a08)) {
		puts8(writer, "PcieRoot(");
		if (uid_string != NULL)
			put_ascii(writer, uid_string);
		else
			put_0x(writer, uid);
		put(writer, ')');
		return EFI_SUCCESS;
	}
	if (hid_string != NULL && uid_string != NULL && cid_string != NULL &&
	    *hid_string == 0 && *cid_string == 0 && *uid_string != 0) {
		puts8(writer, "AcpiExp(");
		put_eisa(writer, hid);
		put(writer, ',');
		if (cid == 0)
			put(writer, '0');
		else
			put_eisa(writer, cid);
		put(writer, ',');
		put_ascii(writer, uid_string);
		put(writer, ')');
		return EFI_SUCCESS;
	}
	puts8(writer, "AcpiEx(");
	if (display_only) {
		if (hid_string != NULL)
			put_ascii(writer, hid_string);
		else
			put_eisa(writer, hid);
		put(writer, ',');
		if (cid_string != NULL)
			put_ascii(writer, cid_string);
		else
			put_eisa(writer, cid);
		put(writer, ',');
		if (uid_string != NULL)
			put_ascii(writer, uid_string);
		else
			put_0x(writer, uid);
	} else {
		put_eisa(writer, hid);
		put(writer, ','); put_eisa(writer, cid);
		put(writer, ','); put_0x(writer, uid);
		put(writer, ',');
		if (hid_string != NULL)
			put_ascii(writer, hid_string);
		put(writer, ',');
		if (cid_string != NULL)
			put_ascii(writer, cid_string);
		put(writer, ',');
		if (uid_string != NULL)
			put_ascii(writer, uid_string);
	}
	put(writer, ')');
	return EFI_SUCCESS;
}

static EFI_STATUS render_node(struct writer *writer, const UINT8 *node,
	UINT16 length, BOOLEAN display_only, BOOLEAN shortcuts)
{
	UINTN index;
	UINT32 hid;
	UINT32 uid;
	if (node[0] == HARDWARE_DEVICE_PATH) {
		switch (node[1]) {
		case HW_PCI_DP:
			if (length != 6)
				return EFI_COMPROMISED_DATA;
			puts8(writer, "Pci("); put_0x(writer, node[5]); put(writer, ',');
			put_0x(writer, node[4]); put(writer, ')'); return EFI_SUCCESS;
		case HW_PCCARD_DP:
			if (length != 5)
				return EFI_COMPROMISED_DATA;
			puts8(writer, "PcCard("); put_0x(writer, node[4]); put(writer, ')'); return EFI_SUCCESS;
		case HW_MEMMAP_DP:
			if (length != 24)
				return EFI_COMPROMISED_DATA;
			puts8(writer, "MemoryMapped("); put_0x(writer, read32(node + 4));
			put(writer, ','); put_0x(writer, read64(node + 8)); put(writer, ',');
			put_0x(writer, read64(node + 16)); put(writer, ')'); return EFI_SUCCESS;
		case HW_VENDOR_DP: return render_vendor(writer, node, length, shortcuts);
		case HW_CONTROLLER_DP:
			if (length != 8)
				return EFI_COMPROMISED_DATA;
			puts8(writer, "Ctrl("); put_0x(writer, read32(node + 4)); put(writer, ')'); return EFI_SUCCESS;
		case HW_BMC_DP:
			if (length != 13)
				return EFI_COMPROMISED_DATA;
			puts8(writer, "BMC("); put_0x(writer, node[4]); put(writer, ',');
			put_0x(writer, read64(node + 5)); put(writer, ')'); return EFI_SUCCESS;
		}
	}
	if ((node[0] == MESSAGING_DEVICE_PATH && node[1] == MSG_VENDOR_DP) ||
	    (node[0] == MEDIA_DEVICE_PATH && node[1] == MEDIA_VENDOR_DP))
		return render_vendor(writer, node, length, shortcuts);
	if (node[0] == ACPI_DEVICE_PATH) {
		switch (node[1]) {
		case ACPI_DP:
			if (length != 12)
				return EFI_COMPROMISED_DATA;
			hid = read32(node + 4); uid = read32(node + 8);
			if ((hid & 0xffff) == 0x41d0) {
				const char *name = NULL;
				switch (hid >> 16) {
				case 0x0a03:
					name = "PciRoot";
					break;
				case 0x0a08:
					name = "PcieRoot";
					break;
				case 0x0604:
					name = "Floppy";
					break;
				case 0x0301:
					name = "Keyboard";
					break;
				case 0x0501:
					name = "Serial";
					break;
				case 0x0401:
					name = "ParallelPort";
					break;
				}
				if (name != NULL) {
					puts8(writer, name);
				} else {
					puts8(writer, "Acpi(PNP");
					put_hex(writer, hid >> 16, 4, FALSE);
				}
				put(writer, '(');
				if (name == NULL) { /* Acpi already owns its opening parenthesis. */
					writer->count--; put(writer, ',');
				}
			} else {
				puts8(writer, "Acpi(0x"); put_hex(writer, hid, 8, FALSE); put(writer, ',');
			}
			put_0x(writer, uid); put(writer, ')'); return EFI_SUCCESS;
		case ACPI_EXTENDED_DP: return render_acpi_ex(writer, node, length, display_only);
		case ACPI_ADR_DP:
			if (length < 8 || ((length - 8) & 3) != 0)
				return EFI_COMPROMISED_DATA;
			puts8(writer, "AcpiAdr(");
			for (index = 4; index < length; index += 4) {
				if (index != 4)
					put(writer, ',');
				put_0x(writer, read32(node + index));
			}
			put(writer, ')'); return EFI_SUCCESS;
		}
	}
	if (node[0] == HARDWARE_DEVICE_PATH)
		puts8(writer, "HardwarePath(");
	else if (node[0] == ACPI_DEVICE_PATH)
		puts8(writer, "AcpiPath(");
	else if (node[0] == MESSAGING_DEVICE_PATH)
		puts8(writer, "Msg(");
	else if (node[0] == MEDIA_DEVICE_PATH)
		puts8(writer, "MediaPath(");
	else {
		puts8(writer, "Path(");
		put_dec(writer, node[0]);
		put(writer, ',');
	}
	put_dec(writer, node[1]);
	if (length > 4) {
		put(writer, ',');
		for (index = 4; index < length; index++)
			put_hex(writer, node[index], 2, FALSE);
	}
	put(writer, ')');
	return EFI_SUCCESS;
}

static EFI_STATUS finish_node(const struct cdk2_device_path *node, UINTN node_size,
	BOOLEAN display_only, BOOLEAN shortcuts, CHAR16 *text, UINTN text_chars,
	UINTN *required_chars)
{
	struct writer count = {0};
	struct writer output;
	UINT16 length;
	EFI_STATUS status;
	if (node == NULL || required_chars == NULL || node_size < 4 ||
	    (text == NULL && text_chars != 0))
		return EFI_INVALID_PARAMETER;
	length = cdk2_device_path_node_length(node);
	if (length < 4 || length > node_size)
		return EFI_COMPROMISED_DATA;
	status = render_node(&count, (const UINT8 *)node, length, display_only, shortcuts);
	if (EFI_ERROR(status))
		return status;
	*required_chars = count.count + 1;
	if (text == NULL || text_chars < *required_chars)
		return EFI_BUFFER_TOO_SMALL;
	output.text = text; output.capacity = text_chars; output.count = 0;
	status = render_node(&output, (const UINT8 *)node, length, display_only, shortcuts);
	if (!EFI_ERROR(status))
		output.text[output.count] = 0;
	return status;
}

EFI_STATUS cdk2_device_path_node_to_text(const struct cdk2_device_path *node,
	UINTN node_size, BOOLEAN display_only, BOOLEAN allow_shortcuts,
	CHAR16 *text, UINTN text_chars, UINTN *required_chars)
{
	return finish_node(node, node_size, display_only, allow_shortcuts, text,
		text_chars, required_chars);
}

EFI_STATUS cdk2_device_path_to_text(const struct cdk2_device_path *path,
	UINTN path_size, BOOLEAN display_only, BOOLEAN allow_shortcuts,
	CHAR16 *text, UINTN text_chars, UINTN *required_chars)
{
	struct writer count = {0};
	struct writer output;
	struct writer *writer = &count;
	UINTN pass;
	EFI_STATUS status;
	if (path == NULL || required_chars == NULL || path_size < 4 ||
	    (text == NULL && text_chars != 0))
		return EFI_INVALID_PARAMETER;
	for (pass = 0; pass < 2; pass++) {
		UINTN offset = 0;
		BOOLEAN separator = FALSE;
		if (pass == 1) {
			*required_chars = count.count + 1;
			if (text == NULL || text_chars < *required_chars)
				return EFI_BUFFER_TOO_SMALL;
			output.text = text; output.capacity = text_chars; output.count = 0; writer = &output;
		}
		for (;;) {
			const UINT8 *node;
			UINT16 length;
			if (offset > path_size - 4)
				return EFI_COMPROMISED_DATA;
			node = (const UINT8 *)path + offset; length = read16(node + 2);
			if (length < 4 || length > path_size - offset)
				return EFI_COMPROMISED_DATA;
			if (node[0] == CDK2_DEVICE_PATH_END_TYPE) {
				if (length != 4)
					return EFI_COMPROMISED_DATA;
				if (node[1] == CDK2_DEVICE_PATH_END_INSTANCE) {
					put(writer, ',');
					separator = FALSE;
				} else if (node[1] == CDK2_DEVICE_PATH_END_ENTIRE) {
					if (offset + length != path_size)
						return EFI_COMPROMISED_DATA;
					break;
				} else {
					return EFI_COMPROMISED_DATA;
				}
			} else {
				if (separator)
					put(writer, '/');
				status = render_node(writer, node, length, display_only, allow_shortcuts);
				if (EFI_ERROR(status))
					return status;
				separator = TRUE;
			}
			offset += length;
		}
	}
	output.text[output.count] = 0;
	return EFI_SUCCESS;
}
