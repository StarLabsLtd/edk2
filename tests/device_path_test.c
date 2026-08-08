/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/device_path.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static UINT32 allocations;
static UINT32 frees;
static BOOLEAN fail_allocation;

static EFI_STATUS allocate(void *context, UINTN size, void **buffer)
{
	(void)context;
	if (fail_allocation)
		return EFI_OUT_OF_RESOURCES;
	*buffer = malloc(size);
	if (*buffer == NULL)
		return EFI_OUT_OF_RESOURCES;
	allocations++;
	return EFI_SUCCESS;
}

static void release(void *context, void *buffer)
{
	(void)context;
	free(buffer);
	frees++;
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "device-path test: %s\n", message);
	return !condition;
}

static void set_node(struct cdk2_device_path *node, UINT8 type, UINT8 subtype,
	UINT16 length)
{
	node->type = type;
	node->subtype = subtype;
	node->length[0] = (UINT8)length;
	node->length[1] = (UINT8)(length >> 8);
}

static int text_equal(const CHAR16 *actual, const char *expected)
{
	while (*expected != '\0' && *actual == (CHAR16)(UINT8)*expected) {
		actual++;
		expected++;
	}
	return *actual == 0 && *expected == '\0';
}

static void put16(UINT8 *bytes, UINT16 value)
{
	bytes[0] = (UINT8)value;
	bytes[1] = (UINT8)(value >> 8);
}

static void put32(UINT8 *bytes, UINT32 value)
{
	put16(bytes, (UINT16)value);
	put16(bytes + 2, (UINT16)(value >> 16));
}

static void put64(UINT8 *bytes, UINT64 value)
{
	put32(bytes, (UINT32)value);
	put32(bytes + 4, (UINT32)(value >> 32));
}

static int expect_text(UINT8 *node, UINTN size, BOOLEAN display_only,
	BOOLEAN shortcuts, const char *expected, const char *message)
{
	CHAR16 output[160];
	CHAR16 sentinel[2] = {0x1234, 0x5678};
	UINTN required = 0;
	UINTN index = 0;
	EFI_STATUS status;
	while (expected[index] != '\0')
		index++;
	status = cdk2_device_path_node_to_text((void *)node, size, display_only,
		shortcuts, NULL, 0, &required);
	if (status != EFI_BUFFER_TOO_SMALL || required != index + 1)
		return expect(FALSE, message);
	if (index != 0) {
		status = cdk2_device_path_node_to_text((void *)node, size, display_only,
			shortcuts, sentinel, 1, &required);
		if (status != EFI_BUFFER_TOO_SMALL || sentinel[0] != 0x1234 ||
		    sentinel[1] != 0x5678)
			return expect(FALSE, message);
	}
	status = cdk2_device_path_node_to_text((void *)node, size, display_only,
		shortcuts, output, ARRAY_SIZE(output), &required);
	return expect(status == EFI_SUCCESS && text_equal(output, expected), message);
}

static int formatter_tests(void)
{
	UINT8 node[96] = {0};
	UINT8 path[32] = {0};
	CHAR16 output[160];
	UINTN required;
	int failures = 0;

	set_node((void *)node, 1, 1, 6);
	node[4] = 2;
	node[5] = 0x1f;
	failures += expect_text(node, 6, FALSE, FALSE, "Pci(0x1f,0x2)", "PCI text");
	set_node((void *)node, 1, 2, 5); node[4] = 3;
	failures += expect_text(node, 5, FALSE, FALSE, "PcCard(0x3)", "PC Card text");
	set_node((void *)node, 1, 3, 24); put32(node + 4, 4);
	put64(node + 8, 0x123456789ULL); put64(node + 16, 0xabcdefULL);
	failures += expect_text(node, 24, FALSE, FALSE,
		"MemoryMapped(0x4,0x123456789,0xabcdef)", "memory map text");
	set_node((void *)node, 1, 5, 8); put32(node + 4, 0x1234);
	failures += expect_text(node, 8, FALSE, FALSE, "Ctrl(0x1234)", "controller text");
	set_node((void *)node, 1, 6, 13); node[4] = 1; put64(node + 5, 0x123456789abcdef0ULL);
	failures += expect_text(node, 13, FALSE, FALSE,
		"BMC(0x1,0x123456789abcdef0)", "BMC text");

	memset(node, 0, sizeof(node)); set_node((void *)node, 1, 4, 22);
	put32(node + 4, 0x11223344); put16(node + 8, 0x5566); put16(node + 10, 0x7788);
	for (UINTN i = 0; i < 8; i++)
		node[12 + i] = (UINT8)(i + 1);
	node[20] = 0xaa; node[21] = 0x05;
	failures += expect_text(node, 22, FALSE, TRUE,
		"VenHw(11223344-5566-7788-0102-030405060708,aa05)", "vendor data text");
	memset(node, 0, sizeof(node)); set_node((void *)node, 3, 0x0a, 20);
	put32(node + 4, 0xe0c14753); put16(node + 8, 0xf9be); put16(node + 10, 0x11d2);
	{ const UINT8 tail[8] = {0x9a, 0x0c, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d}; memcpy(node + 12, tail, 8); }
	failures += expect_text(node, 20, FALSE, TRUE, "VenPcAnsi()", "vendor shortcut");
	failures += expect_text(node, 20, FALSE, FALSE,
		"VenMsg(e0c14753-f9be-11d2-9a0c-0090273fc14d)", "disabled vendor shortcut");
	{
		struct alias_fixture {
			UINT32 d1;
			UINT16 d2;
			UINT16 d3;
			UINT8 d4[8];
			const char *text;
		};
		static const struct alias_fixture aliases[] = {
			{0xdfa66065, 0xb419, 0x11d3,
				{0x9a, 0x2d, 0, 0x90, 0x27, 0x3f, 0xc1, 0x4d}, "VenVt100()"},
			{0x7baec70b, 0x57e0, 0x4c76,
				{0x8e, 0x87, 0x2f, 0x9e, 0x28, 0x08, 0x83, 0x43}, "VenVt100Plus()"},
			{0xad15a0d6, 0x8bec, 0x4acf,
				{0xa0, 0x73, 0xd0, 0x1d, 0xe7, 0x7e, 0x2d, 0x88}, "VenUtf8()"},
			{0xeba4e8d2, 0x3858, 0x41ec,
				{0xa2, 0x81, 0x26, 0x47, 0xba, 0x96, 0x60, 0xd0}, "DebugPort()"},
		};
		for (UINTN i = 0; i < ARRAY_SIZE(aliases); i++) {
			put32(node + 4, aliases[i].d1); put16(node + 8, aliases[i].d2);
			put16(node + 10, aliases[i].d3); memcpy(node + 12, aliases[i].d4, 8);
			failures += expect_text(node, 20, FALSE, TRUE, aliases[i].text,
				"terminal vendor alias");
		}
	}
	set_node((void *)node, 3, 0x0a, 24); put32(node + 4, 0x37499a9d);
	put16(node + 8, 0x542f); put16(node + 10, 0x4c89);
	{
		const UINT8 tail[8] = {0xa0, 0x26, 0x35, 0xda, 0x14, 0x20, 0x94, 0xe4};
		memcpy(node + 12, tail, 8);
	}
	for (UINT32 flow = 0; flow < 3; flow++) {
		static const char *const texts[] = {
			"UartFlowCtrl(None)", "UartFlowCtrl(Hardware)", "UartFlowCtrl(XonXoff)"};
		put32(node + 20, flow);
		failures += expect_text(node, 24, FALSE, TRUE, texts[flow], "UART flow alias");
	}
	set_node((void *)node, 3, 0x0a, 44); put32(node + 4, 0xd487ddb4);
	put16(node + 8, 0x008b); put16(node + 10, 0x11d9);
	{
		const UINT8 tail[8] = {0xaf, 0xdc, 0, 0x10, 0x83, 0xff, 0xca, 0x4d};
		memcpy(node + 12, tail, 8);
	}
	put32(node + 20, 9); put64(node + 24, 0x11); put64(node + 32, 0x22);
	put16(node + 40, 0); put16(node + 42, 3);
	failures += expect_text(node, 44, FALSE, TRUE,
		"SAS(0x11,0x22,0x3,NoTopology,0,0,0,0x9)", "SAS vendor alias");

	memset(node, 0, sizeof(node)); set_node((void *)node, 2, 1, 12);
	put32(node + 4, 0x0a0341d0); put32(node + 8, 2);
	failures += expect_text(node, 12, FALSE, FALSE, "PciRoot(0x2)", "ACPI PCI shortcut");
	put32(node + 4, 0x123441d0);
	failures += expect_text(node, 12, FALSE, FALSE, "Acpi(PNP1234,0x2)", "ACPI PNP text");
	put32(node + 4, 0x12345678);
	failures += expect_text(node, 12, FALSE, FALSE, "Acpi(0x12345678,0x2)", "ACPI raw text");

	memset(node, 0, sizeof(node)); set_node((void *)node, 2, 2, 23);
	put32(node + 4, 0x0a0341d0); put32(node + 8, 7); put32(node + 12, 0);
	node[16] = 0; memcpy(node + 17, "ROOT", 5); node[22] = 0;
	failures += expect_text(node, 23, FALSE, FALSE, "AcpiExp(PNP0A03,0,ROOT)", "ACPI Exp text");
	failures += expect_text(node, 23, TRUE, FALSE, "PciRoot(ROOT)", "ACPI Ex shortcut");
	memset(node + 16, 0, 7); memcpy(node + 16, "HID", 4); memcpy(node + 20, "U", 2);
	node[22] = 0;
	failures += expect_text(node, 23, FALSE, FALSE,
		"AcpiEx(PNP0A03,@@@0000,0x7,HID,,U)", "ACPI Ex full tails");
	failures += expect_text(node, 23, TRUE, FALSE, "PciRoot(U)", "ACPI Ex display root");

	memset(node, 0, sizeof(node)); set_node((void *)node, 2, 3, 16);
	put32(node + 4, 0x111); put32(node + 8, 0x222); put32(node + 12, 0x333);
	failures += expect_text(node, 16, FALSE, FALSE,
		"AcpiAdr(0x111,0x222,0x333)", "ACPI ADR text");
	set_node((void *)node, 1, 0x77, 7); node[4] = 1; node[5] = 2; node[6] = 0xff;
	failures += expect_text(node, 7, FALSE, FALSE,
		"HardwarePath(119,0102ff)", "known-type unknown node");
	set_node((void *)node, 9, 8, 5); node[4] = 0xaa;
	failures += expect_text(node, 5, FALSE, FALSE, "Path(9,8,aa)", "unknown node");

	set_node((void *)node, 1, 1, 7);
	failures += expect(cdk2_device_path_node_to_text((void *)node, 7, FALSE, FALSE,
		output, 160, &required) == EFI_COMPROMISED_DATA, "malformed known node accepted");
	memset(node, 0, sizeof(node)); set_node((void *)node, 2, 2, 19);
	put32(node + 4, 0x0a0341d0); node[16] = 'x'; node[17] = 0; node[18] = 0;
	failures += expect_text(node, 19, FALSE, FALSE,
		"AcpiEx(PNP0A03,@@@0000,0x0,x,,)", "partial ACPI tails");
	set_node((void *)node, 2, 2, 17);
	node[16] = 'x';
	failures += expect(cdk2_device_path_node_to_text((void *)node, 17, FALSE, FALSE,
		output, 160, &required) == EFI_COMPROMISED_DATA,
		"unterminated ACPI tail accepted");
	set_node((void *)node, 2, 2, 16);
	failures += expect_text(node, 16, TRUE, FALSE,
		"PciRoot(0x0)", "absent ACPI tails");

	memset(path, 0, sizeof(path)); set_node((void *)path, 1, 1, 6);
	path[4] = 2; path[5] = 3; set_node((void *)(path + 6), 1, 2, 5); path[10] = 4;
	set_node((void *)(path + 11), 0x7f, 0xff, 4);
	failures += expect(cdk2_device_path_to_text((void *)path, 15, FALSE, FALSE,
		output, 160, &required) == EFI_SUCCESS &&
		text_equal(output, "Pci(0x3,0x2)/PcCard(0x4)"), "whole path text");
	return failures;
}

static int messaging_formatter_tests(void)
{
	struct fixture {
		UINT8 subtype;
		UINT16 length;
		BOOLEAN display_only;
		const char *text;
	};
	static const struct fixture fixtures[] = {
		{0x01, 8, FALSE, "Ata(Primary,Master,0x0)"},
		{0x02, 8, FALSE, "Scsi(0x0,0x0)"},
		{0x03, 24, FALSE, "Fibre(0x0,0x0)"},
		{0x04, 16, FALSE, "I1394(0000000000000000)"},
		{0x05, 6, FALSE, "USB(0x0,0x0)"},
		{0x06, 8, FALSE, "I2O(0x0)"},
		{0x09, 48, FALSE,
			"Infiniband(0x0,00000000-0000-0000-0000-000000000000,0x0,0x0,0x0)"},
		{0x0b, 37, FALSE, "MAC(000000000000,0x0)"},
		{0x0c, 27, TRUE, "IPv4(0.0.0.0)"},
		{0x0d, 60, TRUE, "IPv6(0000:0000:0000:0000:0000:0000:0000:0000)"},
		{0x0e, 19, FALSE, "Uart(DEFAULT,DEFAULT,D,D)"},
		{0x0f, 11, FALSE, "UsbClass(0x0,0x0,0x0,0x0,0x0)"},
		{0x10, 10, FALSE, "UsbWwid(0x0,0x0,0x0,\"\")"},
		{0x11, 5, FALSE, "Unit(0x0)"},
		{0x12, 10, FALSE, "Sata(0x0,0x0,0x0)"},
		{0x13, 19, FALSE, "iSCSI(,0x0,0x0000000000000000,None,None,CHAP_BI,TCP)"},
		{0x14, 6, FALSE, "Vlan(0)"},
		{0x15, 24, FALSE, "FibreEx(0x0000000000000000,0x0000000000000000)"},
		{0x16, 24, FALSE,
			"SasEx(0x0000000000000000,0x0000000000000000,0x0,NoTopology,0,0,0)"},
		{0x17, 16, FALSE, "NVMe(0x0,00-00-00-00-00-00-00-00)"},
		{0x18, 4, FALSE, "Uri()"},
		{0x19, 6, FALSE, "UFS(0x0,0x0)"},
		{0x1a, 5, FALSE, "SD(0x0)"},
		{0x1b, 10, FALSE, "Bluetooth(000000000000)"},
		{0x1c, 36, FALSE, "Wi-Fi()"},
		{0x1d, 5, FALSE, "eMMC(0x0)"},
		{0x1e, 11, FALSE, "BluetoothLE(000000000000,0x0)"},
		{0x1f, 5, FALSE, "Dns()"},
	};
	UINT8 node[64];
	CHAR16 output[16] = {0x7777};
	UINTN required;
	int failures = 0;
	UINTN index;
	for (index = 0; index < ARRAY_SIZE(fixtures); index++) {
		memset(node, 0, sizeof(node));
		set_node((void *)node, 3, fixtures[index].subtype, fixtures[index].length);
		failures += expect_text(node, fixtures[index].length,
			fixtures[index].display_only, TRUE, fixtures[index].text,
			"messaging handler fixture");
		set_node((void *)node, 3, fixtures[index].subtype,
			(UINT16)(fixtures[index].length - 1));
		failures += expect(cdk2_device_path_node_to_text((void *)node,
			fixtures[index].length, fixtures[index].display_only, TRUE,
			output, ARRAY_SIZE(output), &required) == EFI_COMPROMISED_DATA,
			"short messaging node accepted");
	}
	memset(node, 0, sizeof(node));
	set_node((void *)node, 3, 1, 8);
	failures += expect_text(node, 8, TRUE, TRUE, "Ata(0x0)", "ATA display variant");
	set_node((void *)node, 3, 0x0c, 27);
	node[8] = 192; node[9] = 0; node[10] = 2; node[11] = 1;
	failures += expect_text(node, 27, FALSE, TRUE,
		"IPv4(192.0.2.1,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)",
		"IPv4 full variant");
	set_node((void *)node, 3, 0x18, 7);
	memcpy(node + 4, "abc", 3);
	failures += expect_text(node, 7, FALSE, TRUE, "Uri(abc)", "bounded URI");
	memset(node, 0, sizeof(node));
	set_node((void *)node, 3, 0x0f, 11);
	node[8] = 3; node[9] = 1; node[10] = 2;
	failures += expect_text(node, 11, FALSE, TRUE,
		"UsbHID(0x0,0x0,0x1,0x2)", "USB class alias");
	node[8] = 0xfe; node[9] = 1;
	failures += expect_text(node, 11, FALSE, TRUE,
		"UsbDeviceFirmwareUpdate(0x0,0x0,0x2)", "USB reserved class alias");
	memset(node, 0, sizeof(node));
	set_node((void *)node, 3, 0x0e, 19);
	put64(node + 8, 115200); node[16] = 8; node[17] = 1; node[18] = 1;
	failures += expect_text(node, 19, FALSE, TRUE,
		"Uart(115200,8,N,1)", "UART explicit variant");
	memset(node, 0, sizeof(node));
	set_node((void *)node, 3, 0x1f, 21);
	node[5] = 8; node[6] = 8; node[7] = 4; node[8] = 4;
	failures += expect_text(node, 21, FALSE, TRUE, "Dns(8.8.4.4)", "DNS IPv4 fixture");
	return failures;
}

static int media_bbs_formatter_tests(void)
{
	struct fixture {
		UINT8 subtype;
		UINT16 length;
		BOOLEAN display_only;
		const char *text;
	};
	static const struct fixture fixtures[] = {
		{0x01, 42, FALSE, "HD(0,0,0,0x0,0x0)"},
		{0x02, 24, FALSE, "CDROM(0x0,0x0,0x0)"},
		{0x04, 6, FALSE, ""},
		{0x05, 20, FALSE, "Media(00000000-0000-0000-0000-000000000000)"},
		{0x06, 20, FALSE, "FvFile(00000000-0000-0000-0000-000000000000)"},
		{0x07, 20, FALSE, "Fv(00000000-0000-0000-0000-000000000000)"},
		{0x08, 24, FALSE, "Offset(0x0,0x0)"},
		{0x09, 38, FALSE,
			"RamDisk(0x0,0x0,0,00000000-0000-0000-0000-000000000000)"},
	};
	struct ram_alias {
		UINT32 d1;
		UINT16 d2;
		UINT16 d3;
		UINT8 d4[8];
		const char *text;
	};
	static const struct ram_alias aliases[] = {
		{0x77ab535a, 0x45fc, 0x624b,
			{0x55, 0x60, 0xf7, 0xb2, 0x81, 0xd1, 0xf9, 0x6e}, "VirtualDisk(0x0,0x0,0)"},
		{0x3d5abd30, 0x4175, 0x87ce,
			{0x6d, 0x64, 0xd2, 0xad, 0xe5, 0x23, 0xc4, 0xbb}, "VirtualCD(0x0,0x0,0)"},
		{0x5cea02c9, 0x4d07, 0x69d3,
			{0x26, 0x9f, 0x44, 0x96, 0xfb, 0xe0, 0x96, 0xf9},
			"PersistentVirtualDisk(0x0,0x0,0)"},
		{0x08018188, 0x42cd, 0xbb48,
			{0x10, 0x0f, 0x53, 0x87, 0xd5, 0x3d, 0xed, 0x3d},
			"PersistentVirtualCD(0x0,0x0,0)"},
	};
	UINT8 node[64];
	UINT8 path[24];
	CHAR16 output[160];
	UINTN required;
	UINTN index;
	int failures = 0;
	for (index = 0; index < ARRAY_SIZE(fixtures); index++) {
		memset(node, 0, sizeof(node));
		set_node((void *)node, 4, fixtures[index].subtype, fixtures[index].length);
		failures += expect_text(node, fixtures[index].length,
			fixtures[index].display_only, TRUE, fixtures[index].text,
			fixtures[index].text);
		set_node((void *)node, 4, fixtures[index].subtype,
			(UINT16)(fixtures[index].length - 1));
		failures += expect(cdk2_device_path_node_to_text((void *)node,
			fixtures[index].length, FALSE, TRUE, output, ARRAY_SIZE(output),
			&required) == EFI_COMPROMISED_DATA, "short media node accepted");
	}
	memset(node, 0, sizeof(node));
	set_node((void *)node, 4, 3, 20);
	failures += expect_text(node, 20, FALSE, FALSE,
		"VenMedia(00000000-0000-0000-0000-000000000000)", "media vendor");
	set_node((void *)node, 4, 2, 24);
	failures += expect_text(node, 24, TRUE, TRUE, "CDROM(0x0)", "CDROM display variant");
	for (index = 0; index < ARRAY_SIZE(aliases); index++) {
		memset(node, 0, sizeof(node)); set_node((void *)node, 4, 9, 38);
		put32(node + 20, aliases[index].d1); put16(node + 24, aliases[index].d2);
		put16(node + 26, aliases[index].d3); memcpy(node + 28, aliases[index].d4, 8);
		failures += expect_text(node, 38, FALSE, TRUE, aliases[index].text,
			"RAM disk alias");
	}
	memset(node, 0, sizeof(node)); set_node((void *)node, 5, 1, 13);
	put16(node + 4, 2); put16(node + 6, 7); memcpy(node + 8, "disk", 5);
	failures += expect_text(node, 13, FALSE, TRUE, "BBS(HD,disk,0x7)", "BBS full");
	failures += expect_text(node, 13, TRUE, TRUE, "BBS(HD,disk)", "BBS display");
	set_node((void *)node, 5, 1, 12); node[11] = 'x';
	failures += expect(cdk2_device_path_node_to_text((void *)node, 12, FALSE, TRUE,
		output, ARRAY_SIZE(output), &required) == EFI_COMPROMISED_DATA,
		"unterminated BBS string accepted");
	memset(node, 0, sizeof(node)); set_node((void *)node, 4, 0x7e, 6);
	node[4] = 0xaa; node[5] = 0xbb;
	failures += expect_text(node, 6, FALSE, TRUE,
		"MediaPath(126,aabb)", "unknown media node");
	set_node((void *)node, 0x7f, 1, 4);
	failures += expect_text(node, 4, FALSE, TRUE, ",", "end instance node");
	memset(path, 0, sizeof(path)); set_node((void *)path, 1, 2, 5); path[4] = 1;
	set_node((void *)(path + 5), 0x7f, 1, 4);
	set_node((void *)(path + 9), 1, 2, 5); path[13] = 2;
	set_node((void *)(path + 14), 0x7f, 0xff, 4);
	failures += expect(cdk2_device_path_to_text((void *)path, 18, FALSE, TRUE,
		output, ARRAY_SIZE(output), &required) == EFI_SUCCESS &&
		text_equal(output, "PcCard(0x1),PcCard(0x2)"), "end instance path separator");
	return failures;
}

int main(void)
{
	struct cdk2_device_path_allocator allocator = {
		.allocate = allocate, .free = release,
	};
	UINT8 first_bytes[12] = {0};
	UINT8 second_bytes[10] = {0};
	struct cdk2_device_path *first = (void *)first_bytes;
	struct cdk2_device_path *second = (void *)second_bytes;
	struct cdk2_device_path *result;
	struct cdk2_device_path *node;
	const struct cdk2_device_path *cursor;
	UINTN size;
	int failures = 0;
	failures += formatter_tests();
	failures += messaging_formatter_tests();
	failures += media_bbs_formatter_tests();

	set_node(first, 1, 1, 8);
	set_node((void *)(first_bytes + 8), CDK2_DEVICE_PATH_END_TYPE,
		CDK2_DEVICE_PATH_END_ENTIRE, 4);
	set_node(second, 2, 3, 6);
	set_node((void *)(second_bytes + 6), CDK2_DEVICE_PATH_END_TYPE,
		CDK2_DEVICE_PATH_END_ENTIRE, 4);
	failures += expect(cdk2_device_path_size(first, sizeof(first_bytes), &size) ==
		EFI_SUCCESS && size == sizeof(first_bytes), "valid path size failed");
	first->length[0] = 3;
	failures += expect(cdk2_device_path_size(first, sizeof(first_bytes), &size) ==
		EFI_COMPROMISED_DATA, "short node accepted");
	first->length[0] = 8;
	failures += expect(cdk2_device_path_duplicate(first, &allocator, &result) ==
		EFI_SUCCESS && memcmp(result, first, sizeof(first_bytes)) == 0,
		"duplicate failed");
	release(NULL, result);
	failures += expect(cdk2_device_path_append(first, second, &allocator, &result) ==
		EFI_SUCCESS && cdk2_device_path_size(result, 18, &size) == EFI_SUCCESS &&
		size == 18, "append failed");
	release(NULL, result);
	failures += expect(cdk2_device_path_create_node(3, 4, 9, &allocator, &node) ==
		EFI_SUCCESS && cdk2_device_path_node_length(node) == 9 &&
		((UINT8 *)node)[8] == 0, "create node failed");
	failures += expect(cdk2_device_path_append_node(first, node, &allocator, &result) ==
		EFI_SUCCESS && cdk2_device_path_size(result, 21, &size) == EFI_SUCCESS &&
		size == 21, "append node failed");
	release(NULL, node);
	release(NULL, result);
	failures += expect(cdk2_device_path_append_instance(first, second, &allocator,
		&result) == EFI_SUCCESS && cdk2_device_path_is_multi_instance(result),
		"append instance failed");
	cursor = result;
	failures += expect(cdk2_device_path_next_instance(&cursor, &size, &allocator,
		&node) == EFI_SUCCESS && size == sizeof(first_bytes) && cursor != NULL &&
		!cdk2_device_path_is_multi_instance(node), "first instance failed");
	release(NULL, node);
	failures += expect(cdk2_device_path_next_instance(&cursor, &size, &allocator,
		&node) == EFI_SUCCESS && size == sizeof(second_bytes) && cursor == NULL,
		"final instance failed");
	release(NULL, node);
	release(NULL, result);
	fail_allocation = TRUE;
	result = (void *)(UINTN)1;
	failures += expect(cdk2_device_path_duplicate(first, &allocator, &result) ==
		EFI_OUT_OF_RESOURCES && result == NULL,
		"allocation failure was not contained");
	failures += expect(allocations == frees, "utility allocation leaked");
	return failures == 0 ? 0 : 1;
}
