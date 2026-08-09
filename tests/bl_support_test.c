/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/bl_support.h>
#include <cdk2/pcd.h>
#include <guid/acpi_board_info.h>
#include <guid/graphics_info_hob.h>
#include <pi/hob.h>

#include <stdio.h>
#include <string.h>

static const EFI_GUID graphics_guid = {
	0x39f62cce, 0x6825, 0x4669, { 0xbb, 0x56, 0x54, 0x1a, 0xba, 0x75, 0x3a, 0x07 }
};
static const EFI_GUID board_guid = {
	0x0ad3d31b, 0xb3d8, 0x4506, { 0xae, 0x71, 0x2e, 0xf1, 0x10, 0x06, 0xd9, 0x0f }
};
static const EFI_GUID hob_list_guid = {
	0x7739f24c, 0x93d7, 0x11d4, { 0x9a, 0x3a, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d }
};
static const EFI_GUID tpm12_guid = {
	0x8b01e5b6, 0x4f19, 0x46e8, { 0xab, 0x93, 0x1c, 0x53, 0x67, 0x1b, 0x90, 0xcc }
};

struct guid_hob_graphics { EFI_HOB_GUID_TYPE header; EFI_PEI_GRAPHICS_INFO_HOB data; };
struct guid_hob_board { EFI_HOB_GUID_TYPE header; ACPI_BOARD_INFO data; };
struct fixture {
	struct guid_hob_graphics graphics;
	struct guid_hob_board board;
	EFI_HOB_GENERIC_HEADER end;
};

static uint32_t values32[64];
static uint64_t values64[64];
static EFI_GUID pointer_value;
static unsigned int calls, fail_call, fail_call2;
static struct cdk2_pcd_protocol protocol;

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "bl support test: %s\n", message);
	return condition ? 0 : 1;
}

static EFI_STATUS fail_if_requested(void)
{
	calls++;
	return calls == fail_call || calls == fail_call2 ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS model_set32(void *context, uint32_t token, uint32_t value)
{
	EFI_STATUS status;
	(void)context;
	status = fail_if_requested();
	if (!EFI_ERROR(status))
		values32[token] = value;
	return status;
}
static uint32_t model_get32(void *context, uint32_t token) { (void)context; return values32[token]; }
static uint64_t model_get64(void *context, uint32_t token) { (void)context; return values64[token]; }
static const void *model_get_ptr(void *context, uint32_t token) { (void)context; (void)token; return &pointer_value; }
static size_t model_get_size(void *context, uint32_t token) { (void)context; (void)token; return sizeof(pointer_value); }
static EFI_STATUS model_set64(void *context, uint32_t token, uint64_t value)
{
	EFI_STATUS status;
	(void)context;
	status = fail_if_requested();
	if (!EFI_ERROR(status))
		values64[token] = value;
	return status;
}
static EFI_STATUS model_set_ptr(void *context, uint32_t token,
	const void *value, size_t size)
{
	EFI_STATUS status;
	(void)context; (void)token;
	status = fail_if_requested();
	if (!EFI_ERROR(status) && size == sizeof(pointer_value))
		memcpy(&pointer_value, value, size);
	return status;
}

static uint64_t CDK2_MS_ABI abi_set32(size_t token, uint32_t value)
{ return model_set32(NULL, (uint32_t)token, value); }
static uint64_t CDK2_MS_ABI abi_set64(size_t token, uint64_t value)
{ return model_set64(NULL, (uint32_t)token, value); }
static uint64_t CDK2_MS_ABI abi_set_ptr(size_t token, size_t *size, void *value)
{ return model_set_ptr(NULL, (uint32_t)token, value, *size); }
static uint32_t CDK2_MS_ABI abi_get32(size_t token) { return values32[token]; }
static uint64_t CDK2_MS_ABI abi_get64(size_t token) { return values64[token]; }
static void *CDK2_MS_ABI abi_get_ptr(size_t token) { (void)token; return &pointer_value; }
static size_t CDK2_MS_ABI abi_get_size(size_t token) { (void)token; return sizeof(pointer_value); }

static uint64_t CDK2_MS_ABI mock_locate(const EFI_GUID *guid, void *registration,
	void **interface)
{
	(void)guid; (void)registration;
	*interface = &protocol;
	return EFI_SUCCESS;
}

static void make_fixture(struct fixture *fixture)
{
	memset(fixture, 0, sizeof(*fixture));
	fixture->graphics.header.header.hob_type = EFI_HOB_TYPE_GUID_EXTENSION;
	fixture->graphics.header.header.hob_length = sizeof(fixture->graphics);
	fixture->graphics.header.name = graphics_guid;
	fixture->graphics.data.frame_buffer_base = 0x80000000ULL;
	fixture->graphics.data.frame_buffer_size = 3840 * 2160 * 4;
	fixture->graphics.data.graphics_mode.horizontal_resolution = 3840;
	fixture->graphics.data.graphics_mode.vertical_resolution = 2160;
	fixture->graphics.data.graphics_mode.pixels_per_scan_line = 3840;
	fixture->board.header.header.hob_type = EFI_HOB_TYPE_GUID_EXTENSION;
	fixture->board.header.header.hob_length = sizeof(fixture->board);
	fixture->board.header.name = board_guid;
	fixture->board.data.pcie_base_address = 0xe0000000ULL;
	fixture->board.data.pcie_base_size = 0x10000000ULL;
	fixture->board.data.tpm12_present = 1;
	fixture->board.data.tpm20_present = 1;
	fixture->end.hob_type = EFI_HOB_TYPE_END_OF_HOB_LIST;
	fixture->end.hob_length = sizeof(fixture->end);
}

int main(void)
{
	static const struct cdk2_bl_support_policy admitted = { 0 };
	static const struct cdk2_bl_support_policy hidpi = {
		TRUE, TRUE, 1920, 1080, 16, 9
	};
	struct cdk2_bl_support_ops ops = {
		model_get32, model_get64, model_get_ptr, model_get_size,
		model_set32, model_set64, model_set_ptr, NULL
	};
	struct fixture fixture;
	uint32_t width, height;
	int failures = 0;

	make_fixture(&fixture);
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_SUCCESS, "complete graphics/board lifecycle succeeds");
	failures += expect(values32[29] == 3840 && values32[30] == 2160 &&
		values32[23] == 3840 && values32[24] == 2160,
		"physical video and setup resolution tokens updated");
	failures += expect(values64[33] == 0xe0000000ULL &&
		values64[34] == 0x10000000ULL, "PCI aperture tokens updated");
	failures += expect(memcmp(&pointer_value, &tpm12_guid, sizeof(tpm12_guid)) == 0,
		"TPM 1.2 retains admitted precedence when both flags are present");
	failures += expect(cdk2_bl_support_viewport(5120, 1440, &hidpi,
		&width, &height) && width == 1280 && height == 720,
		"wide HiDPI viewport is capped then halved without overflow");
	failures += expect(!cdk2_bl_support_viewport(1919, 1080, &hidpi,
		&width, &height) && width == 1919 && height == 1080,
		"below-threshold framebuffer remains physical size");

	make_fixture(&fixture); calls = 0; fail_call = 3;
	{
		uint32_t before_video = values32[29], before_vertical = values32[30];
		failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
			&ops) == EFI_DEVICE_ERROR && calls == 5 && values32[29] == before_video &&
			values32[30] == before_vertical,
			"configuration mutation failure rolls prior writes back in reverse");
	}
	fail_call = 0;
	make_fixture(&fixture);
	fixture.graphics.header.header.hob_length = 4;
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_COMPROMISED_DATA, "malformed HOB length fails closed");
	make_fixture(&fixture);
	fixture.graphics.data.graphics_mode.horizontal_resolution = 0;
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_COMPROMISED_DATA, "zero graphics geometry rejected before mutation");
	make_fixture(&fixture);
	fixture.board.data.tpm20_present = 2;
	values32[29] = 77;
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_COMPROMISED_DATA && values32[29] == 77,
		"malformed later board HOB cannot partially mutate graphics PCDs");
	make_fixture(&fixture);
	fixture.end.hob_length = 0;
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_COMPROMISED_DATA, "short end HOB rejected");
	{
		uint8_t unaligned[sizeof(fixture) + 1];
		memcpy(unaligned + 1, &fixture, sizeof(fixture));
		failures += expect(cdk2_bl_support_apply(unaligned + 1, sizeof(fixture),
			&admitted, &ops) == EFI_INVALID_PARAMETER, "unaligned HOB list rejected");
	}
	make_fixture(&fixture); calls = 0; fail_call = 3; fail_call2 = 4;
	values32[29] = 101; values32[30] = 102;
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_DEVICE_ERROR && calls == 5 && values32[29] == 101 &&
		values32[30] == 2160,
		"rollback failure is best effort and preserves original setter error");
	fail_call = 0; fail_call2 = 0;
	make_fixture(&fixture);
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &hidpi,
		&ops) == EFI_SUCCESS && values32[29] == 3840 && values32[30] == 2160 &&
		values32[23] == 1920 && values32[24] == 1080,
		"HiDPI preserves physical Video PCDs and scales only Setup PCDs");
	failures += expect(!cdk2_bl_support_viewport(1920, 1080, &hidpi, &width, &height),
		"HiDPI thresholds are strictly greater than admitted dimensions");

	make_fixture(&fixture);
	memset(&protocol, 0, sizeof(protocol));
	protocol.set32 = (void *)abi_set32;
	protocol.set64 = (void *)abi_set64;
	protocol.set_ptr = (void *)abi_set_ptr;
	protocol.get32 = (void *)abi_get32;
	protocol.get64 = (void *)abi_get64;
	protocol.get_ptr = (void *)abi_get_ptr;
	protocol.get_size = (void *)abi_get_size;
	{
		struct configuration_table { EFI_GUID guid; void *table; } table = {
			hob_list_guid, &fixture
		};
		struct system {
			uint8_t header[24]; uint16_t *vendor; uint32_t revision, pad;
			void *console[6], *runtime; struct cdk2_pcd_boot_services *boot;
			size_t count; struct configuration_table *tables;
		} system;
		struct cdk2_pcd_boot_services boot;

		memset(&system, 0, sizeof(system)); memset(&boot, 0, sizeof(boot));
		boot.locate_protocol = mock_locate;
		system.boot = &boot; system.count = 1; system.tables = &table;
		calls = 0;
		failures += expect(cdk2_bl_support_entry((void *)1, &system) == EFI_SUCCESS &&
			calls == 7, "real entry locates configuration service and consumes HOBs");
		boot.locate_protocol = NULL;
		failures += expect(cdk2_bl_support_entry((void *)1, &system) ==
			EFI_UNSUPPORTED, "missing configuration dependency is reported");
	}
	return failures == 0 ? 0 : 1;
}
