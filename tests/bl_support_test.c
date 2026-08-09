/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/bl_support.h>
#include <cdk2/pcd.h>
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

struct graphics_info {
	uint64_t framebuffer_base;
	uint32_t framebuffer_size, version, horizontal, vertical;
};
struct board_info {
	uint8_t revision, reserved[2], reset_value;
	uint64_t pm_evt_base, pm_gpe_en_base, pm_ctrl_reg_base, pm_timer_reg_base;
	uint64_t reset_reg_address, pcie_base, pcie_size;
	uint8_t tpm20_present, tpm12_present;
};
struct guid_hob_graphics { EFI_HOB_GUID_TYPE header; struct graphics_info data; };
struct guid_hob_board { EFI_HOB_GUID_TYPE header; struct board_info data; };
struct fixture {
	struct guid_hob_graphics graphics;
	struct guid_hob_board board;
	EFI_HOB_GENERIC_HEADER end;
};

static uint32_t values32[64];
static uint64_t values64[64];
static EFI_GUID pointer_value;
static unsigned calls, fail_call;
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
	return calls == fail_call ? EFI_DEVICE_ERROR : EFI_SUCCESS;
}

static EFI_STATUS model_set32(void *context, uint32_t token, uint32_t value)
{
	EFI_STATUS status;
	(void)context;
	status = fail_if_requested();
	if (!EFI_ERROR(status)) values32[token] = value;
	return status;
}
static EFI_STATUS model_set64(void *context, uint32_t token, uint64_t value)
{
	EFI_STATUS status;
	(void)context;
	status = fail_if_requested();
	if (!EFI_ERROR(status)) values64[token] = value;
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
	fixture->graphics.data.horizontal = 3840;
	fixture->graphics.data.vertical = 2160;
	fixture->board.header.header.hob_type = EFI_HOB_TYPE_GUID_EXTENSION;
	fixture->board.header.header.hob_length = sizeof(fixture->board);
	fixture->board.header.name = board_guid;
	fixture->board.data.pcie_base = 0xe0000000ULL;
	fixture->board.data.pcie_size = 0x10000000ULL;
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
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_DEVICE_ERROR && calls == 3,
		"configuration mutation failure stops later lifecycle operations");
	fail_call = 0;
	make_fixture(&fixture);
	fixture.graphics.header.header.hob_length = 4;
	failures += expect(cdk2_bl_support_apply(&fixture, sizeof(fixture), &admitted,
		&ops) == EFI_COMPROMISED_DATA, "malformed HOB length fails closed");

	make_fixture(&fixture);
	memset(&protocol, 0, sizeof(protocol));
	protocol.set32 = (void *)abi_set32;
	protocol.set64 = (void *)abi_set64;
	protocol.set_ptr = (void *)abi_set_ptr;
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
