/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/sata_controller.h>

#include <stddef.h>

struct guid { UINT32 a; UINT16 b, c; UINT8 d[8]; };
static const struct guid driver_guid = { 0x18a031ab, 0xb443, 0x4d1a,
	{ 0xa5, 0xc0, 0x0c, 0x09, 0x26, 0x1e, 0x9f, 0x71 } };
static const struct guid component_guid = { 0x107a772c, 0xd5e1, 0x11d4,
	{ 0x9a, 0x46, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } };
static const struct guid component2_guid = { 0x6a7a5cff, 0xe8d9, 0x4f70,
	{ 0xba, 0xda, 0x75, 0xab, 0x30, 0x25, 0xce, 0x14 } };
static const struct guid pci_guid = { 0x4cf5b200, 0x68b8, 0x4ca5,
	{ 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a } };
static const struct guid path_guid = { 0x09576e91, 0x6d3f, 0x11d2,
	{ 0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b } };
static const struct guid ide_guid = { 0xa1e37052, 0x80d9, 0x4e65,
	{ 0xa3, 0x17, 0x3e, 0x9a, 0x55, 0xc4, 0x3e, 0xc9 } };
typedef EFI_STATUS CDK2_MS_ABI alloc_fn(UINT32, UINTN, void **);
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI open_fn(void *, const struct guid *, void **,
	void *, void *, UINT32);
typedef EFI_STATUS CDK2_MS_ABI close_fn(void *, const struct guid *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI install_fn(void **, const struct guid *, void *, ...);
typedef EFI_STATUS CDK2_MS_ABI uninstall_fn(void *, const struct guid *, void *, ...);
struct boot_services { UINT8 before_alloc[64]; alloc_fn *allocate_pool; free_fn *free_pool;
	UINT8 before_open[200]; open_fn *open_protocol; close_fn *close_protocol;
	UINT8 before_install[32]; install_fn *install_multiple; uninstall_fn *uninstall_multiple; };
struct system_table { UINT8 before_boot_services[96]; struct boot_services *boot_services; };
struct pci_io;
typedef EFI_STATUS CDK2_MS_ABI access_fn(struct pci_io *, UINT32, UINT8, UINT64,
	UINTN, void *);
struct access { access_fn *read; void *write; };
typedef EFI_STATUS CDK2_MS_ABI config_fn(struct pci_io *, UINT32, UINT32, UINTN, void *);
struct config_access { config_fn *read; void *write; };
typedef EFI_STATUS CDK2_MS_ABI attr_fn(struct pci_io *, UINT32, UINT64, UINT64 *);
struct pci_io { void *poll_mem, *poll_io; struct access mem, io; struct config_access pci;
	void *copy, *map, *unmap, *alloc, *free, *flush, *location; attr_fn *attributes; };
struct ata_mode { BOOLEAN valid; UINT8 pad[3]; UINT32 mode; };
struct collective { struct ata_mode pio, single, multi, udma; void *extended; };
struct ide_protocol;
typedef EFI_STATUS CDK2_MS_ABI channel_fn(struct ide_protocol *, UINT8, BOOLEAN *, UINT8 *);
typedef EFI_STATUS CDK2_MS_ABI phase_fn(struct ide_protocol *, UINT32, UINT8);
typedef EFI_STATUS CDK2_MS_ABI submit_fn(struct ide_protocol *, UINT8, UINT8, void *);
typedef EFI_STATUS CDK2_MS_ABI disqualify_fn(struct ide_protocol *, UINT8, UINT8,
	struct collective *);
typedef EFI_STATUS CDK2_MS_ABI calculate_fn(struct ide_protocol *, UINT8, UINT8,
	struct collective **);
typedef EFI_STATUS CDK2_MS_ABI timing_fn(struct ide_protocol *, UINT8, UINT8,
	struct collective *);
struct ide_protocol { channel_fn *get_channel; phase_fn *notify; submit_fn *submit;
	disqualify_fn *disqualify; calculate_fn *calculate; timing_fn *timing;
	BOOLEAN enum_all; UINT8 channel_count; };
struct context { struct ide_protocol ide; struct cdk2_sata_controller controller;
	struct pci_io *pci; void *handle; UINT64 original; BOOLEAN changed; };
struct driver_binding;
typedef EFI_STATUS CDK2_MS_ABI supported_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI start_fn(struct driver_binding *, void *, void *);
typedef EFI_STATUS CDK2_MS_ABI stop_fn(struct driver_binding *, void *, UINTN, void **);
struct driver_binding { supported_fn *supported; start_fn *start; stop_fn *stop;
	UINT32 version; void *image; void *handle; };
typedef EFI_STATUS CDK2_MS_ABI driver_name_fn(void *, CHAR8 *, CHAR16 **);
typedef EFI_STATUS CDK2_MS_ABI controller_name_fn(void *, void *, void *, CHAR8 *, CHAR16 **);
struct component_name { driver_name_fn *driver_name; controller_name_fn *controller_name;
	CHAR8 *languages; };
static struct boot_services *bs;
static void *driver_handle;
static CHAR16 name[] = L"SATA Controller Init Driver";
static CHAR16 controller_name[] = L"Sata Controller";

static struct context *from_ide(struct ide_protocol *ide)
{ return (struct context *)((UINT8 *)ide - offsetof(struct context, ide)); }
static EFI_STATUS CDK2_MS_ABI channel(struct ide_protocol *ide, UINT8 channel_no,
	BOOLEAN *enabled, UINT8 *devices)
{ return cdk2_sata_get_channel(&from_ide(ide)->controller, channel_no, enabled, devices); }
static EFI_STATUS CDK2_MS_ABI phase(struct ide_protocol *ide, UINT32 value, UINT8 channel_no)
{ (void)ide; (void)value; (void)channel_no; return EFI_SUCCESS; }
static struct cdk2_ata_identify identify_view(const UINT16 *words)
{ return (struct cdk2_ata_identify){ words[51], words[53], words[64], words[68], words[88] }; }
static EFI_STATUS CDK2_MS_ABI submit(struct ide_protocol *ide, UINT8 channel_no,
	UINT8 device, void *identify)
{ struct cdk2_ata_identify view; if (identify == NULL)
		return cdk2_sata_submit(&from_ide(ide)->controller, channel_no, device, NULL);
	view = identify_view(identify); return cdk2_sata_submit(&from_ide(ide)->controller,
		channel_no, device, &view); }
static struct cdk2_ata_mode mode_view(const struct collective *mode)
{ return (struct cdk2_ata_mode){ (UINT16)mode->pio.mode, (UINT16)mode->udma.mode,
	mode->udma.valid }; }
static EFI_STATUS CDK2_MS_ABI disqualify(struct ide_protocol *ide, UINT8 channel_no,
	UINT8 device, struct collective *mode)
{ struct cdk2_ata_mode view; if (mode == NULL) return EFI_INVALID_PARAMETER;
	view = mode_view(mode); return cdk2_sata_disqualify(&from_ide(ide)->controller,
		channel_no, device, &view); }
static EFI_STATUS CDK2_MS_ABI calculate(struct ide_protocol *ide, UINT8 channel_no,
	UINT8 device, struct collective **result)
{ struct cdk2_ata_mode mode; struct collective *value; EFI_STATUS status;
	if (result == NULL) return EFI_INVALID_PARAMETER;
	status = cdk2_sata_mode(&from_ide(ide)->controller, channel_no, device, &mode);
	if (EFI_ERROR(status)) return status;
	status = bs->allocate_pool(4U, sizeof(*value), (void **)&value);
	if (EFI_ERROR(status)) return status;
	__builtin_memset(value, 0, sizeof(*value)); value->pio.valid = TRUE;
	value->pio.mode = mode.pio_mode; value->udma.valid = mode.udma_valid;
	value->udma.mode = mode.udma_mode; *result = value; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI timing(struct ide_protocol *ide, UINT8 channel_no,
	UINT8 device, struct collective *mode)
{ (void)ide; (void)channel_no; (void)device; (void)mode; return EFI_SUCCESS; }
static EFI_STATUS read_class(struct pci_io *pci, UINT8 *base, UINT8 *sub)
{ UINT8 class_code[3]; EFI_STATUS status = pci->pci.read(pci, 0U, 0x09U, 3U, class_code);
	if (!EFI_ERROR(status)) { *sub = class_code[1]; *base = class_code[2]; } return status; }
static EFI_STATUS CDK2_MS_ABI supported(struct driver_binding *driver, void *controller,
	void *remaining)
{ struct pci_io *pci; void *path; UINT8 base, sub; EFI_STATUS status; (void)remaining;
	status = bs->open_protocol(controller, &path_guid, &path, driver->handle, controller, 0x10U);
	if (EFI_ERROR(status))
		return status;
	(void)bs->close_protocol(controller, &path_guid,
		driver->handle, controller);
	status = bs->open_protocol(controller, &pci_guid, (void **)&pci, driver->handle,
		controller, 0x02U); if (EFI_ERROR(status)) return status;
	status = read_class(pci, &base, &sub); return !EFI_ERROR(status) && base == 1U &&
		(sub == 1U || sub == 6U) ? EFI_SUCCESS : EFI_UNSUPPORTED; }
static EFI_STATUS CDK2_MS_ABI start(struct driver_binding *driver, void *handle,
	void *remaining)
{ struct context *ctx; struct cdk2_sata_geometry geometry; UINT8 base, sub;
	UINT32 cap = 0, pi = 0; UINT64 supported_attributes; EFI_STATUS status; (void)remaining;
	status = bs->open_protocol(handle, &pci_guid, (void **)&ctx, driver->handle, handle, 0x10U);
	if (EFI_ERROR(status))
		return status;
	{ struct pci_io *pci = (struct pci_io *)ctx;
	status = bs->allocate_pool(4U, sizeof(*ctx), (void **)&ctx); if (EFI_ERROR(status)) goto close;
	__builtin_memset(ctx, 0, sizeof(*ctx)); ctx->pci = pci; ctx->handle = handle;
	status = pci->attributes(pci, 0U, 0U, &ctx->original); if (EFI_ERROR(status)) goto free;
	status = pci->attributes(pci, 4U, 0U, &supported_attributes); if (EFI_ERROR(status)) goto free;
	status = pci->attributes(pci, 2U, supported_attributes & 0x700U, NULL);
	if (EFI_ERROR(status)) goto free;
	ctx->changed = TRUE;
	status = read_class(pci, &base, &sub); if (EFI_ERROR(status)) goto restore;
	if (sub == 6U) { status = pci->mem.read(pci, 2U, 5U, 0xcU, 1U, &pi);
		if (EFI_ERROR(status) || pi == 0U) { status = EFI_UNSUPPORTED; goto restore; }
		status = pci->mem.read(pci, 2U, 5U, 0U, 1U, &cap); if (EFI_ERROR(status)) goto restore; }
	status = cdk2_sata_geometry(base, sub, cap, pi, &geometry); if (EFI_ERROR(status)) goto restore;
	status = cdk2_sata_controller_init(&ctx->controller, &geometry); if (EFI_ERROR(status)) goto restore;
	ctx->ide = (struct ide_protocol){ channel, phase, submit, disqualify, calculate,
		timing, FALSE, geometry.channels };
	status = bs->install_multiple(&handle, &ide_guid, &ctx->ide, NULL);
	if (!EFI_ERROR(status)) return status;
restore: if (ctx->changed) (void)pci->attributes(pci, 1U, ctx->original, NULL);
free: (void)bs->free_pool(ctx); close: (void)bs->close_protocol(handle, &pci_guid,
		driver->handle, handle); return status; } }
static EFI_STATUS CDK2_MS_ABI stop(struct driver_binding *driver, void *handle,
	UINTN children, void **child_handles)
{ struct ide_protocol *ide; struct context *ctx; EFI_STATUS status;
	(void)children; (void)child_handles; status = bs->open_protocol(handle, &ide_guid,
		(void **)&ide, driver->handle, handle, 0x02U); if (EFI_ERROR(status)) return EFI_UNSUPPORTED;
	ctx = from_ide(ide); status = bs->uninstall_multiple(handle, &ide_guid, ide, NULL);
	if (EFI_ERROR(status)) return status;
	if (ctx->changed)
		(void)ctx->pci->attributes(ctx->pci, 1U, ctx->original, NULL);
	(void)bs->free_pool(ctx); return bs->close_protocol(handle, &pci_guid,
		driver->handle, handle); }
static EFI_STATUS CDK2_MS_ABI get_name(void *component, CHAR8 *language, CHAR16 **result)
{ (void)component; if (language == NULL || result == NULL) return EFI_INVALID_PARAMETER;
	if (language[0] != 'e' || language[1] != 'n') return EFI_UNSUPPORTED;
	*result = name; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI get_controller_name(void *component, void *controller,
	void *child, CHAR8 *language, CHAR16 **result)
{
	void *ide;
	EFI_STATUS status;

	(void)component;
	if (controller == NULL || language == NULL || result == NULL)
		return EFI_INVALID_PARAMETER;
	if (child != NULL || language[0] != 'e' || language[1] != 'n')
		return EFI_UNSUPPORTED;
	status = bs->open_protocol(controller, &ide_guid, &ide, driver_handle,
		controller, 0x02U);
	if (EFI_ERROR(status))
		return status;
	*result = controller_name;
	return EFI_SUCCESS;
}
static struct driver_binding binding = { supported, start, stop, 0x0aU, NULL, NULL };
static struct component_name component = { get_name, get_controller_name, "eng" };
static struct component_name component2 = { get_name, get_controller_name, "en" };
EFI_STATUS CDK2_MS_ABI cdk2_sata_controller_entry(void *image, struct system_table *system)
{ if (image == NULL || system == NULL || system->boot_services == NULL)
		return EFI_INVALID_PARAMETER;
	bs = system->boot_services;
	driver_handle = image;
	binding.image = image; binding.handle = image; return bs->install_multiple(&image,
		&driver_guid, &binding, &component_guid, &component, &component2_guid, &component2, NULL); }
