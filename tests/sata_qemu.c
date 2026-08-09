/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/sata_controller.h>

struct guid {
	UINT32 a;
	UINT16 b, c;
	UINT8 d[8];
};
typedef EFI_STATUS CDK2_MS_ABI free_fn(void *);
typedef EFI_STATUS CDK2_MS_ABI locate_fn(const struct guid *, void *, void **);
struct boot_view {
	UINT8 before_free[72];
	free_fn *free_pool;
	UINT8 before_locate[240];
	locate_fn *locate_protocol;
};
struct system_view {
	UINT8 before_boot[96];
	struct boot_view *boot;
};
struct ata_mode {
	BOOLEAN valid;
	UINT8 pad[3];
	UINT32 mode;
};
struct extended_mode {
	UINT32 protocol, mode;
};
struct collective {
	struct ata_mode pio, single, multi, udma;
	UINT32 extended_count;
	struct extended_mode extended;
};
typedef char collective_size_must_be_44[sizeof(struct collective) == 44U ? 1 : -1];
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
struct ide_protocol {
	channel_fn *get_channel;
	phase_fn *notify_phase;
	submit_fn *submit_data;
	disqualify_fn *disqualify_mode;
	calculate_fn *calculate_mode;
	timing_fn *set_timing;
	BOOLEAN enum_all;
	UINT8 channel_count;
};
static const struct guid ide_guid = { 0xa1e37052U, 0x80d9U, 0x4e65U,
	{ 0xa3U, 0x17U, 0x3eU, 0x9aU, 0x55U, 0xc4U, 0x3eU, 0xc9U } };

static UINT8 port_read(UINT16 port)
{
	UINT8 value;
	__asm__ volatile("inb %w1, %0" : "=a"(value) : "Nd"(port));
	return value;
}

static void serial(const char *text)
{
	while (*text != '\0') {
		while ((port_read(0x3fd) & 0x20U) == 0U)
			;
		__asm__ volatile("outb %0, %w1" : : "a"((UINT8)*text++), "Nd"((UINT16)0x3f8));
	}
}

EFI_STATUS CDK2_MS_ABI sata_qemu_entry(void *image, void *table)
{
	struct system_view *system = table;
	struct ide_protocol *ide = NULL;
	struct collective *modes = NULL;
	UINT16 identify[256] = { 0 };
	BOOLEAN enabled = FALSE;
	UINT8 devices = 0;
	EFI_STATUS status;
	(void)image;

	serial("CDK2_SATA_ORACLE_ENTRY\r\n");
	if (system == NULL || system->boot == NULL || system->boot->locate_protocol == NULL ||
	    system->boot->free_pool == NULL ||
	    EFI_ERROR(system->boot->locate_protocol(&ide_guid, NULL, (void **)&ide)) ||
	    ide == NULL || ide->get_channel == NULL || ide->submit_data == NULL ||
	    ide->notify_phase == NULL || ide->disqualify_mode == NULL ||
	    ide->calculate_mode == NULL || ide->set_timing == NULL || ide->channel_count == 0U)
		goto bad;
	serial("SATA_STAGE_LOCATE_OK\r\n");
	status = ide->get_channel(ide, 0U, &enabled, &devices);
	if (EFI_ERROR(status) || !enabled || devices == 0U)
		goto bad;
	serial("SATA_STAGE_CHANNEL_OK\r\n");
	if (EFI_ERROR(ide->notify_phase(ide, 0U, 0U)))
		goto bad;
	serial("SATA_STAGE_PHASE_OK\r\n");
	identify[51] = 2U << 8;
	identify[53] = 6U;
	identify[64] = 3U;
	identify[68] = 120U;
	identify[88] = 0x3fU;
	if (EFI_ERROR(ide->submit_data(ide, 0U, 0U, identify)))
		goto bad;
	serial("SATA_STAGE_SUBMIT_OK\r\n");
	if (EFI_ERROR(ide->calculate_mode(ide, 0U, 0U, &modes)) || modes == NULL ||
	    !modes->pio.valid || modes->pio.mode != 4U || !modes->udma.valid ||
	    modes->udma.mode != 5U)
		goto bad;
	serial("SATA_STAGE_MODE_OK\r\n");
	if (EFI_ERROR(ide->set_timing(ide, 0U, 0U, modes)) ||
	    EFI_ERROR(system->boot->free_pool(modes)))
		goto bad;
	modes = NULL;
	serial("SATA_STAGE_TIMING_OK\r\n");
	{
		struct collective bad_modes = { 0 };

		bad_modes.pio.valid = TRUE;
		bad_modes.pio.mode = 1U;
		bad_modes.udma.valid = TRUE;
		bad_modes.udma.mode = 0U;
		if (EFI_ERROR(ide->disqualify_mode(ide, 0U, 0U, &bad_modes)) ||
		    EFI_ERROR(ide->calculate_mode(ide, 0U, 0U, &modes)) || modes == NULL ||
		    modes->pio.valid || modes->udma.valid)
			goto bad;
	}
	serial("SATA_STAGE_DISQUALIFY_OK\r\n");
	if (EFI_ERROR(system->boot->free_pool(modes)))
		goto bad;
	serial("CDK2_SATA_ORACLE_OK\r\n");
	return EFI_SUCCESS;
bad:
	if (modes != NULL)
		(void)system->boot->free_pool(modes);
	serial("CDK2_SATA_ORACLE_BAD\r\n");
	return EFI_DEVICE_ERROR;
}
