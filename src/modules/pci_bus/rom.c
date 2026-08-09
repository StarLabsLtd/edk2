/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

#include <string.h>

static uint16_t get16(const uint8_t *bytes)
{
	return bytes[0] | ((uint16_t)bytes[1] << 8);
}

int cdk2_pci_discover_option_rom(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *function)
{
	struct cdk2_pci_function staged;
	const struct cdk2_pci_bar *rom = NULL;
	uint64_t offset = 0;
	if (cfg == NULL || cfg->read_memory == NULL || function == NULL)
		return -1;
	for (uint8_t i = 0; i < function->bar_count; i++)
		if (function->bars[i].kind == CDK2_PCI_BAR_ROM)
			rom = &function->bars[i];
	if (rom == NULL || rom->base == 0U || rom->size < 0x20U)
		return -1;
	staged = *function;
	staged.option_rom_images = 0;
	staged.option_rom_efi_images = 0;
	staged.option_rom_load_file = 0;
	while (offset < rom->size) {
		uint8_t header[0x20], pcir[0x18];
		uint16_t pcir_offset, blocks;
		uint64_t length;
		if (rom->size - offset < sizeof(header) ||
		    cfg->read_memory(cfg->context, rom->base + offset, header,
			sizeof(header)) != 0 || header[0] != 0x55U || header[1] != 0xaaU)
			return -1;
		pcir_offset = get16(header + 0x18);
		if (pcir_offset > rom->size - offset - sizeof(pcir) ||
		    cfg->read_memory(cfg->context, rom->base + offset + pcir_offset,
			pcir, sizeof(pcir)) != 0 || memcmp(pcir, "PCIR", 4) != 0)
			return -1;
		blocks = get16(pcir + 0x10);
		length = (uint64_t)blocks * 512U;
		if (blocks == 0U || length > rom->size - offset)
			return -1;
		if (staged.option_rom_images == UINT8_MAX)
			return -1;
		staged.option_rom_images++;
		if (pcir[0x14] == 3U) {
			staged.option_rom_efi_images++;
			staged.option_rom_load_file = 1;
		}
		if ((pcir[0x15] & 0x80U) != 0U) {
			*function = staged;
			return 0;
		}
		offset += length;
	}
	return -1;
}

int cdk2_pci_prepare_option_rom(const struct cdk2_pci_cfg *cfg,
	const struct cdk2_pci_rom_ops *ops, struct cdk2_pci_function *function)
{
	struct cdk2_pci_function staged;
	const struct cdk2_pci_bar *rom = NULL;
	void *shadow, *expanded = NULL, *handle = NULL;
	size_t shadow_size, expanded_size;
	if (cfg == NULL || ops == NULL || ops->allocate == NULL || ops->free == NULL ||
	    ops->load_image == NULL || function == NULL ||
	    function->option_rom_shadow != NULL)
		return -1;
	staged = *function;
	if (cdk2_pci_discover_option_rom(cfg, &staged) != 0)
		return -1;
	for (uint8_t i = 0; i < function->bar_count; i++)
		if (function->bars[i].kind == CDK2_PCI_BAR_ROM)
			rom = &function->bars[i];
	if (rom == NULL || rom->size > SIZE_MAX)
		return -1;
	shadow_size = (size_t)rom->size;
	shadow = ops->allocate(ops->context, shadow_size);
	if (shadow == NULL || cfg->read_memory(cfg->context, rom->base, shadow,
		shadow_size) != 0) {
		if (shadow != NULL)
			ops->free(ops->context, shadow);
		return -1;
	}
	if (ops->decompress != NULL && shadow_size <= SIZE_MAX / 4U) {
		expanded_size = shadow_size * 4U;
		expanded = ops->allocate(ops->context, expanded_size);
		if (expanded != NULL && ops->decompress(ops->context, shadow, shadow_size,
			expanded, &expanded_size) == 0) {
			ops->free(ops->context, shadow);
			shadow = expanded;
			shadow_size = expanded_size;
			expanded = NULL;
		}
		if (expanded != NULL)
			ops->free(ops->context, expanded);
	}
	if (ops->load_image(ops->context, shadow, shadow_size, &handle) != 0) {
		ops->free(ops->context, shadow);
		return -1;
	}
	staged.option_rom_shadow = shadow;
	staged.option_rom_shadow_size = shadow_size;
	staged.option_rom_image_handle = handle;
	*function = staged;
	return 0;
}

void cdk2_pci_release_option_rom(const struct cdk2_pci_rom_ops *ops,
	struct cdk2_pci_function *function)
{
	if (ops == NULL || function == NULL)
		return;
	if (function->option_rom_image_handle != NULL && ops->unload_image != NULL)
		ops->unload_image(ops->context, function->option_rom_image_handle);
	if (function->option_rom_shadow != NULL && ops->free != NULL)
		ops->free(ops->context, function->option_rom_shadow);
	function->option_rom_image_handle = NULL;
	function->option_rom_shadow = NULL;
	function->option_rom_shadow_size = 0;
}
