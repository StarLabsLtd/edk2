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
		if (staged.option_rom_images == CDK2_PCI_MAX_ROM_IMAGES)
			return -1;
		staged.option_rom[staged.option_rom_images].offset = (uint32_t)offset;
		staged.option_rom[staged.option_rom_images].size = (uint32_t)length;
		staged.option_rom[staged.option_rom_images].code_type = pcir[0x14];
		if (pcir[0x14] == 3U) {
			uint16_t payload_offset = get16(header + 0x16);
			if (get16(header + 4) != 0x0ef1U || payload_offset >= length)
				return -1;
			if ((function->vendor_id != 0U &&
			     get16(pcir + 4) != function->vendor_id) ||
			    (function->device_id != 0U &&
			     get16(pcir + 6) != function->device_id))
				return -1;
			staged.option_rom[staged.option_rom_images].payload_offset =
				payload_offset;
			staged.option_rom[staged.option_rom_images].machine =
				get16(header + 0x0a);
			staged.option_rom[staged.option_rom_images].subsystem =
				get16(header + 8);
			staged.option_rom[staged.option_rom_images].compression =
				header[0x0c];
			if (header[0x0c] > 1U)
				return -1;
		}
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
	void *shadow;
	size_t shadow_size;
	if (cfg == NULL || ops == NULL || ops->allocate == NULL || ops->free == NULL ||
	    ops->load_image == NULL || ops->start_image == NULL || function == NULL ||
	    function->option_rom_shadow != NULL)
		return -1;
	staged = *function;
	if (cdk2_pci_discover_option_rom(cfg, &staged) != 0)
		return 1;
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
	for (uint8_t i = 0; i < staged.option_rom_images; i++) {
		void *payload, *handle;
		size_t payload_size;
		if (staged.option_rom[i].code_type != 3U ||
		    (staged.option_rom[i].machine != 0x014cU &&
		     staged.option_rom[i].machine != 0x8664U) ||
		    (staged.option_rom[i].subsystem != 11U &&
		     staged.option_rom[i].subsystem != 12U))
			continue;
		payload = (uint8_t *)shadow + staged.option_rom[i].offset +
			staged.option_rom[i].payload_offset;
		payload_size = staged.option_rom[i].size -
			staged.option_rom[i].payload_offset;
		if (staged.option_rom[i].compression == 1U) {
			void *scratch = NULL;
			size_t scratch_size;
			if (ops->decompress_info == NULL || ops->decompress == NULL ||
			    ops->decompress_info(ops->context, payload, payload_size,
				&staged.option_rom[i].decompressed_size,
				&scratch_size) != 0 ||
			    staged.option_rom[i].decompressed_size == 0U)
				goto rollback;
			staged.option_rom[i].decompressed = ops->allocate(ops->context,
				staged.option_rom[i].decompressed_size);
			if (scratch_size != 0U)
				scratch = ops->allocate(ops->context, scratch_size);
			if (staged.option_rom[i].decompressed == NULL ||
			    (scratch_size != 0U && scratch == NULL) ||
			    ops->decompress(ops->context, payload, payload_size,
				staged.option_rom[i].decompressed,
				staged.option_rom[i].decompressed_size, scratch,
				scratch_size) != 0) {
				if (scratch != NULL)
					ops->free(ops->context, scratch);
				goto rollback;
			}
			if (scratch != NULL)
				ops->free(ops->context, scratch);
			payload = staged.option_rom[i].decompressed;
			payload_size = staged.option_rom[i].decompressed_size;
		}
		if (ops->load_image(ops->context, payload, payload_size,
			staged.option_rom[i].offset + staged.option_rom[i].payload_offset,
			staged.option_rom[i].offset + staged.option_rom[i].size - 1U,
			&handle) != 0)
			goto rollback;
		staged.option_rom[i].image_handle = handle;
		if (ops->start_image(ops->context, handle) != 0)
			goto rollback;
		if (staged.option_rom_image_handle == NULL)
			staged.option_rom_image_handle = handle;
	}
	staged.option_rom_shadow = shadow;
	staged.option_rom_shadow_size = shadow_size;
	*function = staged;
	return 0;
rollback:
	for (uint8_t i = 0; i < staged.option_rom_images; i++) {
		if (staged.option_rom[i].image_handle != NULL && ops->unload_image != NULL)
			ops->unload_image(ops->context, staged.option_rom[i].image_handle);
		if (staged.option_rom[i].decompressed != NULL)
			ops->free(ops->context, staged.option_rom[i].decompressed);
	}
	ops->free(ops->context, shadow);
	return -1;
}

void cdk2_pci_release_option_rom(const struct cdk2_pci_rom_ops *ops,
	struct cdk2_pci_function *function)
{
	if (ops == NULL || function == NULL)
		return;
	for (uint8_t i = 0; i < function->option_rom_images; i++) {
		if (function->option_rom[i].image_handle != NULL &&
		    ops->unload_image != NULL)
			ops->unload_image(ops->context,
				function->option_rom[i].image_handle);
		if (function->option_rom[i].decompressed != NULL && ops->free != NULL)
			ops->free(ops->context, function->option_rom[i].decompressed);
		function->option_rom[i].image_handle = NULL;
		function->option_rom[i].decompressed = NULL;
		function->option_rom[i].decompressed_size = 0;
	}
	if (function->option_rom_shadow != NULL && ops->free != NULL)
		ops->free(ops->context, function->option_rom_shadow);
	function->option_rom_image_handle = NULL;
	function->option_rom_shadow = NULL;
	function->option_rom_shadow_size = 0;
}

int cdk2_pci_option_rom_load_file(const struct cdk2_pci_function *function,
	unsigned int image, size_t offset, void *buffer, size_t *size)
{
	const uint8_t *source;
	size_t available;
	if (function == NULL || size == NULL || image >= function->option_rom_images ||
	    function->option_rom[image].code_type != 3U ||
	    function->option_rom_shadow == NULL)
		return -1;
	if (function->option_rom[image].decompressed != NULL) {
		source = function->option_rom[image].decompressed;
		available = function->option_rom[image].decompressed_size;
	} else {
		source = (const uint8_t *)function->option_rom_shadow +
			function->option_rom[image].offset +
			function->option_rom[image].payload_offset;
		available = function->option_rom[image].size -
			function->option_rom[image].payload_offset;
	}
	if (offset > available)
		return -1;
	available -= offset;
	if (buffer == NULL || *size < available) {
		*size = available;
		return 1;
	}
	memcpy(buffer, source + offset, available);
	*size = available;
	return 0;
}

static uint64_t get64(const uint8_t *bytes)
{
	uint64_t value = 0;
	for (unsigned int byte = 0; byte < 8U; byte++)
		value |= (uint64_t)bytes[byte] << (byte * 8U);
	return value;
}

int cdk2_pci_option_rom_load_file_path(const struct cdk2_pci_function *function,
	const void *device_path, size_t path_size, size_t offset, void *buffer,
	size_t *size)
{
	const uint8_t *path = device_path;
	uint64_t start, end;
	if (function == NULL || path == NULL || path_size != 24U || path[0] != 4U ||
	    path[1] != 8U || get16(path + 2) != 24U)
		return -1;
	start = get64(path + 8);
	end = get64(path + 16);
	if (start > end)
		return -1;
	for (unsigned int image = 0; image < function->option_rom_images; image++) {
		uint64_t image_start = function->option_rom[image].offset +
			function->option_rom[image].payload_offset;
		uint64_t image_end = function->option_rom[image].offset +
			function->option_rom[image].size - 1U;
		if (start == image_start && end == image_end)
			return cdk2_pci_option_rom_load_file(function, image, offset,
				buffer, size);
	}
	return -1;
}
