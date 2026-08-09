/* SPDX-License-Identifier: BSD-2-Clause-Patent */

#include <cdk2/pci_host_bridge.h>

#include <string.h>

#define PCI_COMMAND 0x04U
#define PCI_HEADER_TYPE 0x0eU
#define PCI_CLASS_BASE 0x0bU
#define PCI_CLASS_SUB 0x0aU
#define PCI_SUBORDINATE_BUS 0x1aU
#define PCI_BAR0 0x10U
#define PCI_HEADER_BRIDGE 1U
#define PCI_HEADER_MULTIFUNCTION 0x80U
#define PCI_CLASS_BRIDGE 0x06U
#define PCI_SUBCLASS_PCI 0x04U
#define PCI_ATTR_ISA 0x00010003ULL
#define PCI_ATTR_VGA 0x0006001cULL
#define PCI_ATTR_VGA_PALETTE 0x00020004ULL
#define PCI_ATTR_IDE_PRIMARY 0x20ULL
#define PCI_ATTR_IDE_SECONDARY 0x40ULL

static void include_range(struct cdk2_pci_aperture *, uint64_t, uint64_t);

static uint64_t read_value(void *context, cdk2_pci_config_scan_fn *read,
	uint8_t bus, uint8_t device, uint8_t function, uint16_t offset,
	size_t width, uint32_t *value)
{
	return read == NULL ? EFI_INVALID_PARAMETER : read(context, bus, device,
		function, offset, width, value);
}

static uint64_t bridge_windows(struct cdk2_pci_root_bridge_view *root,
	void *context, cdk2_pci_config_scan_fn *read, uint8_t bus,
	uint8_t device, uint8_t function)
{
	uint32_t io_base, io_limit, io_upper_base, io_upper_limit;
	uint32_t mem_base, mem_limit, pref_base, pref_limit;
	uint32_t pref_upper_base, pref_upper_limit;
	uint64_t base, limit, status;

	status = read_value(context, read, bus, device, function, 0x1c, 1, &io_base);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x1d, 1,
			&io_limit);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x30, 2,
			&io_upper_base);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x32, 2,
			&io_upper_limit);
	if (status != EFI_SUCCESS)
		return status;
	base = (io_base & 0xf0U) << 8;
	limit = ((io_limit & 0xf0U) << 8) | 0xfffU;
	if ((io_base & 0x0fU) == 1U) {
		base |= (uint64_t)io_upper_base << 16;
		limit |= (uint64_t)io_upper_limit << 16;
	}
	if (base != 0 && base < limit)
		include_range(&root->aperture[1], base, limit - base + 1U);
	status = read_value(context, read, bus, device, function, 0x20, 2, &mem_base);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x22, 2,
			&mem_limit);
	if (status != EFI_SUCCESS)
		return status;
	base = (uint64_t)(mem_base & 0xfff0U) << 16;
	limit = ((uint64_t)(mem_limit & 0xfff0U) << 16) | 0xfffffU;
	if (base != 0 && base < limit)
		include_range(&root->aperture[2], base, limit - base + 1U);
	status = read_value(context, read, bus, device, function, 0x24, 2, &pref_base);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x26, 2,
			&pref_limit);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x28, 4,
			&pref_upper_base);
	if (status == EFI_SUCCESS)
		status = read_value(context, read, bus, device, function, 0x2c, 4,
			&pref_upper_limit);
	if (status != EFI_SUCCESS)
		return status;
	base = (uint64_t)(pref_base & 0xfff0U) << 16;
	limit = ((uint64_t)(pref_limit & 0xfff0U) << 16) | 0xfffffU;
	if ((pref_base & 0x0fU) == 1U) {
		base |= (uint64_t)pref_upper_base << 32;
		limit |= (uint64_t)pref_upper_limit << 32;
	}
	if (base != 0 && base < limit)
		include_range(&root->aperture[base >= 0x100000000ULL ? 3 : 2],
			base, limit - base + 1U);
	return EFI_SUCCESS;
}

static uint64_t config_read(void *context, cdk2_pci_config_scan_fn *read,
	uint8_t bus, uint8_t device, uint8_t function, uint16_t offset,
	size_t width, uint32_t *value)
{
	return read == NULL ? EFI_INVALID_PARAMETER : read(context, bus, device,
		function, offset, width, value);
}

static void include_range(struct cdk2_pci_aperture *range, uint64_t base,
	uint64_t length)
{
	uint64_t limit;

	if (length == 0 || base > UINT64_MAX - (length - 1U))
		return;
	limit = base + length - 1U;
	if (range->base > range->limit) {
		range->base = base;
		range->limit = limit;
	} else {
		if (base < range->base)
			range->base = base;
		if (limit > range->limit)
			range->limit = limit;
	}
}

static uint64_t probe_bars(struct cdk2_pci_root_bridge_view *root,
	void *context, cdk2_pci_config_scan_fn *read,
	cdk2_pci_config_scan_fn *write, uint8_t bus, uint8_t device,
	uint8_t function, uint8_t bridge)
{
	uint16_t end = bridge ? 0x18U : 0x28U;
	uint16_t offset;
	uint32_t command, disabled;
	uint64_t status;

	status = config_read(context, read, bus, device, function, PCI_COMMAND,
		2, &command);
	if (status != EFI_SUCCESS)
		return status;
	disabled = command & ~3U;
	status = write(context, bus, device, function, PCI_COMMAND, 2, &disabled);
	if (status != EFI_SUCCESS)
		return status;

	for (offset = PCI_BAR0; offset < end; offset += 4U) {
		uint32_t original, mask, upper = 0, upper_mask = 0, all = UINT32_MAX;
		uint64_t base, size_mask, length;
		uint64_t restore_status;
		uint8_t io, wide;
		status = config_read(context, read, bus, device, function, offset, 4,
			&original);

		if (status != EFI_SUCCESS)
			goto restore_command;
		io = (original & 1U) != 0;
		wide = !io && (original & 6U) == 4U;
		if (wide) {
			status = config_read(context, read, bus, device, function,
				offset + 4U, 4, &upper);
			if (status != EFI_SUCCESS)
				goto restore_command;
		}
		status = write(context, bus, device, function, offset, 4, &all);
		if (status == EFI_SUCCESS)
			status = config_read(context, read, bus, device, function,
				offset, 4, &mask);
		if (wide && status == EFI_SUCCESS) {
			status = write(context, bus, device, function, offset + 4U, 4,
				&all);
			if (status == EFI_SUCCESS)
				status = config_read(context, read, bus, device, function,
					offset + 4U, 4, &upper_mask);
		}
		restore_status = write(context, bus, device, function, offset, 4,
			&original);
		if (restore_status != EFI_SUCCESS)
			(void)write(context, bus, device, function, offset, 4, &original);
		if (wide && write(context, bus, device, function, offset + 4U, 4,
		    &upper) != EFI_SUCCESS) {
			restore_status = EFI_DEVICE_ERROR;
			(void)write(context, bus, device, function, offset + 4U, 4, &upper);
		}
		if (restore_status != EFI_SUCCESS && status == EFI_SUCCESS)
			status = restore_status;
		if (status != EFI_SUCCESS)
			goto restore_command;
		if (io) {
			base = original & ~3U;
			size_mask = (mask & ~3U) | 0xffffffff00000000ULL;
		} else {
			base = original & ~15U;
			size_mask = (mask & ~15U) | 0xffffffff00000000ULL;
			if (wide) {
				base |= (uint64_t)upper << 32;
				size_mask = (mask & ~15U) |
					((uint64_t)upper_mask << 32);
			}
		}
		length = size_mask == 0 ? 0 : (~size_mask + 1U);
		if (base != 0 && length != 0)
			include_range(&root->aperture[io ? 1U :
				(base >= 0x100000000ULL ? 3U : 2U)], base, length);
		if (wide)
			offset += 4U;
	}
restore_command:
	if (write(context, bus, device, function, PCI_COMMAND, 2, &command) !=
	    EFI_SUCCESS) {
		(void)write(context, bus, device, function, PCI_COMMAND, 2, &command);
		if (status == EFI_SUCCESS)
			status = EFI_DEVICE_ERROR;
	}
	return status;
}

uint64_t cdk2_pci_host_scan(struct cdk2_pci_host_model *host, void *context,
	cdk2_pci_config_scan_fn *read, cdk2_pci_config_scan_fn *write)
{
	struct cdk2_pci_host_model scanned;
	uint16_t primary;

	if (host == NULL || read == NULL || write == NULL)
		return EFI_INVALID_PARAMETER;
	memset(&scanned, 0, sizeof(scanned));
	for (primary = 0; primary <= UINT8_MAX;) {
		struct cdk2_pci_root_bridge_view root;
		uint16_t subordinate = primary;
		uint8_t device;
		uint8_t found = 0;

		memset(&root, 0, sizeof(root));
		for (device = 0; device < CDK2_PCI_ROOT_BRIDGE_APERTURES; device++)
			root.aperture[device].base = 1;
		for (device = 0; device < 32U; device++) {
			uint8_t function;
			uint8_t functions = 1;

			for (function = 0; function < functions; function++) {
				uint32_t vendor, header, base_class, subclass;
				uint64_t status = config_read(context, read, primary,
					device, function, 0, 2, &vendor);

				if (status != EFI_SUCCESS)
					return status;
				if ((vendor & 0xffffU) == 0xffffU)
					continue;
				found = 1;
				status = config_read(context, read, primary, device,
					function, PCI_HEADER_TYPE, 1, &header);
				if (status != EFI_SUCCESS)
					return status;
				if (function == 0 && (header & PCI_HEADER_MULTIFUNCTION))
					functions = 8;
				status = config_read(context, read, primary, device,
					function, PCI_CLASS_BASE, 1, &base_class);
				if (status == EFI_SUCCESS)
					status = config_read(context, read, primary, device,
						function, PCI_CLASS_SUB, 1, &subclass);
				if (status != EFI_SUCCESS)
					return status;
				if (base_class == PCI_CLASS_BRIDGE &&
				    subclass == PCI_SUBCLASS_PCI) {
					uint32_t bus_limit;

					status = config_read(context, read, primary, device,
						function, PCI_SUBORDINATE_BUS, 1, &bus_limit);
					if (status != EFI_SUCCESS)
						return status;
					if (bus_limit > subordinate)
						subordinate = bus_limit;
					status = bridge_windows(&root, context, read, primary,
						device, function);
					if (status != EFI_SUCCESS)
						return status;
				}
				if (base_class == 3U && subclass == 0U)
					root.supports |= PCI_ATTR_VGA;
				else if (base_class == 0U && subclass == 1U)
					root.supports |= PCI_ATTR_VGA;
				else if (base_class == PCI_CLASS_BRIDGE &&
					 (subclass == 1U || subclass == 0x80U))
					root.supports |= PCI_ATTR_ISA;
				else if (base_class == 1U && subclass == 1U) {
					uint32_t programming;

					status = config_read(context, read, primary, device,
						function, 9, 1, &programming);
					if (status != EFI_SUCCESS)
						return status;
					if (programming & 1U)
						root.supports |= PCI_ATTR_IDE_PRIMARY;
					if (programming & 4U)
						root.supports |= PCI_ATTR_IDE_SECONDARY;
				}
				{
					uint32_t command;

					status = config_read(context, read, primary, device,
						function, PCI_COMMAND, 2, &command);
					if (status != EFI_SUCCESS)
						return status;
					if (command & 0x20U)
						root.supports |= PCI_ATTR_VGA_PALETTE;
				}
				status = probe_bars(&root, context, read, write, primary,
					device, function, (header & 0x7fU) == PCI_HEADER_BRIDGE);
				if (status != EFI_SUCCESS)
					return status;
			}
		}
		if (found) {
			if (scanned.count == CDK2_PCI_HOST_MAX_ROOTS)
				return EFI_OUT_OF_RESOURCES;
			root.aperture[0].base = primary;
			root.aperture[0].limit = subordinate;
			root.no_extended_config = 0;
			root.hid = 0x0a0341d0U;
			root.uid = primary;
			root.attributes = root.supports;
			scanned.root[scanned.count++] = root;
		}
		if (subordinate == UINT8_MAX)
			break;
		primary = subordinate + 1U;
	}
	if (scanned.count == 0)
		return EFI_NOT_FOUND;
	scanned.resource_assigned = 1;
	scanned.can_restart = 1;
	*host = scanned;
	return EFI_SUCCESS;
}
