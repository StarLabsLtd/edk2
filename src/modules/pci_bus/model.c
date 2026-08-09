/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

#include <string.h>

#define PCI_COMMAND 0x04U
#define PCI_STATUS 0x06U
#define PCI_CLASS 0x08U
#define PCI_HEADER 0x0cU
#define PCI_BAR0 0x10U
#define PCI_CAP_PTR 0x34U
#define PCI_BRIDGE_BUSES 0x18U
#define PCI_ROM_TYPE0 0x30U
#define PCI_ROM_TYPE1 0x38U
#define PCI_STATUS_CAP_LIST 0x10U
#define PCI_CAP_PCIE 0x10U
#define PCI_EXT_CAP_START 0x100U
#define PCI_EXT_CAP_ARI 0x000eU
#define PCI_EXT_CAP_SRIOV 0x0010U
#define PCI_EXT_CAP_REBAR 0x0015U
#define PCI_EXP_DEVCAP2 0x24U
#define PCI_EXP_DEVCTL2 0x28U
#define PCI_EXP_DEVCAP2_ARI 0x20U
#define PCI_EXP_DEVCTL2_ARI 0x20U

static int read_cfg(const struct cdk2_pci_cfg *cfg, uint8_t b, uint8_t d,
	uint8_t f, uint16_t o, uint8_t w, uint32_t *v);

static int read_id(const struct cdk2_pci_cfg *cfg, uint8_t b, uint8_t d,
	uint8_t f, uint32_t *value)
{
	unsigned int retry;
	if (cfg == NULL)
		return -1;
	for (retry = 0; retry <= cfg->crs_retries; retry++) {
		if (read_cfg(cfg, b, d, f, 0, 4, value) != 0)
			return -1;
		if (*value != 0xffff0001U)
			return 0;
	}
	return -1;
}

static int read_cfg(const struct cdk2_pci_cfg *cfg, uint8_t b, uint8_t d,
	uint8_t f, uint16_t o, uint8_t w, uint32_t *v)
{
	if (cfg == NULL || cfg->read == NULL || v == NULL)
		return -1;
	return cfg->read(cfg->context, b, d, f, o, w, v);
}

static int write_cfg(const struct cdk2_pci_cfg *cfg, uint8_t b, uint8_t d,
	uint8_t f, uint16_t o, uint8_t w, uint32_t v)
{
	if (cfg == NULL || cfg->write == NULL)
		return -1;
	return cfg->write(cfg->context, b, d, f, o, w, v);
}

static int restore_cfg(const struct cdk2_pci_cfg *cfg, uint8_t b, uint8_t d,
	uint8_t f, uint16_t o, uint8_t w, uint32_t v)
{
	/* A transport error does not prove the write was rejected; retry once. */
	if (write_cfg(cfg, b, d, f, o, w, v) == 0)
		return 0;
	return write_cfg(cfg, b, d, f, o, w, v);
}

static int probe_bar(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn, uint8_t index, uint16_t offset,
	int rom, int *consumed)
{
	uint32_t original_low, original_high = 0, mask_low, mask_high = 0;
	uint64_t mask, base, size;
	int is64 = 0, failed = 0;

	*consumed = 1;
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, offset, 4,
		&original_low) != 0)
		return -1;
	if (!rom && (original_low & 1U) == 0U &&
	    ((original_low >> 1) & 3U) == 2U) {
		is64 = 1;
		*consumed = 2;
		if (read_cfg(cfg, fn->bus, fn->device, fn->function, offset + 4U, 4,
			&original_high) != 0)
			return -1;
	}
	if (write_cfg(cfg, fn->bus, fn->device, fn->function, offset, 4,
		rom ? 0xfffff800U : 0xffffffffU) != 0)
		return -1;
	if (is64 && write_cfg(cfg, fn->bus, fn->device, fn->function,
		offset + 4U, 4, 0xffffffffU) != 0)
		failed = 1;
	if (!failed && read_cfg(cfg, fn->bus, fn->device, fn->function, offset, 4,
		&mask_low) != 0)
		failed = 1;
	if (!failed && is64 && read_cfg(cfg, fn->bus, fn->device, fn->function,
		offset + 4U, 4, &mask_high) != 0)
		failed = 1;
	/* Restore high first so a live 64-bit decoder never observes a mixed base. */
	if (is64 && restore_cfg(cfg, fn->bus, fn->device, fn->function,
		offset + 4U, 4, original_high) != 0)
		failed = 1;
	if (restore_cfg(cfg, fn->bus, fn->device, fn->function, offset, 4,
		original_low) != 0)
		failed = 1;
	if (failed)
		return -1;
	if ((rom && (mask_low & 0xfffff800U) == 0U) ||
	    (!rom && (original_low & 1U) != 0U && (mask_low & 0xfffffffcU) == 0U) ||
	    (!rom && (original_low & 1U) == 0U &&
	     (mask_low & 0xfffffff0U) == 0U && (!is64 || mask_high == 0U)))
		return 0;
	if (rom) {
		mask = UINT64_C(0xffffffff00000000) | (mask_low & 0xfffff800U);
		base = original_low & 0xfffff800U;
	} else if ((original_low & 1U) != 0U) {
		mask = UINT64_C(0xffffffff00000000) | (mask_low & 0xfffffffcU);
		base = original_low & 0xfffffffcU;
	} else {
		mask = (is64 ? ((uint64_t)mask_high << 32) :
			UINT64_C(0xffffffff00000000)) | (mask_low & 0xfffffff0U);
		base = ((uint64_t)original_high << 32) | (original_low & 0xfffffff0U);
	}
	size = (~mask) + 1U;
	if (size == 0U || (size & (size - 1U)) != 0U)
		return -1;
	fn->bars[fn->bar_count].kind = rom ? CDK2_PCI_BAR_ROM :
		((original_low & 1U) ? CDK2_PCI_BAR_IO :
		(is64 ? CDK2_PCI_BAR_MEM64 : CDK2_PCI_BAR_MEM32));
	fn->bars[fn->bar_count].index = index;
	fn->bars[fn->bar_count].prefetchable =
		(!rom && (original_low & 1U) == 0U && (original_low & 8U) != 0U);
	fn->bars[fn->bar_count].base = base;
	fn->bars[fn->bar_count].size = size;
	fn->bar_count++;
	return 0;
}

static int parse_capabilities(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn)
{
	uint32_t status, pointer, value;
	uint8_t visited[256 / 8] = { 0 };
	unsigned int count;

	if (read_cfg(cfg, fn->bus, fn->device, fn->function, PCI_STATUS, 2,
		&status) != 0)
		return -1;
	if ((status & PCI_STATUS_CAP_LIST) != 0U) {
		if (read_cfg(cfg, fn->bus, fn->device, fn->function, PCI_CAP_PTR, 1,
			&pointer) != 0)
			return -1;
		for (count = 0; pointer != 0U && count < 48U; count++) {
			pointer &= 0xfcU;
			if (pointer < 0x40U || pointer > 0xfcU ||
			    (visited[pointer / 8U] & (1U << (pointer & 7U))) != 0U)
				return -1;
			visited[pointer / 8U] |= (uint8_t)(1U << (pointer & 7U));
			if (read_cfg(cfg, fn->bus, fn->device, fn->function,
				(uint16_t)pointer, 2, &value) != 0)
				return -1;
			if ((value & 0xffU) == PCI_CAP_PCIE)
				fn->pcie_cap = (uint16_t)pointer;
			pointer = (value >> 8) & 0xffU;
		}
	}
	for (pointer = PCI_EXT_CAP_START, count = 0; pointer != 0U && count < 256U;
	    count++) {
		if ((pointer & 3U) != 0U || pointer < PCI_EXT_CAP_START ||
		    pointer > 0xffcU)
			return -1;
		if (read_cfg(cfg, fn->bus, fn->device, fn->function,
			(uint16_t)pointer, 4, &value) != 0)
			return -1;
		if (value == 0U || value == 0xffffffffU)
			break;
		switch (value & 0xffffU) {
		case PCI_EXT_CAP_ARI:
			fn->ari_cap = (uint16_t)pointer;
			break;
		case PCI_EXT_CAP_SRIOV:
			fn->sriov_cap = (uint16_t)pointer;
			break;
		case PCI_EXT_CAP_REBAR:
			fn->resizable_bar_cap = (uint16_t)pointer;
			break;
		default:
			break;
		}
		value = (value >> 20) & 0xfffU;
		if (value == pointer)
			return -1;
		pointer = value;
	}
	if (fn->pcie_cap != 0U) {
		if (read_cfg(cfg, fn->bus, fn->device, fn->function,
			fn->pcie_cap + PCI_EXP_DEVCAP2, 4, &value) != 0)
			return -1;
		if ((value & PCI_EXP_DEVCAP2_ARI) != 0U) {
			if (read_cfg(cfg, fn->bus, fn->device, fn->function,
				fn->pcie_cap + PCI_EXP_DEVCTL2, 2, &value) != 0)
				return -1;
			fn->ari_forwarding = (value & PCI_EXP_DEVCTL2_ARI) != 0U;
		}
	}
	if (fn->sriov_cap != 0U) {
		if (read_cfg(cfg, fn->bus, fn->device, fn->function,
			fn->sriov_cap + 0x0cU, 4, &value) != 0)
			return -1;
		fn->initial_vfs = (uint16_t)value;
		fn->total_vfs = (uint16_t)(value >> 16);
		if (read_cfg(cfg, fn->bus, fn->device, fn->function,
			fn->sriov_cap + 0x14U, 4, &value) != 0)
			return -1;
		fn->vf_offset = (uint16_t)value;
		fn->vf_stride = (uint16_t)(value >> 16);
		if (read_cfg(cfg, fn->bus, fn->device, fn->function,
			fn->sriov_cap + 0x1aU, 2, &value) != 0)
			return -1;
		fn->vf_device_id = (uint16_t)value;
		if (fn->initial_vfs > fn->total_vfs ||
		    fn->total_vfs > CDK2_PCI_MAX_VFS ||
		    (fn->total_vfs != 0U && fn->vf_stride == 0U))
			return -1;
		for (uint16_t vf = 0; vf < fn->total_vfs; vf++) {
			uint32_t rid = ((uint32_t)fn->bus << 8) |
				((uint32_t)fn->device << 3) | fn->function;
			rid += fn->vf_offset + vf * fn->vf_stride;
			if (rid > 0xffffU)
				return -1;
			fn->vf_rids[fn->vf_count++] = (uint16_t)rid;
		}
	}
	if (fn->resizable_bar_cap != 0U) {
		uint32_t control;
		unsigned int entries;
		if (read_cfg(cfg, fn->bus, fn->device, fn->function,
			fn->resizable_bar_cap + 8U, 4, &control) != 0)
			return -1;
		entries = ((control >> 5) & 7U) + 1U;
		if (entries > CDK2_PCI_MAX_REBAR)
			return -1;
		for (unsigned int entry = 0; entry < entries; entry++) {
			uint16_t offset = fn->resizable_bar_cap + 4U + entry * 8U;
			if (read_cfg(cfg, fn->bus, fn->device, fn->function,
				offset, 4, &value) != 0 ||
			    read_cfg(cfg, fn->bus, fn->device, fn->function,
				offset + 4U, 4, &control) != 0)
				return -1;
			value >>= 4;
			if (value == 0U || (control & 7U) >= 6U)
				return -1;
			fn->rebar[entry].control_offset = offset + 4U;
			fn->rebar[entry].supported_sizes = value;
			fn->rebar[entry].bar_index = control & 7U;
			fn->rebar[entry].selected_size =
				(uint8_t)(31U - __builtin_clz(value));
		}
		fn->rebar_count = entries;
		fn->selected_rebar_size = fn->rebar[0].selected_size;
	}
	return count == 256U ? -1 : 0;
}

static int decode_bridge_windows(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn)
{
	uint32_t value, high_base, high_limit;
	if ((fn->header_type & 0x7fU) != 1U)
		goto cardbus;
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x1c, 4, &value) != 0)
		return -1;
	fn->io_base = (uint64_t)(value & 0xf0U) << 8;
	fn->io_limit = ((uint64_t)((value >> 8) & 0xf0U) << 8) | 0xfffU;
	if ((value & 0x0fU) == 1U) {
		if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x30, 4,
			&high_base) != 0)
			return -1;
		fn->io_base |= (uint64_t)(high_base & 0xffffU) << 16;
		fn->io_limit |= (uint64_t)(high_base >> 16) << 16;
	}
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x20, 4, &value) != 0)
		return -1;
	fn->memory_base = (uint64_t)(value & 0xfff0U) << 16;
	fn->memory_limit = ((uint64_t)(value & 0xfff00000U)) | 0xfffffU;
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x24, 4, &value) != 0)
		return -1;
	fn->prefetch_base = (uint64_t)(value & 0xfff0U) << 16;
	fn->prefetch_limit = ((uint64_t)(value & 0xfff00000U)) | 0xfffffU;
	if ((value & 0x0fU) == 1U) {
		if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x28, 4,
			&high_base) != 0 ||
		    read_cfg(cfg, fn->bus, fn->device, fn->function, 0x2c, 4,
			&high_limit) != 0)
			return -1;
		fn->prefetch_base |= (uint64_t)high_base << 32;
		fn->prefetch_limit |= (uint64_t)high_limit << 32;
	}
	return 0;
cardbus:
	if ((fn->header_type & 0x7fU) != 2U)
		return 0;
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x1c, 4,
		&high_base) != 0 ||
	    read_cfg(cfg, fn->bus, fn->device, fn->function, 0x20, 4,
		&high_limit) != 0)
		return -1;
	fn->memory_base = high_base;
	fn->memory_limit = high_limit;
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, 0x2c, 4,
		&high_base) != 0 ||
	    read_cfg(cfg, fn->bus, fn->device, fn->function, 0x30, 4,
		&high_limit) != 0)
		return -1;
	fn->io_base = high_base;
	fn->io_limit = high_limit;
	return 0;
}

int cdk2_pci_probe_function(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn)
{
	uint32_t id, value, command;
	uint8_t bars, index;
	int consumed, failed = 0;

	if (fn == NULL || read_id(cfg, fn->bus, fn->device, fn->function,
		&id) != 0 || (id & 0xffffU) == 0xffffU)
		return -1;
	fn->vendor_id = (uint16_t)id;
	fn->device_id = (uint16_t)(id >> 16);
	if (read_cfg(cfg, fn->bus, fn->device, fn->function, PCI_CLASS, 4, &value) != 0 ||
	    read_cfg(cfg, fn->bus, fn->device, fn->function, PCI_HEADER, 4, &id) != 0 ||
	    read_cfg(cfg, fn->bus, fn->device, fn->function, PCI_COMMAND, 2, &command) != 0)
		return -1;
	fn->programming_interface = (uint8_t)(value >> 8);
	fn->subclass = (uint8_t)(value >> 16);
	fn->class_code = (uint8_t)(value >> 24);
	fn->header_type = (uint8_t)(id >> 16);
	fn->bar_count = 0;
	/* Stable enumeration disables decoding while BARs are sized. */
	if (write_cfg(cfg, fn->bus, fn->device, fn->function, PCI_COMMAND, 2,
		command & ~3U) != 0)
		return -1;
	bars = ((fn->header_type & 0x7fU) == 1U) ? 2U :
		(((fn->header_type & 0x7fU) == 2U) ? 1U : 6U);
	for (index = 0; index < bars;) {
		if (probe_bar(cfg, fn, index, PCI_BAR0 + index * 4U, 0, &consumed) != 0) {
			failed = 1;
			break;
		}
		index = (uint8_t)(index + consumed);
	}
	if (!failed && (fn->header_type & 0x7fU) != 2U && probe_bar(cfg, fn, 6,
		((fn->header_type & 0x7fU) == 1U) ? PCI_ROM_TYPE1 : PCI_ROM_TYPE0,
		1, &consumed) != 0)
		failed = 1;
	if (restore_cfg(cfg, fn->bus, fn->device, fn->function, PCI_COMMAND, 2,
		command) != 0)
		failed = 1;
	if (failed || parse_capabilities(cfg, fn) != 0)
		return -1;
	if (fn->sriov_cap != 0U && fn->total_vfs != 0U) {
		uint8_t normal_count = fn->bar_count;
		struct cdk2_pci_bar normal_bars[CDK2_PCI_MAX_BARS];
		memcpy(normal_bars, fn->bars, sizeof(normal_bars));
		fn->bar_count = 0;
		if (write_cfg(cfg, fn->bus, fn->device, fn->function, PCI_COMMAND, 2,
			command & ~3U) != 0)
			return -1;
		for (index = 0; index < 6U;) {
			if (probe_bar(cfg, fn, index, fn->sriov_cap + 0x24U + index * 4U,
				0, &consumed) != 0) {
				failed = 1;
				break;
			}
			index = (uint8_t)(index + consumed);
		}
		fn->vf_bar_count = fn->bar_count;
		memcpy(fn->vf_bars, fn->bars,
			fn->vf_bar_count * sizeof(fn->vf_bars[0]));
		memcpy(fn->bars, normal_bars, sizeof(normal_bars));
		fn->bar_count = normal_count;
		if (restore_cfg(cfg, fn->bus, fn->device, fn->function, PCI_COMMAND,
			2, command) != 0)
			failed = 1;
		if (failed)
			return -1;
	}
	if (decode_bridge_windows(cfg, fn) != 0)
		return -1;
	if ((fn->header_type & 0x7fU) == 1U ||
	    (fn->header_type & 0x7fU) == 2U) {
		if (read_cfg(cfg, fn->bus, fn->device, fn->function, PCI_BRIDGE_BUSES,
			4, &value) != 0)
			return -1;
		fn->secondary_bus = (uint8_t)(value >> 8);
		fn->subordinate_bus = (uint8_t)(value >> 16);
	}
	return 0;
}

static int scan_bus(const struct cdk2_pci_cfg *cfg, uint8_t bus, uint8_t last,
	struct cdk2_pci_topology *topology, uint8_t visited[32], uint8_t *next_bus,
	int ari_bus, uint16_t parent_index)
{
	uint32_t id, header;
	uint8_t device, function, limit;

	if ((visited[bus / 8U] & (1U << (bus & 7U))) != 0U)
		return 0;
	visited[bus / 8U] |= (uint8_t)(1U << (bus & 7U));
	for (device = 0; device < 32U; device++) {
		if (read_id(cfg, bus, device, 0, &id) != 0)
			return -1;
		if ((id & 0xffffU) == 0xffffU && !ari_bus)
			continue;
		if ((id & 0xffffU) != 0xffffU &&
		    read_cfg(cfg, bus, device, 0, PCI_HEADER, 4, &header) != 0)
			return -1;
		limit = ari_bus ? 8U : (((header >> 16) & 0x80U) ? 8U : 1U);
		for (function = 0; function < limit; function++) {
			struct cdk2_pci_function *fn;
			uint16_t current_index;
			if (read_id(cfg, bus, device, function, &id) != 0)
				return -1;
			if ((id & 0xffffU) == 0xffffU)
				continue;
			if (topology->count == CDK2_PCI_MAX_FUNCTIONS)
				return -1;
			fn = &topology->functions[topology->count];
			memset(fn, 0, sizeof(*fn));
			fn->bus = bus; fn->device = device; fn->function = function;
			fn->parent_index = parent_index;
			if (cdk2_pci_probe_function(cfg, fn) != 0)
				return -1;
			current_index = (uint16_t)topology->count;
			topology->count++;
			if ((fn->header_type & 0x7fU) == 1U ||
			    (fn->header_type & 0x7fU) == 2U) {
				uint32_t original_buses;
				uint8_t child = fn->secondary_bus;
				int temporary = 0, status;
				if (child == 0U) {
					if (*next_bus >= last &&
					    (fn->header_type & 0x7fU) == 1U)
						return -1;
					if (*next_bus >= last)
						continue;
					child = ++*next_bus;
					if (read_cfg(cfg, bus, device, function, PCI_BRIDGE_BUSES,
						4, &original_buses) != 0 ||
					    write_cfg(cfg, bus, device, function, PCI_BRIDGE_BUSES,
						4, bus | ((uint32_t)child << 8) |
						((uint32_t)last << 16)) != 0)
						return -1;
					temporary = 1;
					fn->secondary_bus = child;
					fn->subordinate_bus = last;
				}
				if (child > *next_bus)
					*next_bus = child;
				status = (child > bus && child <= last &&
					fn->subordinate_bus >= child) ?
					scan_bus(cfg, child, fn->subordinate_bus < last ?
					fn->subordinate_bus : last, topology, visited, next_bus,
					fn->ari_forwarding, current_index) : 0;
				if (temporary && restore_cfg(cfg, bus, device, function,
					PCI_BRIDGE_BUSES, 4, original_buses) != 0)
					status = -1;
				if (status != 0)
					return -1;
			}
		}
	}
	return 0;
}

int cdk2_pci_enumerate(const struct cdk2_pci_cfg *cfg, uint8_t first_bus,
	uint8_t last_bus, struct cdk2_pci_topology *topology)
{
	struct cdk2_pci_topology staged;
	uint8_t visited[32] = { 0 };
	uint8_t next_bus = first_bus;
	if (topology == NULL || first_bus > last_bus)
		return -1;
	memset(&staged, 0, sizeof(staged));
	if (scan_bus(cfg, first_bus, last_bus, &staged, visited, &next_bus, 0,
		CDK2_PCI_ROOT_PARENT) != 0)
		return -1;
	for (size_t i = 0; i < staged.count; i++) {
		struct cdk2_pci_function *fn = &staged.functions[i];
		for (uint8_t j = 0; j < fn->bar_count; j++) {
			struct cdk2_pci_bar *bar = &fn->bars[j];
			unsigned int request = bar->kind == CDK2_PCI_BAR_IO ? 0U :
				(bar->prefetchable ?
				(bar->kind == CDK2_PCI_BAR_MEM64 ? 4U : 2U) :
				(bar->kind == CDK2_PCI_BAR_MEM64 ? 3U : 1U));
			uint64_t alignment = bar->size - 1U;
			uint64_t length = staged.requests[request].length;
			if (length > UINT64_MAX - alignment)
				return -1;
			length = (length + alignment) & ~alignment;
			if (UINT64_MAX - length < bar->size)
				return -1;
			staged.requests[request].kind = bar->kind;
			staged.requests[request].length = length + bar->size;
			if (alignment > staged.requests[request].alignment)
				staged.requests[request].alignment = alignment;
		}
		for (uint8_t j = 0; j < fn->vf_bar_count; j++) {
			struct cdk2_pci_bar *bar = &fn->vf_bars[j];
			unsigned int request = bar->kind == CDK2_PCI_BAR_IO ? 0U :
				(bar->prefetchable ?
				(bar->kind == CDK2_PCI_BAR_MEM64 ? 4U : 2U) :
				(bar->kind == CDK2_PCI_BAR_MEM64 ? 3U : 1U));
			uint64_t length = bar->size * fn->total_vfs;
			if ((fn->total_vfs != 0U && length / fn->total_vfs != bar->size) ||
			    UINT64_MAX - staged.requests[request].length < length)
				return -1;
			staged.requests[request].length += length;
		}
	}
	*topology = staged;
	return 0;
}
