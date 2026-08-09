/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

#include <string.h>

#define PCI_COMMAND 0x04U
#define PCI_BAR0 0x10U
#define PCI_BRIDGE_IO 0x1cU
#define PCI_BRIDGE_MEMORY 0x20U
#define PCI_BRIDGE_PREFETCH 0x24U
#define PCI_SRIOV_CONTROL 0x08U
#define PCI_SRIOV_VF_ENABLE 0x01U
#define JOURNAL_MAX 192U

struct allocation_item {
	struct cdk2_pci_function *function;
	struct cdk2_pci_bar *bar;
	uint64_t length;
	uint8_t vf;
};

struct journal_entry {
	uint8_t bus, device, function, width;
	uint16_t offset;
	uint32_t original, value;
};

struct journal {
	struct journal_entry entries[JOURNAL_MAX];
	size_t count;
};

static int cfg_read(const struct cdk2_pci_cfg *cfg,
	const struct cdk2_pci_function *fn, uint16_t offset, uint8_t width,
	uint32_t *value)
{
	return cfg->read(cfg->context, fn->bus, fn->device, fn->function,
		offset, width, value);
}

static int stage_write(const struct cdk2_pci_cfg *cfg,
	const struct cdk2_pci_function *fn, uint16_t offset, uint8_t width,
	uint32_t value, struct journal *journal)
{
	struct journal_entry *entry;
	if (journal->count == JOURNAL_MAX)
		return -1;
	entry = &journal->entries[journal->count];
	if (cfg_read(cfg, fn, offset, width, &entry->original) != 0)
		return -1;
	entry->bus = fn->bus;
	entry->device = fn->device;
	entry->function = fn->function;
	entry->offset = offset;
	entry->width = width;
	entry->value = value;
	journal->count++;
	return 0;
}

static int commit(const struct cdk2_pci_cfg *cfg, struct journal *journal)
{
	size_t done = 0;
	while (done < journal->count) {
		struct journal_entry *entry = &journal->entries[done];
		if (cfg->write(cfg->context, entry->bus, entry->device,
			entry->function, entry->offset, entry->width, entry->value) != 0)
			break;
		done++;
	}
	if (done == journal->count)
		return 0;
	while (done != 0U) {
		struct journal_entry *entry = &journal->entries[--done];
		if (cfg->write(cfg->context, entry->bus, entry->device,
			entry->function, entry->offset, entry->width,
			entry->original) != 0)
			return -1;
	}
	return -1;
}

static int allocate(struct cdk2_pci_aperture *aperture, uint64_t size,
	uint64_t alignment, uint64_t *base)
{
	uint64_t start;
	if (size == 0U || (alignment & (alignment + 1U)) != 0U ||
	    aperture->cursor > UINT64_MAX - alignment)
		return -1;
	start = (aperture->cursor + alignment) & ~alignment;
	if (start < aperture->base)
		start = (aperture->base + alignment) & ~alignment;
	if (start > aperture->limit || size - 1U > aperture->limit - start)
		return -1;
	aperture->cursor = start + size;
	*base = start;
	return 0;
}

static struct cdk2_pci_aperture *bar_aperture(
	struct cdk2_pci_allocation_policy *policy, const struct cdk2_pci_bar *bar)
{
	if (bar->kind == CDK2_PCI_BAR_IO)
		return &policy->io;
	if (bar->prefetchable)
		return &policy->prefetch;
	return bar->kind == CDK2_PCI_BAR_MEM64 ? &policy->mem64 : &policy->mem32;
}

static int stage_bar(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn, struct cdk2_pci_bar *bar,
	struct cdk2_pci_allocation_policy *policy, struct journal *journal)
{
	uint64_t base;
	uint16_t offset;
	uint32_t original;
	if (allocate(bar_aperture(policy, bar), bar->size, bar->size - 1U,
		&base) != 0)
		return -1;
	bar->base = base;
	offset = bar->index == 6U ?
		(((fn->header_type & 0x7fU) == 1U) ? 0x38U : 0x30U) :
		(uint16_t)(PCI_BAR0 + bar->index * 4U);
	if (cfg_read(cfg, fn, offset, 4, &original) != 0 ||
	    stage_write(cfg, fn, offset, 4,
		(uint32_t)base | (original & (bar->kind == CDK2_PCI_BAR_IO ? 3U :
		(bar->kind == CDK2_PCI_BAR_ROM ? 0x7ffU : 0x0fU))), journal) != 0)
		return -1;
	if (bar->kind == CDK2_PCI_BAR_MEM64 &&
	    stage_write(cfg, fn, offset + 4U, 4, (uint32_t)(base >> 32),
		journal) != 0)
		return -1;
	return 0;
}

static int stage_vf_bar(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn, struct cdk2_pci_bar *bar,
	struct cdk2_pci_allocation_policy *policy, struct journal *journal)
{
	uint64_t base, length;
	uint16_t offset = fn->sriov_cap + 0x24U + bar->index * 4U;
	uint32_t original;
	if (fn->total_vfs == 0U || bar->size > UINT64_MAX / fn->total_vfs)
		return -1;
	length = bar->size * fn->total_vfs;
	if (allocate(bar_aperture(policy, bar), length, bar->size - 1U, &base) != 0 ||
	    cfg_read(cfg, fn, offset, 4, &original) != 0 ||
	    stage_write(cfg, fn, offset, 4,
		(uint32_t)base | (original & (bar->kind == CDK2_PCI_BAR_IO ? 3U : 0x0fU)),
		journal) != 0)
		return -1;
	bar->base = base;
	if (bar->kind == CDK2_PCI_BAR_MEM64 &&
	    stage_write(cfg, fn, offset + 4U, 4, (uint32_t)(base >> 32),
		journal) != 0)
		return -1;
	return 0;
}

static uint8_t choose_rebar(uint32_t supported, uint8_t maximum)
{
	uint8_t choice = maximum == 0U ? 31U : maximum;
	while (choice != 0U && (supported & (1U << choice)) == 0U)
		choice--;
	return choice;
}

static int stage_controls(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn,
	const struct cdk2_pci_allocation_policy *policy, struct journal *journal)
{
	uint32_t control;
	for (uint8_t i = 0; i < fn->rebar_count; i++) {
		uint8_t selected = choose_rebar(fn->rebar[i].supported_sizes,
			policy->maximum_rebar_size);
		if (cfg_read(cfg, fn, fn->rebar[i].control_offset, 4, &control) != 0 ||
		    stage_write(cfg, fn, fn->rebar[i].control_offset, 4,
			(control & ~(0x1fU << 8)) | ((uint32_t)selected << 8),
			journal) != 0)
			return -1;
		fn->rebar[i].selected_size = selected;
		for (uint8_t bar = 0; bar < fn->bar_count; bar++)
			if (fn->bars[bar].index == fn->rebar[i].bar_index)
				fn->bars[bar].size = UINT64_C(1) << (selected + 20U);
	}
	return 0;
}

static int stage_sriov(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *fn,
	const struct cdk2_pci_allocation_policy *policy, struct journal *journal)
{
	uint32_t control;
	if (policy->enable_sriov && fn->sriov_cap != 0U && fn->total_vfs != 0U) {
		if (cfg_read(cfg, fn, fn->sriov_cap + PCI_SRIOV_CONTROL, 2,
			&control) != 0 ||
		    stage_write(cfg, fn, fn->sriov_cap + PCI_SRIOV_CONTROL, 2,
			control | PCI_SRIOV_VF_ENABLE, journal) != 0)
			return -1;
	}
	return 0;
}

static int stage_bridge(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *bridge, const struct cdk2_pci_topology *topology,
	struct cdk2_pci_allocation_policy *policy, struct journal *journal)
{
	uint64_t io_min = UINT64_MAX, io_max = 0, mem_min = UINT64_MAX, mem_max = 0;
	uint64_t pref_min = UINT64_MAX, pref_max = 0;
	for (size_t i = 0; i < topology->count; i++) {
		const struct cdk2_pci_function *child = &topology->functions[i];
		if (child->bus < bridge->secondary_bus || child->bus > bridge->subordinate_bus)
			continue;
		for (uint8_t j = 0; j < child->bar_count; j++) {
			const struct cdk2_pci_bar *bar = &child->bars[j];
			uint64_t end = bar->base + bar->size - 1U;
			if (bar->kind == CDK2_PCI_BAR_IO) {
				if (bar->base < io_min)
					io_min = bar->base;
				if (end > io_max)
					io_max = end;
			} else if (bar->prefetchable) {
				if (bar->base < pref_min)
					pref_min = bar->base;
				if (end > pref_max)
					pref_max = end;
			} else {
				if (bar->base < mem_min)
					mem_min = bar->base;
				if (end > mem_max)
					mem_max = end;
			}
		}
	}
	if (bridge->hotplug_bridge) {
		uint64_t base;
		if (policy->hotplug_padding[0] != 0U &&
		    allocate(&policy->io, policy->hotplug_padding[0], 0xfffU, &base) == 0) {
			if (base < io_min)
				io_min = base;
			if (base + policy->hotplug_padding[0] - 1U > io_max)
				io_max = base + policy->hotplug_padding[0] - 1U;
		}
		if (policy->hotplug_padding[1] != 0U &&
		    allocate(&policy->mem32, policy->hotplug_padding[1], 0xfffffU,
			&base) == 0) {
			if (base < mem_min)
				mem_min = base;
			if (base + policy->hotplug_padding[1] - 1U > mem_max)
				mem_max = base + policy->hotplug_padding[1] - 1U;
		}
	}
	if (stage_write(cfg, bridge, PCI_BRIDGE_IO, 4,
		io_min == UINT64_MAX ? 0x000000f0U :
		(((uint32_t)(io_min >> 8) & 0xf0U) |
		 ((uint32_t)io_max & 0xf000U) |
		 ((io_max > 0xffffU) ? 0x101U : 0U)), journal) != 0)
		return -1;
	if (io_min != UINT64_MAX && io_max > 0xffffU &&
	    stage_write(cfg, bridge, 0x30U, 4,
		((uint32_t)(io_min >> 16) & 0xffffU) |
		((uint32_t)io_max & 0xffff0000U), journal) != 0)
		return -1;
	if (stage_write(cfg, bridge, PCI_BRIDGE_MEMORY, 4,
		mem_min == UINT64_MAX ? 0x0000fff0U :
		(((uint32_t)(mem_min >> 16) & 0xfff0U) |
		 ((uint32_t)mem_max & 0xfff00000U)), journal) != 0)
		return -1;
	if (stage_write(cfg, bridge, PCI_BRIDGE_PREFETCH, 4,
		pref_min == UINT64_MAX ? 0x0000fff0U :
		(((uint32_t)(pref_min >> 16) & 0xfff0U) |
		 ((uint32_t)pref_max & 0xfff00000U) |
		 ((pref_max > UINT32_MAX) ? 0x10001U : 0U)), journal) != 0)
		return -1;
	if (pref_min != UINT64_MAX && pref_max > UINT32_MAX &&
	    (stage_write(cfg, bridge, 0x28U, 4, (uint32_t)(pref_min >> 32),
		journal) != 0 ||
	     stage_write(cfg, bridge, 0x2cU, 4, (uint32_t)(pref_max >> 32),
		journal) != 0))
		return -1;
	return 0;
}

static int stage_cardbus(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_function *bridge, struct cdk2_pci_allocation_policy *policy,
	struct journal *journal)
{
	uint64_t base;
	if (policy->hotplug_padding[1] != 0U) {
		if (allocate(&policy->mem32, policy->hotplug_padding[1], 0xfffU,
			&base) != 0 || base > UINT32_MAX ||
		    stage_write(cfg, bridge, 0x1cU, 4, (uint32_t)base, journal) != 0 ||
		    stage_write(cfg, bridge, 0x20U, 4,
			(uint32_t)(base + policy->hotplug_padding[1] - 1U), journal) != 0)
			return -1;
	}
	if (policy->hotplug_padding[0] != 0U) {
		if (allocate(&policy->io, policy->hotplug_padding[0], 3U, &base) != 0 ||
		    base > UINT32_MAX ||
		    stage_write(cfg, bridge, 0x2cU, 4, (uint32_t)base, journal) != 0 ||
		    stage_write(cfg, bridge, 0x30U, 4,
			(uint32_t)(base + policy->hotplug_padding[0] - 1U), journal) != 0)
			return -1;
	}
	return 0;
}

int cdk2_pci_allocate_resources(const struct cdk2_pci_cfg *cfg,
	struct cdk2_pci_topology *topology,
	const struct cdk2_pci_allocation_policy *input_policy)
{
	struct cdk2_pci_topology staged;
	struct cdk2_pci_allocation_policy policy;
	struct journal journal = { 0 };
	struct allocation_item items[JOURNAL_MAX];
	uint32_t commands[CDK2_PCI_MAX_FUNCTIONS];
	size_t item_count = 0;
	if (cfg == NULL || cfg->read == NULL || cfg->write == NULL ||
	    topology == NULL || input_policy == NULL)
		return -1;
	staged = *topology;
	policy = *input_policy;
	for (size_t i = 0; i < staged.count; i++) {
		struct cdk2_pci_function *fn = &staged.functions[i];
		if (cfg_read(cfg, fn, PCI_COMMAND, 2, &commands[i]) != 0 ||
		    stage_write(cfg, fn, PCI_COMMAND, 2, commands[i] & ~3U, &journal) != 0 ||
		    stage_controls(cfg, fn, &policy, &journal) != 0)
			return -1;
		for (uint8_t bar = 0; bar < fn->bar_count; bar++) {
			if (item_count == JOURNAL_MAX)
				return -1;
			items[item_count++] = (struct allocation_item) {
				fn, &fn->bars[bar], fn->bars[bar].size, 0 };
		}
		if (policy.enable_sriov)
			for (uint8_t bar = 0; bar < fn->vf_bar_count; bar++) {
				if (item_count == JOURNAL_MAX || fn->total_vfs == 0U ||
				    fn->vf_bars[bar].size > UINT64_MAX / fn->total_vfs)
					return -1;
				items[item_count++] = (struct allocation_item) {
					fn, &fn->vf_bars[bar],
					fn->vf_bars[bar].size * fn->total_vfs, 1 };
			}
	}
	for (size_t i = 1; i < item_count; i++) {
		struct allocation_item item = items[i];
		size_t j = i;
		while (j != 0U && items[j - 1U].length < item.length) {
			items[j] = items[j - 1U];
			j--;
		}
		items[j] = item;
	}
	for (size_t i = 0; i < item_count; i++) {
		int status = items[i].vf ?
			stage_vf_bar(cfg, items[i].function, items[i].bar, &policy,
				&journal) :
			stage_bar(cfg, items[i].function, items[i].bar, &policy, &journal);
		if (status != 0)
			return -1;
	}
	for (size_t i = 0; i < staged.count; i++)
		if (stage_sriov(cfg, &staged.functions[i], &policy, &journal) != 0 ||
		    stage_write(cfg, &staged.functions[i], PCI_COMMAND, 2, commands[i],
			&journal) != 0)
			return -1;
	for (size_t i = staged.count; i != 0U; i--) {
		struct cdk2_pci_function *fn = &staged.functions[i - 1U];
		if ((fn->header_type & 0x7fU) == 1U &&
		    stage_bridge(cfg, fn, &staged, &policy, &journal) != 0)
			return -1;
		if ((fn->header_type & 0x7fU) == 2U &&
		    stage_cardbus(cfg, fn, &policy, &journal) != 0)
			return -1;
	}
	if (commit(cfg, &journal) != 0)
		return -1;
	*topology = staged;
	return 0;
}
