/* SPDX-License-Identifier: GPL-2.0-only */
#include <cdk2/pci_bus_model.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct device {
	uint8_t bus, dev, fun;
	uint8_t data[4096];
	uint32_t masks[7];
};

struct fixture {
	struct device devices[8];
	size_t count;
	unsigned int writes;
	unsigned int fail_write;
	unsigned int crs_reads;
	uint8_t rom[1024];
};

static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v)
{ p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static uint32_t get(const uint8_t *p, uint8_t w)
{
	uint32_t v = p[0];
	if (w > 1)
		v |= (uint32_t)p[1] << 8;
	if (w > 2)
		v |= (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
	return v;
}

static struct device *find(struct fixture *f, uint8_t b, uint8_t d, uint8_t n)
{
	size_t i;
	for (i = 0; i < f->count; i++)
		if (f->devices[i].bus == b && f->devices[i].dev == d &&
		    f->devices[i].fun == n)
			return &f->devices[i];
	return NULL;
}

static int rd(void *context, uint8_t b, uint8_t d, uint8_t n,
	uint16_t off, uint8_t width, uint32_t *value)
{
	struct device *dev = find(context, b, d, n);
	struct fixture *fixture = context;
	unsigned int bar;
	if (dev == NULL) {
		*value = 0xffffffffU;
		return 0;
	}
	if (off == 0U && width == 4U && fixture->crs_reads != 0U) {
		fixture->crs_reads--;
		*value = 0xffff0001U;
		return 0;
	}
	if (off + width > sizeof(dev->data))
		return -1;
	if (width == 4 && ((off >= 0x10 && off <= 0x24) || off == 0x30 || off == 0x38)) {
		bar = off >= 0x30 ? 6U : (off - 0x10U) / 4U;
		if (get(dev->data + off, 4) == 0xffffffffU ||
		    get(dev->data + off, 4) == 0xfffff800U) {
			*value = dev->masks[bar]; return 0;
		}
	}
	*value = get(dev->data + off, width);
	return 0;
}

static int wr(void *context, uint8_t b, uint8_t d, uint8_t n,
	uint16_t off, uint8_t width, uint32_t value)
{
	struct fixture *f = context;
	struct device *dev = find(f, b, d, n);
	if (dev == NULL || off + width > sizeof(dev->data))
		return -1;
	f->writes++;
	if (f->fail_write != 0 && f->writes == f->fail_write)
		return -1;
	if (width == 1)
		dev->data[off] = value;
	else if (width == 2)
		put16(dev->data + off, value);
	else
		put32(dev->data + off, value);
	return 0;
}

static int read_memory(void *context, uint64_t address, void *buffer, size_t size)
{
	struct fixture *fixture = context;
	if (address < 0x100000U || address - 0x100000U > sizeof(fixture->rom) ||
	    size > sizeof(fixture->rom) - (address - 0x100000U))
		return -1;
	memcpy(buffer, fixture->rom + address - 0x100000U, size);
	return 0;
}

static struct device *add(struct fixture *f, uint8_t b, uint8_t d, uint8_t n,
	uint16_t vendor, uint16_t device, uint8_t header)
{
	struct device *p = &f->devices[f->count++];
	memset(p, 0, sizeof(*p)); p->bus = b; p->dev = d; p->fun = n;
	put16(p->data, vendor); put16(p->data + 2, device);
	p->data[0x0e] = header;
	return p;
}

static void check(int condition, int line, const char *expression)
{
	if (!condition) {
		fprintf(stderr, "FAIL line %d: %s\n", line, expression);
		exit(1);
	}
}

#define CHECK(x) check((x), __LINE__, #x)

static int topology_test(void)
{
	struct fixture f = { 0 };
	struct cdk2_pci_cfg cfg = { .context = &f, .crs_retries = 2,
		.read = rd, .write = wr };
	struct cdk2_pci_topology topology, before; struct device *p;
	p = add(&f, 0, 1, 0, 0x1234, 1, 0x80); p->data[0x0b] = 2;
	put16(p->data + 4, 7); put32(p->data + 0x10, 0x80000008);
	p->masks[0] = 0xfffff008; p->masks[6] = 0;
	p = add(&f, 0, 1, 3, 0x1234, 3, 0); p->masks[0] = 0xffffff01;
	p->masks[6] = 0; put16(p->data + 6, 0x10); p->data[0x34] = 0x40;
	put16(p->data + 0x40, 0x10); put32(p->data + 0x100, 0x1201000e);
	put32(p->data + 0x120, 0x14010010); put32(p->data + 0x140, 0x00010015);
	put32(p->data + 0x64, 0x20); put16(p->data + 0x68, 0x20);
	put32(p->data + 0x12c, 0x00040002); put32(p->data + 0x134, 0x00020008);
	put16(p->data + 0x13a, 0x9876); put32(p->data + 0x144, 0x00000120);
	p = add(&f, 0, 2, 0, 0x1234, 2, 1); p->data[0x0b] = 6; p->data[0x0a] = 4;
	put32(p->data + 0x18, 0x00020200); p->masks[6] = 0;
	p = add(&f, 2, 0, 0, 0xabcd, 4, 0); p->masks[6] = 0;
	memset(&topology, 0xa5, sizeof(topology));
	CHECK(cdk2_pci_enumerate(&cfg, 0, 4, &topology) == 0);
	CHECK(topology.count == 4); CHECK(topology.functions[0].bar_count == 1);
	CHECK(topology.functions[0].bars[0].size == 0x1000);
	CHECK(topology.functions[1].pcie_cap == 0x40);
	CHECK(topology.functions[1].ari_cap == 0x100);
	CHECK(topology.functions[1].sriov_cap == 0x120);
	CHECK(topology.functions[1].resizable_bar_cap == 0x140);
	CHECK(topology.functions[1].ari_forwarding == 1);
	CHECK(topology.functions[1].initial_vfs == 2);
	CHECK(topology.functions[1].total_vfs == 4);
	CHECK(topology.functions[1].vf_offset == 8);
	CHECK(topology.functions[1].vf_stride == 2);
	CHECK(topology.functions[1].vf_device_id == 0x9876);
	CHECK(topology.functions[1].vf_count == 4);
	CHECK(topology.functions[1].vf_rids[0] == 0x0013);
	CHECK(topology.functions[1].vf_rids[3] == 0x0019);
	CHECK(topology.functions[1].selected_rebar_size == 4);
	CHECK(topology.functions[3].bus == 2);
	CHECK(topology.requests[3].length == 0x1000);
	CHECK(topology.requests[3].alignment == 0xfff);
	CHECK(get(f.devices[0].data + 4, 2) == 7);
	CHECK(get(f.devices[0].data + 0x10, 4) == 0x80000008);
	before = topology; f.fail_write = f.writes + 2;
	CHECK(cdk2_pci_enumerate(&cfg, 0, 4, &topology) != 0);
	CHECK(memcmp(&before, &topology, sizeof(before)) == 0);
	CHECK(get(f.devices[0].data + 4, 2) == 7);
	CHECK(get(f.devices[0].data + 0x10, 4) == 0x80000008);
	return 0;
}

static int overflow_and_cardbus_test(void)
{
	struct fixture f = { 0 };
	struct cdk2_pci_cfg cfg = { .context = &f, .read = rd, .write = wr };
	struct cdk2_pci_topology topology, before;
	struct device *p;
	p = add(&f, 0, 0, 0, 1, 1, 2); p->masks[0] = 0xfffff000;
	put32(p->data + 0x1c, 0x10000000); put32(p->data + 0x20, 0x100fffff);
	put32(p->data + 0x2c, 0x1000); put32(p->data + 0x30, 0x1fff);
	CHECK(cdk2_pci_enumerate(&cfg, 0, 0, &topology) == 0);
	CHECK(topology.functions[0].memory_base == 0x10000000);
	CHECK(topology.functions[0].memory_limit == 0x100fffff);
	CHECK(topology.functions[0].io_base == 0x1000);
	CHECK(topology.functions[0].io_limit == 0x1fff);
	memset(&f, 0, sizeof(f));
	p = add(&f, 0, 0, 0, 1, 1, 0); put32(p->data + 0x10, 4);
	p->masks[0] = 0; p->masks[1] = 0x80000000; p->masks[6] = 0;
	p = add(&f, 0, 1, 0, 1, 2, 0); put32(p->data + 0x10, 4);
	p->masks[0] = 0; p->masks[1] = 0x80000000; p->masks[6] = 0;
	memset(&topology, 0x5a, sizeof(topology)); before = topology;
	CHECK(cdk2_pci_enumerate(&cfg, 0, 0, &topology) != 0);
	CHECK(memcmp(&before, &topology, sizeof(before)) == 0);
	CHECK(get(f.devices[0].data + 0x10, 4) == 4);
	CHECK(get(f.devices[0].data + 0x14, 4) == 0);
	return 0;
}

static int allocator_test(void)
{
	struct fixture f = { 0 };
	struct cdk2_pci_cfg cfg = { .context = &f, .read = rd, .write = wr };
	struct cdk2_pci_topology topology = { 0 }, before;
	struct cdk2_pci_allocation_policy policy = {
		.io = { 0x1000, 0xffff, 0x1000 },
		.mem32 = { 0x80000000, 0x8fffffff, 0x80000000 },
		.mem64 = { 0x100000000ULL, 0x10fffffffULL, 0x100000000ULL },
		.prefetch = { 0x90000000, 0x9fffffff, 0x90000000 },
		.hotplug_padding = { 0x1000, 0x100000, 0, 0 },
		.maximum_rebar_size = 4, .enable_sriov = 1,
	};
	struct cdk2_pci_function *bridge, *child, *cardbus;
	add(&f, 0, 0, 0, 1, 1, 1);
	add(&f, 1, 0, 0, 2, 2, 0);
	add(&f, 0, 2, 0, 3, 3, 2);
	topology.count = 3;
	bridge = &topology.functions[0];
	bridge->bus = 0; bridge->header_type = 1;
	bridge->hotplug_bridge = 1;
	bridge->secondary_bus = 1; bridge->subordinate_bus = 1;
	child = &topology.functions[1];
	child->bus = 1; child->bar_count = 3;
	child->bars[0] = (struct cdk2_pci_bar) {
		.kind = CDK2_PCI_BAR_MEM32, .index = 0, .size = 0x2000 };
	child->bars[1] = (struct cdk2_pci_bar) {
		.kind = CDK2_PCI_BAR_IO, .index = 1, .size = 0x100 };
	child->bars[2] = (struct cdk2_pci_bar) {
		.kind = CDK2_PCI_BAR_MEM32, .index = 2, .size = 0x1000 };
	child->rebar_count = 2;
	child->rebar[0].control_offset = 0x148;
	child->rebar[0].supported_sizes = 0x12;
	child->rebar[1].control_offset = 0x150;
	child->rebar[1].supported_sizes = 0x0c;
	child->rebar[1].bar_index = 2;
	put32(f.devices[1].data + 0x150, 2);
	child->sriov_cap = 0x200; child->total_vfs = 2;
	child->vf_bar_count = 1;
	child->vf_bars[0] = (struct cdk2_pci_bar) {
		.kind = CDK2_PCI_BAR_MEM32, .index = 0, .size = 0x1000 };
	cardbus = &topology.functions[2];
	cardbus->bus = 0; cardbus->device = 2; cardbus->header_type = 2;
	CHECK(cdk2_pci_allocate_resources(&cfg, &topology, &policy) == 0);
	CHECK(child->bars[0].base == 0x80000000);
	CHECK(child->bars[1].base == 0x1000);
	CHECK((get(f.devices[1].data + 0x148, 4) & 0x1f00) == 0x400);
	CHECK((get(f.devices[1].data + 0x150, 4) & 0x1f00) == 0x300);
	CHECK(child->vf_bars[0].base == 0x81800000);
	CHECK(get(f.devices[1].data + 0x224, 4) == 0x81800000);
	CHECK((get(f.devices[1].data + 0x208, 2) & 1U) != 0U);
	CHECK((get(f.devices[0].data + 0x20, 4) & 0xfff0U) == 0x8000);
	CHECK(get(f.devices[2].data + 0x20, 4) >=
		get(f.devices[2].data + 0x1c, 4));
	CHECK(get(f.devices[2].data + 0x30, 4) >=
		get(f.devices[2].data + 0x2c, 4));
	memset(f.devices[0].data + 0x1c, 0, 0x20);
	memset(f.devices[1].data + 0x10, 0, 0x150);
	topology.functions[1].bars[0].base = 0;
	topology.functions[1].bars[1].base = 0;
	before = topology; f.writes = 0; f.fail_write = 3;
	CHECK(cdk2_pci_allocate_resources(&cfg, &topology, &policy) != 0);
	CHECK(memcmp(&before, &topology, sizeof(before)) == 0);
	CHECK(get(f.devices[1].data + 0x10, 4) == 0);
	CHECK(get(f.devices[1].data + 0x14, 4) == 0);
	return 0;
}

static int host_and_rom_test(void)
{
	struct fixture f = { 0 };
	struct cdk2_pci_cfg cfg = { .context = &f, .read = rd, .write = wr,
		.read_memory = read_memory };
	struct cdk2_pci_topology topology = { 0 };
	struct cdk2_pci_host_model host = { 0 };
	struct cdk2_pci_allocation_policy policy = {
		.mem32 = { 0x80000000, 0x8fffffff, 0x80000000 } };
	struct cdk2_pci_function function = { 0 }, before;
	add(&f, 0, 0, 0, 1, 1, 0);
	topology.count = 1;
	CHECK(cdk2_pci_host_set(&host) != 0);
	CHECK(cdk2_pci_host_begin(&host, &cfg, &topology) == 0);
	CHECK(cdk2_pci_host_end(&host) != 0);
	CHECK(cdk2_pci_host_submit(&host, &policy) == 0);
	CHECK(cdk2_pci_host_allocate(&host) == 0);
	CHECK(host.allocation_status == 0);
	CHECK(cdk2_pci_host_set(&host) == 0);
	CHECK(cdk2_pci_host_end(&host) == 0);
	function.bar_count = 1;
	function.bars[0] = (struct cdk2_pci_bar) {
		.kind = CDK2_PCI_BAR_ROM, .base = 0x100000, .size = sizeof(f.rom) };
	f.rom[0] = 0x55; f.rom[1] = 0xaa; put16(f.rom + 0x18, 0x20);
	memcpy(f.rom + 0x20, "PCIR", 4); put16(f.rom + 0x30, 1);
	f.rom[0x34] = 3; f.rom[0x35] = 0x80;
	CHECK(cdk2_pci_discover_option_rom(&cfg, &function) == 0);
	CHECK(function.option_rom_images == 1);
	CHECK(function.option_rom_efi_images == 1);
	CHECK(function.option_rom_load_file == 1);
	before = function; f.rom[0x20] = 0;
	CHECK(cdk2_pci_discover_option_rom(&cfg, &function) != 0);
	CHECK(memcmp(&before, &function, sizeof(before)) == 0);
	return 0;
}

static int temporary_bridge_and_crs_test(void)
{
	struct fixture f = { 0 };
	struct cdk2_pci_cfg cfg = { .context = &f, .crs_retries = 2,
		.read = rd, .write = wr };
	struct cdk2_pci_topology topology = { 0 };
	struct device *bridge, *child;
	bridge = add(&f, 0, 3, 0, 0x1111, 1, 1);
	bridge->data[0x0b] = 6; bridge->data[0x0a] = 4; bridge->masks[6] = 0;
	put16(bridge->data + 6, 0x10); bridge->data[0x34] = 0x40;
	put16(bridge->data + 0x40, 0x10); put32(bridge->data + 0x64, 0x20);
	put16(bridge->data + 0x68, 0x20);
	put32(bridge->data + 0x1c, 0x0000f101);
	put32(bridge->data + 0x20, 0x8ff08000);
	put32(bridge->data + 0x24, 0x9ff19001);
	put32(bridge->data + 0x28, 1); put32(bridge->data + 0x2c, 1);
	child = add(&f, 1, 0, 0, 0x2222, 2, 0); child->masks[6] = 0;
	child = add(&f, 1, 1, 3, 0x3333, 3, 0); child->masks[6] = 0;
	f.crs_reads = 2;
	CHECK(cdk2_pci_enumerate(&cfg, 0, 4, &topology) == 0);
	CHECK(topology.count == 3);
	CHECK(topology.functions[0].secondary_bus == 1);
	CHECK(topology.functions[1].bus == 1);
	CHECK(topology.functions[2].device == 1);
	CHECK(topology.functions[2].function == 3);
	CHECK(get(bridge->data + 0x18, 4) == 0);
	CHECK(topology.functions[0].memory_base == 0x80000000ULL);
	CHECK(topology.functions[0].memory_limit == 0x8fffffffULL);
	CHECK(topology.functions[0].prefetch_base == 0x0000000190000000ULL);
	CHECK(topology.functions[0].prefetch_limit == 0x000000019fffffffULL);
	return 0;
}

static int corruption_test(void)
{
	struct fixture f = { 0 };
	struct cdk2_pci_cfg cfg = { .context = &f, .read = rd, .write = wr };
	struct cdk2_pci_topology topology = { 0 }; struct device *p;
	p = add(&f, 0, 0, 0, 1, 2, 0); p->masks[6] = 0;
	put16(p->data + 6, 0x10); p->data[0x34] = 0x40;
	put16(p->data + 0x40, 0x4010); /* cyclic conventional list */
	CHECK(cdk2_pci_enumerate(&cfg, 0, 0, &topology) != 0);
	CHECK(topology.count == 0);
	return 0;
}

int main(void)
{
	if (topology_test() || temporary_bridge_and_crs_test() ||
	    overflow_and_cardbus_test() || allocator_test() || host_and_rom_test() ||
	    corruption_test())
		return 1;
	puts("pci bus model tests: PASS");
	return 0;
}
