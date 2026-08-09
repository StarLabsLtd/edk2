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
	unsigned int bar;
	if (dev == NULL) {
		*value = 0xffffffffU;
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
	struct fixture f = { 0 }; struct cdk2_pci_cfg cfg = { &f, rd, wr };
	struct cdk2_pci_topology topology, before; struct device *p;
	p = add(&f, 0, 1, 0, 0x1234, 1, 0x80); p->data[0x0b] = 2;
	put16(p->data + 4, 7); put32(p->data + 0x10, 0x80000008);
	p->masks[0] = 0xfffff008; p->masks[6] = 0;
	p = add(&f, 0, 1, 3, 0x1234, 3, 0); p->masks[0] = 0xffffff01;
	p->masks[6] = 0; put16(p->data + 6, 0x10); p->data[0x34] = 0x40;
	put16(p->data + 0x40, 0x10); put32(p->data + 0x100, 0x1201000e);
	put32(p->data + 0x120, 0x14010010); put32(p->data + 0x140, 0x00010015);
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
	CHECK(topology.functions[3].bus == 2);
	CHECK(get(f.devices[0].data + 4, 2) == 7);
	CHECK(get(f.devices[0].data + 0x10, 4) == 0x80000008);
	before = topology; f.fail_write = f.writes + 2;
	CHECK(cdk2_pci_enumerate(&cfg, 0, 4, &topology) != 0);
	CHECK(memcmp(&before, &topology, sizeof(before)) == 0);
	CHECK(get(f.devices[0].data + 4, 2) == 7);
	CHECK(get(f.devices[0].data + 0x10, 4) == 0x80000008);
	return 0;
}

static int corruption_test(void)
{
	struct fixture f = { 0 }; struct cdk2_pci_cfg cfg = { &f, rd, wr };
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
	if (topology_test() || corruption_test())
		return 1;
	puts("pci bus model tests: PASS");
	return 0;
}
