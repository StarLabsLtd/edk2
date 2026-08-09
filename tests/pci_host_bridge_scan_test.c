/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/pci_host_bridge.h>

#include <stdio.h>
#include <string.h>

struct function {
	uint8_t bus, device, function, present, header, class_base, class_sub, sub_bus;
	uint32_t bar[6], mask[6];
};

struct fixture {
	struct function function[8];
	size_t count;
	uint8_t fail, writes, restores;
};

static struct function *find_function(struct fixture *fixture, uint8_t bus,
	uint8_t device, uint8_t function)
{
	size_t index;

	for (index = 0; index < fixture->count; index++)
		if (fixture->function[index].bus == bus &&
		    fixture->function[index].device == device &&
		    fixture->function[index].function == function)
			return &fixture->function[index];
	return NULL;
}

static uint64_t config(void *context, uint8_t bus, uint8_t device,
	uint8_t function, uint16_t offset, size_t width, uint32_t *value,
	uint8_t write)
{
	struct fixture *fixture = context;
	struct function *entry = find_function(fixture, bus, device, function);
	size_t bar;

	if (value == NULL || fixture->fail)
		return EFI_DEVICE_ERROR;
	if (entry == NULL || !entry->present) {
		if (!write)
			*value = UINT32_MAX;
		return EFI_SUCCESS;
	}
	if (offset >= 0x10 && offset < 0x28 && width == 4) {
		bar = (offset - 0x10U) / 4U;
		if (write) {
			fixture->writes++;
			if (*value == UINT32_MAX)
				entry->bar[bar] = entry->mask[bar];
			else {
				entry->bar[bar] = *value;
				fixture->restores++;
			}
		} else {
			*value = entry->bar[bar];
		}
		return EFI_SUCCESS;
	}
	if (write)
		return EFI_SUCCESS;
	if (offset == 0 && width == 2)
		*value = 0x8086;
	else if (offset == 0x0e && width == 1)
		*value = entry->header;
	else if (offset == 0x0b && width == 1)
		*value = entry->class_base;
	else if (offset == 0x0a && width == 1)
		*value = entry->class_sub;
	else if (offset == 0x1a && width == 1)
		*value = entry->sub_bus;
	else
		*value = 0;
	return EFI_SUCCESS;
}

static uint64_t read_config(void *context, uint8_t bus, uint8_t device,
	uint8_t function, uint16_t offset, size_t width, uint32_t *value)
{
	return config(context, bus, device, function, offset, width, value, 0);
}

static uint64_t write_config(void *context, uint8_t bus, uint8_t device,
	uint8_t function, uint16_t offset, size_t width, uint32_t *value)
{
	return config(context, bus, device, function, offset, width, value, 1);
}

static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "%s\n", message);
	return !condition;
}

int main(void)
{
	struct cdk2_pci_host_model host, saved;
	struct fixture fixture;
	int failures = 0;

	memset(&fixture, 0, sizeof(fixture));
	memset(&host, 0xa5, sizeof(host));
	saved = host;
	failures += expect(cdk2_pci_host_scan(&host, &fixture, read_config,
		write_config) == EFI_NOT_FOUND && memcmp(&host, &saved, sizeof(host)) == 0,
		"empty scan mutated the caller model");
	fixture.count = 4;
	fixture.function[0] = (struct function){ .present = 1, .header = 0x80,
		.bar = { 0x80001000 }, .mask = { 0xfffff000 } };
	fixture.function[1] = (struct function){ .present = 1, .function = 1,
		.bar = { 0x2001 }, .mask = { 0xffffff01 } };
	fixture.function[2] = (struct function){ .present = 1, .device = 1,
		.header = 1, .class_base = 6, .class_sub = 4, .sub_bus = 3 };
	fixture.function[3] = (struct function){ .present = 1, .device = 2,
		.bar = { 4, 1 }, .mask = { 0xfffff004, UINT32_MAX } };
	failures += expect(cdk2_pci_host_scan(&host, &fixture, read_config,
		write_config) == EFI_SUCCESS, "valid topology scan failed");
	failures += expect(host.count == 1 && host.root[0].aperture[0].limit == 3,
		"bridge bus bound was not preserved");
	failures += expect(host.root[0].aperture[1].base == 0x2000 &&
		host.root[0].aperture[2].base == 0x80001000 &&
		host.root[0].aperture[3].base == 0x100000000ULL,
		"multifunction BAR apertures were not aggregated");
	failures += expect(fixture.writes != 0 && fixture.writes == fixture.restores * 2,
		"BAR probes were not restored");
	saved = host;
	fixture.fail = 1;
	failures += expect(cdk2_pci_host_scan(&host, &fixture, read_config,
		write_config) == EFI_DEVICE_ERROR && memcmp(&host, &saved, sizeof(host)) == 0,
		"failed scan was not atomic");
	return failures != 0;
}
