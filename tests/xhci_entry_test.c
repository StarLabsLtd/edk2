/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/xhci.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/modules/xhci/entry.c"

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	struct loaded_image loaded;
	struct cdk2_efi_pci_io_protocol pci;
	UINT32 registers[0x3000U / 4U];
	UINT64 attributes;
	UINTN installs, uninstalls, opens, closes, allocations, frees;
	UINTN events, event_closes;
	struct driver_binding *binding;
	struct cdk2_usb2_hc_protocol *usb2;
};
static struct fixture fixture;

static EFI_STATUS CDK2_MS_ABI allocate_pool(UINT32 type, UINTN size, void **value)
{
	(void)type;
	*value = calloc(1U, size);
	fixture.allocations++;
	return *value == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI free_pool(void *value)
{
	fixture.frees++;
	free(value);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI create_event(UINT32 type, UINTN tpl,
	event_notify_fn * notify, void *context, void **event)
{
	(void)type; (void)tpl; (void)notify; (void)context;
	*event = &fixture.events;
	fixture.events++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI set_timer(void *event, UINTN type, UINT64 time)
{ (void)event; (void)type; (void)time; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI close_event(void *event)
{ (void)event; fixture.event_closes++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI handle_protocol(void *handle,
	const struct guid *protocol, void **value)
{
	(void)handle;
	if (protocol == &loaded_guid) {
		*value = &fixture.loaded;
		return EFI_SUCCESS;
	}
	return EFI_UNSUPPORTED;
}
static EFI_STATUS CDK2_MS_ABI open_protocol(void *handle,
	const struct guid *protocol, void **value, void *agent, void *controller,
	UINT32 attributes_value)
{
	(void)handle;
	(void)agent;
	(void)controller;
	(void)attributes_value;
	fixture.opens++;
	if (protocol == &pci_guid)
		*value = &fixture.pci;
	else if (protocol == &path_guid)
		*value = &fixture;
	else
		return EFI_UNSUPPORTED;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI close_protocol(void *handle,
	const struct guid *protocol, void *agent, void *controller)
{
	(void)handle; (void)protocol; (void)agent; (void)controller;
	fixture.closes++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI install_multiple(void **handle,
	const struct guid *protocol, void *interface, ...)
{
	(void)handle;
	fixture.installs++;
	if (protocol == &driver_guid)
		fixture.binding = interface;
	else if (protocol == &usb2_guid)
		fixture.usb2 = interface;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI uninstall_multiple(void *handle,
	const struct guid *protocol, void *interface, ...)
{
	(void)handle; (void)interface;
	fixture.uninstalls++;
	if (protocol == &usb2_guid)
		fixture.usb2 = NULL;
	return EFI_SUCCESS;
}
static void CDK2_MS_ABI stall(UINTN microseconds) { (void)microseconds; }

static EFI_STATUS CDK2_MS_ABI mem_read(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{
	(void)pci; (void)width; (void)bar;
	memcpy(buffer, &fixture.registers[offset / 4U], count * 4U);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI mem_write(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT8 bar, UINT64 offset, UINTN count, void *buffer)
{
	(void)pci; (void)width; (void)bar;
	memcpy(&fixture.registers[offset / 4U], buffer, count * 4U);
	if (offset == 0x40U && (fixture.registers[offset / 4U] & 2U) != 0U)
		fixture.registers[offset / 4U] &= ~2U;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI pci_read(struct cdk2_efi_pci_io_protocol *pci,
	UINTN width, UINT32 offset, UINTN count, void *buffer)
{
	const UINT8 class_code[3] = { 0x30U, 0x03U, 0x0cU };
	(void)pci; (void)width; (void)offset;
	memcpy(buffer, class_code, count);
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI attributes(struct cdk2_efi_pci_io_protocol *pci,
	UINTN operation, UINT64 value, UINT64 *result)
{
	(void)pci;
	if (operation == 0U)
		*result = fixture.attributes;
	else if (operation == 1U)
		*result = 0x700U;
	else if (operation == 2U)
		fixture.attributes |= value;
	else if (operation == 4U)
		fixture.attributes = value;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI allocate_buffer(struct cdk2_efi_pci_io_protocol *pci,
	UINTN type, UINTN memory, UINTN pages, void **host, UINT64 attributes_value)
{
	(void)pci; (void)type; (void)memory; (void)attributes_value;
	*host = aligned_alloc(4096U, pages * 4096U);
	return *host == NULL ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI free_buffer(struct cdk2_efi_pci_io_protocol *pci,
	UINTN pages, void *host)
{ (void)pci; (void)pages; free(host); return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI map(struct cdk2_efi_pci_io_protocol *pci,
	UINTN operation, void *host, UINTN *bytes, UINT64 *device, void **mapping)
{ (void)pci; (void)operation; (void)bytes; *device = (UINTN)host;
	*mapping = host; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI unmap(struct cdk2_efi_pci_io_protocol *pci,
	void *mapping)
{ (void)pci; (void)mapping; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI flush(struct cdk2_efi_pci_io_protocol *pci)
{ (void)pci; return EFI_SUCCESS; }

int main(void)
{
	struct boot_services boot = { 0 };
	struct system_table system = { .boot = &boot };
	void *image = &fixture;

	boot.allocate_pool = allocate_pool; boot.free_pool = free_pool;
	boot.create_event = create_event; boot.set_timer = set_timer;
	boot.close_event = close_event;
	boot.handle_protocol = handle_protocol; boot.stall = stall;
	boot.open_protocol = open_protocol; boot.close_protocol = close_protocol;
	boot.install_multiple = install_multiple; boot.uninstall_multiple = uninstall_multiple;
	fixture.pci = (struct cdk2_efi_pci_io_protocol) {
		.mem = { mem_read, mem_write }, .pci = { pci_read, pci_read },
		.map = map, .unmap = unmap, .allocate_buffer = allocate_buffer,
		.free_buffer = free_buffer, .flush = flush, .attributes = attributes };
	fixture.attributes = 0x200U;
	fixture.registers[0] = 0x01100040U;
	fixture.registers[1] = 8U | 1U << 8 | 4U << 24;
	fixture.registers[2] = 0U;
	fixture.registers[4] = 0U;
	fixture.registers[5] = 0x1000U;
	fixture.registers[6] = 0x2000U;
	fixture.registers[(0x40U + 8U) / 4U] = 1U;
	fixture.registers[0x44U / 4U] = 1U;
	CHECK(cdk2_xhci_entry(image, &system) == EFI_SUCCESS &&
		fixture.binding != NULL && fixture.loaded.unload != NULL);
	CHECK(fixture.binding->supported(fixture.binding, image, NULL) == EFI_SUCCESS);
	CHECK(fixture.binding->start(fixture.binding, image, NULL) == EFI_SUCCESS &&
		fixture.usb2 != NULL && fixture.attributes == 0x700U);
	CHECK(fixture.binding->stop(fixture.binding, image, 0U, NULL) == EFI_SUCCESS &&
		fixture.usb2 == NULL && fixture.allocations == fixture.frees &&
		fixture.events == fixture.event_closes);
	CHECK(fixture.loaded.unload(image) == EFI_SUCCESS && fixture.uninstalls == 2U);
	puts("xhci entry tests: PASS");
	return 0;
}
