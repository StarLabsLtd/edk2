/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/graphics_output_driver.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned int calls, fail_call, closes, uninstalls, close_events;
static struct cdk2_graphics_pci_info pci_info;
static void (CDK2_MS_ABI * ready_notify)(void *, void *);
static void *ready_context;

static uint64_t fail(void)
{
	calls++;
	return calls == fail_call ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI open_protocol(void *handle, const EFI_GUID *guid,
					  void **interface, void *agent,
					  void *controller, uint32_t attributes)
{
	uint64_t status = fail();
	(void)handle;
	(void)guid;
	(void)agent;
	(void)controller;
	(void)attributes;
	if (status == EFI_SUCCESS)
		*interface = (void *)4;
	return status;
}
static uint64_t CDK2_MS_ABI close_protocol(void *handle, const EFI_GUID *guid,
					   void *agent, void *controller)
{
	(void)handle;
	(void)guid;
	(void)agent;
	(void)controller;
	closes++;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI install(void **handle, const EFI_GUID *guid,
				    void *interface, ...)
{
	uint64_t status = fail();
	(void)guid;
	(void)interface;
	if (status == EFI_SUCCESS)
		*handle = (void *)5;
	return status;
}
static uint64_t CDK2_MS_ABI uninstall(void *handle, const EFI_GUID *guid,
				      void *interface, ...)
{
	(void)handle;
	(void)guid;
	(void)interface;
	uninstalls++;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI event(uint32_t type, size_t tpl, void *notify,
				  void *context, const EFI_GUID *group,
				  void **event_handle)
{
	uint64_t status = fail();
	(void)type;
	(void)tpl;
	(void)group;
	ready_notify = notify;
	ready_context = context;
	if (status == EFI_SUCCESS)
		*event_handle = (void *)6;
	return status;
}
static uint64_t CDK2_MS_ABI close_event(void *event_handle)
{
	(void)event_handle;
	close_events++;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI get_pci(void *pci,
				    struct cdk2_graphics_pci_info *info)
{
	(void)pci;
	*info = pci_info;
	return EFI_SUCCESS;
}
static void *CDK2_MS_ABI allocate(size_t size)
{
	return malloc(size);
}
static void CDK2_MS_ABI release(void *buffer)
{
	free(buffer);
}
static int expect(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "graphics driver test: %s\n", message);
	return condition ? 0 : 1;
}
static void reset(uint32_t *framebuffer)
{
	calls = fail_call = closes = uninstalls = close_events = 0;
	ready_notify = NULL;
	ready_context = NULL;
	pci_info = (struct cdk2_graphics_pci_info){
		0x8086,	    0x1234, 0x8086, 0x5678, 1, 2, (size_t)framebuffer,
		16 * 12 * 4};
}

int main(void)
{
	uint32_t framebuffer[16 * 12];
	EFI_PEI_GRAPHICS_INFO_HOB hob = {
		(size_t)framebuffer,
		sizeof(framebuffer),
		{0,
		 16,
		 12,
		 pixel_blue_green_red_reserved8_bit_per_color,
		 {0, 0, 0, 0},
		 16}};
	struct cdk2_graphics_device_info expected = {0x8086, 0x1234, 0x8086,
						     0x5678, 1,	     2};
	struct cdk2_graphics_services services = {
		open_protocol, close_protocol, install,	 uninstall, event,
		close_event,   get_pci,	       allocate, release};
	struct cdk2_graphics_child child;
	EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
	size_t info_size;
	unsigned int stage;
	int failures = 0;

	for (stage = 1; stage <= 4; stage++) {
		reset(framebuffer);
		fail_call = stage;
		failures += expect(cdk2_graphics_start(&child, &services,
						       (void *)1, (void *)2,
						       &hob, &expected) ==
					   EFI_OUT_OF_RESOURCES,
				   "fault returned from start");
		failures += expect(!child.started,
				   "failed start remains unpublished");
	}
	reset(framebuffer);
	failures +=
		expect(cdk2_graphics_supported(&services, (void *)1, (void *)2,
					       &expected) == EFI_SUCCESS,
		       "matching PCI controller supported");
	reset(framebuffer);
	failures += expect(cdk2_graphics_start(&child, &services, (void *)1,
					       (void *)2, &hob,
					       &expected) == EFI_SUCCESS &&
				   child.started,
			   "graphics child starts");
	failures += expect(child.path.type == 2 && child.path.subtype == 3 &&
				   child.path.adr == 0x10000,
			   "ACPI ADR child path published");
	failures += expect(child.gop.query_mode(&child.gop, 0, &info_size,
						&info) == EFI_SUCCESS &&
				   info_size == sizeof(*info) &&
				   info->horizontal_resolution == 16,
			   "QueryMode returns allocated copy");
	release(info);
	failures += expect(child.gop.set_mode(&child.gop, 1) == EFI_SUCCESS &&
				   child.mode.framebuffer_base == 0,
			   "software HiDPI hides framebuffer");
	ready_notify(NULL, ready_context);
	failures +=
		expect(child.mode.mode == 0 && child.mode.framebuffer_base ==
						       (size_t)framebuffer,
		       "ReadyToBoot restores physical framebuffer");
	failures += expect(
		cdk2_graphics_stop(&child) == EFI_SUCCESS && !child.started &&
			uninstalls == 1 && close_events == 1 && closes == 2,
		"stop releases publication, event, child, and parent");
	reset(framebuffer);
	pci_info.bar_size = 8;
	failures += expect(cdk2_graphics_start(&child, &services, (void *)1,
					       (void *)2, &hob,
					       &expected) == EFI_UNSUPPORTED,
			   "framebuffer outside matching BAR rejected");
	return failures == 0 ? 0 : 1;
}
