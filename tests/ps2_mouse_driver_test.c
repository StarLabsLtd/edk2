/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ps2_mouse_driver.h>
#include <stdio.h>
#include <string.h>

struct script {
	uint8_t data[32], aux[32];
	size_t count, index;
} script;
static unsigned int events, closed_events, closes, installs, uninstalls,
	fail_install;
static uint8_t CDK2_MS_ABI read8(void *context, uint16_t port)
{
	struct script *s = context;
	if (port == 0x64)
		return s->index < s->count ? 1 | (s->aux[s->index] ? 0x20 : 0)
					   : 0;
	return s->data[s->index++];
}
static void CDK2_MS_ABI write8(void *context, uint16_t port, uint8_t value)
{
	(void)context;
	(void)port;
	(void)value;
}
static uint64_t CDK2_MS_ABI open_protocol(void *h, const EFI_GUID *g, void **i,
					  void *a, void *c, uint32_t f)
{
	(void)h;
	(void)g;
	(void)a;
	(void)c;
	(void)f;
	*i = (void *)4;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI close_protocol(void *h, const EFI_GUID *g, void *a,
					   void *c)
{
	(void)h;
	(void)g;
	(void)a;
	(void)c;
	closes++;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI install(void **h, const EFI_GUID *g, void *i, ...)
{
	(void)h;
	(void)g;
	(void)i;
	installs++;
	return fail_install ? EFI_OUT_OF_RESOURCES : EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI uninstall(void *h, const EFI_GUID *g, void *i, ...)
{
	(void)h;
	(void)g;
	(void)i;
	uninstalls++;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI event(uint32_t t, size_t p, void *n, void *c,
				  void **e)
{
	(void)t;
	(void)p;
	(void)n;
	(void)c;
	*e = (void *)(size_t)(++events);
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI timer(void *e, uint32_t t, uint64_t p)
{
	(void)e;
	(void)t;
	(void)p;
	return EFI_SUCCESS;
}
static uint64_t CDK2_MS_ABI close_event(void *e)
{
	(void)e;
	closed_events++;
	return EFI_SUCCESS;
}
static int expect(int c, const char *m)
{
	if (!c)
		fprintf(stderr, "ps2 driver test: %s\n", m);
	return c ? 0 : 1;
}
static void prepare(void)
{
	static const uint8_t data[] = {0x55, 0xfa, 0xaa, 0,    0xfa, 0xfa,
				       0xfa, 0xfa, 0xfa, 0xfa, 0xfa};
	static const uint8_t aux[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
	memset(&script, 0, sizeof(script));
	memcpy(script.data, data, sizeof(data));
	memcpy(script.aux, aux, sizeof(aux));
	script.count = sizeof(data);
}
int main(void)
{
	struct cdk2_mouse_services services = {
		open_protocol, close_protocol, install,	   uninstall,
		event,	       timer,	       close_event};
	struct cdk2_mouse_device device;
	struct cdk2_ps2_io io = {&script, read8, write8, NULL, 8};
	int failures = 0;
	failures +=
		expect(cdk2_ps2_mouse_hid_supported(0x030fd041, 0) &&
			       cdk2_ps2_mouse_hid_supported(0x0303d041, 1) &&
			       !cdk2_ps2_mouse_hid_supported(0x0303d041, 0),
		       "ACPI mouse HID/UID filter");
	prepare();
	fail_install = 0;
	failures +=
		expect(cdk2_ps2_mouse_start(&device, &services, io, (void *)1,
					    (void *)2) == EFI_SUCCESS &&
			       device.started,
		       "SIO child starts and publishes SimplePointer");
	failures += expect(cdk2_ps2_mouse_stop(&device) == EFI_SUCCESS &&
				   !device.started && uninstalls == 1 &&
				   closed_events == 2 && closes == 1,
			   "stop releases protocol/events/SIO");
	prepare();
	fail_install = 1;
	closed_events = closes = 0;
	failures += expect(
		cdk2_ps2_mouse_start(&device, &services, io, (void *)1,
				     (void *)2) == EFI_OUT_OF_RESOURCES &&
			!device.started && closed_events == 2 && closes == 1,
		"publication failure rolls back controller and events");
	return failures == 0 ? 0 : 1;
}
