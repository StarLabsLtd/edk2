/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_bus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { UINT8 address; UINTN controls, resets, delays; };
static struct fixture fixture;
static const UINT8 device_descriptor[18] = { 18U, 1U, 0U, 3U, 0U, 0U, 0U,
	9U, 0x34U, 0x12U, 0x78U, 0x56U, 0U, 1U, 1U, 2U, 3U, 1U };
static const UINT8 configuration[] = { 9U, 2U, 41U, 0U, 2U, 1U, 0U, 0x80U, 50U,
	9U, 4U, 0U, 0U, 1U, 8U, 6U, 80U, 0U,
	7U, 5U, 0x81U, 2U, 0U, 2U, 0U,
	9U, 4U, 1U, 0U, 1U, 3U, 1U, 1U, 0U,
	7U, 5U, 0x82U, 3U, 8U, 0U, 10U };

static EFI_STATUS CDK2_MS_ABI get_port(struct cdk2_usb2_hc_protocol *host,
	UINT8 port, struct cdk2_usb_port_status *status)
{ (void)host; (void)port; *status = (struct cdk2_usb_port_status) {
	1U | 1U << 11, 1U }; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI set_port(struct cdk2_usb2_hc_protocol *host,
	UINT8 port, UINTN feature)
{ (void)host; (void)port; (void)feature; fixture.resets++; return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb2_hc_protocol *host,
	UINT8 address, UINT8 speed, UINTN packet, struct cdk2_usb_request *request,
	UINTN direction, void *data, UINTN * length, UINTN timeout, void *translator,
	UINT32 * result)
{
	(void)host; (void)speed; (void)packet; (void)direction; (void)timeout;
	(void)translator; fixture.controls++; *result = 0U;
	if (request->request == 5U)
		fixture.address = request->value;
	else if ((request->value >> 8) == 1U) {
		memcpy(data, device_descriptor, *length); fixture.address = address;
	} else if ((request->value >> 8) == 2U) {
		memcpy(data, configuration, *length);
	}
	return EFI_SUCCESS;
}
static void delay(void *context, UINTN microseconds)
{ (void)context; fixture.delays += microseconds; }

int main(void)
{
	struct cdk2_usb2_hc_protocol host = { .control_transfer = control,
		.get_root_hub_port_status = get_port,
		.set_root_hub_port_feature = set_port };
	struct cdk2_usb_bus *bus = calloc(1U, sizeof(*bus));

	CHECK(bus != NULL && cdk2_usb_bus_init(bus, &host, NULL, delay) == EFI_SUCCESS &&
		cdk2_usb_bus_enumerate_port(bus, 0U) == EFI_SUCCESS &&
		bus->child_count == 2U && bus->children[0].address == 1U &&
		bus->children[1].interface == 1U && fixture.address == 1U &&
		fixture.delays == 2000U);
	CHECK(cdk2_usb_bus_enumerate_port(bus, 0U) == EFI_ALREADY_STARTED &&
		cdk2_usb_bus_remove_port(bus, 0U) == EFI_SUCCESS &&
		bus->child_count == 0U && cdk2_usb_bus_remove_port(bus, 0U) == EFI_NOT_FOUND);
	free(bus);
	puts("usb bus enumeration tests: PASS");
	return 0;
}
