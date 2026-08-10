/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/usb_bus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture { UINTN controls, bulks, resets; UINT8 endpoint, address; };
static struct fixture fixture;

static EFI_STATUS CDK2_MS_ABI control(struct cdk2_usb2_hc_protocol *this,
	UINT8 address, UINT8 speed, UINTN packet, struct cdk2_usb_request *request,
	UINTN direction, void *data, UINTN * length, UINTN timeout, void *translator,
	UINT32 * result)
{
	UINT8 *bytes = data;
	(void)this; (void)speed; (void)packet; (void)direction; (void)timeout;
	(void)translator;
	fixture.controls++; fixture.address = address; *result = 0U;
	if (request->request == 6U && request->value == 3U << 8) {
		const UINT8 languages[] = { 4U, 3U, 0x09U, 0x04U };
		memcpy(bytes, languages, sizeof(languages)); *length = sizeof(languages);
	} else if (request->request == 6U && (request->value >> 8) == 3U) {
		const UINT8 string[] = { 6U, 3U, 'O', 0U, 'K', 0U };
		memcpy(bytes, string, sizeof(string)); *length = sizeof(string);
	}
	return EFI_SUCCESS;
}

static EFI_STATUS CDK2_MS_ABI bulk(struct cdk2_usb2_hc_protocol *this,
	UINT8 address, UINT8 endpoint, UINT8 speed, UINTN packet, UINT8 buffers,
	void **data, UINTN * length, UINT8 *toggle, UINTN timeout, void *translator,
	UINT32 * result)
{
	(void)this; (void)speed; (void)packet; (void)data; (void)length;
	(void)toggle; (void)timeout; (void)translator;
	fixture.bulks++; fixture.address = address; fixture.endpoint = endpoint;
	*result = 0U;
	return buffers == 1U ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

static EFI_STATUS CDK2_MS_ABI reset(struct cdk2_usb2_hc_protocol *this,
	UINT8 port, UINTN feature)
{ (void)this; (void)port; fixture.resets++; return feature == 4U ? EFI_SUCCESS : 1U; }

int main(void)
{
	UINT8 descriptors[] = { 9U, 2U, 25U, 0U, 1U, 1U, 0U, 0x80U, 50U,
		9U, 4U, 0U, 0U, 1U, 8U, 6U, 80U, 0U,
		7U, 5U, 0x81U, 2U, 0x00U, 2U, 0U };
	UINT8 device_descriptor[18] = { 18U, 1U, 0U, 3U, 0U, 0U, 0U, 9U };
	struct cdk2_usb2_hc_protocol host = { .control_transfer = control,
		.bulk_transfer = bulk, .set_root_hub_port_feature = reset };
	struct cdk2_usb_configuration configuration;
	struct cdk2_usb_io_device device;
	UINT8 output[18], endpoint[7], buffer[8];
	UINTN length = sizeof(buffer);
	UINT32 result;
	UINT16 *languages;
	UINT16 count;
	CHAR16 *string;

	CHECK(sizeof(struct cdk2_usb_io_protocol) == 104U &&
		cdk2_usb_parse_configuration(descriptors, sizeof(descriptors),
			&configuration) == EFI_SUCCESS &&
		cdk2_usb_io_init(&device, &host, 3U, 1U, 3U, 512U,
			device_descriptor, &configuration, 0U, 0U) == EFI_SUCCESS);
	CHECK(device.protocol.get_device_descriptor(&device.protocol, output) ==
		EFI_SUCCESS && memcmp(output, device_descriptor, 18U) == 0);
	CHECK(device.protocol.get_endpoint_descriptor(&device.protocol, 0U, endpoint) ==
		EFI_SUCCESS && endpoint[2] == 0x81U && endpoint[4] == 0U &&
		endpoint[5] == 2U);
	CHECK(device.protocol.bulk_transfer(&device.protocol, 0x81U, buffer, &length,
		100U, &result) == EFI_SUCCESS && fixture.bulks == 1U &&
		fixture.address == 3U && fixture.endpoint == 0x81U);
	CHECK(device.protocol.get_supported_languages(&device.protocol, &languages,
		&count) == EFI_SUCCESS && count == 1U && languages[0] == 0x0409U);
	CHECK(device.protocol.get_string_descriptor(&device.protocol, 0x0409U, 1U,
		&string) == EFI_SUCCESS && string[0] == 'O' && string[1] == 'K');
	CHECK(device.protocol.port_reset(&device.protocol) == EFI_SUCCESS &&
		fixture.resets == 1U);
	puts("usb bus I/O tests: PASS");
	return 0;
}
