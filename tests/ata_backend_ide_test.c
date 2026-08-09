/* SPDX-License-Identifier: GPL-2.0-only */

#include <cdk2/ata_atapi_backend.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "failed: %s:%d: %s\n", \
	__FILE__, __LINE__, #x); exit(EXIT_FAILURE); } } while (0)

struct fixture {
	UINT8 device, command, status;
	unsigned int words, notify_calls, submit_calls, calculate_calls, timing_calls;
	unsigned int fail_notify, fail_submit, fail_calculate, fail_timing;
	unsigned int submitted_mask;
	UINT64 now;
};
struct combined { struct fixture fixture; struct cdk2_ide_init_protocol ide; };
static struct fixture *from_ide(struct cdk2_ide_init_protocol *ide)
{ return &((struct combined *)((UINT8 *)ide - offsetof(struct combined, ide)))->fixture; }
static UINT8 read8(void *opaque, UINT16 port)
{ struct fixture *fixture = opaque;
	if ((port & 7U) == 7U) {
		if (fixture->command == 0xecU && fixture->device == 1U)
			return 1U;
		return fixture->words < 256U && fixture->command != 0U ? 0x08U : 0U;
	}
	return 0; }
static UINT16 read16(void *opaque, UINT16 port)
{ struct fixture *fixture = opaque; unsigned int word = fixture->words++;
	(void)port;
	if (word == 0U)
		return fixture->command == 0xa1U ? 0x8000U : 0x0040U;
	if (word == 106U)
		return 0x5000U;
	if (word == 117U)
		return 2048U;
	if (word == 118U)
		return 0U;
	if (word == 209U)
		return 0x4003U;
	return (UINT16)word; }
static EFI_STATUS write8(void *opaque, UINT16 port, UINT8 value)
{ struct fixture *fixture = opaque;
	if ((port & 7U) == 6U)
		fixture->device = (value & 0x10U) != 0U;
	if ((port & 7U) == 7U) {
		fixture->command = value;
		fixture->words = 0;
	}
	if (port == 0x3f6U && value == 0U) {
		fixture->command = 0;
		fixture->words = 0;
	}
	return EFI_SUCCESS; }
static EFI_STATUS write16(void *opaque, UINT16 port, UINT16 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS write32(void *opaque, UINT16 port, UINT32 value)
{ (void)opaque; (void)port; (void)value; return EFI_SUCCESS; }
static EFI_STATUS map(void *opaque, enum cdk2_ahci_dma_operation operation,
	void *host, size_t *size, UINT64 *device, void **mapping)
{ (void)opaque; (void)operation; (void)size; *device = (UINT64)(uintptr_t)host;
	*mapping = host; return EFI_SUCCESS; }
static EFI_STATUS unmap(void *opaque, void *mapping)
{ (void)opaque; (void)mapping; return EFI_SUCCESS; }
static EFI_STATUS flush(void *opaque)
{ (void)opaque; return EFI_SUCCESS; }
static EFI_STATUS engine_timing(void *opaque, UINT8 channel, UINT8 device)
{ struct fixture *fixture = opaque; (void)channel; (void)device;
	if ((fixture->submitted_mask & (1U << (channel * 2U + device))) == 0U)
		return EFI_SUCCESS;
	fixture->calculate_calls++;
	if (fixture->fail_calculate == fixture->calculate_calls)
		return EFI_DEVICE_ERROR;
	fixture->timing_calls++;
	return fixture->fail_timing == fixture->timing_calls ? EFI_DEVICE_ERROR :
		EFI_SUCCESS; }
static UINT64 get_time(void *opaque)
{ return ((struct fixture *)opaque)->now++; }
static void delay(void *opaque, UINTN usec)
{ ((struct fixture *)opaque)->now += usec; }
static EFI_STATUS CDK2_MS_ABI get_channel(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, BOOLEAN *enabled, UINT8 *devices)
{ (void)ide; *enabled = channel == 0U; *devices = channel == 0U ? 2U : 0U;
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI notify(struct cdk2_ide_init_protocol *ide,
	UINTN phase, UINT8 channel)
{ struct fixture *fixture = from_ide(ide);
	(void)phase; CHECK(channel == 0U); fixture->notify_calls++;
	return fixture->fail_notify == fixture->notify_calls ? EFI_DEVICE_ERROR :
		EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI submit(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void *identify)
{ struct fixture *fixture = from_ide(ide); CHECK(channel == 0U && device < 2U);
	CHECK(identify != NULL); fixture->submit_calls++;
	if (fixture->fail_submit == fixture->submit_calls)
		return EFI_DEVICE_ERROR;
	fixture->submitted_mask |= 1U << (channel * 2U + device);
	return EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI calculate(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void **mode)
{ struct fixture *fixture = from_ide(ide); (void)channel; (void)device;
	fixture->calculate_calls++; *mode = fixture;
	return fixture->fail_calculate == fixture->calculate_calls ? EFI_DEVICE_ERROR :
		EFI_SUCCESS; }
static EFI_STATUS CDK2_MS_ABI timing(struct cdk2_ide_init_protocol *ide,
	UINT8 channel, UINT8 device, void *mode)
{ struct fixture *fixture = from_ide(ide); (void)channel; (void)device;
	CHECK(mode == fixture); fixture->timing_calls++;
	return fixture->fail_timing == fixture->timing_calls ? EFI_DEVICE_ERROR :
		EFI_SUCCESS; }
static EFI_STATUS run(struct combined *combined, unsigned int fail_notify,
	unsigned int fail_submit, unsigned int fail_calculate, unsigned int fail_timing,
	struct cdk2_ata_topology *topology)
{
	struct cdk2_ata_controller_backend backend = { 0 };
	struct cdk2_ata_controller controller = { .ide = &combined->ide,
		.ide_engine = &backend.ide, .backend = &backend };
	struct cdk2_ide_services services = { &combined->fixture, read8, read16,
		write8, write16, write32, map, unmap, flush, engine_timing,
		get_time, delay };
	struct cdk2_ide_channel channel = { 0x1f0U, 0x3f6U, 0U };

	memset(&combined->fixture, 0, sizeof(combined->fixture));
	combined->fixture.fail_notify = fail_notify;
	combined->fixture.fail_submit = fail_submit;
	combined->fixture.fail_calculate = fail_calculate;
	combined->fixture.fail_timing = fail_timing;
	CHECK(cdk2_ide_engine_init(&backend.ide, &services, &channel, 1U) == EFI_SUCCESS);
	CHECK(cdk2_ata_topology_init(topology, CDK2_ATA_IDE) == EFI_SUCCESS);
	return cdk2_ata_backend_discover_ide(&controller, topology);
}

int main(void)
{
	struct combined combined = { .ide = { get_channel, notify, submit, NULL,
		calculate, timing, FALSE, 2 } };
	struct cdk2_ata_topology topology;

	CHECK(run(&combined, 0, 0, 0, 0, &topology) == EFI_SUCCESS);
	CHECK(topology.count == 2 && topology.devices[0].type == CDK2_ATA_DISK &&
		topology.devices[1].type == CDK2_ATAPI_DEVICE);
	CHECK(topology.devices[0].block_size == 4096U &&
		topology.devices[0].alignment == 3U);
	for (unsigned int failure = 1; failure <= 6; failure++) {
		CHECK(EFI_ERROR(run(&combined, failure, 0, 0, 0, &topology)));
		CHECK(topology.count == 0U);
	}
	for (unsigned int failure = 1; failure <= 2; failure++) {
		CHECK(EFI_ERROR(run(&combined, 0, failure, 0, 0, &topology)));
		CHECK(topology.count == 0U);
		CHECK(EFI_ERROR(run(&combined, 0, 0, failure, 0, &topology)));
		CHECK(topology.count == 0U);
		CHECK(EFI_ERROR(run(&combined, 0, 0, 0, failure, &topology)));
		CHECK(topology.count == 0U);
	}
	puts("ata backend IDE tests: PASS");
	return 0;
}
