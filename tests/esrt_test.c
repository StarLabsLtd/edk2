/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <string.h>
#include <cdk2/esrt.h>

struct fixture {
	struct cdk2_esrt_entry fmp[4], non[4], published[8];
	UINTN fmp_count, non_count, published_count, writes, locks, closes;
	EFI_STATUS write_status, event_status, install_status, close_status;
};

static EFI_STATUS read_cache(void *p, enum cdk2_esrt_store which,
	struct cdk2_esrt_entry *out, UINTN capacity, UINTN *count)
{
	struct fixture *f = p; UINTN n = which == CDK2_ESRT_FMP ? f->fmp_count : f->non_count;
	struct cdk2_esrt_entry *src = which == CDK2_ESRT_FMP ? f->fmp : f->non;
	if (n > capacity)
		return EFI_BUFFER_TOO_SMALL;
	memcpy(out, src, n * sizeof(*out)); *count = n; return n ? EFI_SUCCESS : EFI_NOT_FOUND;
}
static EFI_STATUS write_cache(void *p, enum cdk2_esrt_store which,
	const struct cdk2_esrt_entry *in, UINTN count)
{
	struct fixture *f = p; struct cdk2_esrt_entry *dst;
	if (EFI_ERROR(f->write_status))
		return f->write_status;
	dst = which == CDK2_ESRT_FMP ? f->fmp : f->non;
	memcpy(dst, in, count * sizeof(*in));
	if (which == CDK2_ESRT_FMP)
		f->fmp_count = count; else f->non_count = count;
	f->writes++; return EFI_SUCCESS;
}
static EFI_STATUS lock_cache(void *p, enum cdk2_esrt_store which)
{ struct fixture *f = p; (void)which; f->locks++; return EFI_SUCCESS; }
static EFI_STATUS publish(void *p, const struct cdk2_esrt_table *table, UINTN bytes)
{
	struct fixture *f = p; UINTN expected = sizeof(*table) +
		table->resource_count * sizeof(table->entries[0]);
	assert(bytes == expected && table->resource_version == 1 &&
		table->resource_count_max == table->resource_count);
	f->published_count = table->resource_count;
	memcpy(f->published, table->entries, table->resource_count * sizeof(table->entries[0]));
	return EFI_SUCCESS;
}
static EFI_STATUS install(void *p, void *protocol)
{ struct fixture *f = p; (void)protocol; return f->install_status; }
static EFI_STATUS uninstall(void *p, void *protocol)
{ struct fixture *f = p; (void)protocol; f->writes++; return EFI_SUCCESS; }
static EFI_STATUS create_event(void *p, void *context, void **event)
{ struct fixture *f = p; (void)context; if (EFI_ERROR(f->event_status)) return f->event_status;
	*event = (void *)0x1234; return EFI_SUCCESS; }
static EFI_STATUS close_event(void *p, void *event)
{ struct fixture *f = p; assert(event == (void *)0x1234); f->closes++; return f->close_status; }

static struct cdk2_esrt_entry entry(UINT32 id, UINT32 version)
{
	struct cdk2_esrt_entry e = { 0 }; e.firmware_class.data1 = id;
	e.firmware_type = CDK2_ESRT_TYPE_DEVICE; e.firmware_version = version; return e;
}

int main(void)
{
	struct fixture f = { 0 }; EFI_GUID system = { .data1 = 2 };
	const struct cdk2_esrt_ops ops = { read_cache, write_cache, lock_cache, publish,
		install, uninstall, create_event, close_event };
	struct cdk2_esrt esrt = { &ops, &f, 4, 4, 0x55, &system, 1, FALSE, FALSE, NULL };
	struct cdk2_esrt_entry a = entry(1, 10), b = entry(3, 30), got;
	struct cdk2_esrt_fmp_image images[4] = { 0 };
	struct { struct cdk2_esrt_table h; struct cdk2_esrt_entry e[1]; } old = { 0 };
	assert(cdk2_esrt_register(&esrt, &a) == EFI_SUCCESS);
	assert(cdk2_esrt_register(&esrt, &a) == EFI_SUCCESS); /* EDK returns lookup success. */
	assert(f.non_count == 1);
	assert(cdk2_esrt_get(&esrt, &a.firmware_class, &got) == EFI_SUCCESS &&
		got.firmware_version == 10);
	f.write_status = EFI_DEVICE_ERROR; a.firmware_version = 11;
	assert(cdk2_esrt_update(&esrt, &a) == EFI_DEVICE_ERROR && f.non[0].firmware_version == 10);
	f.write_status = EFI_SUCCESS; assert(cdk2_esrt_update(&esrt, &a) == EFI_SUCCESS);
	assert(cdk2_esrt_unregister(&esrt, &a.firmware_class) == EFI_SUCCESS && f.non_count == 0);
	images[0] = (struct cdk2_esrt_fmp_image){ .image_type_id = system, .version = 9,
		.attributes_supported = CDK2_ESRT_IMAGE_IN_USE | CDK2_ESRT_IMAGE_RESET_REQUIRED,
		.attributes_setting = CDK2_ESRT_IMAGE_IN_USE | CDK2_ESRT_IMAGE_RESET_REQUIRED,
		.lowest_supported_version = 4, .last_attempt_version = 8,
		.last_attempt_status = 7, .descriptor_version = 3 };
	images[1] = images[0]; images[1].version = 7; /* duplicate: smallest wins */
	images[1].lowest_supported_version = 2;
	images[1].attributes_supported = CDK2_ESRT_IMAGE_IN_USE;
	images[1].attributes_setting = CDK2_ESRT_IMAGE_IN_USE;
	images[1].last_attempt_version = 6;
	images[1].last_attempt_status = 9;
	images[2] = (struct cdk2_esrt_fmp_image){ .image_type_id = b.firmware_class,
		.version = 30, .attributes_supported = CDK2_ESRT_IMAGE_IN_USE,
		.attributes_setting = CDK2_ESRT_IMAGE_IN_USE, .descriptor_version = 1 };
	images[3] = images[2]; images[3].image_type_id.data1 = 4; images[3].attributes_setting = 0;
	old.h.resource_count = 1; old.e[0] = b; old.e[0].firmware_type = CDK2_ESRT_TYPE_UEFI_DRIVER;
	assert(cdk2_esrt_sync_fmp(&esrt, images, 4, &old.h) == EFI_SUCCESS && f.fmp_count == 2);
	assert(f.fmp[0].firmware_version == 7 && f.fmp[0].firmware_type == CDK2_ESRT_TYPE_SYSTEM &&
		f.fmp[0].lowest_supported_version == 4 && f.fmp[0].last_attempt_version == 6 &&
		f.fmp[0].last_attempt_status == 9 &&
		f.fmp[0].capsule_flags == 0x55);
	/* Duplicate ordering cannot weaken restrictive metadata or change the minimum. */
	images[0].version = 7; images[0].lowest_supported_version = 2;
	images[0].attributes_supported = CDK2_ESRT_IMAGE_IN_USE;
	images[0].attributes_setting = CDK2_ESRT_IMAGE_IN_USE;
	images[1].version = 9; images[1].lowest_supported_version = 6;
	images[1].attributes_supported = CDK2_ESRT_IMAGE_IN_USE |
		CDK2_ESRT_IMAGE_RESET_REQUIRED;
	images[1].attributes_setting = CDK2_ESRT_IMAGE_IN_USE |
		CDK2_ESRT_IMAGE_RESET_REQUIRED;
	assert(cdk2_esrt_sync_fmp(&esrt, images, 2, NULL) == EFI_SUCCESS &&
		f.fmp_count == 1 && f.fmp[0].firmware_version == 7 &&
		f.fmp[0].lowest_supported_version == 6 && f.fmp[0].capsule_flags == 0x55);
	assert(f.fmp[1].firmware_type == CDK2_ESRT_TYPE_UEFI_DRIVER &&
		f.fmp[1].lowest_supported_version == 0 && f.fmp[1].last_attempt_status == 0);
	/* Providers that cannot report IN_USE are presumed active. */
	images[0] = (struct cdk2_esrt_fmp_image){ .image_type_id = system,
		.version = 11, .descriptor_version = 1 };
	assert(cdk2_esrt_sync_fmp(&esrt, images, 1, NULL) == EFI_SUCCESS &&
		f.fmp_count == 1 && f.fmp[0].firmware_version == 11);
	/* An explicit registration wins over an enumerated FMP of the same class. */
	f.non[0] = entry(2, 12); f.non_count = 1;
	assert(cdk2_esrt_sync_fmp(&esrt, images, 1, NULL) == EFI_SUCCESS &&
		f.fmp_count == 0 && f.non_count == 1);
	esrt.max_non_fmp = 0;
	{
		UINTN before = f.writes;
		assert(cdk2_esrt_sync_fmp(&esrt, images, 1, NULL) == EFI_BUFFER_TOO_SMALL &&
			f.writes == before);
	}
	esrt.max_non_fmp = 4; f.non_count = 0;
	assert(cdk2_esrt_sync_fmp(&esrt, images, 1, NULL) == EFI_SUCCESS &&
		f.fmp_count == 1);
	/* A non-FMP registration may not duplicate an FMP firmware class. */
	a.firmware_class = system;
	assert(cdk2_esrt_register(&esrt, &a) == EFI_SUCCESS && f.non_count == 0);
	/* Capacity exhaustion is atomic and preserves the existing repository. */
	esrt.max_fmp = 1;
	images[1] = images[0]; images[1].image_type_id.data1 = 99;
	assert(cdk2_esrt_sync_fmp(&esrt, images, 2, NULL) == EFI_OUT_OF_RESOURCES &&
		f.fmp_count == 1 && f.fmp[0].firmware_version == 11);
	esrt.max_fmp = 4;
	f.non[0] = entry(9, 1); f.non_count = 1;
	assert(cdk2_esrt_activate(&esrt) == EFI_SUCCESS && esrt.management_installed && esrt.ready_event);
	assert(cdk2_esrt_ready_to_boot(&esrt) == EFI_SUCCESS && f.published_count == 2 &&
		f.published[0].firmware_class.data1 == 9 && f.closes == 1 && esrt.ready_event == NULL);
	assert(cdk2_esrt_lock(&esrt) == EFI_SUCCESS && esrt.locked && f.locks == 2);
	assert(cdk2_esrt_register(&esrt, &a) == EFI_WRITE_PROTECTED);
	memset(&f, 0, sizeof(f)); esrt.locked = FALSE; esrt.management_installed = FALSE;
	f.event_status = EFI_OUT_OF_RESOURCES;
	assert(cdk2_esrt_activate(&esrt) == EFI_OUT_OF_RESOURCES &&
		!esrt.management_installed && f.writes == 0);
	memset(&f, 0, sizeof(f)); esrt.ready_event = NULL;
	f.install_status = EFI_DEVICE_ERROR;
	assert(cdk2_esrt_activate(&esrt) == EFI_DEVICE_ERROR &&
		!esrt.management_installed && esrt.ready_event == NULL && f.closes == 1);
	memset(&f, 0, sizeof(f)); esrt.ready_event = NULL;
	f.install_status = EFI_DEVICE_ERROR; f.close_status = EFI_WRITE_PROTECTED;
	assert(cdk2_esrt_activate(&esrt) == EFI_SUCCESS &&
		!esrt.management_installed && esrt.ready_event == (void *)0x1234 && f.closes == 1);
	memset(&f, 0, sizeof(f));
	esrt.locked = FALSE;
	esrt.ready_event = NULL;
	assert(cdk2_esrt_ready_to_boot(&esrt) == EFI_SUCCESS &&
		f.published_count == 0);
	return 0;
}
