/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>

#include "../src/modules/sata_controller/entry.c"

static unsigned int allocations;
static UINTN allocated_size;
static BOOLEAN canary_ok = TRUE;
static EFI_STATUS CDK2_MS_ABI test_allocate(UINT32 type, UINTN size, void **buffer)
{
	(void)type;
	*buffer = calloc(1, size + 1U);
	if (*buffer == NULL)
		return EFIERR(9);
	allocated_size = size;
	*((UINT8 *)*buffer + size) = 0xa5U;
	allocations++;
	return EFI_SUCCESS;
}
static EFI_STATUS CDK2_MS_ABI test_free(void *buffer)
{
	if (*((UINT8 *)buffer + allocated_size) != 0xa5U)
		canary_ok = FALSE;
	free(buffer);
	allocations--;
	return EFI_SUCCESS;
}

static int check(int condition, const char *message)
{
	if (!condition)
		fprintf(stderr, "sata entry: %s\n", message);
	return !condition;
}

int main(void)
{
	struct boot_services services = { 0 };
	struct context context = { 0 };
	struct collective *result = NULL;
	CHAR16 *driver_name = NULL;
	struct cdk2_ata_identify identify = { 2U << 8, 2U, 3U, 120U, 0U };
	int failures = 0;

	services.allocate_pool = test_allocate;
	services.free_pool = test_free;
	bs = &services;
	failures += check(get_name(&component, "eng", &driver_name) == EFI_SUCCESS,
		"ComponentName accepts eng");
	failures += check(get_name(&component, "en", &driver_name) == EFI_UNSUPPORTED,
		"ComponentName rejects en");
	failures += check(get_name(&component2, "en", &driver_name) == EFI_SUCCESS,
		"ComponentName2 accepts en");
	failures += check(get_name(&component2, "eng", &driver_name) == EFI_UNSUPPORTED,
		"ComponentName2 rejects eng");
	failures += check(cdk2_sata_controller_init(&context.controller,
		&(struct cdk2_sata_geometry){ 1U, 1U, FALSE }) == EFI_SUCCESS,
		"controller init");
	failures += check(cdk2_sata_submit(&context.controller, 0, 0, &identify) ==
		EFI_SUCCESS, "identify submit");
	failures += check(calculate(&context.ide, 0, 0, &result) == EFI_SUCCESS &&
		result != NULL && result->pio.valid && !result->udma.valid,
		"first CalculateMode returns allocated partial collective");
	failures += check(allocated_size == 44U, "collective uses canonical 44-byte ABI");
	if (result != NULL)
		test_free(result);
	failures += check(allocations == 0, "collective ownership balanced");
	failures += check(canary_ok, "collective initialization stays within allocation");
	managed = NULL;
	failures += check(get_controller_name(&component, (void *)1, NULL, "eng",
		&driver_name) == EFI_UNSUPPORTED, "unmanaged controller rejected");
	return failures != 0;
}
